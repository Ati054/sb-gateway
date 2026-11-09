package policydns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/dnsroute"
	"github.com/sb-gateway/sb-gateway/internal/netpolicy"
)

type Options struct {
	// RouteEpochs is wired by the in-process appliance, never inferred in standalone mode.
	RouteEpochs  *dnsroute.Registry
	Workers      int
	TCPSessions  int
	CacheEntries int
	CacheBytes   int
	StaleTTL     time.Duration
}

func OptionsFromEnvironment() Options {
	workers := boundedEnvironmentInt("SB_POLICY_DNS_WORKERS", 32, 2, 64)
	// Idle TCP sessions do not occupy upstream workers. Keep enough transport
	// capacity for ordinary bursts while preserving the explicit session cap.
	defaultTCPSessions := min(32, max(8, workers))
	return Options{
		Workers:      workers,
		TCPSessions:  boundedEnvironmentInt("SB_POLICY_DNS_TCP_SESSIONS", defaultTCPSessions, 2, 32),
		CacheEntries: boundedEnvironmentInt("SB_POLICY_DNS_CACHE_ENTRIES", 4096, 256, 65536),
		CacheBytes:   boundedEnvironmentInt("SB_POLICY_DNS_CACHE_BYTES", 4*1024*1024, 1024*1024, 64*1024*1024),
		StaleTTL:     boundedEnvironmentDuration("SB_POLICY_DNS_STALE_SECONDS", 3600, 0, 86400),
	}
}

func boundedEnvironmentDuration(name string, fallback, minimum, maximum int) time.Duration {
	return time.Duration(boundedEnvironmentInt(name, fallback, minimum, maximum)) * time.Second
}

func boundedEnvironmentInt(name string, fallback, minimum, maximum int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

type service struct {
	ctx           context.Context
	runtimeMu     sync.RWMutex
	runtime       *runtime
	limit         chan struct{}
	pending       chan struct{}
	tcpLimit      chan struct{}
	closers       []io.Closer
	wait          sync.WaitGroup
	udpBuffers    sync.Pool
	admissionMu   sync.Mutex
	queryBytes    int
	sharedQueries int
	routes        map[string]*routeBudget
}

func Serve(ctx context.Context, path string, options Options) error {
	current, err := waitForRuntime(ctx, path, options)
	if err != nil {
		return err
	}
	current.attachRouteEpochs(options.RouteEpochs)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	service := &service{
		ctx:     ctx,
		runtime: current,
		limit:   make(chan struct{}, options.Workers),
		// Bound burst buffering without increasing concurrent upstream work.
		pending:  make(chan struct{}, options.Workers*4),
		tcpLimit: make(chan struct{}, options.TCPSessions),
	}
	service.udpBuffers.New = func() any { return new([maxDNSMessage]byte) }
	if err := service.listen(current); err != nil {
		cancel()
		service.close()
		service.closeRuntime()
		return err
	}
	defer func() {
		cancel()
		service.close()
		service.closeRuntime()
	}()
	log.Printf(
		"policy-dns: ready lanes=%d workers=%d tcp_sessions=%d cache_entries=%d cache_bytes=%d",
		len(current.ordered), options.Workers, options.TCPSessions, options.CacheEntries, options.CacheBytes,
	)

	<-ctx.Done()
	return nil
}

func waitForRuntime(
	ctx context.Context,
	path string,
	options Options,
) (*runtime, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		current, err := loadRuntime(path, options.CacheEntries, options.CacheBytes, options.StaleTTL)
		if err == nil {
			return current, nil
		}
		if !errors.Is(err, errNoLanes) && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (service *service) listen(current *runtime) error {
	for _, lane := range current.ordered {
		address := net.JoinHostPort(lane.host, strconv.Itoa(lane.port))
		packet, err := net.ListenPacket("udp", address)
		if err != nil {
			return fmt.Errorf("listen UDP lane %s: %w", lane.id, err)
		}
		listener, err := netpolicy.ListenTCP("tcp", address)
		if err != nil {
			packet.Close()
			return fmt.Errorf("listen TCP lane %s: %w", lane.id, err)
		}
		service.closers = append(service.closers, packet, listener)
		service.wait.Add(2)
		go service.serveUDP(lane.id, packet)
		go service.serveTCP(lane.id, listener)
	}
	if current.managed != nil {
		for _, endpoint := range current.managed.listeners {
			address := net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
			packet, err := net.ListenPacket("udp", address)
			if err != nil {
				return fmt.Errorf("listen managed DNS UDP: %w", err)
			}
			listener, err := netpolicy.ListenTCP("tcp", address)
			if err != nil {
				_ = packet.Close()
				return fmt.Errorf("listen managed DNS TCP: %w", err)
			}
			service.closers = append(service.closers, packet, listener)
			service.wait.Add(2)
			go service.serveUDPSource("", packet, true)
			go service.serveTCPSource("", listener, true)
		}
	}
	return nil
}

func (service *service) close() {
	for _, closer := range service.closers {
		_ = closer.Close()
	}
	service.wait.Wait()
}

func (service *service) acquire() bool {
	select {
	case service.limit <- struct{}{}:
		return true
	default:
		return false
	}
}

func (service *service) release() {
	<-service.limit
}

func (service *service) acquireTCP() bool {
	select {
	case service.tcpLimit <- struct{}{}:
		return true
	default:
		return false
	}
}

func (service *service) releaseTCP() {
	<-service.tcpLimit
}

func (service *service) overloadResponse(laneID string, query []byte) []byte {
	if answer, local := service.localAnswer(laneID, query); local {
		return answer
	}
	return refusal(query, true)
}

func (service *service) context() context.Context {
	if service.ctx != nil {
		return service.ctx
	}
	return context.Background()
}

func (service *service) closeRuntime() {
	service.runtimeMu.Lock()
	defer service.runtimeMu.Unlock()
	service.runtime.close()
}

func (service *service) serveUDP(laneID string, connection net.PacketConn) {
	service.serveUDPSource(laneID, connection, false)
}

func (service *service) managedLane(address net.Addr) (string, bool) {
	service.runtimeMu.RLock()
	defer service.runtimeMu.RUnlock()
	return service.runtime.managedLane(managedPeer(address))
}

func (service *service) serveUDPSource(laneID string, connection net.PacketConn, managed bool) {
	defer service.wait.Done()
	buffer := service.udpBuffers.Get().(*[maxDNSMessage]byte)
	defer service.udpBuffers.Put(buffer)
	for {
		size, address, err := connection.ReadFrom(buffer[:])
		if err != nil {
			return
		}
		selected := laneID
		if managed {
			var ok bool
			selected, ok = service.managedLane(address)
			if !ok {
				continue
			}
		}
		query := buffer[:size]
		admission := service.admitQuery(selected, query)
		if admission.immediate {
			if len(admission.answer) > 0 {
				_, _ = connection.WriteTo(admission.answer, address)
			}
			continue
		}
		// Reuse the listener buffer; handlers retain only their actual packet.
		query = append([]byte(nil), query...)
		service.wait.Add(1)
		go func(admission queryAdmission, query []byte, address net.Addr, selected string) {
			defer service.wait.Done()
			response, resolveErr := service.resolveAdmitted(admission, selected, query)
			if resolveErr == nil && len(response) > 0 {
				_, _ = connection.WriteTo(response, address)
			}
		}(admission, query, address, selected)
	}
}

func (service *service) serveTCP(laneID string, listener net.Listener) {
	service.serveTCPSource(laneID, listener, false)
}

func (service *service) serveTCPSource(laneID string, listener net.Listener, managed bool) {
	defer service.wait.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		if managed {
			if _, ok := service.managedLane(connection.RemoteAddr()); !ok {
				_ = connection.Close()
				continue
			}
		}
		if !service.acquireTCP() {
			_ = connection.Close()
			continue
		}
		service.wait.Add(1)
		go func() {
			defer service.wait.Done()
			stop := context.AfterFunc(service.context(), func() { _ = connection.Close() })
			defer stop()
			defer service.releaseTCP()
			defer connection.Close()
			header := make([]byte, 2)
			// DNS-over-TCP is persistent. Bound one connection to 64 messages so
			// an idle or abusive peer cannot retain a session slot indefinitely.
			for messages := 0; messages < 64; messages++ {
				service.runtimeMu.RLock()
				timeout := service.runtime.timeout
				service.runtimeMu.RUnlock()
				_ = connection.SetDeadline(time.Now().Add(timeout))
				if _, err := io.ReadFull(connection, header); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(header))
				if size < 12 {
					return
				}
				query := make([]byte, size)
				if _, err := io.ReadFull(connection, query); err != nil {
					return
				}
				selected := laneID
				if managed {
					var ok bool
					selected, ok = service.managedLane(connection.RemoteAddr())
					if !ok {
						return
					}
				}
				admission := service.admitQuery(selected, query)
				_ = connection.SetDeadline(admission.deadline)
				answer, err := service.resolveAdmitted(admission, selected, query)
				if err != nil || len(answer) > maxDNSMessage {
					return
				}
				if len(answer) == 0 {
					continue // Ignored responses must not create empty TCP frames.
				}
				frame := make([]byte, 2+len(answer))
				binary.BigEndian.PutUint16(frame[:2], uint16(len(answer)))
				copy(frame[2:], answer)
				if err := writeAll(connection, frame); err != nil {
					return
				}
			}
		}()
	}
}
