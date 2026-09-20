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
)

type Options struct {
	Workers      int
	TCPSessions  int
	CacheEntries int
	CacheBytes   int
	StaleTTL     time.Duration
}

func OptionsFromEnvironment() Options {
	return Options{
		Workers:      boundedEnvironmentInt("SB_POLICY_DNS_WORKERS", 16, 2, 64),
		TCPSessions:  boundedEnvironmentInt("SB_POLICY_DNS_TCP_SESSIONS", 8, 2, 32),
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
	runtimeMu  sync.RWMutex
	runtime    *runtime
	limit      chan struct{}
	tcpLimit   chan struct{}
	closers    []io.Closer
	wait       sync.WaitGroup
	udpBuffers sync.Pool
}

func Serve(ctx context.Context, path string, options Options) error {
	current, err := waitForRuntime(ctx, path, options)
	if err != nil {
		return err
	}
	service := &service{
		runtime:  current,
		limit:    make(chan struct{}, options.Workers),
		tcpLimit: make(chan struct{}, options.TCPSessions),
	}
	service.udpBuffers.New = func() any { return make([]byte, maxDNSMessage) }
	if err := service.listen(current); err != nil {
		current.close()
		service.close()
		return err
	}
	defer func() {
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
		listener, err := net.Listen("tcp", address)
		if err != nil {
			packet.Close()
			return fmt.Errorf("listen TCP lane %s: %w", lane.id, err)
		}
		service.closers = append(service.closers, packet, listener)
		service.wait.Add(2)
		go service.serveUDP(lane.id, packet)
		go service.serveTCP(lane.id, listener)
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

func (service *service) resolve(laneID string, query []byte) ([]byte, error) {
	service.runtimeMu.RLock()
	defer service.runtimeMu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), service.runtime.timeout)
	defer cancel()
	return service.runtime.resolve(ctx, laneID, query)
}

func (service *service) closeRuntime() {
	service.runtimeMu.Lock()
	defer service.runtimeMu.Unlock()
	service.runtime.close()
}

func (service *service) serveUDP(laneID string, connection net.PacketConn) {
	defer service.wait.Done()
	for {
		buffer := service.udpBuffers.Get().([]byte)
		size, address, err := connection.ReadFrom(buffer)
		if err != nil {
			service.udpBuffers.Put(buffer)
			return
		}
		query := buffer[:size]
		if !service.acquire() {
			_, _ = connection.WriteTo(refusal(query, true), address)
			service.udpBuffers.Put(buffer)
			continue
		}
		go func(query, buffer []byte, address net.Addr) {
			defer service.release()
			defer service.udpBuffers.Put(buffer)
			response, resolveErr := service.resolve(laneID, query)
			if resolveErr == nil && len(response) > 0 {
				_, _ = connection.WriteTo(response, address)
			}
		}(query, buffer, address)
	}
}

func (service *service) serveTCP(laneID string, listener net.Listener) {
	defer service.wait.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		if !service.acquireTCP() {
			_ = connection.Close()
			continue
		}
		go func() {
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
				if !service.acquire() {
					answer := refusal(query, true)
					frame := make([]byte, 2+len(answer))
					binary.BigEndian.PutUint16(frame[:2], uint16(len(answer)))
					copy(frame[2:], answer)
					if err := writeAll(connection, frame); err != nil {
						return
					}
					continue
				}
				answer, err := service.resolve(laneID, query)
				service.release()
				if err != nil || len(answer) > maxDNSMessage {
					return
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
