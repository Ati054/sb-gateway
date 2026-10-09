package policydns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// FreshResolverConfig describes one encrypted recursive upstream. It is kept
// separate from policy DNS lanes because an ACME pre-check must never use a
// cached answer, especially a negative answer created before a TXT record.
type FreshResolverConfig struct {
	Type        string
	Server      string
	ServerName  string
	ServerPort  int
	Path        string
	DoTFallback bool
}

type FreshResolverOptions struct {
	Workers     int
	TCPSessions int
	Timeout     time.Duration
}

// FreshResolver is a short-lived loopback DNS bridge. Every accepted request
// reaches the selected encrypted upstream; there is deliberately no shared or
// in-process cache.
type FreshResolver struct {
	address  string
	ctx      context.Context
	cancel   context.CancelFunc
	timeout  time.Duration
	upstream upstream
	limit    chan struct{}

	packet   net.PacketConn
	listener net.Listener
	udp      *dns.Server
	tcp      *dns.Server

	closeOnce sync.Once
}

type freshLimitedListener struct {
	net.Listener
	limit chan struct{}
}

type freshLimitedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (listener *freshLimitedListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case listener.limit <- struct{}{}:
			return &freshLimitedConn{Conn: connection, release: func() { <-listener.limit }}, nil
		default:
			_ = connection.Close()
		}
	}
}

func (connection *freshLimitedConn) Close() error {
	err := connection.Conn.Close()
	connection.once.Do(connection.release)
	return err
}

func StartFreshResolver(ctx context.Context, config FreshResolverConfig, options FreshResolverOptions) (*FreshResolver, error) {
	return startFreshResolver(ctx, config, options, newUpstream)
}

func startFreshResolver(ctx context.Context, config FreshResolverConfig, options FreshResolverOptions, createUpstream func(serverConfig, time.Duration) (upstream, error)) (*FreshResolver, error) {
	if err := validateFreshResolverConfig(config); err != nil {
		return nil, err
	}
	if options.Workers < 1 || options.Workers > 16 || options.TCPSessions < 1 || options.TCPSessions > 8 || options.Timeout < time.Second || options.Timeout > 30*time.Second {
		return nil, errors.New("invalid fresh resolver limits")
	}
	resolver, err := createUpstream(serverConfig{
		Type:        config.Type,
		Server:      config.Server,
		ServerName:  config.ServerName,
		ServerPort:  config.ServerPort,
		Path:        config.Path,
		DoTFallback: config.DoTFallback,
	}, options.Timeout)
	if err != nil {
		return nil, err
	}
	packet, listener, err := listenFreshResolverSockets(net.Listen, net.ListenPacket)
	if err != nil {
		resolver.close()
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	forwarder := &FreshResolver{
		address:  listener.Addr().String(),
		ctx:      child,
		cancel:   cancel,
		timeout:  options.Timeout,
		upstream: resolver,
		limit:    make(chan struct{}, options.Workers),
		packet:   packet,
		listener: listener,
	}
	handler := dns.HandlerFunc(forwarder.handle)
	forwarder.udp = &dns.Server{
		PacketConn:    packet,
		Handler:       handler,
		ReadTimeout:   options.Timeout,
		WriteTimeout:  options.Timeout,
		UDPSize:       maxDNSMessage,
		MaxTCPQueries: 1,
	}
	forwarder.tcp = &dns.Server{
		Listener:      &freshLimitedListener{Listener: listener, limit: make(chan struct{}, options.TCPSessions)},
		Handler:       handler,
		ReadTimeout:   options.Timeout,
		WriteTimeout:  options.Timeout,
		IdleTimeout:   func() time.Duration { return options.Timeout },
		MaxTCPQueries: 1,
	}
	go func() { _ = forwarder.udp.ActivateAndServe() }()
	go func() { _ = forwarder.tcp.ActivateAndServe() }()
	go func() {
		<-child.Done()
		_ = forwarder.Close()
	}()
	return forwarder, nil
}

func listenFreshResolverSockets(
	listenTCP func(string, string) (net.Listener, error),
	listenUDP func(string, string) (net.PacketConn, error),
) (net.PacketConn, net.Listener, error) {
	var lastError error
	// Choose a TCP-valid port first; a free UDP port may still be occupied or
	// reserved for TCP. Retry boundedly if the matching UDP port is unavailable.
	for range 8 {
		listener, err := listenTCP("tcp4", "127.0.0.1:0")
		if err != nil {
			return nil, nil, fmt.Errorf("listen fresh resolver TCP: %w", err)
		}
		packet, err := listenUDP("udp4", listener.Addr().String())
		if err == nil {
			return packet, listener, nil
		}
		_ = listener.Close()
		lastError = err
	}
	return nil, nil, fmt.Errorf("listen fresh resolver UDP: %w", lastError)
}

func validateFreshResolverConfig(config FreshResolverConfig) error {
	address, err := netip.ParseAddr(config.Server)
	if err != nil || !address.IsValid() || config.ServerName == "" || len(config.ServerName) > 253 || config.ServerPort < 1 || config.ServerPort > 65535 {
		return errors.New("invalid fresh resolver configuration")
	}
	switch config.Type {
	case "https":
		if config.Path != "/dns-query" {
			return errors.New("invalid fresh resolver configuration")
		}
	case "tls":
		if config.Path != "" || config.DoTFallback {
			return errors.New("invalid fresh resolver configuration")
		}
	default:
		return errors.New("invalid fresh resolver configuration")
	}
	return nil
}

func (resolver *FreshResolver) Address() string { return resolver.address }

// LookupCNAME resolves through this forwarder's no-cache loopback lane. It is
// used by the ACME-DNS delegation check, which must make the same fresh lookup
// as lego's DNS-01 pre-check.
func (resolver *FreshResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	lookup := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, resolver.address)
		},
	}
	return lookup.LookupCNAME(ctx, name)
}

func (resolver *FreshResolver) Close() error {
	resolver.closeOnce.Do(func() {
		resolver.cancel()
		_ = resolver.packet.Close()
		_ = resolver.listener.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), resolver.timeout)
		defer cancel()
		_ = resolver.udp.ShutdownContext(shutdown)
		_ = resolver.tcp.ShutdownContext(shutdown)
		resolver.upstream.close()
	})
	return nil
}

func (resolver *FreshResolver) handle(writer dns.ResponseWriter, request *dns.Msg) {
	if request == nil {
		return
	}
	if len(request.Question) != 1 || request.Response {
		resolver.reply(writer, request, dns.RcodeFormatError)
		return
	}
	select {
	case resolver.limit <- struct{}{}:
		defer func() { <-resolver.limit }()
	default:
		resolver.reply(writer, request, dns.RcodeServerFailure)
		return
	}
	query, err := request.Pack()
	if err != nil || len(query) > maxDNSMessage {
		resolver.reply(writer, request, dns.RcodeServerFailure)
		return
	}
	ctx, cancel := context.WithTimeout(resolver.ctx, resolver.timeout)
	defer cancel()
	responseBody, err := resolver.upstream.exchange(ctx, query)
	if err != nil || !matchingQuestion(query, responseBody) {
		resolver.reply(writer, request, dns.RcodeServerFailure)
		return
	}
	response := new(dns.Msg)
	if response.Unpack(responseBody) != nil {
		resolver.reply(writer, request, dns.RcodeServerFailure)
		return
	}
	response.Id = request.Id
	if writer.LocalAddr().Network() == "udp" {
		response.Truncate(udpResponseLimit(request))
	}
	_ = writer.WriteMsg(response)
}

func udpResponseLimit(request *dns.Msg) int {
	limit := dns.MinMsgSize
	if option := request.IsEdns0(); option != nil && option.UDPSize() >= dns.MinMsgSize {
		limit = int(option.UDPSize())
	}
	if limit > maxDNSMessage {
		return maxDNSMessage
	}
	return limit
}

func (resolver *FreshResolver) reply(writer dns.ResponseWriter, request *dns.Msg, code int) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Rcode = code
	_ = writer.WriteMsg(response)
}
