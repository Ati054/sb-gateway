package policydns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type upstream interface {
	exchange(context.Context, []byte) ([]byte, error)
	close()
}

type udpUpstream struct {
	address string
	timeout time.Duration
	poolMu  sync.Mutex
	idle    chan net.Conn
	closed  bool
}

type tcpUpstream struct {
	address   string
	timeout   time.Duration
	tlsConfig *tls.Config
	poolMu    sync.Mutex
	idle      chan net.Conn
	closed    bool
}

type dohUpstream struct {
	poolMu    sync.Mutex
	closed    bool
	client    *http.Client
	transport *http.Transport
	url       string
	fallback  upstream
}

var udpResponseBuffers = sync.Pool{
	New: func() any { return new([maxDNSMessage]byte) },
}

func newUpstream(config serverConfig, timeout time.Duration) (upstream, error) {
	port := config.ServerPort
	switch config.Type {
	case "udp":
		if port == 0 {
			port = 53
		}
		if config.Server == "" {
			return nil, errors.New("UDP server is empty")
		}
		return &udpUpstream{
			address: net.JoinHostPort(config.Server, strconv.Itoa(port)),
			timeout: timeout,
			idle:    make(chan net.Conn, 4),
		}, nil
	case "tls":
		if port == 0 {
			port = 853
		}
		return newTCPUpstream(config, port, timeout, true)
	case "https":
		return newDoHUpstream(config, timeout)
	default:
		return nil, fmt.Errorf("unsupported upstream type %q", config.Type)
	}
}

func newTCPUpstream(
	config serverConfig,
	port int,
	timeout time.Duration,
	encrypted bool,
) (upstream, error) {
	host := config.TunnelHost
	if host == "" {
		host = config.Server
	}
	if config.TunnelPort != 0 {
		port = config.TunnelPort
	}
	if host == "" || port == 0 {
		return nil, errors.New("TCP upstream endpoint is incomplete")
	}
	result := &tcpUpstream{
		address: net.JoinHostPort(host, strconv.Itoa(port)),
		timeout: timeout,
		idle:    make(chan net.Conn, 4),
	}
	if encrypted {
		if config.ServerName == "" {
			return nil, errors.New("DoT server name is empty")
		}
		result.tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: config.ServerName,
		}
	}
	return result, nil
}

func newDoHUpstream(config serverConfig, timeout time.Duration) (upstream, error) {
	if config.ServerName == "" {
		return nil, errors.New("DoH server name is empty")
	}
	port := config.TunnelPort
	host := config.TunnelHost
	if host == "" {
		host = config.Server
		port = config.ServerPort
	}
	if port == 0 {
		port = 443
	}
	if host == "" {
		return nil, errors.New("DoH endpoint is incomplete")
	}
	dialAddress := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: config.ServerName,
			NextProtos: []string{"h2", "http/1.1"},
		},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", dialAddress)
		},
	}
	path := config.Path
	if path == "" {
		path = "/dns-query"
	}
	result := &dohUpstream{
		transport: transport,
		client: &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("DoH redirect is not allowed")
		}},
		url: "https://" + config.ServerName + path,
	}
	if config.DoTFallback {
		fallbackConfig := config
		fallbackConfig.TunnelHost = ""
		fallbackConfig.TunnelPort = 0
		fallback, err := newTCPUpstream(fallbackConfig, 853, timeout, true)
		if err != nil {
			return nil, err
		}
		result.fallback = fallback
	}
	return result, nil
}

func (upstream *udpUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	var lastError error
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		connection, err := upstream.borrow(ctx)
		if err != nil {
			return nil, err
		}
		response, err := upstream.exchangeOnConnection(ctx, connection, query)
		if contextErr := ctx.Err(); contextErr != nil {
			_ = connection.Close()
			return nil, contextErr
		}
		if err == nil {
			upstream.release(connection)
			return response, nil
		}
		lastError = err
		_ = connection.Close()
	}
	return nil, lastError
}

func (upstream *udpUpstream) borrow(ctx context.Context) (net.Conn, error) {
	upstream.poolMu.Lock()
	if upstream.closed {
		upstream.poolMu.Unlock()
		return nil, errors.New("UDP upstream is closed")
	}
	select {
	case connection := <-upstream.idle:
		upstream.poolMu.Unlock()
		return connection, nil
	default:
		upstream.poolMu.Unlock()
	}
	dialer := net.Dialer{Timeout: upstream.timeout}
	return dialer.DialContext(ctx, "udp", upstream.address)
}

func (upstream *udpUpstream) exchangeOnConnection(ctx context.Context, connection net.Conn, query []byte) ([]byte, error) {
	stop, err := bindExchangeContext(ctx, connection, upstream.timeout)
	if err != nil {
		return nil, err
	}
	defer stop()
	if _, err := connection.Write(query); err != nil {
		return nil, err
	}
	buffer := udpResponseBuffers.Get().(*[maxDNSMessage]byte)
	size, err := connection.Read(buffer[:])
	if err != nil {
		udpResponseBuffers.Put(buffer)
		return nil, err
	}
	response := append([]byte(nil), buffer[:size]...)
	udpResponseBuffers.Put(buffer)
	if len(response) >= 4 && binary.BigEndian.Uint16(response[2:4])&0x0200 != 0 {
		fallback := &tcpUpstream{address: upstream.address, timeout: upstream.timeout, idle: make(chan net.Conn, 1)}
		defer fallback.close()
		return fallback.exchange(ctx, query)
	}
	return response, nil
}

func (upstream *udpUpstream) release(connection net.Conn) {
	_ = connection.SetDeadline(time.Time{})
	upstream.poolMu.Lock()
	defer upstream.poolMu.Unlock()
	if upstream.closed {
		_ = connection.Close()
		return
	}
	select {
	case upstream.idle <- connection:
	default:
		_ = connection.Close()
	}
}

func (upstream *udpUpstream) close() {
	upstream.poolMu.Lock()
	defer upstream.poolMu.Unlock()
	if upstream.closed {
		return
	}
	upstream.closed = true
	for {
		select {
		case connection := <-upstream.idle:
			_ = connection.Close()
		default:
			return
		}
	}
}

func (upstream *tcpUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	var lastError error
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		connection, err := upstream.borrow(ctx)
		if err != nil {
			return nil, err
		}
		response, err := upstream.exchangeOnConnection(ctx, connection, query)
		if contextErr := ctx.Err(); contextErr != nil {
			_ = connection.Close()
			return nil, contextErr
		}
		if err == nil {
			upstream.release(connection)
			return response, nil
		}
		lastError = err
		_ = connection.Close()
	}
	return nil, lastError
}

func (upstream *tcpUpstream) borrow(ctx context.Context) (net.Conn, error) {
	upstream.poolMu.Lock()
	if upstream.closed {
		upstream.poolMu.Unlock()
		return nil, errors.New("TCP upstream is closed")
	}
	select {
	case connection := <-upstream.idle:
		upstream.poolMu.Unlock()
		return connection, nil
	default:
		upstream.poolMu.Unlock()
	}

	dialer := &net.Dialer{Timeout: upstream.timeout}
	connection, err := dialer.DialContext(ctx, "tcp", upstream.address)
	if err != nil {
		return nil, err
	}
	if upstream.tlsConfig != nil {
		tlsConnection := tls.Client(connection, upstream.tlsConfig.Clone())
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return nil, err
		}
		connection = tlsConnection
	}
	upstream.poolMu.Lock()
	closed := upstream.closed
	upstream.poolMu.Unlock()
	if closed {
		_ = connection.Close()
		return nil, errors.New("TCP upstream is closed")
	}
	return connection, nil
}

func (upstream *tcpUpstream) exchangeOnConnection(
	ctx context.Context,
	connection net.Conn,
	query []byte,
) ([]byte, error) {
	stop, err := bindExchangeContext(ctx, connection, upstream.timeout)
	if err != nil {
		return nil, err
	}
	defer stop()
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if err := writeAll(connection, frame); err != nil {
		return nil, err
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header))
	response := make([]byte, size)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

// Join a running cancellation callback before a connection can return to its
// pool, so a late callback cannot interrupt the next query on that connection.
func bindExchangeContext(ctx context.Context, connection net.Conn, timeout time.Duration) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if ctx.Done() == nil {
		return func() {}, nil
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
		close(done)
	})
	return func() {
		if !stop() {
			<-done
		}
	}, nil
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func (upstream *tcpUpstream) release(connection net.Conn) {
	_ = connection.SetDeadline(time.Time{})
	upstream.poolMu.Lock()
	defer upstream.poolMu.Unlock()
	if upstream.closed {
		_ = connection.Close()
		return
	}
	select {
	case upstream.idle <- connection:
	default:
		_ = connection.Close()
	}
}

func (upstream *tcpUpstream) close() {
	upstream.poolMu.Lock()
	defer upstream.poolMu.Unlock()
	if upstream.closed {
		return
	}
	upstream.closed = true
	for {
		select {
		case connection := <-upstream.idle:
			_ = connection.Close()
		default:
			return
		}
	}
}

func (upstream *dohUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client, _, closed := upstream.dohSnapshot()
	if closed {
		return nil, context.Canceled
	}
	timeout := client.Timeout
	if timeout > 0 {
		queryCtx, cancelQuery := context.WithTimeout(ctx, timeout)
		defer cancelQuery()
		ctx = queryCtx
	}
	primaryCtx := ctx
	cancel := func() {}
	if upstream.fallback != nil {
		budget := timeout
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if budget <= 0 || remaining < budget {
				budget = remaining
			}
		}
		if budget > 0 {
			// Keep one third of the existing query deadline for encrypted fallback.
			primaryCtx, cancel = context.WithTimeout(ctx, budget-budget/3)
		}
	}
	response, err := upstream.exchangeDoH(primaryCtx, query)
	cancel()
	if err == nil || upstream.fallback == nil {
		return response, err
	}
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	response, fallbackErr := upstream.fallback.exchange(ctx, query)
	if fallbackErr != nil {
		return nil, errors.Join(err, fallbackErr)
	}
	return response, nil
}

func (upstream *dohUpstream) exchangeDoH(ctx context.Context, query []byte) ([]byte, error) {
	response, err := upstream.exchangeDoHOnce(ctx, query)
	if err == nil {
		return response, err
	}
	if ctx.Err() != nil || !dohConnectionClosed(err) {
		return nil, err
	}
	// A provider can retire a keep-alive connection between requests. Retry
	// once within the same deadline; never retry HTTP, DNS or TLS trust errors.
	return upstream.exchangeDoHOnce(ctx, query)
}

func dohConnectionClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)
}

func (upstream *dohUpstream) dohSnapshot() (*http.Client, *http.Transport, bool) {
	upstream.poolMu.Lock()
	defer upstream.poolMu.Unlock()
	return upstream.client, upstream.transport, upstream.closed
}

func (upstream *dohUpstream) finishDoH(transport *http.Transport, err error) {
	if transport == nil {
		return
	}
	var networkErr net.Error
	failed := dohConnectionClosed(err) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &networkErr) && networkErr.Timeout())
	upstream.poolMu.Lock()
	if failed && !upstream.closed && upstream.transport == transport {
		// Closing idle connections alone misses a timed-out HTTP/2 stream
		// whose asynchronous cleanup still marks the channel busy.
		next := transport.Clone()
		client := *upstream.client
		client.Transport = next
		upstream.transport, upstream.client = next, &client
	}
	retired := upstream.closed || upstream.transport != transport
	upstream.poolMu.Unlock()
	if retired {
		// Every finishing request drains its retired generation. Busy requests
		// remain intact; the last completion closes the remaining idle pool.
		transport.CloseIdleConnections()
	}
}

func (upstream *dohUpstream) exchangeDoHOnce(ctx context.Context, query []byte) (payload []byte, err error) {
	client, transport, closed := upstream.dohSnapshot()
	if closed {
		return nil, context.Canceled
	}
	defer func() { upstream.finishDoH(transport, err) }()
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, upstream.url, bytes.NewReader(query),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")
	// DNS queries are replayable. Allow Transport to retry a lost reused
	// connection without transmitting an idempotency header to the resolver.
	request.Header["Idempotency-Key"] = nil
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status %s", response.Status)
	}
	contentType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil || contentType != "application/dns-message" {
		return nil, errors.New("DoH response has unexpected content type")
	}
	payload, err = io.ReadAll(io.LimitReader(response.Body, maxDNSMessage+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxDNSMessage {
		return nil, errors.New("DoH response is too large")
	}
	if !matchingQuestion(query, payload) {
		return nil, errors.New("DoH response question mismatch")
	}
	return payload, nil
}

func (upstream *dohUpstream) close() {
	upstream.poolMu.Lock()
	upstream.closed = true
	transport := upstream.transport
	upstream.poolMu.Unlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
	if upstream.fallback != nil {
		upstream.fallback.close()
	}
}

func (runtime *runtime) resolve(
	ctx context.Context,
	laneID string,
	query []byte,
) ([]byte, error) {
	lane := runtime.lanes[laneID]
	if lane == nil {
		return nil, fmt.Errorf("unknown policy DNS lane %q", laneID)
	}
	name, err := questionName(query)
	if err != nil {
		return refusal(query, false), nil
	}
	target, rejected := lane.target(name)
	if rejected {
		return refusal(query, false), nil
	}
	server := runtime.servers[target]
	if server == nil {
		return refusal(query, false), nil
	}
	key, err := normalizedQueryKey(laneID, query)
	if err != nil {
		return refusal(query, false), nil
	}
	now := time.Now()
	if response, ok := runtime.cache.get(key, query[:2], now); ok {
		return response, nil
	}
	stale, hasStale := runtime.cache.getStale(key, query[:2], now)
	normalized, err := runtime.flights.do(ctx, key, func() ([]byte, error) {
		response, exchangeErr := server.exchange(ctx, query)
		if exchangeErr != nil {
			return nil, exchangeErr
		}
		if len(response) < 12 {
			return nil, errors.New("short upstream DNS response")
		}
		if !matchingQuestion(query, response) {
			return nil, errors.New("upstream DNS response question mismatch")
		}
		ttl := responseTTL(response)
		response[0], response[1] = 0, 0
		runtime.cache.putOwned(key, response, ttl, time.Now())
		return response, nil
	})
	if err != nil {
		if hasStale {
			return stale, nil
		}
		return refusal(query, true), nil
	}
	return responseWithID(normalized, query[:2]), nil
}

func matchingQuestion(query, response []byte) bool {
	if len(query) < 12 || len(response) < 12 ||
		binary.BigEndian.Uint16(query[0:2]) != binary.BigEndian.Uint16(response[0:2]) ||
		binary.BigEndian.Uint16(query[2:4])&0x8000 != 0 ||
		binary.BigEndian.Uint16(response[2:4])&0x8000 == 0 ||
		binary.BigEndian.Uint16(query[4:6]) != 1 ||
		binary.BigEndian.Uint16(response[4:6]) != 1 {
		return false
	}
	queryName, queryType, queryClass, queryOK := questionIdentity(query)
	responseName, responseType, responseClass, responseOK := questionIdentity(response)
	return queryOK && responseOK && queryName == responseName && queryType == responseType && queryClass == responseClass
}

func questionIdentity(message []byte) (string, uint16, uint16, bool) {
	name, end, ok := parseQuestionName(message)
	if !ok || end+4 > len(message) {
		return "", 0, 0, false
	}
	return name, binary.BigEndian.Uint16(message[end : end+2]), binary.BigEndian.Uint16(message[end+2 : end+4]), true
}

func questionName(message []byte) (string, error) {
	name, _, ok := parseQuestionName(message)
	if !ok {
		return "", errors.New("invalid DNS question")
	}
	return name, nil
}

func parseQuestionName(message []byte) (string, int, bool) {
	if len(message) < 12 {
		return "", 0, false
	}
	var name strings.Builder
	name.Grow(64)
	for offset := 12; ; {
		if offset >= len(message) {
			return "", 0, false
		}
		length := int(message[offset])
		offset++
		if length == 0 {
			return name.String(), offset, true
		}
		if length > 63 || length&0xC0 != 0 || offset+length > len(message) {
			return "", 0, false
		}
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		for _, character := range message[offset : offset+length] {
			if character >= 'A' && character <= 'Z' {
				character += 'a' - 'A'
			}
			name.WriteByte(character)
		}
		offset += length
	}
}

func refusal(query []byte, serverFailure bool) []byte {
	if len(query) < 12 {
		return nil
	}
	response := append([]byte(nil), query...)
	flags := binary.BigEndian.Uint16(response[2:4])
	flags = (flags | 0x8080) &^ 0x000f
	if serverFailure {
		flags |= 2
	} else {
		flags |= 5
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	for index := 6; index < 12; index++ {
		response[index] = 0
	}
	return response
}
