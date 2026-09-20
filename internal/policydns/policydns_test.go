package policydns

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dnsQuery(id uint16, name string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range splitLabels(name) {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, 0, 1, 0, 1)
	return message
}

func splitLabels(name string) []string {
	var result []string
	start := 0
	for index := 0; index <= len(name); index++ {
		if index == len(name) || name[index] == '.' {
			result = append(result, name[start:index])
			start = index + 1
		}
	}
	return result
}

func dnsAResponse(query []byte, ttl uint32) []byte {
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
		0x00, 0x04,
		192, 0, 2, 1,
	)
	return response
}

func dnsNXDomainResponse(query []byte, ttl, minimum uint32) []byte {
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8183)
	binary.BigEndian.PutUint16(response[8:10], 1)
	response = append(response,
		0xc0, 0x0c, // owner name
		0x00, 0x06, // SOA
		0x00, 0x01, // IN
		byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl),
		0x00, 0x16, // 22-byte RDATA
		0x00, // root MNAME
		0x00, // root RNAME
	)
	for _, value := range []uint32{1, 2, 3, 4, minimum} {
		response = binary.BigEndian.AppendUint32(response, value)
	}
	return response
}

func TestCompiledLanePreservesFirstMatch(t *testing.T) {
	lane, err := compileLane(laneConfig{
		ID: "lane", Host: "127.0.0.1", Port: 30000, Final: "wan",
		Rules: []ruleConfig{
			{DomainSuffix: []string{"example.com"}, Action: "route", Server: "vpn"},
			{Domain: []string{"api.example.com"}, Action: "route", Server: "wan"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	target, rejected := lane.target("api.example.com")
	if target != "vpn" || rejected {
		t.Fatalf("first match lost: target=%q rejected=%v", target, rejected)
	}
	if target, _ := lane.target("unrelated.test"); target != "wan" {
		t.Fatalf("unexpected final target %q", target)
	}
}

func TestResponseCacheRestoresPerClientTransactionID(t *testing.T) {
	cache := newResponseCache(4, 1<<20, time.Hour)
	query := dnsQuery(0x1111, "api.example.com")
	response := dnsAResponse(query, 60)
	cache.putOwned("key", response, time.Minute, time.Now())
	cached, ok := cache.get("key", []byte{0x22, 0x22}, time.Now())
	if !ok {
		t.Fatal("cache miss")
	}
	if got := binary.BigEndian.Uint16(cached[:2]); got != 0x2222 {
		t.Fatalf("transaction ID=%x", got)
	}
	if ttl := responseTTL(response); ttl != time.Minute {
		t.Fatalf("TTL=%s", ttl)
	}
}

func TestResponseCacheAgesTTLAndServesBoundedStale(t *testing.T) {
	cache := newResponseCache(4, 1<<20, time.Hour)
	query := dnsQuery(0x1111, "api.example.com")
	response := dnsAResponse(query, 60)
	base := time.Unix(1000, 0)
	cache.putOwned("key", response, time.Minute, base)

	cached, ok := cache.get("key", []byte{0x22, 0x22}, base.Add(10*time.Second))
	if !ok || responseTTL(cached) != 50*time.Second {
		t.Fatalf("aged cache response: ok=%v TTL=%s", ok, responseTTL(cached))
	}
	if _, ok := cache.get("key", query[:2], base.Add(61*time.Second)); ok {
		t.Fatal("expired response remained fresh")
	}
	stale, ok := cache.getStale("key", []byte{0x33, 0x33}, base.Add(61*time.Second))
	if !ok || responseTTL(stale) != 30*time.Second {
		t.Fatalf("stale cache response: ok=%v TTL=%s", ok, responseTTL(stale))
	}
}

func TestResponseCacheHonorsMemoryBudget(t *testing.T) {
	query := dnsQuery(1, "example.com")
	response := dnsAResponse(query, 60)
	budget := 128 + len("a") + len(response)
	cache := newResponseCache(10, budget, time.Hour)
	cache.putOwned("a", response, time.Minute, time.Now())
	cache.putOwned("b", dnsAResponse(query, 60), time.Minute, time.Now())
	if _, ok := cache.get("a", query[:2], time.Now()); ok {
		t.Fatal("oldest entry survived memory-budget eviction")
	}
	if _, ok := cache.get("b", query[:2], time.Now()); !ok {
		t.Fatal("newest entry was evicted")
	}
	if cache.used > cache.byteLimit {
		t.Fatalf("cache uses %d bytes with %d-byte limit", cache.used, cache.byteLimit)
	}
}

type countingUpstream struct {
	calls atomic.Int32
	wait  chan struct{}
	err   error
}

func (upstream *countingUpstream) exchange(_ context.Context, query []byte) ([]byte, error) {
	upstream.calls.Add(1)
	if upstream.wait != nil {
		<-upstream.wait
	}
	if upstream.err != nil {
		return nil, upstream.err
	}
	return dnsAResponse(query, 60), nil
}

func (upstream *countingUpstream) close() {}

func TestRuntimeCachesAndCoalescesDuplicateQueries(t *testing.T) {
	backend := &countingUpstream{wait: make(chan struct{})}
	compiledLane := &lane{
		id: "lane", final: "wan",
		exact:  map[string]ruleDecision{},
		suffix: map[string]ruleDecision{},
	}
	runtime := &runtime{
		servers: map[string]upstream{"wan": backend},
		lanes:   map[string]*lane{"lane": compiledLane},
		ordered: []*lane{compiledLane},
		cache:   newResponseCache(16, 1<<20, time.Hour),
	}
	queries := [][]byte{
		dnsQuery(1, "api.example.com"),
		dnsQuery(2, "api.example.com"),
	}
	var wait sync.WaitGroup
	wait.Add(len(queries))
	results := make([][]byte, len(queries))
	for index := range queries {
		go func(index int) {
			defer wait.Done()
			results[index], _ = runtime.resolve(context.Background(), "lane", queries[index])
		}(index)
	}
	time.Sleep(10 * time.Millisecond)
	close(backend.wait)
	wait.Wait()
	if calls := backend.calls.Load(); calls != 1 {
		t.Fatalf("upstream calls=%d", calls)
	}
	for index, response := range results {
		if got := binary.BigEndian.Uint16(response[:2]); got != uint16(index+1) {
			t.Fatalf("response %d transaction ID=%d", index, got)
		}
	}
	third, err := runtime.resolve(
		context.Background(), "lane", dnsQuery(3, "api.example.com"),
	)
	if err != nil || binary.BigEndian.Uint16(third[:2]) != 3 {
		t.Fatalf("cached third response: id=%d err=%v", binary.BigEndian.Uint16(third[:2]), err)
	}
	if calls := backend.calls.Load(); calls != 1 {
		t.Fatalf("cached upstream calls=%d", calls)
	}
}

func TestResponseTTLIsBounded(t *testing.T) {
	query := dnsQuery(1, "example.com")
	if ttl := responseTTL(dnsAResponse(query, 3600)); ttl != 5*time.Minute {
		t.Fatalf("bounded TTL=%s", ttl)
	}
}

func TestResponseTTLCachesNegativeSOA(t *testing.T) {
	query := dnsQuery(1, "missing.example.com")
	if ttl := responseTTL(dnsNXDomainResponse(query, 120, 45)); ttl != 45*time.Second {
		t.Fatalf("negative TTL=%s", ttl)
	}
	failed := dnsNXDomainResponse(query, 120, 45)
	binary.BigEndian.PutUint16(failed[2:4], 0x8182)
	if ttl := responseTTL(failed); ttl != 0 {
		t.Fatalf("SERVFAIL TTL=%s", ttl)
	}
}

func TestMatchingQuestionRejectsSpoofedResponse(t *testing.T) {
	query := dnsQuery(1, "example.com")
	if !matchingQuestion(query, dnsAResponse(query, 60)) {
		t.Fatal("matching response rejected")
	}
	wrongID := dnsAResponse(query, 60)
	binary.BigEndian.PutUint16(wrongID[:2], 2)
	if matchingQuestion(query, wrongID) {
		t.Fatal("response with wrong transaction ID accepted")
	}
	notResponse := append([]byte(nil), query...)
	if matchingQuestion(query, notResponse) {
		t.Fatal("query accepted as a response")
	}
}

func TestRuntimeUsesStaleOnlyWhenUpstreamFails(t *testing.T) {
	backend := &countingUpstream{err: errors.New("upstream unavailable")}
	compiledLane := &lane{id: "lane", final: "wan", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	runtime := &runtime{
		servers: map[string]upstream{"wan": backend},
		lanes:   map[string]*lane{"lane": compiledLane},
		ordered: []*lane{compiledLane},
		cache:   newResponseCache(4, 1<<20, time.Hour),
	}
	query := dnsQuery(7, "example.com")
	key, err := normalizedQueryKey("lane", query)
	if err != nil {
		t.Fatal(err)
	}
	runtime.cache.putOwned(key, dnsAResponse(query, 60), time.Second, time.Now().Add(-2*time.Second))
	response, err := runtime.resolve(context.Background(), "lane", query)
	if err != nil {
		t.Fatal(err)
	}
	if responseTTL(response) != 30*time.Second || backend.calls.Load() != 1 {
		t.Fatalf("fallback TTL=%s upstream calls=%d", responseTTL(response), backend.calls.Load())
	}
}

func TestUDPUpstreamReusesConnectedSocket(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addresses := make(chan string, 2)
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, maxDNSMessage)
		for request := 0; request < 2; request++ {
			size, address, readErr := listener.ReadFromUDP(buffer)
			if readErr != nil {
				serverDone <- readErr
				return
			}
			addresses <- address.String()
			if _, writeErr := listener.WriteToUDP(dnsAResponse(buffer[:size], 60), address); writeErr != nil {
				serverDone <- writeErr
				return
			}
		}
		serverDone <- nil
	}()

	upstream := &udpUpstream{address: listener.LocalAddr().String(), timeout: 2 * time.Second, idle: make(chan net.Conn, 4)}
	defer upstream.close()
	for id := uint16(1); id <= 2; id++ {
		if _, err := upstream.exchange(context.Background(), dnsQuery(id, "example.com")); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	first, second := <-addresses, <-addresses
	if first != second {
		t.Fatalf("UDP source changed: %s then %s", first, second)
	}
}

func TestDoHUsesHTTP2AndReusesTLSConnection(t *testing.T) {
	var protocol atomic.Int32
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		protocol.Store(int32(request.ProtoMajor))
		query, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(dnsAResponse(query, 60))
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	configured, err := newDoHUpstream(serverConfig{
		Type: "https", ServerName: "example.com",
		TunnelHost: host, TunnelPort: port, Path: "/dns-query",
	}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	doh := configured.(*dohUpstream)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	doh.transport.TLSClientConfig.RootCAs = roots
	defer doh.close()
	for id := uint16(1); id <= 2; id++ {
		if _, err := doh.exchange(context.Background(), dnsQuery(id, "example.com")); err != nil {
			t.Fatal(err)
		}
	}
	if got := protocol.Load(); got != 2 {
		t.Fatalf("DoH protocol HTTP/%d", got)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("TLS connections=%d", got)
	}
}

func TestTCPUpstreamReusesPersistentConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := atomic.Int32{}
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		accepted.Add(1)
		defer connection.Close()
		for request := 0; request < 2; request++ {
			header := make([]byte, 2)
			if _, readErr := io.ReadFull(connection, header); readErr != nil {
				serverDone <- readErr
				return
			}
			payload := make([]byte, int(binary.BigEndian.Uint16(header)))
			if _, readErr := io.ReadFull(connection, payload); readErr != nil {
				serverDone <- readErr
				return
			}
			response := dnsAResponse(payload, 60)
			binary.BigEndian.PutUint16(header, uint16(len(response)))
			if writeErr := writeAll(connection, append(header, response...)); writeErr != nil {
				serverDone <- writeErr
				return
			}
		}
		serverDone <- nil
	}()

	upstream := &tcpUpstream{
		address: listener.Addr().String(),
		timeout: 2 * time.Second,
		idle:    make(chan net.Conn, 4),
	}
	defer upstream.close()
	for id := uint16(1); id <= 2; id++ {
		response, exchangeErr := upstream.exchange(
			context.Background(), dnsQuery(id, "example.com"),
		)
		if exchangeErr != nil {
			t.Fatal(exchangeErr)
		}
		if got := binary.BigEndian.Uint16(response[:2]); got != id {
			t.Fatalf("response transaction ID=%d", got)
		}
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("TCP connections=%d", got)
	}
}

func TestTCPListenerHandlesMultipleQueriesPerConnection(t *testing.T) {
	backend := &countingUpstream{}
	compiledLane := &lane{id: "lane", final: "wan", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	runtime := &runtime{
		servers: map[string]upstream{"wan": backend},
		lanes:   map[string]*lane{"lane": compiledLane},
		ordered: []*lane{compiledLane},
		cache:   newResponseCache(16, 1<<20, time.Hour),
		timeout: 2 * time.Second,
	}
	service := &service{runtime: runtime, limit: make(chan struct{}, 2), tcpLimit: make(chan struct{}, 2)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	service.wait.Add(1)
	go service.serveTCP("lane", listener)
	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for id, name := range []string{"one.example.com", "two.example.com"} {
		query := dnsQuery(uint16(id+1), name)
		frame := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
		copy(frame[2:], query)
		if err := writeAll(connection, frame); err != nil {
			t.Fatal(err)
		}
		header := make([]byte, 2)
		if _, err := io.ReadFull(connection, header); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, int(binary.BigEndian.Uint16(header)))
		if _, err := io.ReadFull(connection, response); err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint16(response[:2]); got != uint16(id+1) {
			t.Fatalf("response transaction ID=%d", got)
		}
	}
	_ = connection.Close()
	_ = listener.Close()
	service.wait.Wait()
	if calls := backend.calls.Load(); calls != 2 {
		t.Fatalf("upstream calls=%d", calls)
	}
}

func BenchmarkResponseCacheHit(b *testing.B) {
	cache := newResponseCache(4096, 4<<20, time.Hour)
	query := dnsQuery(1, "api.example.com")
	cache.putOwned("lane\x00api.example.com", dnsAResponse(query, 60), time.Minute, time.Now())
	queryID := query[:2]
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := cache.get("lane\x00api.example.com", queryID, now); !ok {
			b.Fatal("cache miss")
		}
	}
}

func BenchmarkLaneTarget(b *testing.B) {
	lane, err := compileLane(laneConfig{
		ID: "lane", Host: "127.0.0.1", Port: 30000, Final: "wan",
		Rules: []ruleConfig{
			{DomainSuffix: []string{"example.com"}, Action: "route", Server: "vpn"},
			{Domain: []string{"api.example.com"}, Action: "route", Server: "wan"},
		},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		lane.target("sub.api.example.com")
	}
}
