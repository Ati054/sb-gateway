package policydns

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func sharedQueryRuntime(t testing.TB, servers map[string]upstream, configs ...laneConfig) *runtime {
	t.Helper()
	current := &runtime{
		servers: servers, lanes: make(map[string]*lane),
		cache: newResponseCache(4096, 4<<20, time.Hour),
	}
	for index, config := range configs {
		config.Host, config.Port = "127.0.0.1", 30000+index
		compiled, err := compileLane(config)
		if err != nil {
			t.Fatal(err)
		}
		current.lanes[config.ID] = compiled
	}
	return current
}

func TestRuntimeSharesCacheAfterEachLanesRoutingDecision(t *testing.T) {
	backend := &countingUpstream{}
	current := sharedQueryRuntime(t, map[string]upstream{"wan": backend},
		laneConfig{ID: "device-a", Final: "wan"},
		laneConfig{ID: "device-b", Final: "reject", Rules: []ruleConfig{{
			DomainSuffix: []string{"example.com"}, Server: "wan",
		}}},
	)
	for index, id := range []string{"device-a", "device-b"} {
		query := dnsQuery(uint16(index+1), "api.example.com")
		answer, err := current.resolve(context.Background(), id, query)
		if err != nil || !matchingQuestion(query, answer) {
			t.Fatalf("lane %s: answer=%x err=%v", id, answer, err)
		}
	}
	if calls := backend.calls.Load(); calls != 1 {
		t.Fatalf("same selected route made %d upstream requests, want 1", calls)
	}
	if entries := len(current.cache.entries); entries != 1 {
		t.Fatalf("same selected route stored %d cache entries, want 1", entries)
	}
}

func TestRuntimeChecksRejectRulesBeforeSharedCache(t *testing.T) {
	backend := &countingUpstream{}
	current := sharedQueryRuntime(t, map[string]upstream{"wan": backend},
		laneConfig{ID: "allowed", Final: "wan"},
		laneConfig{ID: "denied", Final: "wan", Rules: []ruleConfig{{
			DomainSuffix: []string{"example.com"}, Action: "reject",
		}}},
		laneConfig{ID: "default-denied", Final: "reject"},
		laneConfig{ID: "missing-server", Final: "missing"},
	)
	query := dnsQuery(1, "api.example.com")
	if _, err := current.resolve(context.Background(), "allowed", query); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"denied", "default-denied", "missing-server"} {
		answer, err := current.resolve(context.Background(), id, query)
		if err != nil || len(answer) < 12 || answer[3]&15 != dns.RcodeRefused {
			t.Fatalf("lane %s bypassed refusal: answer=%x err=%v", id, answer, err)
		}
	}
	if _, err := current.resolve(context.Background(), "unknown", query); err == nil {
		t.Fatal("unknown lane used another lane's cache")
	}
	if backend.calls.Load() != 1 {
		t.Fatal("rejected query reached upstream")
	}
}

func TestRuntimeSeparatesSelectedRoutesEvenWithSameUpstream(t *testing.T) {
	// Distinct route tags must remain isolated even when the endpoint (or this
	// test's exchange implementation) is identical, for example WAN vs VLESS.
	backend := &countingUpstream{}
	current := sharedQueryRuntime(t, map[string]upstream{"wan": backend, "proxy": backend},
		laneConfig{ID: "device-a", Final: "wan"},
		laneConfig{ID: "device-b", Final: "proxy"},
		laneConfig{ID: "rule-route", Final: "wan", Rules: []ruleConfig{{
			Domain: []string{"api.example.com"}, Server: "proxy",
		}}},
	)
	for _, id := range []string{"device-a", "device-b", "rule-route"} {
		if _, err := current.resolve(context.Background(), id, dnsQuery(1, "api.example.com")); err != nil {
			t.Fatal(err)
		}
	}
	if calls := backend.calls.Load(); calls != 2 {
		t.Fatalf("two selected routes made %d upstream requests, want 2", calls)
	}
}

func TestSharedQueryKeyPreservesDNSOptions(t *testing.T) {
	base := dnsQuery(1, "api.example.com")
	variants := map[string][]byte{}
	for _, name := range []string{"type", "class", "checking-disabled", "recursion-desired"} {
		query := append([]byte(nil), base...)
		switch name {
		case "type":
			binary.BigEndian.PutUint16(query[len(query)-4:], dns.TypeAAAA)
		case "class":
			binary.BigEndian.PutUint16(query[len(query)-2:], dns.ClassCHAOS)
		case "checking-disabled":
			query[3] ^= 0x10
		case "recursion-desired":
			query[2] ^= 1
		}
		variants[name] = query
	}
	for _, size := range []uint16{512, 1232} {
		message := new(dns.Msg)
		message.SetQuestion("api.example.com.", dns.TypeA)
		message.Id = 1
		message.SetEdns0(size, true)
		wire, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		variants["edns-"+strconv.Itoa(int(size))] = wire
	}
	key, err := normalizedQueryKey("route", base)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{key: true}
	for name, query := range variants {
		key, err := normalizedQueryKey("route", query)
		if err != nil || seen[key] {
			t.Fatalf("%s collapsed into a different DNS request: %v", name, err)
		}
		seen[key] = true
	}
	otherID := append([]byte(nil), base...)
	binary.BigEndian.PutUint16(otherID, 99)
	otherKey, err := normalizedQueryKey("route", otherID)
	if err != nil || otherKey != key {
		t.Fatal("transaction IDs should not partition a shared request")
	}
}

type gatedQueryUpstream struct {
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

func (backend *gatedQueryUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	backend.calls.Add(1)
	backend.started <- struct{}{}
	select {
	case <-backend.release:
		return dnsAResponse(query, 60), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*gatedQueryUpstream) close() {}

// Signal when a follower starts waiting, without scheduling sleeps in the test.
type joinedQueryContext struct {
	context.Context
	joined chan struct{}
	once   sync.Once
}

func (ctx *joinedQueryContext) Done() <-chan struct{} {
	ctx.once.Do(func() { close(ctx.joined) })
	return ctx.Context.Done()
}

func TestRuntimeCoalescesAcrossLanesAndKeepsClientIDs(t *testing.T) {
	backend := &gatedQueryUpstream{started: make(chan struct{}, 32), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(backend.release) }) }
	t.Cleanup(unblock)
	const clients = 16
	configs := make([]laneConfig, clients)
	for index := range configs {
		configs[index] = laneConfig{ID: string(rune('a' + index)), Final: "proxy"}
	}
	current := sharedQueryRuntime(t, map[string]upstream{"proxy": backend}, configs...)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := make(chan error, clients)
	resolve := func(index int, ctx context.Context) {
		query := dnsQuery(uint16(index+1), "api.example.com")
		answer, err := current.resolve(ctx, configs[index].ID, query)
		if err == nil && !matchingQuestion(query, answer) {
			err = errors.New("shared response lost the caller's question or ID")
		}
		results <- err
	}
	go resolve(0, ctx)
	select {
	case <-backend.started:
	case <-ctx.Done():
		t.Fatal("leader did not start")
	}
	for index := 1; index < clients; index++ {
		follower := &joinedQueryContext{Context: ctx, joined: make(chan struct{})}
		go resolve(index, follower)
		select {
		case <-follower.joined:
		case <-ctx.Done():
			t.Fatal("follower did not join")
		}
	}
	if calls := backend.calls.Load(); calls != 1 {
		t.Fatalf("concurrent clients made %d upstream requests, want 1", calls)
	}
	unblock()
	for range clients {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuntimeSharedCacheDoesNotCrossRuntimeGeneration(t *testing.T) {
	backend := &countingUpstream{}
	path := filepath.Join(t.TempDir(), "policy-dns.json")
	raw := rawConfig{
		Version: 2, Servers: map[string]serverConfig{"proxy": {Type: "udp", Server: "127.0.0.1", ServerPort: 53}},
		Lanes: []laneConfig{{ID: "device", Host: "127.0.0.1", Port: 30000, Final: "proxy"}},
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		current, err := loadRuntime(path, 16, 1<<20, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(current.close)
		current.servers["proxy"].close()
		current.servers["proxy"] = backend
		if _, err := current.resolve(context.Background(), "device", dnsQuery(1, "api.example.com")); err != nil {
			t.Fatal(err)
		}
	}
	if calls := backend.calls.Load(); calls != 2 {
		t.Fatalf("new configuration reused old runtime answers: requests=%d", calls)
	}
}

func TestRuntimeSharedFailureDoesNotPoisonRetry(t *testing.T) {
	backend := &countingUpstream{err: errors.New("temporary upstream error")}
	current := sharedQueryRuntime(t, map[string]upstream{"proxy": backend},
		laneConfig{ID: "device-a", Final: "proxy"}, laneConfig{ID: "device-b", Final: "proxy"},
	)
	query := dnsQuery(1, "api.example.com")
	answer, err := current.resolve(context.Background(), "device-a", query)
	if err != nil || answer[3]&15 != dns.RcodeServerFailure {
		t.Fatalf("expected upstream failure, got %x %v", answer, err)
	}
	backend.err = nil
	answer, err = current.resolve(context.Background(), "device-b", query)
	if err != nil || answer[3]&15 != dns.RcodeSuccess || backend.calls.Load() != 2 {
		t.Fatalf("failure poisoned another client: %x %v calls=%d", answer, err, backend.calls.Load())
	}
}

func TestRuntimeSharedStaleRespectsSelectedRouteAndRejection(t *testing.T) {
	backend := &countingUpstream{err: errors.New("temporary upstream error")}
	current := sharedQueryRuntime(t, map[string]upstream{"proxy": backend, "wan": backend},
		laneConfig{ID: "device-a", Final: "proxy"}, laneConfig{ID: "device-b", Final: "wan"},
		laneConfig{ID: "denied", Final: "reject"},
	)
	query := dnsQuery(71, "api.example.com")
	key, err := normalizedQueryKey("proxy", query)
	if err != nil {
		t.Fatal(err)
	}
	current.cache.putOwned(key, dnsAResponse(query, 60), time.Second, time.Now().Add(-2*time.Second))
	for _, test := range []struct {
		lane string
		code byte
	}{{"device-a", dns.RcodeSuccess}, {"device-b", dns.RcodeServerFailure}, {"denied", dns.RcodeRefused}} {
		answer, err := current.resolve(context.Background(), test.lane, query)
		if err != nil || len(answer) < 12 || answer[3]&15 != test.code || binary.BigEndian.Uint16(answer) != 71 {
			t.Fatalf("stale isolation for %s: %x %v", test.lane, answer, err)
		}
	}
	if backend.calls.Load() != 2 {
		t.Fatal("rejected stale query reached upstream")
	}
}

func TestRuntimeCanceledSharedFollowerDoesNotCancelLeader(t *testing.T) {
	backend := &gatedQueryUpstream{started: make(chan struct{}, 2), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(backend.release) }) }
	defer unblock()
	current := sharedQueryRuntime(t, map[string]upstream{"proxy": backend},
		laneConfig{ID: "device-a", Final: "proxy"}, laneConfig{ID: "device-b", Final: "proxy"},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		query := dnsQuery(1, "api.example.com")
		answer, err := current.resolve(ctx, "device-a", query)
		if err == nil && !matchingQuestion(query, answer) {
			err = errors.New("leader did not receive an answer")
		}
		finished <- err
	}()
	select {
	case <-backend.started:
	case <-ctx.Done():
		t.Fatal("leader did not start")
	}
	follower, stop := context.WithCancel(ctx)
	stop()
	answer, err := current.resolve(follower, "device-b", dnsQuery(2, "api.example.com"))
	if err != nil || len(answer) < 12 || answer[3]&15 != dns.RcodeServerFailure || backend.calls.Load() != 1 {
		t.Fatalf("canceled follower: %x %v calls=%d", answer, err, backend.calls.Load())
	}
	unblock()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestServiceSharesAnswersAcrossUDPAndTCPLanes(t *testing.T) {
	backend := &countingUpstream{}
	ctx, cancel := context.WithCancel(context.Background())
	s := burstService(ctx, backend, 2, time.Second)
	s.runtime = sharedQueryRuntime(t, map[string]upstream{"proxy": backend},
		laneConfig{ID: "device-a", Final: "proxy"}, laneConfig{ID: "device-b", Final: "proxy"},
	)
	s.runtime.timeout = time.Second
	defer func() { cancel(); s.close() }()
	for index, network := range []string{"udp", "tcp"} {
		id := []string{"device-a", "device-b"}[index]
		var address string
		if network == "udp" {
			listener, err := net.ListenPacket(network, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address = listener.LocalAddr().String()
			s.closers = append(s.closers, listener)
			s.wait.Add(1)
			go s.serveUDP(id, listener)
		} else {
			listener, err := net.Listen(network, "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address = listener.Addr().String()
			s.closers = append(s.closers, listener)
			s.wait.Add(1)
			go s.serveTCP(id, listener)
		}
		for sequence := range 24 {
			query := new(dns.Msg)
			query.SetQuestion("api.example.com.", dns.TypeA)
			query.Id = uint16(100*index + sequence)
			answer, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(query, address)
			if err != nil || answer == nil || answer.Id != query.Id || answer.Rcode != dns.RcodeSuccess {
				t.Fatalf("%s query %d: %v %v", network, sequence, answer, err)
			}
		}
	}
	if backend.calls.Load() != 1 {
		t.Fatalf("UDP/TCP lanes made %d upstream requests, want 1", backend.calls.Load())
	}
	if len(s.limit) != 0 || len(s.pending) != 0 {
		t.Fatal("DNS admission tokens leaked")
	}
}

func BenchmarkRuntimeSharedRouteCache(b *testing.B) {
	for _, clients := range []int{1, 48} {
		b.Run(strconv.Itoa(clients)+"-clients", func(b *testing.B) {
			backend := &countingUpstream{}
			configs := make([]laneConfig, clients)
			for index := range configs {
				configs[index] = laneConfig{ID: string(rune('a' + index)), Final: "proxy"}
			}
			current := sharedQueryRuntime(b, map[string]upstream{"proxy": backend}, configs...)
			query := dnsQuery(1, "api.example.com")
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, err := current.resolve(context.Background(), configs[index%clients].ID, query); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(backend.calls.Load()), "upstream-requests")
			b.ReportMetric(float64(current.cache.used), "cache-bytes")
		})
	}
}
