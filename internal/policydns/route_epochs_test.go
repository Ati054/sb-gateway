package policydns

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/dnsroute"
)

func epochConfig(detour string) serverConfig {
	return serverConfig{Type: "https", Server: "127.0.0.1", ServerName: "resolver.example.test", TunnelHost: "127.0.0.1", TunnelPort: 443, Detour: detour}
}

func epochRuntime(t *testing.T, servers map[string]upstream, configs map[string]serverConfig) (*runtime, *dnsroute.Publisher) {
	t.Helper()
	lanes := make([]laneConfig, 0, len(servers))
	for tag := range servers {
		lanes = append(lanes, laneConfig{ID: tag, Final: tag})
	}
	r := sharedQueryRuntime(t, servers, lanes...)
	r.timeout = 3 * time.Second
	r.serverConfigs = configs
	registry := dnsroute.New()
	p := registry.NewPublisher()
	p.Sync(dnsroute.Core{PID: 1, StartTicks: 1}, []string{"policy-a", "policy-b"})
	p.Confirm("policy-a", "A")
	r.attachRouteEpochs(registry)
	t.Cleanup(r.close)
	t.Cleanup(p.Close)
	return r, p
}

func mustEpochAnswer(t *testing.T, r *runtime, tag string, id uint16, name string) []byte {
	t.Helper()
	q := dnsQuery(id, name)
	a, err := r.resolve(context.Background(), tag, q)
	if err != nil || len(a) < 12 || binary.BigEndian.Uint16(a[2:4])&15 != 0 || binary.BigEndian.Uint16(a[:2]) != id {
		t.Fatalf("invalid DNS answer: err=%v", err)
	}
	return a
}

func TestDNSRouteEpochHeldH2ResponseCannotSeedNewCacheOrFlight(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	entered := make(chan struct{})
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		query, err := io.ReadAll(request.Body)
		if err != nil {
			return
		}
		n := calls.Add(1)
		if n == 1 {
			close(entered)
			select {
			case <-release:
			case <-request.Context().Done():
				return
			}
		}
		response := dnsAResponse(query, 60)
		response[len(response)-1] = byte(n)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	makeUpstream := func() (upstream, error) {
		v, err := newUpstream(epochConfig("policy-a"), 3*time.Second)
		if err != nil {
			return nil, err
		}
		d := v.(*dohUpstream)
		d.url = server.URL + "/dns-query"
		d.transport.DialContext = nil
		d.transport.TLSClientConfig.ServerName = ""
		d.transport.TLSClientConfig.RootCAs = roots
		return d, nil
	}
	first, err := makeUpstream()
	if err != nil {
		t.Fatal(err)
	}
	wan := &countingUpstream{}
	r, p := epochRuntime(t, map[string]upstream{"proxy": first, "wan": wan}, map[string]serverConfig{"proxy": epochConfig("policy-a"), "wan": {Type: "udp", Server: "127.0.0.1"}})
	r.routeProfiles["proxy"].factory = func(serverConfig, time.Duration) (upstream, error) { return makeUpstream() }
	mustEpochAnswer(t, r, "wan", 1, "warm.example.test")
	oldDone := make(chan []byte, 1)
	oldErr := make(chan error, 1)
	go func() {
		a, e := r.resolve(context.Background(), "proxy", dnsQuery(2, "held.example.test"))
		oldDone <- a
		oldErr <- e
	}()
	defer func() {
		once.Do(func() { close(release) })
		select {
		case <-oldErr:
		case <-time.After(4 * time.Second):
			t.Error("old H2 stream did not join")
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("H2 owner did not start")
	}
	p.Confirm("policy-a", "B")
	fresh := mustEpochAnswer(t, r, "proxy", 3, "held.example.test")
	if fresh[len(fresh)-1] != 2 {
		t.Fatal("new request joined old generation")
	}
	once.Do(func() { close(release) })
	select {
	case old := <-oldDone:
		if len(old) < 12 || binary.BigEndian.Uint16(old[2:4])&15 != 0 || binary.BigEndian.Uint16(old[6:8]) != 1 || old[len(old)-1] != 1 {
			t.Fatal("healthy old H2 request was aborted")
		}
	case <-time.After(time.Second):
		t.Fatal("old stream stalled")
	}
	fresh = mustEpochAnswer(t, r, "proxy", 4, "held.example.test")
	if fresh[len(fresh)-1] != 2 || calls.Load() != 2 {
		t.Fatal("retired reply contaminated the current cache")
	}
	mustEpochAnswer(t, r, "wan", 5, "warm.example.test")
	if wan.calls.Load() != 1 {
		t.Fatal("unrelated WAN cache was reset")
	}
}

func TestDNSRouteEpochQueuedPlanFailsClosedAndABADoesNotResurrect(t *testing.T) {
	old := &countingUpstream{}
	r, p := epochRuntime(t, map[string]upstream{"proxy": old}, map[string]serverConfig{"proxy": epochConfig("policy-a")})
	var made atomic.Int32
	r.routeProfiles["proxy"].factory = func(serverConfig, time.Duration) (upstream, error) { made.Add(1); return &countingUpstream{}, nil }
	query := dnsQuery(1, "queued.example.test")
	plan, err := r.planQuery("proxy", query)
	if err != nil {
		t.Fatal(err)
	}
	mustEpochAnswer(t, r, "proxy", 2, "cached.example.test")
	p.Confirm("policy-a", "B")
	answer, err := r.exchangePlan(context.Background(), plan, query)
	if err != errDNSRouteRetired || answer != nil || old.calls.Load() != 1 {
		t.Fatal("queued retired plan started upstream work")
	}
	p.Confirm("policy-a", "A")
	fresh, _ := r.planQuery("proxy", dnsQuery(3, "cached.example.test"))
	if fresh.local || fresh.key == plan.key || made.Load() != 2 {
		t.Fatal("A-B-A reused a cache or generation")
	}
	p.Confirm("policy-a", "A")
	p.Sync(dnsroute.Core{PID: 1, StartTicks: 1}, []string{"policy-a", "policy-b", "unrelated"})
	p.Confirm("policy-b", "changed")
	if made.Load() != 2 {
		t.Fatal("same route or unrelated subscription cooled a transport")
	}
}

func TestDNSRouteEpochDoesNotWaitForUnrelatedNetworkRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	slow := &gatedQueryUpstream{started: make(chan struct{}, 1), release: release}
	r, p := epochRuntime(t, map[string]upstream{"proxy": &countingUpstream{}, "wan": slow}, map[string]serverConfig{"proxy": epochConfig("policy-a"), "wan": {Type: "udp", Server: "127.0.0.1"}})
	r.routeProfiles["proxy"].factory = func(serverConfig, time.Duration) (upstream, error) { return &countingUpstream{}, nil }
	s := burstService(ctx, slow, 4, 3*time.Second)
	s.runtime = r
	q := dnsQuery(1, "held-wan.example.test")
	admitted := s.admitQuery("wan", q)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = s.resolveAdmitted(admitted, "wan", q) }()
	defer func() {
		once.Do(func() { close(release) })
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("held query did not join")
		}
	}()
	select {
	case <-slow.started:
	case <-time.After(time.Second):
		t.Fatal("unrelated request did not enter")
	}
	changed := make(chan struct{})
	go func() { p.Confirm("policy-a", "B"); close(changed) }()
	defer func() {
		once.Do(func() { close(release) })
		select {
		case <-changed:
		case <-time.After(time.Second):
			t.Error("publication did not join")
		}
	}()
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("route publication waited for runtimeMu network reader")
	}
}

func TestDNSRouteEpochRetiresErrorStaleCacheAndCoreOnlyTunnels(t *testing.T) {
	proxy := &countingUpstream{}
	wan := &countingUpstream{}
	r, p := epochRuntime(t, map[string]upstream{"proxy": proxy, "wan": wan}, map[string]serverConfig{"proxy": epochConfig("policy-a"), "wan": {Type: "udp", Server: "127.0.0.1"}})
	var made atomic.Int32
	r.routeProfiles["proxy"].factory = func(serverConfig, time.Duration) (upstream, error) { made.Add(1); return &countingUpstream{}, nil }
	q := dnsQuery(1, "stale.example.test")
	old, _ := r.profilePlan("proxy", q)
	stale := dnsAResponse(q, 60)
	stale[0], stale[1] = 0, 0
	r.cache.putOwned(old.key, stale, time.Millisecond, time.Now().Add(-time.Second))
	p.Sync(dnsroute.Core{PID: 1, StartTicks: 2}, []string{"policy-a"})
	if made.Load() != 1 || r.routeProfiles["wan"] != nil {
		t.Fatal("core restart did not isolate tunnel dependencies")
	}
	a := r.queryResult(old, q, nil, context.DeadlineExceeded)
	if len(a) < 12 || binary.BigEndian.Uint16(a[2:4])&15 != 2 {
		t.Fatal("retired failed request used stale old cache")
	}
}
