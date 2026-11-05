package policydns

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func managedTestRuntime(t *testing.T, servers map[string]upstream, rules []managedSourceConfig) *runtime {
	t.Helper()
	r := sharedQueryRuntime(t, servers, laneConfig{ID: "a", Final: "wan"}, laneConfig{ID: "b", Final: "proxy"}, laneConfig{ID: "denied", Final: "reject"})
	r.timeout = time.Second
	var err error
	r.managed, err = compileManagedIngress(&managedIngressConfig{Listeners: []managedListenerConfig{{Host: "127.0.0.1", Port: 31053}}, Rules: rules}, r.lanes)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func managedTestService(r *runtime) (*service, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &service{ctx: ctx, runtime: r, limit: make(chan struct{}, 4), pending: make(chan struct{}, 16), tcpLimit: make(chan struct{}, 2)}
	s.udpBuffers.New = func() any { return new([maxDNSMessage]byte) }
	return s, cancel
}

func TestManagedIngressPreservesRuleOrderAndAddressFamily(t *testing.T) {
	r := managedTestRuntime(t, nil, []managedSourceConfig{
		{SourceCIDRs: []string{"192.0.2.0/24"}, LaneID: "a"},
		{SourceCIDRs: []string{"192.0.2.7/32"}, LaneID: "b"},
		{SourceCIDRs: []string{"2001:db8:1::/64"}, LaneID: "b"},
		{SourceCIDRs: []string{"::ffff:198.51.100.0/120"}, LaneID: "denied"},
	})
	for _, test := range []struct{ address, lane string }{
		{"192.0.2.7", "a"}, {"::ffff:192.0.2.7", "a"}, {"2001:db8:1::8", "b"}, {"198.51.100.8", "denied"}, {"2001:db8:2::1", ""}, {"203.0.113.1", ""},
	} {
		got, ok := r.managedLane(netip.MustParseAddr(test.address))
		if got != test.lane || ok != (test.lane != "") {
			t.Fatalf("%s: lane=%q matched=%v", test.address, got, ok)
		}
	}
	if _, ok := r.managedLane(netip.Addr{}); ok {
		t.Fatal("invalid peer matched")
	}
	if got, _ := r.managedLane(managedPeer(&net.TCPAddr{IP: net.ParseIP("::ffff:192.0.2.7"), Port: 40000})); got != "a" {
		t.Fatal("mapped TCP peer lost IPv4 identity")
	}
}

func TestManagedIngressRejectsUnsafeRuntimeDocuments(t *testing.T) {
	base := `{"version":1,"lane_layout_version":2,"servers":{},"lanes":[{"id":"a","host":"127.0.0.1","port":30000,"final":"reject"}],"managed_ingress":%s}`
	for name, value := range map[string]string{
		"wildcard4":              `{"listeners":[{"host":"0.0.0.0","port":1053}]}`,
		"wildcard6":              `{"listeners":[{"host":"::","port":1053}]}`,
		"multicast":              `{"listeners":[{"host":"ff02::1","port":1053}]}`,
		"broadcast":              `{"listeners":[{"host":"255.255.255.255","port":1053}]}`,
		"hostname":               `{"listeners":[{"host":"resolver.test","port":1053}]}`,
		"unsafe-port":            `{"listeners":[{"host":"127.0.0.2","port":53}]}`,
		"missing-listener":       `{"rules":[]}`,
		"collision":              `{"listeners":[{"host":"::ffff:127.0.0.1","port":30000}]}`,
		"duplicate-listener":     `{"listeners":[{"host":"127.0.0.2","port":1053},{"host":"::ffff:127.0.0.2","port":1053}]}`,
		"unknown-lane":           `{"listeners":[{"host":"127.0.0.2","port":1053}],"rules":[{"source_cidrs":["192.0.2.0/24"],"lane_id":"missing"}]}`,
		"no-cidrs":               `{"listeners":[{"host":"127.0.0.2","port":1053}],"rules":[{"lane_id":"a"}]}`,
		"bad-cidr":               `{"listeners":[{"host":"127.0.0.2","port":1053}],"rules":[{"source_cidrs":["not-cidr"],"lane_id":"a"}]}`,
		"ambiguous-mapped":       `{"listeners":[{"host":"127.0.0.2","port":1053}],"rules":[{"source_cidrs":["::ffff:192.0.2.0/80"],"lane_id":"a"}]}`,
		"ignored-auth-predicate": `{"listeners":[{"host":"127.0.0.2","port":1053}],"rules":[{"source_cidrs":["192.0.2.0/24"],"lane_id":"a","user":"account"}]}`,
		"duplicate-lane-key":     `{"listeners":[{"host":"127.0.0.2","port":1053}],"rules":[{"source_cidrs":["192.0.2.0/24"],"lane_id":"a","lane_id":"other"}]}`,
		"case-alias-lane-key":    `{"listeners":[{"host":"127.0.0.2","port":1053}],"rules":[{"source_cidrs":["192.0.2.0/24"],"lane_id":"a","LANE_ID":"other"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dns.json")
			if err := os.WriteFile(path, []byte(fmt.Sprintf(base, value)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateFile(path, Options{}); err == nil {
				t.Fatal("unsafe managed document admitted")
			}
		})
	}
}

func TestManagedIngressRequiresLayoutTwoAndRetainsLegacyStandalone(t *testing.T) {
	for version := 0; version <= 2; version++ {
		for _, managed := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "dns.json")
			body := fmt.Sprintf(`{"version":%d,"lanes":[{"id":"a","host":"127.0.0.1","port":30000,"final":"reject"}]%s}`, version, map[bool]string{false: "", true: `,"managed_ingress":{"listeners":[{"host":"127.0.0.2","port":1053}]}`}[managed])
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateFile(path, Options{}); (err != nil) != managed {
				t.Fatalf("version=%d managed=%v err=%v", version, managed, err)
			}
		}
	}
}

func TestManagedIngressLayoutTwoLoadsWithoutExposingOrdinaryLanes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns.json")
	body := `{"version":1,"lane_layout_version":2,"servers":{},"lanes":[{"id":"a","host":"127.0.0.1","port":30000,"final":"reject"}],"managed_ingress":{"listeners":[{"host":"::1","port":1053}],"rules":[{"source_cidrs":["2001:db8::/32"],"lane_id":"a"}]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := loadRuntime(path, 256, 1<<20, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	if got, ok := r.managedLane(netip.MustParseAddr("2001:db8::1")); !ok || got != "a" {
		t.Fatal("managed document lost source mapping")
	}
	if r.lanes["a"].host != "127.0.0.1" || r.managed.listeners[0].Host != "::1" {
		t.Fatal("ordinary lane host was replaced by public ingress")
	}
	if r.topology() == (&runtime{ordered: r.ordered}).topology() {
		t.Fatal("managed listener missing from topology")
	}
	if _, err := compileLane(laneConfig{ID: "exposed", Host: "192.0.2.1", Port: 30000}); err == nil {
		t.Fatal("ordinary lane accepts a public address")
	}
}

type managedPacket struct {
	query   []byte
	address net.Addr
}
type managedPacketConn struct {
	input  chan managedPacket
	output chan []byte
}

func (c *managedPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	p, ok := <-c.input
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(buf, p.query), p.address, nil
}
func (c *managedPacketConn) WriteTo(buf []byte, _ net.Addr) (int, error) {
	c.output <- append([]byte(nil), buf...)
	return len(buf), nil
}
func (*managedPacketConn) Close() error { return nil }
func (*managedPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1053}
}
func (*managedPacketConn) SetDeadline(time.Time) error      { return nil }
func (*managedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*managedPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestManagedUDPUnknownCannotReadSharedCacheOrAdmitWork(t *testing.T) {
	backend := &countingUpstream{}
	r := managedTestRuntime(t, map[string]upstream{"wan": backend}, []managedSourceConfig{{SourceCIDRs: []string{"192.0.2.1/32"}, LaneID: "a"}})
	if _, err := r.resolve(context.Background(), "a", dnsQuery(1, "cache.test")); err != nil {
		t.Fatal(err)
	}
	s, cancel := managedTestService(r)
	defer cancel()
	c := &managedPacketConn{input: make(chan managedPacket, 1), output: make(chan []byte, 1)}
	c.input <- managedPacket{dnsQuery(2, "cache.test"), &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 40000}}
	close(c.input)
	s.wait.Add(1)
	s.serveUDPSource("", c, true)
	s.wait.Wait()
	if len(c.output) != 0 || backend.calls.Load() != 1 || s.queryBytes != 0 || len(s.limit) != 0 || len(s.pending) != 0 {
		t.Fatal("unknown UDP source reached cache/admission/upstream")
	}
}

func TestManagedUDPReusesCoalescingAndKeepsRouteIsolation(t *testing.T) {
	backend := &gatedQueryUpstream{started: make(chan struct{}, 4), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(backend.release) }) }
	defer release()
	r := managedTestRuntime(t, map[string]upstream{"wan": backend}, []managedSourceConfig{{SourceCIDRs: []string{"192.0.2.1/32", "192.0.2.2/32"}, LaneID: "a"}})
	s, cancel := managedTestService(r)
	defer cancel()
	c := &managedPacketConn{input: make(chan managedPacket, 2), output: make(chan []byte, 2)}
	s.wait.Add(1)
	go s.serveUDPSource("", c, true)
	defer func() { close(c.input); release(); s.wait.Wait() }()
	for i, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		c.input <- managedPacket{dnsQuery(uint16(i+10), "shared.test"), &net.UDPAddr{IP: net.ParseIP(ip), Port: 40000 + i}}
	}
	deadline := time.After(3 * time.Second)
	for {
		s.admissionMu.Lock()
		shared := s.sharedQueries
		s.admissionMu.Unlock()
		if shared == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("managed duplicate did not join flight")
		case <-time.After(time.Millisecond):
		}
	}
	release()
	ids := map[uint16]bool{}
	for range 2 {
		select {
		case answer := <-c.output:
			ids[binary.BigEndian.Uint16(answer)] = true
		case <-deadline:
			t.Fatal("managed duplicate response missing")
		}
	}
	if backend.calls.Load() != 1 || !ids[10] || !ids[11] {
		t.Fatal("shared admission or per-client transaction IDs lost")
	}
	other := &countingUpstream{}
	r2 := managedTestRuntime(t, map[string]upstream{"wan": other, "proxy": other}, []managedSourceConfig{{SourceCIDRs: []string{"192.0.2.1/32"}, LaneID: "a"}, {SourceCIDRs: []string{"192.0.2.2/32"}, LaneID: "b"}})
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		id, _ := r2.managedLane(netip.MustParseAddr(ip))
		if _, err := r2.resolve(context.Background(), id, dnsQuery(20, "isolated.test")); err != nil {
			t.Fatal(err)
		}
	}
	if other.calls.Load() != 2 {
		t.Fatal("managed source routes shared a WAN/VLESS cache entry")
	}
}

// Re-entering ReadFrom proves that both previous packets finished admission.
// The upstream gate keeps the shared flight alive until the test observes it.
type managedUDPReadBarrier struct {
	net.PacketConn
	reads        int
	pairAdmitted chan struct{}
}

func (c *managedUDPReadBarrier) ReadFrom(buf []byte) (int, net.Addr, error) {
	c.reads++
	if c.reads == 3 {
		close(c.pairAdmitted)
	}
	return c.PacketConn.ReadFrom(buf)
}

func TestManagedUDPSameSocketPreservesConcurrentAndCachedIDs(t *testing.T) {
	backend := &gatedQueryUpstream{started: make(chan struct{}, 32), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(backend.release) }) }
	r := managedTestRuntime(t, map[string]upstream{"wan": backend}, []managedSourceConfig{{SourceCIDRs: []string{"127.0.0.1/32"}, LaneID: "a"}})
	r.timeout = 5 * time.Second
	s, cancel := managedTestService(r)
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	listener := &managedUDPReadBarrier{PacketConn: packet, pairAdmitted: make(chan struct{})}
	s.closers = append(s.closers, listener)
	s.wait.Add(1)
	go s.serveUDPSource("", listener, true)
	defer func() { cancel(); release(); s.close(); r.close() }()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	destination := packet.LocalAddr().(*net.UDPAddr)
	source := client.LocalAddr().(*net.UDPAddr).AddrPort()
	send := func(id uint16) []byte {
		t.Helper()
		query := dnsQuery(id, "same-socket.test")
		if n, err := client.WriteToUDP(query, destination); err != nil || n != len(query) {
			t.Fatalf("send query %d: bytes=%d err=%v", id, n, err)
		}
		return query
	}
	queries := make(map[uint16][]byte, 2)
	for _, id := range []uint16{41, 42} {
		queries[id] = send(id)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for _, ready := range []<-chan struct{}{listener.pairAdmitted, backend.started} {
		select {
		case <-ready:
		case <-deadline.C:
			t.Fatal("concurrent UDP pair did not reach the held shared flight")
		}
	}
	s.admissionMu.Lock()
	shared := s.sharedQueries
	s.admissionMu.Unlock()
	if shared != 1 || backend.calls.Load() != 1 {
		t.Fatalf("pair was not coalesced before release: shared=%d upstream=%d", shared, backend.calls.Load())
	}
	release()
	readAll := func(want map[uint16][]byte) {
		t.Helper()
		seen := make(map[uint16]bool, len(want))
		buf := make([]byte, maxDNSMessage)
		for range len(want) {
			n, from, err := client.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("UDP replies=%d/%d: %v", len(seen), len(want), err)
			}
			if from.AddrPort() != destination.AddrPort() || n < 12 {
				t.Fatalf("unexpected reply endpoint/length: source=%v length=%d", from, n)
			}
			id := binary.BigEndian.Uint16(buf[:2])
			query, ok := want[id]
			if !ok || seen[id] || !matchingQuestion(query, buf[:n]) || buf[3]&15 != 0 {
				t.Fatalf("missing/duplicate/mismatched UDP transaction %d", id)
			}
			seen[id] = true
		}
	}
	readAll(queries)
	queries = make(map[uint16][]byte, 16)
	for id := uint16(100); id < 116; id++ {
		queries[id] = send(id)
	}
	readAll(queries)
	if client.LocalAddr().(*net.UDPAddr).AddrPort() != source || backend.calls.Load() != 1 {
		t.Fatal("cached burst changed the client socket or performed another upstream query")
	}
	// A received reply can precede the handler's deferred admission release.
	s.close()
	s.admissionMu.Lock()
	retained, shared := s.queryBytes, s.sharedQueries
	s.admissionMu.Unlock()
	if retained != 0 || shared != 0 || len(s.limit) != 0 || len(s.pending) != 0 {
		t.Fatal("same-socket UDP pair or cached burst leaked admission resources")
	}
}

type managedRemoteConn struct {
	net.Conn
	peer net.Addr
}

func (c managedRemoteConn) RemoteAddr() net.Addr { return c.peer }

type managedOneListener struct {
	connection net.Conn
	once       sync.Once
	stop       chan struct{}
	closed     sync.Once
}

func (l *managedOneListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.connection })
	if conn != nil {
		return conn, nil
	}
	<-l.stop
	return nil, net.ErrClosed
}
func (l *managedOneListener) Close() error { l.closed.Do(func() { close(l.stop) }); return nil }
func (*managedOneListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1053}
}

func managedTCPFrame(t *testing.T, c net.Conn, query []byte) []byte {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	frame = append(frame, query...)
	if err := writeAll(c, frame); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, int(binary.BigEndian.Uint16(header)))
	if _, err := io.ReadFull(c, answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

func TestManagedTCPPersistentConnectionLooksUpPolicyPerMessage(t *testing.T) {
	backend := &countingUpstream{}
	r := managedTestRuntime(t, map[string]upstream{"wan": backend}, []managedSourceConfig{{SourceCIDRs: []string{"192.0.2.1/32"}, LaneID: "a"}})
	s, cancel := managedTestService(r)
	client, server := net.Pipe()
	l := &managedOneListener{connection: managedRemoteConn{server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}}, stop: make(chan struct{})}
	s.wait.Add(1)
	go s.serveTCPSource("", l, true)
	defer func() { cancel(); _ = client.Close(); _ = l.Close(); s.wait.Wait() }()
	if answer := managedTCPFrame(t, client, dnsQuery(1, "cached.test")); answer[3]&15 != 0 {
		t.Fatal("first managed message failed")
	}
	s.runtimeMu.Lock()
	r.managed.rules[0].laneID = "denied"
	s.runtimeMu.Unlock()
	if answer := managedTCPFrame(t, client, dnsQuery(2, "cached.test")); answer[3]&15 != 5 {
		t.Fatal("persistent managed connection retained old policy/cache access")
	}
	if backend.calls.Load() != 1 {
		t.Fatal("reject policy reached upstream")
	}
}

func TestManagedTCPUnknownClosesWithoutSessionOrResolver(t *testing.T) {
	backend := &countingUpstream{}
	r := managedTestRuntime(t, map[string]upstream{"wan": backend}, nil)
	s, cancel := managedTestService(r)
	client, server := net.Pipe()
	l := &managedOneListener{connection: managedRemoteConn{server, &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 40000}}, stop: make(chan struct{})}
	s.wait.Add(1)
	go s.serveTCPSource("", l, true)
	defer func() { cancel(); _ = client.Close(); _ = l.Close(); s.wait.Wait() }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := client.Read(buf); err != io.EOF {
		t.Fatalf("unknown TCP peer was not closed: %v", err)
	}
	if len(s.tcpLimit) != 0 || len(s.limit) != 0 || backend.calls.Load() != 0 {
		t.Fatal("unknown TCP source consumed DNS session/work")
	}
}

func TestManagedTCPUsesExistingSharedSessionCap(t *testing.T) {
	backend := &countingUpstream{}
	r := managedTestRuntime(t, map[string]upstream{"wan": backend}, []managedSourceConfig{{SourceCIDRs: []string{"192.0.2.1/32"}, LaneID: "a"}})
	s, cancel := managedTestService(r)
	for range cap(s.tcpLimit) {
		s.tcpLimit <- struct{}{}
	}
	client, server := net.Pipe()
	l := &managedOneListener{connection: managedRemoteConn{server, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}}, stop: make(chan struct{})}
	s.wait.Add(1)
	go s.serveTCPSource("", l, true)
	defer func() { cancel(); _ = client.Close(); _ = l.Close(); s.wait.Wait() }()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("known source bypassed full shared TCP cap: %v", err)
	}
	if len(s.tcpLimit) != cap(s.tcpLimit) || backend.calls.Load() != 0 {
		t.Fatal("managed TCP changed occupied capacity or reached resolver")
	}
}

func TestManagedIngressProbeIncludesManagedListener(t *testing.T) {
	listeners := make([]net.Listener, 0, 2)
	accepted := make(chan struct{}, 2)
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, l)
		go func() {
			c, err := l.Accept()
			if err == nil {
				_ = c.Close()
				accepted <- struct{}{}
			}
		}()
	}
	port := func(l net.Listener) int { return l.Addr().(*net.TCPAddr).Port }
	doc := map[string]any{"version": 1, "lane_layout_version": 2, "lanes": []any{map[string]any{"id": "a", "host": "127.0.0.1", "port": port(listeners[0]), "final": "reject"}}, "managed_ingress": managedIngressConfig{Listeners: []managedListenerConfig{{Host: "127.0.0.1", Port: port(listeners[1])}}, Rules: []managedSourceConfig{{SourceCIDRs: []string{"127.0.0.1/32"}, LaneID: "a"}}}}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "dns.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ProbeListeners(ctx, path); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-accepted:
		case <-ctx.Done():
			t.Fatal("one listener not probed")
		}
	}
}

func TestManagedListenerServesUDPAndTCPThroughSameLaneCache(t *testing.T) {
	reservations := make([]net.Listener, 0, 2)
	defer func() {
		for _, l := range reservations {
			_ = l.Close()
		}
	}()
	for range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, l)
	}
	lanePort := reservations[0].Addr().(*net.TCPAddr).Port
	managedPort := reservations[1].Addr().(*net.TCPAddr).Port
	backend := &countingUpstream{}
	r := managedTestRuntime(t, map[string]upstream{"wan": backend}, []managedSourceConfig{{SourceCIDRs: []string{"127.0.0.1/32"}, LaneID: "a"}})
	r.lanes["a"].port = lanePort
	r.ordered = []*lane{r.lanes["a"]}
	r.managed.listeners = []managedListenerConfig{{Host: "127.0.0.1", Port: managedPort}}
	s, cancel := managedTestService(r)
	defer func() { cancel(); s.close(); r.close() }()
	for _, l := range reservations {
		_ = l.Close()
	}
	if err := s.listen(r); err != nil {
		t.Fatal(err)
	}
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(managedPort))
	u, err := net.DialTimeout("udp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	_ = u.SetDeadline(time.Now().Add(2 * time.Second))
	query := dnsQuery(41, "both-protocols.test")
	if _, err := u.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := u.Read(buf)
	if err != nil || !matchingQuestion(query, buf[:n]) {
		t.Fatalf("managed UDP response: %v", err)
	}
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	answer := managedTCPFrame(t, c, dnsQuery(42, "both-protocols.test"))
	if binary.BigEndian.Uint16(answer) != 42 || answer[3]&15 != 0 {
		t.Fatal("managed TCP response lost lane/cache")
	}
	if backend.calls.Load() != 1 {
		t.Fatal("managed UDP/TCP did not share the existing selected-route cache")
	}
}
