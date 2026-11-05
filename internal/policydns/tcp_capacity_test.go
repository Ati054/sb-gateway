package policydns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestDefaultTCPSessionsFollowWorkerCapacity(t *testing.T) {
	for _, test := range []struct {
		name, workers, sessions string
		wantWorkers, wantTCP    int
	}{
		{"defaults", "", "", 32, 32},
		{"small-worker-budget", "2", "", 2, 8},
		{"moderate-worker-budget", "16", "", 16, 16},
		{"maximum-worker-budget", "64", "", 64, 32},
		{"invalid-worker-budget", "invalid", "", 32, 32},
		{"invalid-session-budget", "16", "invalid", 16, 16},
		{"explicit-small-session-budget", "32", "8", 32, 8},
		{"explicit-minimum", "64", "2", 64, 2},
		{"explicit-low-clamp", "32", "1", 32, 2},
		{"explicit-high-clamp", "32", "100", 32, 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SB_POLICY_DNS_WORKERS", test.workers)
			t.Setenv("SB_POLICY_DNS_TCP_SESSIONS", test.sessions)
			got := OptionsFromEnvironment()
			if got.Workers != test.wantWorkers || got.TCPSessions != test.wantTCP {
				t.Fatalf("workers=%d TCP sessions=%d; want %d/%d",
					got.Workers, got.TCPSessions, test.wantWorkers, test.wantTCP)
			}
		})
	}
}

type observedTCPAccepts struct {
	net.Listener
	accepted chan struct{}
}

func (listener *observedTCPAccepts) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted <- struct{}{}
	}
	return connection, err
}

func TestDefaultTCPSessionsServeConcurrentCachedBurst(t *testing.T) {
	t.Setenv("SB_POLICY_DNS_WORKERS", "")
	t.Setenv("SB_POLICY_DNS_TCP_SESSIONS", "")
	options := OptionsFromEnvironment()
	backend := &countingUpstream{}
	l := &lane{id: "lane", final: "wan", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	r := &runtime{
		lanes: map[string]*lane{"lane": l}, servers: map[string]upstream{"wan": backend},
		cache: newResponseCache(16, 1<<20, time.Hour), timeout: 5 * time.Second,
	}
	if _, err := r.resolve(context.Background(), "lane", dnsQuery(1, "burst.example.test")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &service{
		ctx: ctx, runtime: r, limit: make(chan struct{}, options.Workers),
		pending: make(chan struct{}, options.Workers*4), tcpLimit: make(chan struct{}, options.TCPSessions),
	}
	// Cached answers must remain independent of occupied upstream workers.
	for range options.Workers {
		s.limit <- struct{}{}
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	const clients = 12
	listener := &observedTCPAccepts{Listener: raw, accepted: make(chan struct{}, clients)}
	s.wait.Add(1)
	go s.serveTCP("lane", listener)
	connections := make([]net.Conn, 0, clients)
	defer func() {
		cancel()
		for _, connection := range connections {
			_ = connection.Close()
		}
		_ = listener.Close()
		s.wait.Wait()
	}()
	for range clients {
		connection, dialErr := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		connections = append(connections, connection)
	}
	// Admit every connection before any client sends a question. An eight-slot
	// limit therefore rejects later clients deterministically, without sleeps.
	for range clients {
		select {
		case <-listener.accepted:
		case <-time.After(2 * time.Second):
			t.Fatal("listener did not accept the complete burst")
		}
	}
	for index, connection := range connections {
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		query := dnsQuery(uint16(1000+index), "burst.example.test")
		frame := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(frame, uint16(len(query)))
		copy(frame[2:], query)
		if err := writeAll(connection, frame); err != nil {
			t.Fatalf("session %d rejected a burst within the default worker budget: %v", index, err)
		}
	}
	for index, connection := range connections {
		header := make([]byte, 2)
		if _, err := io.ReadFull(connection, header); err != nil {
			t.Fatalf("session %d closed before a framed DNS answer: %v", index, err)
		}
		size := int(binary.BigEndian.Uint16(header))
		if size < 12 {
			t.Fatalf("session %d returned a short DNS frame", index)
		}
		answer := make([]byte, size)
		if _, err := io.ReadFull(connection, answer); err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint16(answer); got != uint16(1000+index) {
			t.Fatalf("session %d transaction ID=%d", index, got)
		}
		if answer[2]&0x80 == 0 || answer[3]&15 != 0 || binary.BigEndian.Uint16(answer[6:8]) != 1 {
			t.Fatalf("session %d did not receive the cached positive DNS answer", index)
		}
	}
	if got := backend.calls.Load(); got != 1 {
		t.Fatalf("cached burst started additional upstream work: calls=%d", got)
	}
}
