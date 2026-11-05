package policydns

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func TestDNSRouteEpochRetiresActualAdmissionQueueWithoutLeakingCapacity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	var once sync.Once
	held := &gatedQueryUpstream{started: make(chan struct{}, 1), release: release}
	proxy := &countingUpstream{}
	r, p := epochRuntime(t, map[string]upstream{"proxy": proxy, "wan": held}, map[string]serverConfig{"proxy": epochConfig("policy-a"), "wan": {Type: "udp", Server: "127.0.0.1"}})
	r.routeProfiles["proxy"].factory = func(serverConfig, time.Duration) (upstream, error) { return &countingUpstream{}, nil }
	s := burstService(ctx, held, 1, 3*time.Second)
	s.runtime = r
	wanQuery := dnsQuery(1, "capacity.example.test")
	wan := s.admitQuery("wan", wanQuery)
	var wg sync.WaitGroup
	defer func() { cancel(); once.Do(func() { close(release) }); wg.Wait() }()
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = s.resolveAdmitted(wan, "wan", wanQuery) }()
	select {
	case <-held.started:
	case <-time.After(time.Second):
		t.Fatal("capacity owner did not start")
	}
	q := dnsQuery(2, "queued.example.test")
	a := s.admitQuery("proxy", q)
	if !a.queued || a.immediate || a.shared {
		t.Fatal("fixture did not enter the real admission queue")
	}
	p.Confirm("policy-a", "B")
	once.Do(func() { close(release) })
	result, err := s.resolveAdmitted(a, "proxy", q)
	wg.Wait()
	if err != nil || len(result) < 12 || binary.BigEndian.Uint16(result[2:4])&15 != 2 || proxy.calls.Load() != 0 {
		t.Fatal("retired queued work was not failed closed")
	}
	if s.queryBytes != 0 || len(s.limit) != 0 || len(s.pending) != 0 || len(r.flights.flights) != 0 {
		t.Fatal("generation retirement leaked admission/flight capacity")
	}
}
