package policydns

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func TestDNSRouteEpochRetirementAndStaleLookupAreSerialized(t *testing.T) {
	r, p := epochRuntime(t, map[string]upstream{"proxy": &countingUpstream{}}, map[string]serverConfig{"proxy": epochConfig("policy-a")})
	q := dnsQuery(1, "stale-interleaving.example.test")
	plan, _ := r.profilePlan("proxy", q)
	response := dnsAResponse(q, 60)
	response[0], response[1] = 0, 0
	r.cache.putOwned(plan.key, response, time.Millisecond, time.Now().Add(-time.Second))
	if _, ok := r.stalePlan(plan, q[:2]); !ok {
		t.Fatal("fixture did not contain a stale old response")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.routeProfiles["proxy"].factory = func(serverConfig, time.Duration) (upstream, error) {
		close(entered)
		<-release
		return &countingUpstream{}, nil
	}
	changed := make(chan struct{})
	go func() { p.Confirm("policy-a", "B"); close(changed) }()
	defer func() {
		once.Do(func() { close(release) })
		select {
		case <-changed:
		case <-time.After(time.Second):
			t.Error("retirement did not join")
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("retirement did not enter")
	} // retirement owns the profile lock
	started, done := make(chan struct{}), make(chan []byte, 1)
	go func() { close(started); done <- r.queryResult(plan, q, nil, context.DeadlineExceeded) }()
	<-started
	once.Do(func() { close(release) })
	<-changed
	select {
	case answer := <-done:
		if len(answer) < 12 || binary.BigEndian.Uint16(answer[2:4])&15 != 2 {
			t.Fatal("interleaved retired lookup used stale data")
		}
	case <-time.After(time.Second):
		t.Fatal("stale lookup did not join")
	}
}

func TestDNSRouteEpochExhaustionDoesNotConstructOrResurrect(t *testing.T) {
	r, p := epochRuntime(t, map[string]upstream{"proxy": &countingUpstream{}}, map[string]serverConfig{"proxy": epochConfig("policy-a")})
	profile := r.routeProfiles["proxy"]
	profile.epoch = ^uint64(0)
	profile.factory = func(serverConfig, time.Duration) (upstream, error) {
		t.Error("exhausted generation allocated an upstream")
		return &countingUpstream{}, nil
	}
	p.Confirm("policy-a", "B")
	if _, err := r.profilePlan("proxy", dnsQuery(1, "exhausted.example.test")); err != errDNSRouteRetired {
		t.Fatal("exhausted generation remained usable")
	}
}
