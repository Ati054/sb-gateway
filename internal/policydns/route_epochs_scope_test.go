package policydns

import (
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/dnsroute"
)

func TestDNSRouteEpochKeepsUnrelatedTunnelPoolsAndCachesWarm(t *testing.T) {
	a, b, wan := &countingUpstream{}, &countingUpstream{}, &countingUpstream{}
	r, p := epochRuntime(t, map[string]upstream{"a": a, "b": b, "wan-tunnel": wan}, map[string]serverConfig{"a": epochConfig("policy-a"), "b": epochConfig("policy-b"), "wan-tunnel": epochConfig("direct-wan")})
	rebuilt := map[string]int{}
	for tag, profile := range r.routeProfiles {
		profile.factory = func(serverConfig, time.Duration) (upstream, error) { rebuilt[tag]++; return &countingUpstream{}, nil }
	}
	mustEpochAnswer(t, r, "b", 1, "warm.example.test")
	mustEpochAnswer(t, r, "wan-tunnel", 2, "warm.example.test")
	beforeB, beforeWAN := r.routeProfiles["b"].keyPrefix, r.routeProfiles["wan-tunnel"].keyPrefix
	p.Confirm("policy-a", "B")
	mustEpochAnswer(t, r, "b", 3, "warm.example.test")
	mustEpochAnswer(t, r, "wan-tunnel", 4, "warm.example.test")
	mustEpochAnswer(t, r, "b", 5, "new.example.test")
	mustEpochAnswer(t, r, "wan-tunnel", 6, "new.example.test")
	if rebuilt["a"] != 1 || rebuilt["b"] != 0 || rebuilt["wan-tunnel"] != 0 || b.calls.Load() != 2 || wan.calls.Load() != 2 || r.routeProfiles["b"].server != b || r.routeProfiles["wan-tunnel"].server != wan || r.routeProfiles["b"].keyPrefix != beforeB || r.routeProfiles["wan-tunnel"].keyPrefix != beforeWAN {
		t.Fatal("unrelated tunnel pool or cache was cooled by a selector switch")
	}
	p.Sync(dnsroute.Core{PID: 1, StartTicks: 2}, []string{"policy-a", "policy-b"})
	if rebuilt["a"] != 2 || rebuilt["b"] != 1 || rebuilt["wan-tunnel"] != 1 {
		t.Fatal("core generation did not rotate every dependent tunnel")
	}
}
