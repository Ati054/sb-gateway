package policydns

import (
	"fmt"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/domainset"
)

func TestSharedDNSSetsKeepLaneDecisionsAndFirstMatch(t *testing.T) {
	set := domainset.Set{DomainSuffix: []string{"example.test"}}
	for n := 0; n < 1000; n++ {
		set.Domain = append(set.Domain, fmt.Sprintf("host-%d.test", n))
	}
	index, ids, err := domainset.Compile(map[string]domainset.Set{set.ID(): set})
	if err != nil {
		t.Fatal(err)
	}
	lanes := []laneConfig{
		{ID: "a", Host: "127.0.0.1", Port: 31001, Final: "wan", Rules: []ruleConfig{{Domain: []string{"first.example.test"}, Server: "exception"}, {DomainSet: set.ID(), Server: "vpn-a"}}},
		{ID: "b", Host: "127.0.0.1", Port: 31002, Final: "wan", Rules: []ruleConfig{{DomainSet: set.ID(), Action: "reject"}, {Domain: []string{"first.example.test"}, Server: "vpn-b"}}},
	}
	a, err := compileLaneWithSets(lanes[0], index, ids)
	if err != nil {
		t.Fatal(err)
	}
	b, err := compileLaneWithSets(lanes[1], index, ids)
	if err != nil {
		t.Fatal(err)
	}
	if a.shared != b.shared || len(a.exact) != 1 || len(a.setDecisions) != 1 {
		t.Fatal("large membership was copied per lane")
	}
	for _, tc := range []struct {
		lane         *lane
		name, server string
		reject       bool
	}{{a, "first.example.test", "exception", false}, {a, "host-999.test", "vpn-a", false}, {b, "first.example.test", "reject", true}, {a, "evilexample.test", "wan", false}} {
		server, reject := tc.lane.target(tc.name)
		if server != tc.server || reject != tc.reject {
			t.Fatalf("%s lane %s: %s/%t", tc.name, tc.lane.id, server, reject)
		}
	}
	if _, err := compileLane(lanes[0]); err == nil {
		t.Fatal("missing shared set did not fail closed")
	}
}

func BenchmarkDNSMembershipCompilation(b *testing.B) {
	set := domainset.Set{}
	for n := 0; n < 10000; n++ {
		set.DomainSuffix = append(set.DomainSuffix, fmt.Sprintf("domain-%d.test", n))
	}
	for _, shared := range []bool{false, true} {
		id := set.ID()
		b.Run(fmt.Sprintf("shared=%t", shared), func(b *testing.B) {
			b.ReportAllocs()
			for n := 0; n < b.N; n++ {
				var index *domainset.Index
				var ids map[string]uint32
				if shared {
					index, ids, _ = domainset.Compile(map[string]domainset.Set{id: set})
				}
				for lane := 0; lane < 8; lane++ {
					rule := ruleConfig{DomainSuffix: set.DomainSuffix, Server: "vpn"}
					if shared {
						rule.DomainSuffix = nil
						rule.DomainSet = id
					}
					if _, err := compileLaneWithSets(laneConfig{ID: fmt.Sprint(lane), Host: "127.0.0.1", Port: 31000 + lane, Rules: []ruleConfig{rule}}, index, ids); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
