package runtimeconfig

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)

func TestPolicyDNSReusesEquivalentClientPolicies(t *testing.T) {
	source := PolicyDNSSource{Final: "direct", Servers: []PolicyDNSSourceServer{
		{Tag: "direct", Type: "udp", Server: "192.0.2.1"},
		{Tag: "vpn-a", Type: "udp", Server: "192.0.2.2"},
		{Tag: "vpn-b", Type: "udp", Server: "192.0.2.2"},
	}}
	for n := 1; n <= 48; n++ {
		server := []string{"direct", "vpn-a", "vpn-b"}[n%3]
		source.Rules = append(source.Rules, PolicyDNSSourceRule{
			SourceCIDR: []string{fmt.Sprintf("198.51.100.%d/32", n)}, Action: "route", Server: server,
		})
	}
	artifacts, err := CompilePolicyDNS(source, PolicyDNSCompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.Runtime.Lanes) != 3 || len(artifacts.XrayOutbounds) != 3 || len(artifacts.XrayRules) != 4 {
		t.Fatalf("expected three effective lanes, three host groups and fallback; got %d/%d/%d",
			len(artifacts.Runtime.Lanes), len(artifacts.XrayOutbounds), len(artifacts.XrayRules))
	}
	lanes := make(map[string]PolicyDNSLane)
	for _, lane := range artifacts.Runtime.Lanes {
		lanes[lane.ID] = lane
	}
	for n := 1; n <= 49; n++ {
		addr := netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", n))
		tag := matchDNSHostRoute(t, artifacts.XrayRules, addr)
		want := "direct"
		if n <= 48 {
			want = []string{"direct", "vpn-a", "vpn-b"}[n%3]
		}
		if lanes[tag].Final != want {
			t.Fatalf("source %s resolved through %q, want %q", addr, lanes[tag].Final, want)
		}
	}
	// Compilation must not consume or mutate the source, and port/tag allocation
	// must remain deterministic when equivalent identities are added.
	again, err := CompilePolicyDNS(source, PolicyDNSCompileOptions{})
	if err != nil || !reflect.DeepEqual(artifacts, again) {
		t.Fatalf("non-deterministic compilation: %v", err)
	}
}

func TestPolicyDNSSharingPreservesOrderedRulesAndAccess(t *testing.T) {
	source := PolicyDNSSource{Final: "direct", Servers: []PolicyDNSSourceServer{
		{Tag: "direct", Type: "udp", Server: "192.0.2.1"},
		{Tag: "vpn", Type: "udp", Server: "192.0.2.2"},
	}, Rules: []PolicyDNSSourceRule{
		{AuthUser: []string{"alice"}, DomainSuffix: []string{"example.test"}, Action: "route", Server: "vpn"},
		{AuthUser: []string{"alice"}, Domain: []string{"blocked.example.test"}, Action: "reject"},
		{AuthUser: []string{"bob"}, Domain: []string{"blocked.example.test"}, Action: "reject"},
		{AuthUser: []string{"bob"}, DomainSuffix: []string{"example.test"}, Action: "route", Server: "vpn"},
		{Inbound: []string{"private"}, Action: "reject"},
		{SourceCIDR: []string{"198.51.100.1/32"}, Action: "route", Server: "direct"},
	}}
	artifacts, err := CompilePolicyDNS(source, PolicyDNSCompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.Runtime.Lanes) != 4 || len(artifacts.XrayRules) != 5 {
		t.Fatalf("ordered rules/reject/fallback were merged incorrectly: %#v", artifacts)
	}
	byTag := make(map[string]PolicyDNSLane)
	for _, lane := range artifacts.Runtime.Lanes {
		byTag[lane.ID] = lane
	}
	for _, route := range artifacts.XrayRules {
		lane := byTag[route["outboundTag"].(string)]
		if users, ok := route["user"].([]string); ok {
			wantFirst := "route"
			if users[0] == "bob" {
				wantFirst = "reject"
			}
			if len(lane.Rules) != 2 || lane.Rules[0].Action != wantFirst {
				t.Fatalf("lost ordered access rules for %v: %#v", users, lane)
			}
		}
		if _, ok := route["inboundTag"]; ok && lane.Final != "reject" {
			t.Fatal("restricted inbound shares an unrestricted lane")
		}
	}
}

func TestCompactPolicyDNSHostRulesPreservesFirstMatch(t *testing.T) {
	host := func(tag string, sources ...string) map[string]any {
		return map[string]any{"type": "field", "network": "tcp,udp", "port": "53", "outboundTag": tag, "source": sources}
	}
	for _, test := range []struct {
		name  string
		rules []map[string]any
	}{
		{"disjoint", []map[string]any{host("a", "198.51.100.1/32"), host("b", "198.51.100.2/32"), host("a", "198.51.100.3/32")}},
		{"overlap", []map[string]any{host("a", "198.51.100.1/32"), host("b", "198.51.100.1/32", "198.51.100.2/32"), host("a", "198.51.100.2/32")}},
		{"prefix", []map[string]any{host("a", "198.51.100.1/32"), host("b", "198.51.100.0/24"), host("a", "198.51.100.2/32")}},
		{"ipv6", []map[string]any{host("a", "2001:db8::1/128"), host("b", "2001:db8::2/128"), host("a", "2001:db8::3/128")}},
		{"mapped overlap", []map[string]any{host("a", "198.51.100.1/32"), host("b", "::ffff:198.51.100.1/128"), host("a", "198.51.100.2/32")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Keep an independent original: compaction owns its generated maps.
			original := make([]map[string]any, len(test.rules))
			for i, rule := range test.rules {
				original[i] = host(rule["outboundTag"].(string), rule["source"].([]string)...)
			}
			compacted := compactPolicyDNSHostRules(test.rules)
			for _, text := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.254", "2001:db8::1", "2001:db8::2", "2001:db8::3"} {
				addr := netip.MustParseAddr(text)
				if matchDNSHostRoute(t, original, addr) != matchDNSHostRoute(t, compacted, addr) {
					t.Fatalf("changed first match for %s", addr)
				}
			}
		})
	}
	for _, key := range []string{"user", "inboundTag"} {
		middle := host("b", "198.51.100.2/32")
		middle[key] = []string{"private"}
		rules := []map[string]any{host("a", "198.51.100.1/32"), middle, host("a", "198.51.100.3/32")}
		if got := compactPolicyDNSHostRules(rules); len(got) != 3 || got[1][key] == nil {
			t.Fatalf("compacted across %s constraint: %#v", key, got)
		}
	}
}

func matchDNSHostRoute(t *testing.T, rules []map[string]any, addr netip.Addr) string {
	t.Helper()
	for _, rule := range rules {
		sources, ok := rule["source"].([]string)
		if !ok {
			return rule["outboundTag"].(string)
		}
		for _, text := range sources {
			prefix := netip.MustParsePrefix(text)
			if prefix.Contains(addr) || (prefix.Bits() == prefix.Addr().BitLen() && prefix.Addr().Unmap() == addr.Unmap()) {
				return rule["outboundTag"].(string)
			}
		}
	}
	return ""
}
