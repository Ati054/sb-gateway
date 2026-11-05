package runtimeconfig

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestManagedGoDNSUsesCompiledSourceOrderAndKeepsOtherIdentities(t *testing.T) {
	lanes := []PolicyDNSLane{{ID: "specific"}, {ID: "broad"}, {ID: "remote"}}
	rules := []map[string]any{
		{"type": "field", "inboundTag": []string{"tun-routeros"}, "source": []string{"192.0.2.9/32"}, "network": "tcp,udp", "port": "53", "outboundTag": "specific"},
		{"type": "field", "inboundTag": []string{"tun-routeros"}, "source": []string{"192.0.2.0/24", "2001:db8::/32"}, "network": "tcp,udp", "port": "53", "outboundTag": "broad"},
		{"type": "field", "inboundTag": []string{"vless-main"}, "user": []string{"remote-user"}, "network": "tcp,udp", "port": "53", "outboundTag": "remote"},
		{"type": "field", "port": "53", "outboundTag": "broad"},
	}
	before, _ := json.Marshal(rules)
	got, err := managedDNSGoIngress("198.18.0.2", rules, lanes)
	if err != nil {
		t.Fatal(err)
	}
	want := []PolicyDNSManagedRule{{SourceCIDRs: []string{"192.0.2.9/32"}, LaneID: "specific"}, {SourceCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}, LaneID: "broad"}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Fatalf("ordered identity or authenticated-user isolation changed: %#v", got.Rules)
	}
	after, _ := json.Marshal(rules)
	if !bytes.Equal(before, after) {
		t.Fatal("generic or authenticated Xray rules were mutated")
	}
	if !reflect.DeepEqual(got.Listeners, []PolicyDNSManagedListener{{Host: "198.18.0.2", Port: ManagedDNSPort}}) {
		t.Fatalf("unexpected managed endpoint: %#v", got.Listeners)
	}
}

func TestManagedGoDNSRejectsRestrictionsItCannotRepresent(t *testing.T) {
	for _, extra := range []map[string]any{
		{"user": []string{"authenticated"}}, {"domain": []string{"full:private.test"}},
		{"network": "tcp"}, {"port": "443"}, {"port": 53}, {"outboundTag": "missing"},
		{"source": []string{"geoip:private"}}, {"source": []any{"192.0.2.0/24", 1}},
		{"source": []string{"::ffff:192.0.2.0/80"}},
	} {
		rule := map[string]any{"type": "field", "inboundTag": []string{"tun-routeros"}, "source": []string{"192.0.2.0/24"}, "network": "tcp,udp", "port": "53", "outboundTag": "lane"}
		for key, value := range extra {
			rule[key] = value
		}
		if _, err := managedDNSGoIngress("198.18.0.2", []map[string]any{rule}, []PolicyDNSLane{{ID: "lane"}}); err == nil {
			t.Fatalf("unrepresentable identity was broadened: %#v", extra)
		}
	}
}

func TestManagedGoDNSNormalizesLiteralAndMappedSourcesWithoutReordering(t *testing.T) {
	got, err := managedDNSGoIngress("::ffff:198.18.0.2", []map[string]any{{"inboundTag": []string{"tun-routeros"}, "source": []string{"192.0.2.1", "::ffff:192.0.2.129/120", "2001:db8::9/64"}, "outboundTag": "lane"}}, []PolicyDNSLane{{ID: "lane"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Listeners[0].Host != "198.18.0.2" || !reflect.DeepEqual(got.Rules[0].SourceCIDRs, []string{"192.0.2.1/32", "192.0.2.0/24", "2001:db8::/64"}) {
		t.Fatalf("CIDR normalization changed: %#v", got)
	}
}

func TestManagedGoDNSRejectsScopedListenerBeforeUnmapping(t *testing.T) {
	for _, test := range []struct {
		name    string
		address string
		want    string
	}{
		{"plain-mapped", "::ffff:198.18.0.2", "198.18.0.2"},
		{"scoped-mapped", "::ffff:198.18.0.2%eth0", ""},
		{"scoped-native", "fe80::2%eth0", ""},
		{"invalid", "not-an-address", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := managedDNSGoIngress(test.address, nil, nil)
			if test.want == "" {
				if err == nil || got != nil {
					t.Fatal("invalid scoped listener was normalized into an accepted endpoint")
				}
				return
			}
			if err != nil || len(got.Listeners) != 1 || got.Listeners[0].Host != test.want || got.Listeners[0].Port != ManagedDNSPort {
				t.Fatalf("unscoped mapped endpoint normalization changed: %#v %v", got, err)
			}
		})
	}
}

func TestManagedDNSArtifactOwnershipPairs(t *testing.T) {
	core := []byte(`{"inbounds":[{"tag":"routeros-client-dns","listen":"198.18.0.2","port":1053,"protocol":"dokodemo-door"}]}`)
	plain := []byte(`{"inbounds":[]}`)
	legacy := []byte(`{"version":1,"lane_layout_version":1}`)
	current := []byte(`{"version":1,"lane_layout_version":2,"managed_ingress":{"listeners":[{"host":"198.18.0.2","port":1053}],"rules":[]}}`)
	for _, test := range []struct {
		name      string
		core, dns []byte
		owner     ManagedDNSOwner
		bad       bool
	}{
		{"legacy", core, legacy, ManagedDNSOwnerXray, false},
		{"direct-Go", plain, current, ManagedDNSOwnerGo, false},
		{"two-owners", core, current, "", true},
		{"new-layout-old-core", core, []byte(`{"version":1,"lane_layout_version":2}`), "", true},
		{"legacy-disabled-intent-required", plain, legacy, ManagedDNSOwnerNone, false},
		{"unconfigured", nil, nil, ManagedDNSOwnerNone, false},
		{"missing-resolver", core, nil, "", true},
		{"missing-core", nil, current, "", true},
		{"unexpected-core-owner", []byte(`{"inbounds":[{"tag":"public","port":"1000-1100"}]}`), legacy, "", true},
		{"duplicate-mapped-listener", plain, []byte(`{"version":1,"lane_layout_version":2,"managed_ingress":{"listeners":[{"host":"198.18.0.2","port":1053},{"host":"::ffff:198.18.0.2","port":1053}],"rules":[]}}`), "", true},
		{"plain-mapped-core", []byte(`{"inbounds":[{"tag":"routeros-client-dns","listen":"::ffff:198.18.0.2","port":1053,"protocol":"dokodemo-door"}]}`), legacy, ManagedDNSOwnerXray, false},
		{"plain-mapped-Go", plain, []byte(`{"version":1,"lane_layout_version":2,"managed_ingress":{"listeners":[{"host":"::ffff:198.18.0.2","port":1053}],"rules":[]}}`), ManagedDNSOwnerGo, false},
		{"scoped-mapped-core", []byte(`{"inbounds":[{"tag":"routeros-client-dns","listen":"::ffff:198.18.0.2%eth0","port":1053,"protocol":"dokodemo-door"}]}`), legacy, "", true},
		{"scoped-mapped-Go", plain, []byte(`{"version":1,"lane_layout_version":2,"managed_ingress":{"listeners":[{"host":"::ffff:198.18.0.2%eth0","port":1053}],"rules":[]}}`), "", true},
		{"scoped-native-core", []byte(`{"inbounds":[{"tag":"routeros-client-dns","listen":"fe80::2%eth0","port":1053,"protocol":"dokodemo-door"}]}`), legacy, "", true},
		{"scoped-native-Go", plain, []byte(`{"version":1,"lane_layout_version":2,"managed_ingress":{"listeners":[{"host":"fe80::2%eth0","port":1053}],"rules":[]}}`), "", true},
		{"wrong-port", plain, []byte(`{"version":1,"lane_layout_version":2,"managed_ingress":{"listeners":[{"host":"198.18.0.2","port":1054}],"rules":[]}}`), "", true},
		{"null-core", []byte(`null`), current, "", true},
		{"null-resolver", plain, []byte(`null`), "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner, err := ValidateManagedDNSOwnership(test.core, test.dns)
			if (err != nil) != test.bad || err == nil && owner != test.owner {
				t.Fatalf("owner=%q err=%v", owner, err)
			}
		})
	}
}
