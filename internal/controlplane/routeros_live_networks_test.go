package controlplane

import (
	"reflect"
	"testing"
)

func TestRouterOSLiveNetworkCIDRsKeepsPrivateRoutesAndExcludesRuntimeLinks(t *testing.T) {
	config := map[string]any{"system": map[string]any{"networking": map[string]any{
		"container_address": "172.30.80.2/30", "tun_address": "172.19.0.1/30",
	}}}
	discovery := map[string]any{
		"access_destination_inventory_complete": true,
		"access_destinations": []any{
			map[string]any{"cidr": "10.15.0.1/32"},
			map[string]any{"cidr": "192.168.50.0/24"},
			map[string]any{"cidr": "192.168.90.0/24"},
			map[string]any{"cidr": "172.30.80.0/30"},
			map[string]any{"cidr": "172.19.0.0/30"},
			map[string]any{"cidr": "203.0.113.0/24"},
			map[string]any{"cidr": "fe80::/64"},
		},
	}
	got, complete := routerOSLiveNetworkCIDRs(config, discovery)
	want := []any{"10.15.0.1/32", "192.168.50.0/24", "192.168.90.0/24"}
	if !complete || !reflect.DeepEqual(got, want) {
		t.Fatalf("live LAN inventory = %#v, complete=%v", got, complete)
	}
	discovery["access_destination_inventory_complete"] = false
	if got, complete = routerOSLiveNetworkCIDRs(config, discovery); complete || got != nil {
		t.Fatalf("partial discovery was published: %#v, complete=%v", got, complete)
	}
}

func TestClientAllowedLANUsesCompleteLiveInventoryForTrustedFull(t *testing.T) {
	config := map[string]any{
		"networks":               []any{map[string]any{"enabled": true, "kind": "internal", "cidrs": []any{"192.168.90.0/24"}}},
		"routeros_live_networks": []any{"192.168.50.0/24", "192.168.92.0/24", "192.168.50.0/24"},
		"routeros": map[string]any{"router_addresses": []any{
			"10.12.0.3/32", "192.168.50.1/32", "fe80::1/128",
		}},
		"system": map[string]any{"networking": map[string]any{"routeros_gateway": "172.30.80.1"}},
	}
	got, ports, err := clientAllowedLAN(config, map[string]any{"role": "trusted-full"})
	want := []string{"192.168.50.0/24", "192.168.92.0/24"}
	if err != nil || len(ports) != 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("trusted-full live LAN = %#v ports=%#v err=%v", got, ports, err)
	}
}

func TestSortedClientCIDRsCompactsContainedNetworks(t *testing.T) {
	got := sortedClientCIDRs([]string{
		"192.168.50.1/32", "192.168.50.0/24", "192.168.50.0/24",
		"10.15.0.1", "fe80::1/128", "fe80::/64",
	})
	want := []string{"10.15.0.1/32", "192.168.50.0/24", "fe80::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compacted client CIDRs = %#v", got)
	}
}

func TestWithRouterOSLiveNetworksPublishesCompleteEmptySnapshot(t *testing.T) {
	server := newTestServer(t)
	config := map[string]any{"networks": []any{map[string]any{"cidrs": []any{"192.168.90.0/24"}}}}
	if got := server.withRouterOSLiveNetworks(config); got["routeros_live_networks"] != nil {
		t.Fatalf("missing live snapshot changed config: %#v", got)
	}
	if err := server.repository.saveAuxiliary("routeros-live-networks", map[string]any{"complete": true, "cidrs": []any{}}); err != nil {
		t.Fatal(err)
	}
	got := server.withRouterOSLiveNetworks(config)
	if live, exists := got["routeros_live_networks"]; !exists || len(anySlice(live)) != 0 {
		t.Fatalf("complete empty live snapshot was lost: %#v", got)
	}
	if _, exists := config["routeros_live_networks"]; exists {
		t.Fatal("live overlay mutated stored configuration")
	}
}
