package runtimeconfig

import "testing"

func TestAugmentRuntimeNodesAddsConfigurationOwnedExitsExactlyOnce(t *testing.T) {
	config := map[string]any{
		"system": map[string]any{"networking": map[string]any{
			"wireguard_egress_enabled": true,
			"wireguard_egress_exits":   []any{map[string]any{"id": "office", "interface": "wg-office", "enabled": true}},
		}},
		"subscription_reserves": []any{map[string]any{"id": "reserve", "enabled": true, "node": map[string]any{
			"id": "sub-reserve-one", "protocol": "vless", "server": "reserve.example", "server_port": 443,
		}}},
		"reverse_vless_exits": []any{map[string]any{"id": "home", "display_name": "Home", "enabled": true, "transport_ids": []any{"ws"}}},
	}
	nodes, err := augmentRuntimeNodes(config, []map[string]any{{"id": "provider", "protocol": "vless"}})
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"provider": false, "sub-reserve-one": false, "wg-egress-office": false, "reverse-vless-home": false}
	for _, node := range nodes {
		id := textValue(node["id"])
		if seen, expected := wanted[id]; expected {
			if seen {
				t.Fatalf("node %q duplicated: %#v", id, nodes)
			}
			wanted[id] = true
		}
	}
	for id, seen := range wanted {
		if !seen {
			t.Fatalf("node %q missing: %#v", id, nodes)
		}
	}
	if _, err := augmentRuntimeNodes(config, []map[string]any{{"id": "reverse-vless-home", "protocol": "vless"}}); err == nil {
		t.Fatal("provider node was allowed to shadow configuration-owned Reverse VLESS")
	}
}
