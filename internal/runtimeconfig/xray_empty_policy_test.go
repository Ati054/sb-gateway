package runtimeconfig

import "testing"

func TestEmptyCanonicalPolicyCannotReuseStableSelectorLeaf(t *testing.T) {
	for _, tc := range []struct {
		name      string
		selection []any
		omitted   bool
		node      map[string]any
		want      string
	}{
		{name: "omitted-selection", omitted: true, node: map[string]any{"id": "node", "subscription_id": "source", "enabled": true}, want: "block"},
		{name: "cleared-selection", selection: []any{}, node: map[string]any{"id": "node", "subscription_id": "source", "enabled": true}, want: "block"},
		{name: "unmatched-group", selection: []any{"group:selected"}, want: "block"},
		{name: "disabled-node", selection: []any{"group:selected"}, node: map[string]any{"id": "node", "subscription_id": "source", "enabled": false}, want: "block"},
		{name: "refresh-only-node", selection: []any{"group:selected"}, node: map[string]any{"id": "node", "subscription_id": "source", "subscription_reserve_id": "refresh", "enabled": true}, want: "block"},
		{name: "eligible-node", selection: []any{"group:selected"}, node: map[string]any{"id": "node", "subscription_id": "source", "enabled": true}, want: "route"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{
				"policies": []any{map[string]any{
					"id": "route", "enabled": true, "mode": "priority", "traffic_mode": "vless_with_wan_exceptions",
					"selection_order": tc.selection,
					"node_groups":     []any{map[string]any{"id": "selected", "name": "Selected", "subscription_ids": []any{"source"}}},
				}},
				"local_clients": []any{map[string]any{"id": "client", "enabled": true, "policy_id": "route", "source_kind": "lan", "source_cidrs": []any{"198.51.100.30/32"}}},
			}
			if tc.omitted {
				delete(objectSlice(config["policies"])[0], "selection_order")
			}
			nodes := []map[string]any{}
			if tc.node != nil {
				nodes = append(nodes, tc.node)
			}
			// A stable selector deliberately keeps all process outbounds. Its old
			// leaf must not make an empty or disabled policy eligible for traffic.
			outbounds := []map[string]any{{"tag": "direct-wan"}, {"tag": "block"}, {"tag": "node"}, {"tag": "route", "type": "selector", "outbounds": []any{"block", "node"}}}
			route, err := BuildXrayRouteSource(config, nodes, outbounds)
			if err != nil {
				t.Fatal(err)
			}
			rule := findXraySourceRule(objectSlice(route["rules"]), func(rule map[string]any) bool {
				return containsText(stringSlice(rule["source_ip_cidr"]), "198.51.100.30/32") && textValue(rule["action"]) == "route" && rule["protocol"] == nil && rule["ip_cidr"] == nil && rule["domain_suffix"] == nil && rule["domain"] == nil && rule["rule_set"] == nil && rule["port"] == nil
			})
			if rule == nil || textValue(rule["outbound"]) != tc.want {
				t.Fatalf("canonical policy route=%#v, want outbound %q", rule, tc.want)
			}
		})
	}
}

func TestEmptyCanonicalWANPreservesWANAndBlocksVLESSExceptions(t *testing.T) {
	config := map[string]any{
		"policies": []any{map[string]any{
			"id": "route", "enabled": true, "mode": "priority", "traffic_mode": "wan_with_vless_exceptions", "final": "direct",
			"selection_order": []any{},
			"custom_routes":   []any{map[string]any{"id": "exception", "kind": "domain", "value": "service.example", "target": "vless"}},
		}},
		"local_clients": []any{map[string]any{"id": "client", "enabled": true, "policy_id": "route", "source_kind": "lan", "source_cidrs": []any{"198.51.100.30/32"}}},
	}
	outbounds := []map[string]any{{"tag": "direct-wan"}, {"tag": "block"}, {"tag": "node"}, {"tag": "route", "type": "selector"}}
	route, err := BuildXrayRouteSource(config, []map[string]any{{"id": "node", "enabled": true}}, outbounds)
	if err != nil {
		t.Fatal(err)
	}
	rules := objectSlice(route["rules"])
	exception := findXraySourceRule(rules, func(rule map[string]any) bool {
		return containsText(stringSlice(rule["source_ip_cidr"]), "198.51.100.30/32") && containsText(stringSlice(rule["domain_suffix"]), "service.example")
	})
	if exception == nil || textValue(exception["outbound"]) != "block" {
		t.Fatalf("empty VLESS exception reused its stable selector: %#v", exception)
	}
	final := findXraySourceRule(rules, func(rule map[string]any) bool {
		return containsText(stringSlice(rule["source_ip_cidr"]), "198.51.100.30/32") && rule["protocol"] == nil && rule["ip_cidr"] == nil && rule["domain_suffix"] == nil && rule["domain"] == nil && rule["rule_set"] == nil
	})
	if final != nil {
		t.Fatalf("explicit WAN default unexpectedly received a proxy route: %#v", final)
	}
	if len(outbounds) != 4 || outbounds[3]["tag"] != "route" {
		t.Fatal("eligibility filtering changed the physical selector inventory")
	}
}
