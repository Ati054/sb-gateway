package runtimeconfig

import "testing"

func TestBuildXrayRouteSourceBuildsOrderedManagedRoutes(t *testing.T) {
	serviceSelector := policyServiceSelectorTag("europe", "claude")
	config := map[string]any{
		"system": map[string]any{"networking": map[string]any{
			"routeros_gateway": "192.168.3.1", "container_address": "198.18.0.2/29", "tun_address": "198.18.0.1/30",
			"remote_ipv6_mode": "proxy_only",
		}},
		"routeros":   map[string]any{"router_addresses": []any{"192.168.3.1/32"}},
		"dns":        map[string]any{"hijack_managed_clients": true, "strict_dns": true, "force_tcp_for_proxy_services": true},
		"security":   map[string]any{"allow_router_management": false},
		"transports": []any{map[string]any{"id": "xr", "kind": "xhttp-reality", "enabled": true}},
		"networks":   []any{map[string]any{"id": "lan", "enabled": true, "kind": "internal", "cidrs": []any{"192.168.3.0/24"}}},
		"policies": []any{map[string]any{
			"id": "europe", "enabled": true, "mode": "priority", "traffic_mode": "vless_with_wan_exceptions",
			"candidate_service_ids": []any{"claude"}, "direct_services": []any{"torrent"},
		}},
		"remote_users": []any{map[string]any{
			"id": "phone", "enabled": true, "role": "trusted-full", "policy_id": "europe",
		}},
		"local_clients": []any{
			map[string]any{"id": "all-lan", "enabled": true, "policy_id": "europe", "source_kind": "lan", "source_scope": "lan-all", "source_cidrs": []any{"192.168.3.0/24"}},
			map[string]any{"id": "laptop", "enabled": true, "policy_id": "europe", "source_kind": "lan", "source_cidrs": []any{"192.168.3.22/32"}},
		},
	}
	outbounds := []map[string]any{
		{"tag": "direct-wan"}, {"tag": "block"}, {"tag": "subscription-update-egress"}, {"tag": "outbound-health-probe"},
		{"tag": "europe"}, {"tag": serviceSelector}, {"tag": "outbound-health-background"},
		{"tag": "outbound-health-background-2"}, {"tag": "outbound-health-background-3"},
	}
	route, err := BuildXrayRouteSource(config, []map[string]any{
		{"server": "edge.example"}, {"server": "203.0.113.7"},
	}, outbounds)
	if err != nil {
		t.Fatal(err)
	}
	rules := objectSlice(route["rules"])
	for _, tag := range []string{"outbound-health-background", "outbound-health-background-2", "outbound-health-background-3"} {
		background := findXraySourceRule(rules, func(rule map[string]any) bool {
			return containsText(stringSlice(rule["inbound"]), tag) && textValue(rule["outbound"]) == tag
		})
		if background == nil || !containsText(stringSlice(rules[2]["inbound"]), tag) {
			t.Fatalf("background probe %s lost isolation or private destination protection", tag)
		}
	}
	if len(rules) < 12 || rules[0]["action"] != "sniff" || rules[1]["action"] != "hijack-dns" {
		t.Fatalf("routing prelude changed: %#v", rules)
	}
	loop := findXraySourceRule(rules, func(rule map[string]any) bool {
		return textValue(rule["outbound"]) == "direct-wan" && containsText(stringSlice(rule["domain"]), "edge.example")
	})
	if loop == nil || !containsText(stringSlice(loop["ip_cidr"]), "203.0.113.7/32") {
		t.Fatalf("node loop-prevention rule = %#v", loop)
	}
	managementGrant := findXraySourceRule(rules, func(rule map[string]any) bool {
		return containsText(stringSlice(rule["auth_user"]), "phone") && containsText(stringSlice(rule["ip_cidr"]), "192.168.3.1/32") && textValue(rule["outbound"]) == "direct-wan"
	})
	if managementGrant == nil {
		t.Fatal("trusted-full management grant is missing")
	}
	privateGrant := findXraySourceRule(rules, func(rule map[string]any) bool {
		return containsText(stringSlice(rule["auth_user"]), "phone") && containsText(stringSlice(rule["ip_cidr"]), "10.0.0.0/8") && textValue(rule["outbound"]) == "direct-wan"
	})
	if privateGrant == nil || !containsText(stringSlice(privateGrant["ip_cidr"]), "192.168.0.0/16") {
		t.Fatalf("trusted-full dynamic private LAN grant = %#v", privateGrant)
	}
	privateBlock := findXraySourceRule(rules, func(rule map[string]any) bool {
		return len(stringSlice(rule["auth_user"])) == 0 && containsText(stringSlice(rule["ip_cidr"]), "10.0.0.0/8") && textValue(rule["outbound"]) == "block"
	})
	if privateBlock == nil {
		t.Fatal("untrusted remote users can reach newly routed private LANs")
	}
	ipv6 := findXraySourceRule(rules, func(rule map[string]any) bool {
		return rule["ip_version"] == 6 && containsText(stringSlice(rule["auth_user"]), "phone")
	})
	if ipv6 == nil || ipv6["outbound"] != "europe" {
		t.Fatalf("remote IPv6 route = %#v", ipv6)
	}
	candidate := findXraySourceRule(rules, func(rule map[string]any) bool {
		return textValue(rule["outbound"]) == serviceSelector && containsText(stringSlice(rule["rule_set"]), "service-claude")
	})
	if candidate == nil {
		t.Fatal("priority service selector route is missing")
	}
	torrent := findXraySourceRule(rules, func(rule map[string]any) bool {
		return textValue(rule["outbound"]) == "direct-wan" && containsText(stringSlice(rule["protocol"]), "bittorrent")
	})
	if torrent == nil {
		t.Fatal("direct sniffed service rule is missing")
	}
	forcedTCP := findXraySourceRule(rules, func(rule map[string]any) bool {
		return textValue(rule["action"]) == "reject" && textValue(rule["network"]) == "udp" && rule["port"] == 443 && containsText(stringSlice(rule["rule_set"]), "service-claude")
	})
	if forcedTCP == nil {
		t.Fatal("forced TCP rule is missing")
	}
	finalLocal := findXraySourceRule(rules, func(rule map[string]any) bool {
		return textValue(rule["outbound"]) == "europe" && containsText(stringSlice(rule["source_ip_cidr"]), "192.168.3.22/32") && rule["ip_version"] == nil
	})
	if finalLocal == nil {
		t.Fatal("local full-tunnel final route is missing")
	}
	exactIndex, allLANIndex := -1, -1
	for index, rule := range rules {
		if rule["ip_version"] != nil || textValue(rule["outbound"]) != "europe" {
			continue
		}
		if containsText(stringSlice(rule["source_ip_cidr"]), "192.168.3.22/32") {
			exactIndex = index
		}
		if containsText(stringSlice(rule["source_ip_cidr"]), "192.168.3.0/24") {
			allLANIndex = index
		}
	}
	if exactIndex < 0 || allLANIndex < 0 || exactIndex >= allLANIndex {
		t.Fatalf("specific LAN client must precede all-LAN fallback: exact=%d all=%d", exactIndex, allLANIndex)
	}
	remoteFallback := rules[len(rules)-1]
	if remoteFallback["outbound"] != "block" || !containsText(stringSlice(remoteFallback["inbound"]), "vless-xhttp-reality") {
		t.Fatalf("remote fallback = %#v", remoteFallback)
	}
	ruleSets := objectSlice(route["rule_set"])
	if findXraySourceRule(ruleSets, func(rule map[string]any) bool { return rule["tag"] == "service-claude" }) == nil ||
		findXraySourceRule(ruleSets, func(rule map[string]any) bool { return rule["tag"] == "service-torrent" }) == nil {
		t.Fatalf("referenced rulesets = %#v", ruleSets)
	}
}

func TestBuildXrayRouteSourceFailsClosedForMissingPolicyAndDisabledIPv6(t *testing.T) {
	config := map[string]any{
		"system":       map[string]any{"networking": map[string]any{"remote_ipv6_mode": "disabled"}},
		"remote_users": []any{map[string]any{"id": "phone", "enabled": true, "policy_id": "missing"}},
	}
	route, err := BuildXrayRouteSource(config, nil, []map[string]any{{"tag": "direct-wan"}, {"tag": "block"}})
	if err != nil {
		t.Fatal(err)
	}
	rules := objectSlice(route["rules"])
	ipv6 := findXraySourceRule(rules, func(rule map[string]any) bool { return rule["ip_version"] == 6 })
	if ipv6 == nil || ipv6["action"] != "reject" || ipv6["outbound"] != nil {
		t.Fatalf("disabled IPv6 route = %#v", ipv6)
	}
	userFinal := findXraySourceRule(rules, func(rule map[string]any) bool {
		return containsText(stringSlice(rule["auth_user"]), "phone") && rule["ip_version"] == nil && rule["outbound"] == "block"
	})
	if userFinal == nil {
		t.Fatal("missing policy did not fail closed")
	}
}

func TestBuildXrayRouteSourceRejectsInvalidManagementAddressAndPort(t *testing.T) {
	config := map[string]any{"system": map[string]any{"networking": map[string]any{"routeros_gateway": "invalid"}}}
	if _, err := BuildXrayRouteSource(config, nil, nil); err == nil {
		t.Fatal("invalid RouterOS gateway was accepted")
	}
	config = map[string]any{
		"system":   map[string]any{"networking": map[string]any{"remote_ipv6_mode": "proxy_only"}},
		"networks": []any{map[string]any{"id": "lan", "enabled": true, "cidrs": []any{"10.0.0.0/8"}}},
		"remote_users": []any{map[string]any{
			"id": "limited", "enabled": true, "role": "trusted-limited", "allowed_network_ids": []any{"lan"}, "allowed_ports": []any{70000},
		}},
	}
	if _, err := BuildXrayRouteSource(config, nil, nil); err == nil {
		t.Fatal("invalid trusted-limited port was accepted")
	}
}

func findXraySourceRule(rules []map[string]any, match func(map[string]any) bool) map[string]any {
	for _, rule := range rules {
		if match(rule) {
			return rule
		}
	}
	return nil
}
