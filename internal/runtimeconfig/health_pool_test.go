package runtimeconfig

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBuildXrayHealthPoolScopesEnabledLocalPolicies(t *testing.T) {
	config := map[string]any{
		"reverse_vless_exits": []any{map[string]any{"id": "exit", "enabled": true}},
		"policies": []any{
			map[string]any{"id": "local-a", "mode": "best", "selection_order": []any{"reverse:exit"}},
			map[string]any{"id": "local-b", "mode": "best", "selection_order": []any{"reverse:exit"}},
			map[string]any{"id": "remote", "mode": "best", "selection_order": []any{"reverse:exit"}},
			map[string]any{"id": "direct-only", "enabled": true, "mode": "direct"},
			map[string]any{"id": "empty", "enabled": true, "mode": "best", "selection_order": []any{"reverse:missing"}},
			map[string]any{"id": "disabled", "enabled": false, "mode": "best", "selection_order": []any{"reverse:exit"}},
		},
		"local_clients": []any{
			map[string]any{"policy_id": "local-b", "enabled": true},
			map[string]any{"policy_id": "local-a"},
			map[string]any{"policy_id": "local-a", "enabled": true},
			map[string]any{"policy_id": "remote", "enabled": false},
			map[string]any{"policy_id": "direct-only", "enabled": true},
			map[string]any{"policy_id": "empty", "enabled": true},
			map[string]any{"policy_id": "disabled", "enabled": true},
			map[string]any{"policy_id": "missing", "enabled": true},
		},
	}
	body, err := BuildXrayHealthPool(config, nil, map[string]any{"outbounds": []any{map[string]any{"tag": "block"}}})
	if err != nil {
		t.Fatal(err)
	}
	var pool map[string]any
	if err := json.Unmarshal(body, &pool); err != nil {
		t.Fatal(err)
	}
	if got := stringSlice(pool["local_policy_ids"]); !reflect.DeepEqual(got, []string{"local-a", "local-b"}) {
		t.Fatalf("local policy availability scope = %v", got)
	}
	if _, ok := objectValue(pool["health_policies"])["remote"]; !ok {
		t.Fatal("remote-only policy disappeared from structural reconciliation")
	}
	for _, id := range []string{"direct-only", "empty"} {
		if _, exists := objectValue(pool["health_policies"])[id]; exists {
			t.Fatalf("unmanaged policy %q unexpectedly has a health contract", id)
		}
	}
}

func TestBuildXrayHealthPoolUsesCurrentPriorityOrder(t *testing.T) {
	config := map[string]any{
		"reverse_vless_exits": []any{
			map[string]any{"id": "reality", "display_name": "Reverse Reality", "enabled": true},
			map[string]any{"id": "grpc", "display_name": "Reverse gRPC", "enabled": true},
			map[string]any{"id": "xhttp", "display_name": "Reverse XHTTP", "enabled": true},
		},
		"policies": []any{map[string]any{
			"id": "europe", "enabled": true, "mode": "priority",
			"max_active_candidates": 1,
			"selection_order":       []any{"reverse:reality", "reverse:grpc", "reverse:xhttp"},
		}},
	}
	body, err := BuildXrayHealthPool(config, nil, map[string]any{
		"outbounds": []any{map[string]any{"tag": "direct-wan"}, map[string]any{"tag": "block"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pool map[string]any
	if err := json.Unmarshal(body, &pool); err != nil {
		t.Fatal(err)
	}
	policy := objectValue(objectValue(pool["health_policies"])["europe"])
	want := []string{"reverse-vless-reality", "reverse-vless-grpc", "reverse-vless-xhttp"}
	if got := stringSlice(policy["candidates"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("health candidates = %v, want %v", got, want)
	}
	base := stringSlice(pool["base_outbound_tags"])
	for _, tag := range want {
		if !containsText(base, tag) {
			t.Fatalf("Reverse runtime tag %q is not a base selector member: %v", tag, base)
		}
	}
}

func TestBuildXrayHealthPoolUsesGlobalDefaultForLegacyBatches(t *testing.T) {
	for _, tc := range []struct {
		name    string
		monitor map[string]any
		batches map[string]int
	}{
		{"absent", nil, map[string]int{"best": 10, "priority": 10}},
		{"empty", map[string]any{}, map[string]int{"best": 10, "priority": 10}},
		{"auto", map[string]any{"probe_batch_size": 0}, map[string]int{"best": 10, "priority": 10}},
		{"explicit-five", map[string]any{"probe_batch_size": 5}, map[string]int{"best": 5, "priority": 5}},
		{"explicit-sixty-four", map[string]any{"probe_batch_size": 64}, map[string]int{"best": 64, "priority": 64}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := map[string]any{
				"reverse_vless_exits": []any{map[string]any{"id": "first", "enabled": true}},
				"policies": []any{
					map[string]any{"id": "best", "enabled": true, "mode": "best", "selection_order": []any{"reverse:first"}, "probe_batch_size": 2},
					map[string]any{"id": "priority", "enabled": true, "mode": "priority", "selection_order": []any{"reverse:first"}, "probe_batch_size": 3},
				},
			}
			if tc.monitor != nil {
				config["system"] = map[string]any{"routing_monitor": tc.monitor}
			}
			before := cloneJSONMap(config)
			body, err := BuildXrayHealthPool(config, nil, map[string]any{"outbounds": []any{map[string]any{"tag": "block"}}})
			if err != nil {
				t.Fatal(err)
			}
			var pool map[string]any
			if err := json.Unmarshal(body, &pool); err != nil {
				t.Fatal(err)
			}
			if got, ok := numericInt(pool["probe_budget"]); !ok || got != tc.batches["best"] {
				t.Fatalf("global budget = %v, want %d", pool["probe_budget"], tc.batches["best"])
			}
			if !reflect.DeepEqual(config, before) {
				t.Fatal("rendering global batches mutated the source config")
			}
			for id, want := range tc.batches {
				policy := objectValue(objectValue(objectValue(pool["health_policies"])[id])["policy"])
				if got, ok := numericInt(policy["probe_batch_size"]); !ok || got != want {
					t.Fatalf("%s batch = %v, want %d", id, policy["probe_batch_size"], want)
				}
			}
		})
	}
}

func TestBuildXrayHealthPoolResolvesGlobalMonitorSettings(t *testing.T) {
	config := map[string]any{
		"system": map[string]any{"routing_monitor": map[string]any{
			"active_liveness_interval_seconds": 4,
			"failure_retry_interval_seconds":   2,
			"block_recovery_interval_seconds":  12,
			"active_quality_interval_seconds":  45,
			"reserve_check_interval_seconds":   180,
			"full_scan_interval_seconds":       900,
			"probe_batch_size":                 0,
		}},
		"reverse_vless_exits": []any{
			map[string]any{"id": "first", "enabled": true},
			map[string]any{"id": "second", "enabled": true},
		},
		"policies": []any{
			map[string]any{"id": "best", "enabled": true, "mode": "best", "selection_order": []any{"reverse:first", "reverse:second"}, "active_check_interval_seconds": 999},
			map[string]any{"id": "priority", "enabled": true, "mode": "priority", "selection_order": []any{"reverse:first", "reverse:second"}, "probe_batch_size": 1},
		},
	}
	body, err := BuildXrayHealthPool(config, nil, map[string]any{"outbounds": []any{map[string]any{"tag": "block"}}})
	if err != nil {
		t.Fatal(err)
	}
	var pool map[string]any
	if err := json.Unmarshal(body, &pool); err != nil {
		t.Fatal(err)
	}
	policies := objectValue(pool["health_policies"])
	if budget, ok := numericInt(pool["probe_budget"]); !ok || budget != 10 {
		t.Fatalf("global budget = %v", pool["probe_budget"])
	}
	for id, wantBatch := range map[string]int{"best": 10, "priority": 10} {
		policy := objectValue(objectValue(policies[id])["policy"])
		for field, want := range map[string]int{
			"active_liveness_interval_seconds": 4,
			"active_check_interval_seconds":    45,
			"probe_batch_size":                 wantBatch,
		} {
			got, ok := numericInt(policy[field])
			if !ok || got != want {
				t.Fatalf("%s %s = %v, want %d", id, field, policy[field], want)
			}
		}
		for _, field := range []string{"failure_retry_interval_seconds", "block_recovery_interval_seconds", "backup_check_interval_seconds", "full_scan_interval_seconds"} {
			if _, exists := policy[field]; exists {
				t.Fatalf("%s retained retired monitor field %s", id, field)
			}
		}
	}

	for _, batch := range []int{1, 2, 5, 6, 7, 8, 9, 10, 24, 64} {
		objectValue(objectValue(config["system"])["routing_monitor"])["probe_batch_size"] = batch
		configured := objectSlice(config["policies"])
		configured[0]["speed_degradation_percent"] = 0
		configured[1]["speed_degradation_percent"] = 30
		body, err = BuildXrayHealthPool(config, nil, map[string]any{"outbounds": []any{map[string]any{"tag": "block"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &pool); err != nil {
			t.Fatal(err)
		}
		if got, ok := numericInt(pool["probe_budget"]); !ok || got != batch {
			t.Fatalf("global manual budget = %v, want %d", pool["probe_budget"], batch)
		}
		policies = objectValue(pool["health_policies"])
		for _, id := range []string{"best", "priority"} {
			policy := objectValue(objectValue(policies[id])["policy"])
			if got, ok := numericInt(policy["probe_batch_size"]); !ok || got != batch {
				t.Fatalf("%s explicit batch = %v, want %d", id, policy["probe_batch_size"], batch)
			}
			if _, exists := policy["speed_degradation_percent"]; exists {
				t.Fatalf("%s retained retired speed setting: %#v", id, policy)
			}
		}
	}
}

func TestHealthPoolPublishesSafeTransportMetadata(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{"id": "test", "enabled": true, "mode": "best", "selection_order": []any{"country:PL"}}}}
	nodes := []map[string]any{
		{"id": "ws", "subscription_id": "provider-one", "label": "Warsaw", "country": "PL", "protocol": "vless", "transport": map[string]any{"type": "ws"}, "_uuid": "must-not-leak"},
		{"id": "reality", "label": "Warsaw", "country": "PL", "protocol": "vless", "tls": map[string]any{"reality": map[string]any{"enabled": true, "public_key": "must-not-leak"}}},
	}
	body, err := BuildXrayHealthPool(config, nodes, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var pool map[string]any
	if err := json.Unmarshal(body, &pool); err != nil {
		t.Fatal(err)
	}
	inventory := objectValue(objectValue(objectValue(pool["health_policies"])["test"])["nodes"])
	if objectValue(inventory["ws"])["subscription_id"] != "provider-one" {
		t.Fatal("subscription identity missing from safe metadata")
	}
	if textValue(objectValue(inventory["ws"])["transport"]) != "ws" || textValue(objectValue(inventory["reality"])["protocol"]) != "reality" {
		t.Fatalf("missing protocol metadata: %s", body)
	}
	for _, raw := range inventory {
		if len(objectValue(raw)) != 5 {
			t.Fatal("metadata must be an explicit safe whitelist")
		}
	}
}

func TestHealthPoolFingerprintTracksOutboundNotDisplayName(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{"id": "test", "enabled": true, "mode": "priority", "selection_order": []any{"country:PL"}}}}
	node := map[string]any{"id": "stable-id", "subscription_id": "source", "label": "Old", "country": "PL", "protocol": "vless", "server": "192.0.2.10", "server_port": 443}
	outbound := map[string]any{"tag": "stable-id", "protocol": "vless", "settings": map[string]any{"port": 443, "uuid": "secret-uuid"}}
	read := func() (string, map[string]any) {
		t.Helper()
		body, err := BuildXrayHealthPool(config, []map[string]any{node}, map[string]any{"outbounds": []any{outbound}})
		if err != nil {
			t.Fatal(err)
		}
		var pool map[string]any
		if err := json.Unmarshal(body, &pool); err != nil {
			t.Fatal(err)
		}
		meta := objectValue(objectValue(objectValue(pool["health_policies"])["test"])["nodes"])
		return textValue(objectValue(meta["stable-id"])["fingerprint"]), objectValue(objectValue(pool["dial_targets"])["stable-id"])
	}
	before, target := read()
	if len(before) != 64 || target["address"] != "192.0.2.10" || target["port"] != float64(443) {
		t.Fatalf("missing endpoint metadata: fingerprint=%q target=%v", before, target)
	}
	node["label"] = "New cosmetic name"
	if renamed, _ := read(); renamed != before {
		t.Fatal("label change altered endpoint fingerprint")
	}
	outbound["settings"] = map[string]any{"port": 8443, "uuid": "secret-uuid"}
	if changed, _ := read(); changed == before {
		t.Fatal("outbound port change retained old fingerprint")
	}
}

func TestHealthPoolFingerprintSurvivesLocalClientAddition(t *testing.T) {
	config := map[string]any{
		"system": map[string]any{"networking": map[string]any{
			"tun_address": "198.18.0.1/30", "container_address": "198.18.0.2/29",
			"tun_mtu": 1400, "tun_stack": "system", "remote_ipv6_mode": "proxy_only",
		}},
		"dns": map[string]any{
			"internal_server": "192.168.3.1",
			"direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
		},
		"policies": []any{map[string]any{"id": "all", "enabled": true, "mode": "best", "selection_order": []any{"country:FR"}}},
	}
	nodes := []map[string]any{{
		"id": "fr", "enabled": true, "country": "FR", "protocol": "vless",
		"server": "fr.example", "server_port": 443, "uuid_secret_ref": "node/fr",
	}}
	fingerprint := func() string {
		t.Helper()
		xray, err := BuildXrayCandidateFromSchema(config, nodes, inboundSecretReader(map[string]string{
			"node/fr": "11111111-1111-1111-1111-111111111111",
		}), inboundSecretPath, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		body, err := BuildXrayHealthPool(config, nodes, xray.Config)
		if err != nil {
			t.Fatal(err)
		}
		var pool map[string]any
		if err := json.Unmarshal(body, &pool); err != nil {
			t.Fatal(err)
		}
		inventory := objectValue(objectValue(objectValue(pool["health_policies"])["all"])["nodes"])
		return textValue(objectValue(inventory["fr"])["fingerprint"])
	}
	before := fingerprint()
	if len(before) != 64 {
		t.Fatalf("missing endpoint fingerprint: %q", before)
	}
	config["local_clients"] = []any{map[string]any{
		"id": "iphone", "enabled": true, "policy_id": "all",
		"source_kind": "wireguard", "source_peer_refs": []any{"iphone-wireguard"},
	}}
	if after := fingerprint(); after != before {
		t.Fatalf("adding a local WireGuard client changed endpoint fingerprint: %q -> %q", before, after)
	}
}

func TestHealthPoolMovesProviderOutboundsToDynamicContract(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{
		"id": "europe", "enabled": true, "mode": "priority", "selection_order": []any{"country:DE"},
		"candidate_service_ids": []any{"claude"},
	}}}
	nodes := []map[string]any{{
		"id": "provider-de", "subscription_id": "provider", "enabled": true,
		"country": "DE", "protocol": "vless", "server": "de.example", "server_port": 443,
	}}
	xray := map[string]any{"outbounds": []any{
		map[string]any{"tag": "provider-de", "protocol": "vless", "settings": map[string]any{"vnext": []any{}}},
		map[string]any{"tag": "direct-wan", "protocol": "freedom"},
		map[string]any{"tag": "block", "protocol": "blackhole"},
	}}
	body, err := BuildXrayHealthPool(config, nodes, xray)
	if err != nil {
		t.Fatal(err)
	}
	var pool map[string]any
	if err := json.Unmarshal(body, &pool); err != nil {
		t.Fatal(err)
	}
	if objectValue(pool["outbounds"])["provider-de"] == nil {
		t.Fatal("provider outbound was not published for HandlerService")
	}
	base := stringSlice(pool["base_outbound_tags"])
	if containsText(base, "provider-de") || !containsText(base, "direct-wan") || !containsText(base, "block") {
		t.Fatalf("dynamic/static split is wrong: %v", base)
	}
	if !reflect.DeepEqual(stringSlice(objectValue(pool["policies"])["europe"]), []string{"provider-de"}) {
		t.Fatalf("priority policy has no dynamic members: %s", body)
	}
	if textValue(objectValue(pool["policy_prefixes"])["europe"]) != urlTestPolicyPrefix("europe") {
		t.Fatalf("priority policy has no stable dynamic prefix: %s", body)
	}
	serviceSelector := policyServiceSelectorTag("europe", "claude")
	if !reflect.DeepEqual(stringSlice(objectValue(pool["policies"])[serviceSelector]), []string{"provider-de"}) ||
		textValue(objectValue(pool["policy_prefixes"])[serviceSelector]) != urlTestPolicyPrefix("europe") {
		t.Fatalf("priority service selector has no dynamic contract: %s", body)
	}
}

func TestPruneDynamicXrayOutboundsKeepsOnlyRuntimeBaseAndPrefixes(t *testing.T) {
	xray := map[string]any{
		"outbounds": []any{
			map[string]any{"tag": "provider-de", "protocol": "vless"},
			map[string]any{"tag": "provider-fi", "protocol": "vless"},
			map[string]any{"tag": "direct-wan", "protocol": "freedom"},
			map[string]any{"tag": "wireguard-home", "protocol": "freedom"},
		},
		"routing": map[string]any{"balancers": []any{
			map[string]any{"tag": "policy", "selector": []any{"provider-de", "provider-fi", "wireguard-home", "sb-urltest-"}},
			map[string]any{"tag": "subscription-update-egress", "selector": []any{"direct-wan", "provider-de", "sb-subscription-update-"}},
		}},
	}
	pool := []byte(`{"outbounds":{"provider-de":{},"provider-fi":{}}}`)
	if err := PruneDynamicXrayOutbounds(xray, pool); err != nil {
		t.Fatal(err)
	}
	outbounds := objectSlice(xray["outbounds"])
	if len(outbounds) != 2 || textValue(outbounds[0]["tag"]) != "direct-wan" || textValue(outbounds[1]["tag"]) != "wireguard-home" {
		t.Fatalf("startup outbounds = %#v", outbounds)
	}
	balancers := objectSlice(objectValue(xray["routing"])["balancers"])
	if got := stringSlice(balancers[0]["selector"]); !reflect.DeepEqual(got, []string{"wireguard-home", "sb-urltest-"}) {
		t.Fatalf("policy selectors = %v", got)
	}
	if got := stringSlice(balancers[1]["selector"]); !reflect.DeepEqual(got, []string{"direct-wan", "sb-subscription-update-"}) {
		t.Fatalf("update selectors = %v", got)
	}
}

func TestPruneDynamicXrayOutboundsRejectsEmptySelector(t *testing.T) {
	xray := map[string]any{
		"outbounds": []any{map[string]any{"tag": "provider-de"}},
		"routing":   map[string]any{"balancers": []any{map[string]any{"tag": "broken", "selector": []any{"provider-de"}}}},
	}
	if err := PruneDynamicXrayOutbounds(xray, []byte(`{"outbounds":{"provider-de":{}}}`)); err == nil {
		t.Fatal("empty selector was accepted")
	}
}
