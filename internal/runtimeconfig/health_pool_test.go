package runtimeconfig

import (
	"encoding/json"
	"reflect"
	"testing"
)

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
	for id, wantBatch := range map[string]int{"best": 2, "priority": 3} {
		policy := objectValue(objectValue(policies[id])["policy"])
		for field, want := range map[string]int{
			"active_liveness_interval_seconds": 4,
			"failure_retry_interval_seconds":   2,
			"block_recovery_interval_seconds":  12,
			"active_check_interval_seconds":    45,
			"backup_check_interval_seconds":    180,
			"full_scan_interval_seconds":       900,
			"probe_batch_size":                 wantBatch,
		} {
			got, ok := numericInt(policy[field])
			if !ok || got != want {
				t.Fatalf("%s %s = %v, want %d", id, field, policy[field], want)
			}
		}
	}

	objectValue(objectValue(config["system"])["routing_monitor"])["probe_batch_size"] = json.Number("1")
	body, err = BuildXrayHealthPool(config, nil, map[string]any{"outbounds": []any{map[string]any{"tag": "block"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &pool); err != nil {
		t.Fatal(err)
	}
	policies = objectValue(pool["health_policies"])
	for _, id := range []string{"best", "priority"} {
		policy := objectValue(objectValue(policies[id])["policy"])
		if batch, ok := numericInt(policy["probe_batch_size"]); !ok || batch != 1 {
			t.Fatalf("%s explicit batch = %v, want 1", id, policy["probe_batch_size"])
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
