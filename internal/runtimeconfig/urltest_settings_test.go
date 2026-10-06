package runtimeconfig

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizeURLTestPoliciesRemovesOnlyRetiredSettings(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		policy := map[string]any{"id": "route", "mode": mode,
			"switch_improvement_ms": 50,
			"selection_order":       []any{"country:DE"}, "service_routes": map[string]any{"chat": "route"}}
		want := cloneJSONMap(policy)
		for _, field := range obsoleteURLTestPolicySettings {
			policy[field] = "obsolete-invalid-value"
		}
		config := map[string]any{"policies": []any{policy}, "system": map[string]any{"network_rate_bps": 12345}}
		NormalizeURLTestPolicies(config)
		NormalizeURLTestPolicies(config)
		if !reflect.DeepEqual(policy, want) || objectValue(config["system"])["network_rate_bps"] != 12345 {
			t.Fatalf("migration changed live routing settings/counters: %#v", config)
		}
	}
}

func TestHealthPoolOmitsRetiredSpeedSettingsWithoutMutatingInput(t *testing.T) {
	policy := map[string]any{"id": "route", "mode": "best", "selection_order": []any{"country:DE"}, "probe_batch_size": 5}
	retired := append(append([]string(nil), obsoleteURLTestSpeedSettings...), "max_latency_ms", "switch_cooldown_seconds")
	for _, field := range retired {
		policy[field] = 123
	}
	config := map[string]any{"policies": []any{policy}}
	body, err := BuildXrayHealthPool(config, []map[string]any{{"id": "node", "country": "DE"}}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var pool map[string]any
	if err := json.Unmarshal(body, &pool); err != nil {
		t.Fatal(err)
	}
	generated := objectValue(objectValue(objectValue(pool["health_policies"])["route"])["policy"])
	for _, field := range retired {
		if _, exists := generated[field]; exists || policy[field] != 123 {
			t.Fatalf("field=%s generated=%v input=%v", field, generated[field], policy[field])
		}
	}
	if batch, _ := numericInt(generated["probe_batch_size"]); batch != 10 || policy["probe_batch_size"] != 5 {
		t.Fatalf("global default missing or source policy mutated: generated=%v input=%v", generated["probe_batch_size"], policy["probe_batch_size"])
	}
}
