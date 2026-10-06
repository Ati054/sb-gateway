package runtimeconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/healthcontract"
)

func TestHealthPoolPublishesOnlyTypedControllerPolicy(t *testing.T) {
	for _, tolerance := range []any{nil, "", 0, 200} {
		policy := map[string]any{
			"id": "route", "mode": "best", "selection_order": []any{"reverse:exit"},
			"switch_improvement_ms": tolerance, "unknown_secret": "do-not-publish",
			"candidate_service_ids":     []any{"web"},
			"candidate_service_access":  map[string]any{"reverse:exit": []any{"web"}},
			"speed_degradation_percent": "retired-invalid-value",
		}
		config := map[string]any{
			"policies": []any{policy}, "reverse_vless_exits": []any{map[string]any{"id": "exit"}},
			"system": map[string]any{"routing_monitor": map[string]any{
				"active_liveness_interval_seconds": 4, "active_quality_interval_seconds": 45, "probe_batch_size": 24,
			}},
		}
		body, err := BuildXrayHealthPool(config, nil, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		var pool struct {
			Policies map[string]struct {
				Policy healthcontract.Policy `json:"policy"`
			} `json:"health_policies"`
		}
		if err := json.Unmarshal(body, &pool); err != nil {
			t.Fatal(err)
		}
		resolved := pool.Policies["route"].Policy
		wantTolerance := 50
		if value, ok := tolerance.(int); ok {
			wantTolerance = value
		}
		if resolved.SwitchImprovementMS != wantTolerance || resolved.ActiveCheckSeconds != 45 ||
			resolved.ActiveLivenessSeconds != 4 || resolved.ProbeBatchSize != 24 ||
			len(resolved.CandidateServiceIDs) != 1 || len(resolved.CandidateServiceAccess["reverse:exit"]) != 1 {
			t.Fatalf("controller contract changed: %+v", resolved)
		}
		if strings.Contains(string(body), "do-not-publish") || strings.Contains(string(body), "speed_degradation_percent") {
			t.Fatal("draft-only fields leaked into the typed runtime policy")
		}
		if policy["unknown_secret"] != "do-not-publish" || policy["speed_degradation_percent"] != "retired-invalid-value" {
			t.Fatal("runtime projection modified the draft")
		}
	}
}

func TestHealthPoolRejectsMalformedControllerSettings(t *testing.T) {
	for _, field := range []string{"active_liveness_interval_seconds", "active_quality_interval_seconds", "probe_batch_size"} {
		config := map[string]any{"system": map[string]any{"routing_monitor": map[string]any{field: "invalid"}}}
		if _, err := BuildXrayHealthPool(config, nil, map[string]any{}); err == nil || !strings.Contains(err.Error(), "system.routing_monitor") {
			t.Fatalf("malformed %s silently became a default: %v", field, err)
		}
	}
	for _, field := range []string{"switch_improvement_ms", "candidate_service_ids", "candidate_service_access"} {
		config := map[string]any{
			"reverse_vless_exits": []any{map[string]any{"id": "exit"}},
			"policies":            []any{map[string]any{"id": "route", "mode": "best", "selection_order": []any{"reverse:exit"}, field: "invalid"}},
		}
		if _, err := BuildXrayHealthPool(config, nil, map[string]any{}); err == nil || !strings.Contains(err.Error(), "health policy") {
			t.Fatalf("malformed %s silently accepted: %v", field, err)
		}
	}
}
