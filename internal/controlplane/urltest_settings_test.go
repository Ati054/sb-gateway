package controlplane

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

var legacyURLTestFields = []string{
	"speed_check_enabled", "speed_improvement_percent", "speed_degradation_percent", "speed_check_interval_seconds", "speed_probe_bytes", "speed_candidate_count",
	"quality_window", "max_packet_loss_percent", "failure_threshold", "recovery_threshold",
	"active_check_interval_seconds", "backup_check_interval_seconds", "full_scan_interval_seconds",
	"max_active_candidates", "max_probe_candidates", "probe_batch_size",
	"active_liveness_interval_seconds", "failure_retry_interval_seconds", "block_recovery_interval_seconds",
	"switch_cooldown", "switch_improvement_percent", "return_to_primary", "interrupt_exist_connections",
	"switch_cooldown_seconds", "max_latency_ms",
}

func legacyURLTestFixture(t *testing.T) map[string]any {
	t.Helper()
	config := currentConfigFixture(t)
	policy := map[string]any{"id": "route", "mode": "best", "selection_order": []any{"country:DE"}, "switch_cooldown_seconds": 600, "recovery_threshold": 3}
	for _, field := range legacyURLTestFields {
		policy[field] = "retired-invalid-value"
	}
	config["policies"] = []any{policy}
	monitor := objectAt(config, "system")["routing_monitor"].(map[string]any)
	monitor["probe_batch_size"] = 5
	for _, field := range []string{"failure_retry_interval_seconds", "block_recovery_interval_seconds", "reserve_check_interval_seconds", "full_scan_interval_seconds"} {
		monitor[field] = "retired-invalid-value"
	}
	return config
}

func assertMigratedURLTestConfig(t *testing.T, config map[string]any) {
	t.Helper()
	policy := objects(config["policies"])[0]
	for _, field := range legacyURLTestFields {
		if _, exists := policy[field]; exists {
			t.Fatalf("retired field survived: %s", field)
		}
	}
	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("migration broke unrelated validation: %#v", result.Errors)
	}
	if got := text(nestedValue(config, "system", "routing_monitor", "probe_batch_size")); got != "5" {
		t.Fatalf("explicit concurrency changed: %v", nestedValue(config, "system", "routing_monitor", "probe_batch_size"))
	}
	for _, field := range []string{"failure_retry_interval_seconds", "block_recovery_interval_seconds", "reserve_check_interval_seconds", "full_scan_interval_seconds"} {
		if nestedValue(config, "system", "routing_monitor", field) != nil {
			t.Fatalf("retired global interval survived migration: %s", field)
		}
	}
}

func TestLegacyURLTestDraftReadAndSaveMigration(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	legacy := legacyURLTestFixture(t)
	if _, err := server.repository.saveDraft(legacy); err != nil {
		t.Fatal(err)
	}
	draft, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	assertMigratedURLTestConfig(t, draft)
	stored, err := server.repository.loadDraft()
	if err != nil || objects(stored["policies"])[0]["speed_probe_bytes"] == nil {
		t.Fatalf("read path rewrote persisted draft: %#v %v", stored, err)
	}
	response := performRequest(t, server, http.MethodPut, apiPrefix+"/drafts/current", map[string]any{"config": legacy}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy save failed: %d %s", response.Code, response.Body.String())
	}
	stored, err = server.repository.loadDraft()
	if err != nil {
		t.Fatal(err)
	}
	assertMigratedURLTestConfig(t, stored)
}

func TestResetLegacyURLTestDraftPreservesGeneration(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	legacy := legacyURLTestFixture(t)
	revision, err := server.repository.stageGeneration(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/reset", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy reset failed: %d %s", response.Code, response.Body.String())
	}
	stored, err := server.repository.loadDraft()
	if err != nil {
		t.Fatal(err)
	}
	assertMigratedURLTestConfig(t, stored)
	generation, err := server.repository.loadGeneration(revision)
	if err != nil || objects(generation["policies"])[0]["speed_probe_bytes"] == nil {
		t.Fatalf("reset rewrote immutable generation: %#v %v", generation, err)
	}
	if active, err := server.repository.activeRevision(); err != nil || active != revision {
		t.Fatalf("draft migration activated another generation: %q %v", active, err)
	}
}

func TestPublicSelectorHealthOmitsRetiredSpeedAndPenalties(t *testing.T) {
	legacy := map[string]any{"route": map[string]any{
		"selected": "node", "runtime_confirmed": true, "availability_ok": map[string]any{"node": true},
		"speed_history": map[string]any{"node": []any{123}}, "speed_median_bps": map[string]any{"node": 123},
		"speed_probation": map[string]any{"node": map[string]any{"until": 999}}, "last_speed_observation": map[string]any{"node": map[string]any{"probe_bps": 123}},
		"optimization_speed_degraded": true, "optimization_active_bps": 123, "optimization_budget_after": 999,
		"outage_penalty": map[string]any{"node": map[string]any{"until": 999}}, "cooldown_until": 999,
		"quality_thresholds":       map[string]any{"speed_probe_bytes": 123, "active_speed_seconds": 180, "backup_speed_seconds": 900, "switch_cooldown_seconds": 600, "max_latency_ms": 2000, "cooldown_seconds": 600, "switch_improvement_ms": 50},
		"optimization_last_result": map[string]any{"active_speed_bps": 123, "candidate_speed_bps": 456, "active_delay_ms": 500, "candidate_delay_ms": 200},
	}}
	before := cloneJSONObject(legacy)
	view := publicSelectorHealth(legacy)
	body, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "speed_") || strings.Contains(string(body), "outage_penalty") || strings.Contains(string(body), "optimization_active_bps") || strings.Contains(string(body), "cooldown") || strings.Contains(string(body), "max_latency_ms") {
		t.Fatalf("retired API fields leaked: %s", body)
	}
	if !reflect.DeepEqual(legacy, before) || nestedValue(view, "route", "runtime_confirmed") != true || nestedValue(view, "route", "quality_thresholds", "switch_improvement_ms") != 50 || nestedValue(view, "route", "optimization_last_result", "candidate_delay_ms") != 200 {
		t.Fatalf("public view changed source or unrelated data: %#v", view)
	}
	server := newTestServer(t)
	if err := server.repository.saveAuxiliary("selector-health", legacy); err != nil {
		t.Fatal(err)
	}
	payload, err := server.statusPayload()
	if err != nil {
		t.Fatal(err)
	}
	if nestedValue(payload, "selector_health", "route", "speed_history") != nil || nestedValue(payload, "selector_health", "route", "runtime_confirmed") != true {
		t.Fatalf("status did not use sanitized selector view: %#v", payload["selector_health"])
	}
}

func TestPublicSelectorHealthCleanFastPathDoesNotCloneHistory(t *testing.T) {
	clean := map[string]any{"route": map[string]any{
		"selected": "node", "runtime_confirmed": true,
		"daily_samples":            map[string]any{"node": []any{map[string]any{"at": 100, "ok": true, "delay_ms": 200}}},
		"quality_thresholds":       map[string]any{"switch_improvement_ms": 50},
		"optimization_last_result": map[string]any{"candidate_delay_ms": 200},
	}}
	before := cloneJSONObject(clean)
	view := publicSelectorHealth(clean)
	if !reflect.DeepEqual(clean, before) {
		t.Fatal("clean scan changed its input")
	}
	// A local sentinel proves map identity without unsafe or a timing assertion.
	view["same-map"] = true
	if clean["same-map"] != true {
		t.Fatal("clean snapshot was unnecessarily copied")
	}
	delete(view, "same-map")
	if publicSelectorHealth(nil) != nil {
		t.Fatal("nil clean view should remain nil")
	}
}

func TestPublicSelectorHealthNestedLegacyStillDetached(t *testing.T) {
	for _, tc := range []struct{ parent, field string }{
		{"quality_thresholds", "speed_probe_bytes"},
		{"quality_thresholds", "active_speed_seconds"},
		{"quality_thresholds", "backup_speed_seconds"},
		{"quality_thresholds", "max_latency_ms"},
		{"quality_thresholds", "cooldown_seconds"},
		{"quality_thresholds", "switch_cooldown_seconds"},
		{"optimization_last_result", "active_speed_bps"},
		{"optimization_last_result", "candidate_speed_bps"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			legacy := map[string]any{"route": map[string]any{tc.parent: map[string]any{tc.field: nil, "keep": true}}}
			before := cloneJSONObject(legacy)
			view := publicSelectorHealth(legacy)
			fields := nestedValue(view, "route", tc.parent).(map[string]any)
			if _, exists := fields[tc.field]; exists || fields["keep"] != true || !reflect.DeepEqual(legacy, before) {
				t.Fatalf("nested cleanup lost its detached contract: %#v", view)
			}
		})
	}
}
