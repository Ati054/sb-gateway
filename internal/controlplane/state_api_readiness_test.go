package controlplane

import (
	"testing"
	"time"
)

func TestRouterReadinessLeaseTTLFavorsFastFailOpen(t *testing.T) {
	tests := []struct {
		name     string
		watchdog map[string]any
		want     int
	}{
		{name: "default", watchdog: map[string]any{}, want: 15},
		{name: "five-second interval", watchdog: map[string]any{"interval_seconds": 5, "failure_threshold": 20}, want: 15},
		{name: "ten-second interval", watchdog: map[string]any{"interval_seconds": 10, "failure_threshold": 1}, want: 25},
		{name: "bounded", watchdog: map[string]any{"interval_seconds": 300}, want: 605},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := routerReadinessLeaseTTL(map[string]any{"watchdog": test.watchdog})
			if got != test.want {
				t.Fatalf("lease TTL = %d, want %d", got, test.want)
			}
		})
	}
}

func TestTrafficReadyPoliciesPreserveModesAndLocalAssignments(t *testing.T) {
	active := map[string]any{
		"policies": []any{
			map[string]any{"id": "all", "enabled": true, "traffic_mode": "vless_with_wan_exceptions"},
			map[string]any{"id": "pc", "enabled": true, "traffic_mode": "vless_with_wan_exceptions"},
			map[string]any{"id": "wan", "enabled": true, "traffic_mode": "wan_with_vless_exceptions"},
		},
		"local_clients": []any{
			map[string]any{"id": "all-lan", "enabled": true, "source_scope": "lan-all", "policy_id": "all", "container_outage": "direct"},
			map[string]any{"id": "pc", "enabled": true, "policy_id": "pc", "container_outage": "lan_only"},
			map[string]any{"id": "wan-device", "enabled": true, "policy_id": "wan"},
			map[string]any{"id": "off", "enabled": false, "policy_id": "missing"},
		},
	}
	selector := map[string]any{
		"all": map[string]any{"runtime_selected": "fi", "runtime_confirmed": true, "runtime_observed_at": "2026-09-19T10:00:01Z"},
		"pc":  map[string]any{"runtime_selected": "block", "runtime_confirmed": true, "runtime_observed_at": "2026-09-19T10:00:01Z"},
		"wan": map[string]any{"runtime_selected": "de", "runtime_confirmed": true, "runtime_observed_at": "2026-09-19T10:00:01Z"},
	}
	notBefore, _ := time.Parse(time.RFC3339, "2026-09-19T10:00:00Z")
	required, pending := trafficReadyPolicies(active, selector, notBefore)
	if len(required) != 3 || required[0] != "all" || required[1] != "pc" || required[2] != "wan" {
		t.Fatalf("required policies = %#v", required)
	}
	if len(pending) != 1 || pending[0] != "pc" {
		t.Fatalf("pending policies = %#v", pending)
	}
	selector["pc"] = map[string]any{"runtime_selected": "fr", "runtime_confirmed": true, "runtime_observed_at": "2026-09-19T10:00:01Z"}
	_, pending = trafficReadyPolicies(active, selector, notBefore)
	if len(pending) != 0 {
		t.Fatalf("confirmed exact-device policy remains pending: %#v", pending)
	}
	selector["pc"] = map[string]any{"runtime_selected": "fr", "runtime_confirmed": true, "runtime_observed_at": "2026-09-19T09:59:59Z"}
	_, pending = trafficReadyPolicies(active, selector, notBefore)
	if len(pending) != 1 || pending[0] != "pc" {
		t.Fatalf("stale pre-restart selector evidence was accepted: %#v", pending)
	}
}

func TestPlannedRuntimeActivationRequiresLiveApplyAndUnchangedRouterOS(t *testing.T) {
	operation := map[string]any{
		"pending": true, "state": "runtime_activated",
		"previous_routeros_source": "managed rules", "target_routeros_source": "managed rules",
	}
	if !plannedRuntimeActivationReady(operation, true) {
		t.Fatal("verified runtime-only Apply must allow watchdog recovery")
	}
	if plannedRuntimeActivationReady(operation, false) {
		t.Fatal("stale journal after process exit must not bypass fail-open")
	}
	operation["target_routeros_source"] = "changed rules"
	if plannedRuntimeActivationReady(operation, true) {
		t.Fatal("RouterOS transaction must not bypass recovery gate")
	}
	operation["target_routeros_source"] = "managed rules"
	operation["state"] = "recovery_pending"
	if plannedRuntimeActivationReady(operation, true) {
		t.Fatal("rollback-pending journal must stay fail-open")
	}
}

func TestHotPolicyReadinessRequiresLiveProvenPublication(t *testing.T) {
	if plannedHotPolicyReadiness(map[string]any{"pending": true, "state": "runtime_hot_activating"}, true) {
		t.Fatal("missing RouterOS source was accepted as unchanged")
	}
	for _, state := range []string{"prepared", "runtime_hot_activating", "runtime_activated", "active_committed", "recovery_pending"} {
		operation := map[string]any{
			"pending": true, "state": state,
			"previous_routeros_source": "unchanged", "target_routeros_source": "unchanged",
		}
		want := state == "runtime_hot_activating" || state == "runtime_activated" || state == "active_committed"
		if got := plannedHotPolicyReadiness(operation, true); got != want {
			t.Fatalf("live hot state %s: ready=%t", state, got)
		}
		if plannedHotPolicyReadiness(operation, false) {
			t.Fatalf("stale journal %s preserved readiness after crash", state)
		}
		operation["target_routeros_source"] = "changed"
		if plannedHotPolicyReadiness(operation, true) {
			t.Fatal("changed RouterOS was allowed to preserve hot readiness")
		}
	}
}
