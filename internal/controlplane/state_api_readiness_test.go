package controlplane

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestTrafficReadinessDatesEachControllerWithoutBypassingProof(t *testing.T) {
	server := newTestServer(t)
	config := routerOSReadyConfig(t)
	config["local_clients"] = []any{}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "router-ready")
	t.Setenv("SB_ROUTER_READY_MARKER", marker)
	server.checkPersistentMounts = func() (bool, []string) { return true, nil }
	wantGeneration := server.trafficReadyAfter.UTC().Format(time.RFC3339Nano)
	for _, healthy := range []bool{false, true, true, false} {
		if healthy {
			if err := os.WriteFile(marker, []byte(strconv.FormatInt(server.now().Unix(), 10)), 0600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
		body := decodeResponse(t, response)
		if body["runtime_started_at"] != wantGeneration || body["traffic_ready"] != healthy {
			t.Fatalf("startup identity bypassed readiness or changed between polls: %s", response.Body.String())
		}
		if (response.Code == http.StatusOK) != healthy {
			t.Fatalf("incorrect readiness HTTP status: %d", response.Code)
		}
	}
	other := newTestServer(t)
	if other.trafficReadyAfter.Equal(server.trafficReadyAfter) {
		t.Fatal("new controller reused the previous startup identity")
	}
}

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
	if len(pending) != 0 {
		t.Fatalf("confirmed policy blackhole withdrew unrelated routes: %#v", pending)
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

func TestTrafficReadyBlockedPolicyStillRequiresFreshRuntimeProof(t *testing.T) {
	active := map[string]any{
		"policies":      []any{map[string]any{"id": "route", "enabled": true}},
		"local_clients": []any{map[string]any{"id": "client", "enabled": true, "policy_id": "route"}},
	}
	notBefore := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		confirmed bool
		selected  string
		observed  string
		pending   bool
	}{
		{"confirmed outage", true, "block", "2026-01-01T12:00:01Z", false},
		{"unconfirmed block", false, "block", "2026-01-01T12:00:01Z", true},
		{"old generation", true, "block", "2026-01-01T11:59:59Z", true},
		{"missing date", true, "block", "", true},
		{"missing selection", true, "", "2026-01-01T12:00:01Z", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selector := map[string]any{"route": map[string]any{
				"runtime_confirmed": test.confirmed, "runtime_selected": test.selected,
				"runtime_observed_at": test.observed,
			}}
			_, pending := trafficReadyPolicies(active, selector, notBefore)
			if (len(pending) != 0) != test.pending {
				t.Fatalf("pending=%v, want pending=%t", pending, test.pending)
			}
		})
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
	operation["state"] = "active_committed"
	if !plannedRuntimeActivationReady(operation, true) || plannedRuntimeActivationReady(operation, false) {
		t.Fatal("only a live completed RouterOS transaction may recover its committed runtime")
	}
	operation["target_routeros_source"] = "managed rules"
	operation["state"] = "recovery_pending"
	if plannedRuntimeActivationReady(operation, true) {
		t.Fatal("rollback-pending journal must stay fail-open")
	}
}

func TestPlannedRuntimeAdmissionRequiresLiveActivationAndTrafficProof(t *testing.T) {
	server := newTestServer(t)
	config := routerOSReadyConfig(t)
	config["local_clients"] = []any{}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "router-ready")
	t.Setenv("SB_ROUTER_READY_MARKER", marker)
	server.checkPersistentMounts = func() (bool, []string) { return true, nil }
	for _, tc := range []struct {
		name, phase, source string
		live, lease, want   bool
	}{
		{"probed planned restart", "runtime_activated", "same", true, true, true},
		{"not yet activated", "prepared", "same", true, true, false},
		{"previous process journal", "runtime_activated", "same", false, true, false},
		{"expired lease", "runtime_activated", "same", true, false, false},
		{"changed router rules", "runtime_activated", "other", true, true, false},
		{"committed changed rules", "active_committed", "other", true, true, true},
		{"stale committed rules", "active_committed", "other", false, true, false},
		{"committed missing lease", "active_committed", "other", true, false, false},
		{"rollback pending", "recovery_pending", "same", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server.plannedRuntimeApply.Store(tc.live)
			operation := map[string]any{"pending": true, "state": tc.phase, "previous_routeros_source": "same", "target_routeros_source": tc.source}
			if err := server.repository.saveAuxiliary("apply-operation", operation); err != nil {
				t.Fatal(err)
			}
			if tc.lease {
				if err := os.WriteFile(marker, []byte(strconv.FormatInt(server.now().Unix(), 10)), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
			body := decodeResponse(t, response)
			if body["planned_runtime_ready"] != tc.want || (tc.want && response.Code != http.StatusOK) {
				t.Fatalf("unproven immediate admission: %s", response.Body.String())
			}
		})
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
