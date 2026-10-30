package controlplane

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func selectorScopeReadinessFixture(t *testing.T) (*Server, map[string]any, string) {
	t.Helper()
	server := newTestServer(t)
	config := routerOSReadyConfig(t)
	config["policies"] = []any{
		map[string]any{"id": "route", "enabled": true, "mode": "priority"},
		map[string]any{"id": "empty", "enabled": true, "mode": "best", "selection_order": []any{"reverse:missing"}},
		map[string]any{"id": "direct", "enabled": true, "mode": "direct"},
	}
	config["local_clients"] = []any{
		map[string]any{"id": "one", "policy_id": "route", "enabled": true},
		map[string]any{"id": "two", "policy_id": "empty", "enabled": true},
		map[string]any{"id": "three", "policy_id": "direct", "enabled": true},
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "router-ready")
	t.Setenv("SB_ROUTER_READY_MARKER", marker)
	if err := os.WriteFile(marker, []byte(strconv.FormatInt(server.now().Unix(), 10)), 0600); err != nil {
		t.Fatal(err)
	}
	server.checkPersistentMounts = func() (bool, []string) { return true, nil }
	if err := server.repository.saveAuxiliary("selector-runtime", map[string]any{
		"route": map[string]any{"runtime_selected": "node", "runtime_confirmed": true, "runtime_observed_at": server.now().Add(time.Second).Format(time.RFC3339Nano)},
	}); err != nil {
		t.Fatal(err)
	}
	pool := filepath.Join(t.TempDir(), "urltest-pool.json")
	if err := os.WriteFile(pool, []byte(`{"version":4,"local_policy_ids":["route"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	server.runtime = &nativeRuntime{options: RuntimeOptions{XrayHealthPool: pool}}
	return server, config, pool
}

func TestNativeTrafficReadinessUsesPublishedSelectorScope(t *testing.T) {
	server, config, _ := selectorScopeReadinessFixture(t)
	response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("static empty/direct routes withdrew unrelated forwarding: %s", response.Body.String())
	}
	body := decodeResponse(t, response)
	if got := stringsOf(body["required_local_policies"]); len(got) != 1 || got[0] != "route" {
		t.Fatalf("required selector scope = %#v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := server.waitLocalApplyTraffic(ctx, config, time.Time{}); err != nil {
		t.Fatalf("completed static route change stalled Apply: %v", err)
	}
}

func TestNativeTrafficReadinessRefreshesScopeAndKeepsProofStrict(t *testing.T) {
	server, _, pool := selectorScopeReadinessFixture(t)
	check := func(want int) {
		t.Helper()
		response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
		if response.Code != want {
			t.Fatalf("status=%d, want=%d: %s", response.Code, want, response.Body.String())
		}
	}
	check(http.StatusOK)
	if err := os.WriteFile(pool, []byte(`{"version":4,"local_policy_ids":["route","empty"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	check(http.StatusServiceUnavailable)
	if err := os.WriteFile(pool, []byte(`{"version":4,"local_policy_ids":["route"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("selector-runtime", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	check(http.StatusServiceUnavailable)
}

func TestNativeTrafficReadinessRejectsMissingOrMalformedScope(t *testing.T) {
	for _, body := range []string{`{`, `{}`, `{"local_policy_ids":null}`, `{"local_policy_ids":[]}{}`} {
		t.Run(body, func(t *testing.T) {
			server, _, pool := selectorScopeReadinessFixture(t)
			if err := os.WriteFile(pool, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
			if response.Code == http.StatusOK {
				t.Fatalf("invalid pool granted readiness: %s", response.Body.String())
			}
		})
	}
}

func TestNativeTrafficReadinessInvalidatesScopeOnAtomicReplacement(t *testing.T) {
	server, _, pool := selectorScopeReadinessFixture(t)
	response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	info, err := os.Stat(pool)
	if err != nil {
		t.Fatal(err)
	}
	next := pool + ".next"
	if err := os.WriteFile(next, []byte(`{"version":4,"local_policy_ids":["empty"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(next, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, pool); err != nil {
		t.Fatal(err)
	}
	response = performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("old scope survived same-size/time replacement: %s", response.Body.String())
	}
	if err := os.Remove(pool); err != nil {
		t.Fatal(err)
	}
	response = performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
	if response.Code == http.StatusOK {
		t.Fatal("cached scope survived removal of its published contract")
	}
}
