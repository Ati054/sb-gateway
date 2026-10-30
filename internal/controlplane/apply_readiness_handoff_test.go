package controlplane

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestHotPolicyReadinessHandoffKeepsTheHealthyRuntime(t *testing.T) {
	for _, artifacts := range [][]string{{"urltest-pool.json"}, {"nginx.conf", "urltest-pool.json"}} {
		t.Run(artifacts[0], func(t *testing.T) {
			server := newTestServer(t)
			config := routerOSReadyConfig(t)
			config["local_clients"] = []any{}
			revision, err := server.repository.stageGeneration(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test"}); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "router-ready")
			t.Setenv("SB_ROUTER_READY_MARKER", marker)
			if err := os.WriteFile(marker, []byte(strconv.FormatInt(server.now().Unix(), 10)), 0600); err != nil {
				t.Fatal(err)
			}
			server.checkPersistentMounts = func() (bool, []string) { return true, nil }
			operation := map[string]any{"pending": true, "state": "prepared",
				"previous_routeros_source": "same", "target_routeros_source": "same"}
			if err := server.repository.saveAuxiliary("apply-operation", operation); err != nil {
				t.Fatal(err)
			}
			server.storeApplyReadiness(&server.plannedUnchangedApply, true)
			server.prepareNativePublication(artifacts)
			check := func(want int) {
				t.Helper()
				r := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
				if r.Code != want {
					t.Fatalf("readiness during hot handoff: %d want %d: %s", r.Code, want, r.Body.String())
				}
			}
			check(http.StatusOK)
			if err := server.prepareHotPolicyReadiness(); err != nil {
				t.Fatal(err)
			}
			check(http.StatusOK)
			stored, err := server.repository.auxiliary("apply-operation")
			if err != nil || stored["pending"] != true || stored["state"] != "runtime_hot_activating" {
				t.Fatalf("hot handoff lost durable recovery: %#v %v", stored, err)
			}
			server.storeApplyReadiness(&server.plannedHotPolicyApply, false)
			check(http.StatusServiceUnavailable)
		})
	}
}
