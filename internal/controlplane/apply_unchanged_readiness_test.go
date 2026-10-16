package controlplane

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPlannedUnchangedReadinessRequiresLiveMatchingOperation(t *testing.T) {
	for _, test := range []struct {
		name, state, previous, target string
		live, pending, want           bool
	}{
		{"preparing", "prepared", "same", "same", true, true, true},
		{"activated", "runtime_activated", "same", "same", true, true, true},
		{"committed", "active_committed", "same", "same", true, true, true},
		{"stale journal", "prepared", "same", "same", false, true, false},
		{"not pending", "prepared", "same", "same", true, false, false},
		{"changed RouterOS", "prepared", "old", "new", true, true, false},
		{"missing RouterOS", "prepared", "", "", true, true, false},
		{"hot publication", "runtime_hot_activating", "same", "same", true, true, false},
		{"rollback", "rolling_back", "same", "same", true, true, false},
		{"recovery", "recovery_pending", "same", "same", true, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation := map[string]any{"pending": test.pending, "state": test.state,
				"previous_routeros_source": test.previous, "target_routeros_source": test.target}
			if got := plannedUnchangedReadiness(operation, test.live); got != test.want {
				t.Fatalf("readiness=%t want=%t", got, test.want)
			}
		})
	}
}

func TestUnchangedApplyKeepsReadinessWithoutClearingRecoveryJournal(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
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
	if err := os.WriteFile(marker, []byte(strconv.FormatInt(server.now().Unix(), 10)), 0600); err != nil {
		t.Fatal(err)
	}
	server.checkPersistentMounts = func() (bool, []string) { return true, nil }
	for _, state := range []string{"prepared", "runtime_activated", "active_committed"} {
		operation := map[string]any{"pending": true, "state": state,
			"previous_routeros_source": "same", "target_routeros_source": "same"}
		if err := server.repository.saveAuxiliary("apply-operation", operation); err != nil {
			t.Fatal(err)
		}
		for _, live := range []bool{true, false} {
			server.plannedUnchangedApply.Store(live)
			for _, path := range []string{apiPrefix + "/health/ready", "/api/health/router-ready", "/api/health/traffic-ready"} {
				response := performRequest(t, server, http.MethodGet, path, nil, nil, cookie)
				wantStatus := http.StatusServiceUnavailable
				if live {
					wantStatus = http.StatusOK
				}
				body := decodeResponse(t, response)
				if response.Code != wantStatus || body["ready"] != live || body["apply_recovery_pending"] != !live {
					t.Fatalf("phase=%s live=%t path=%s: %d %s", state, live, path, response.Code, response.Body.String())
				}
			}
		}
		stored, err := server.repository.auxiliary("apply-operation")
		if err != nil || stored["pending"] != true || stored["state"] != state {
			t.Fatalf("readiness changed durable recovery state: %#v %v", stored, err)
		}
	}
}

func TestNativePublicationRevokesPreparationReadinessBeforeChanges(t *testing.T) {
	for _, changed := range []bool{false, true} {
		name, target := "unchanged", hotPolicyOldPool
		if changed {
			name, target = "changed", hotPolicyNewPool
		}
		t.Run(name, func(t *testing.T) {
			runtime, candidate, controller := hotPolicyFixtureWithPools(t, hotPolicyOldPool, target)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			live, calls := true, 0
			receipt, err := runtime.activateWithHooks(ctx, candidate, nil, func(context.Context) error {
				if live {
					t.Fatal("changed publication retained preparation readiness")
				}
				cancel()
				return nil
			}, func(changes []string) {
				calls++
				body, readErr := os.ReadFile(runtime.options.XrayHealthPool)
				if readErr != nil || string(body) != hotPolicyOldPool {
					t.Fatal("readiness hook ran after publication")
				}
				if len(changes) > 0 {
					live = false
				}
			})
			wantCalls := 0
			if changed {
				wantCalls = 1
			}
			if calls != wantCalls || live != !changed || (len(receipt.Changed()) > 0) != changed {
				t.Fatalf("hook calls=%d live=%t changed=%v", calls, live, receipt.Changed())
			}
			if changed && !errors.Is(err, context.Canceled) || !changed && err != nil {
				t.Fatalf("activation error=%v", err)
			}
			if len(controller.restarts) != 0 {
				t.Fatal("pool/no-op publication restarted Xray")
			}
		})
	}
}
