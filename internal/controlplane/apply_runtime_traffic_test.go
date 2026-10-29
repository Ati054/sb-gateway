package controlplane

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestRuntimeOnlyApplyWaitsForTrafficAfterCommit(t *testing.T) {
	for _, failWait := range []bool{false, true} {
		t.Run(strconv.FormatBool(failWait), func(t *testing.T) {
			server := newTestServer(t)
			active := routerOSReadyConfig(t)
			source, err := runtimeconfig.RenderRouterOSTrafficCandidate(active, nil)
			if err != nil {
				t.Fatal(err)
			}
			revision, err := server.repository.stageGeneration(active)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{Revision: revision, RuntimeRevision: strings.Repeat("1", 64), RouterOSSource: source, Actor: "test"}); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			live := filepath.Join(root, "nginx.conf")
			if err := os.WriteFile(live, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "state"), map[string]string{"nginx.conf": live})
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := store.Prepare(strings.Repeat("2", 64), map[string][]byte{"nginx.conf": []byte("new")})
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := store.Activate(candidate)
			if err != nil {
				t.Fatal(err)
			}
			runtime := &fakeRuntimeApplier{revision: candidate.Revision, activationReceipt: receipt}
			server.runtime = runtime
			waited := false
			server.waitApplyTraffic = func(_ context.Context, _ map[string]any, notBefore time.Time) error {
				waited = true
				if notBefore.IsZero() {
					t.Fatal("runtime restart reused an earlier lease")
				}
				operation, err := server.repository.auxiliary("apply-operation")
				if err != nil || operation["state"] != "active_committed" || !plannedRuntimeActivationReady(operation, server.plannedRuntimeApply.Load()) {
					t.Fatalf("uncommitted runtime allowed traffic: %#v %v", operation, err)
				}
				if failWait {
					return errors.New("no new readiness lease")
				}
				return nil
			}
			desired := cloneJSONObject(active)
			objectAt(desired, "ingress")["subscription_origin_server_name"] = "origin.example.test"
			result, status, err := server.applyConfiguration(context.Background(), desired, "test")
			if !waited || server.plannedRuntimeApply.Load() || runtime.rollbackCalls != 0 {
				t.Fatalf("wait=%t live=%t rollback=%d", waited, server.plannedRuntimeApply.Load(), runtime.rollbackCalls)
			}
			if failWait {
				var failure *applyFailureError
				if status != http.StatusConflict || !errors.As(err, &failure) || failure.state != applyRecoveryPending || result != nil {
					t.Fatalf("false success: %d %#v %v", status, result, err)
				}
			} else if err != nil || status != http.StatusOK || result["routeros_changed"] != false {
				t.Fatalf("unexpected RouterOS mutation or failure: %d %#v %v", status, result, err)
			}
		})
	}
}

func TestLocalApplyTrafficRequiresActualLease(t *testing.T) {
	for _, condition := range []string{"missing", "expired", "unwritable", "older-proof", "fresh", "renewed"} {
		t.Run(condition, func(t *testing.T) {
			server := newTestServer(t)
			config := map[string]any{"local_clients": []any{}}
			marker := filepath.Join(t.TempDir(), "router-ready")
			t.Setenv("SB_ROUTER_READY_MARKER", marker)
			server.checkPersistentMounts = func() (bool, []string) { return condition != "unwritable", nil }
			writeLease := func(at time.Time) error { return os.WriteFile(marker, []byte(strconv.FormatInt(at.Unix(), 10)), 0600) }
			var notBefore time.Time
			if condition != "missing" && condition != "renewed" {
				at := server.now()
				if condition == "expired" {
					at = at.Add(-20 * time.Second)
				}
				if err := writeLease(at); err != nil {
					t.Fatal(err)
				}
				if condition == "older-proof" {
					notBefore = server.now()
					if err := os.Chtimes(marker, notBefore.Add(-time.Minute), notBefore.Add(-time.Minute)); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if condition == "renewed" {
				notBefore = server.now()
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				finished := make(chan error, 1)
				go func() { time.Sleep(10 * time.Millisecond); finished <- writeLease(server.now()) }()
				defer func() {
					if err := <-finished; err != nil {
						t.Error(err)
					}
				}()
			}
			err := server.waitLocalApplyTraffic(ctx, config, notBefore)
			if condition == "fresh" || condition == "renewed" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("invalid lease accepted: %v", err)
			}
		})
	}
}
