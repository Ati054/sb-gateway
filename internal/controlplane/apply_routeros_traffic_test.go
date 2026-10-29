package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func TestRouterOSApplyWaitsForTrafficAfterTransactionCommits(t *testing.T) {
	for _, failWait := range []bool{false, true} {
		t.Run(map[bool]string{false: "traffic restored", true: "traffic unconfirmed"}[failWait], func(t *testing.T) {
			server := newTestServer(t)
			active := routerOSReadyConfig(t)
			revision, err := server.repository.stageGeneration(active)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{Revision: revision, RouterOSSource: "old rules", Actor: "test", CommittedAt: server.now()}); err != nil {
				t.Fatal(err)
			}
			desired := cloneJSONObject(active)
			objectAt(desired, "watchdog")["interval_seconds"] = float64(6)
			runtime := &fakeRuntimeApplier{revision: strings.Repeat("2", 64)}
			server.runtime = runtime
			transactionDone := false
			server.applyRouterOS = func(ctx context.Context, _ map[string]any, _, _ string, health func(context.Context) error, finalize func(context.Context, routeros.BackupRef) error) (routerOSApplyOutput, error) {
				if err := health(ctx); err != nil {
					return routerOSApplyOutput{}, err
				}
				if server.plannedRuntimeApply.Load() {
					t.Fatal("admission enabled during RouterOS transaction")
				}
				if err := finalize(ctx, routeros.BackupRef{}); err != nil {
					return routerOSApplyOutput{}, err
				}
				if server.plannedRuntimeApply.Load() {
					t.Fatal("admission enabled before RouterOS transaction returned")
				}
				transactionDone = true
				return routerOSApplyOutput{Kind: "delta"}, nil
			}
			waited := false
			server.waitApplyTraffic = func(context.Context, map[string]any, time.Time) error {
				waited = true
				operation, err := server.repository.auxiliary("apply-operation")
				if err != nil || !transactionDone || !plannedRuntimeActivationReady(operation, server.plannedRuntimeApply.Load()) {
					t.Fatalf("unproven admission: done=%t operation=%#v err=%v", transactionDone, operation, err)
				}
				if failWait {
					return errors.New("managed traffic did not recover")
				}
				return nil
			}
			result, status, err := server.applyConfiguration(context.Background(), desired, "test")
			if !waited || server.plannedRuntimeApply.Load() || runtime.rollbackCalls != 0 {
				t.Fatalf("wait=%t live=%t rollback=%d", waited, server.plannedRuntimeApply.Load(), runtime.rollbackCalls)
			}
			committed, loadErr := server.repository.loadActive()
			if loadErr != nil || fmt.Sprint(objectAt(committed, "watchdog")["interval_seconds"]) != "6" {
				t.Fatalf("committed configuration lost: %v", loadErr)
			}
			operation, _ := server.repository.auxiliary("apply-operation")
			if failWait {
				var failure *applyFailureError
				if status != http.StatusConflict || !errors.As(err, &failure) || failure.state != applyRecoveryPending || operation["state"] != "recovery_pending" || result != nil {
					t.Fatalf("unconfirmed traffic reported success: status=%d result=%#v operation=%#v err=%v", status, result, operation, err)
				}
			} else if err != nil || status != http.StatusOK || result["ok"] != true || len(operation) != 0 {
				t.Fatalf("successful traffic recovery: status=%d result=%#v operation=%#v err=%v", status, result, operation, err)
			}
		})
	}
}
