package controlplane

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

// Finalize represents the durable commit after the RouterOS guard is disarmed.
// Blocking the fake's subsequent housekeeping must hold the Apply response,
// while allowing the independent watchdog to see the already committed runtime.
func TestRouterOSApplyReadinessBeforeHousekeeping(t *testing.T) {
	for _, condition := range []string{"committed", "commit-unpublished", "runtime-commit-failed"} {
		t.Run(condition, func(t *testing.T) {
			server := newTestServer(t)
			active := routerOSReadyConfig(t)
			// No selector is needed for this isolated admission-ordering test.
			// The existing selector-scope tests retain their stricter proof cases.
			active["local_clients"] = []any{}
			revision, err := server.repository.stageGeneration(active)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{
				Revision: revision, RouterOSSource: "old rules", Actor: "test", CommittedAt: server.now(),
			}); err != nil {
				t.Fatal(err)
			}
			desired := cloneJSONObject(active)
			objectAt(desired, "watchdog")["interval_seconds"] = float64(6)
			desiredRevision, err := revisionFor(desired)
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "router-ready")
			t.Setenv("SB_ROUTER_READY_MARKER", marker)
			writeLease := func() error {
				return os.WriteFile(marker, []byte(strconv.FormatInt(server.now().Unix(), 10)), 0600)
			}
			if err := writeLease(); err != nil {
				t.Fatal(err)
			}
			server.checkPersistentMounts = func() (bool, []string) { return true, nil }
			runtime := &fakeRuntimeApplier{revision: strings.Repeat("2", 64)}
			if condition == "runtime-commit-failed" {
				runtime.commitErr = errors.New("runtime LKG publication failed")
			}
			server.runtime = runtime
			type commitObservation struct{ err error }
			atHousekeeping := make(chan commitObservation, 1)
			releaseHousekeeping := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseHousekeeping) }) }
			server.applyRouterOS = func(ctx context.Context, config map[string]any, _, _ string,
				health func(context.Context) error, finalize func(context.Context, routeros.BackupRef) error,
			) (routerOSApplyOutput, error) {
				if err := health(ctx); err != nil {
					return routerOSApplyOutput{}, err
				}
				if server.plannedRuntimeApply.Load() {
					return routerOSApplyOutput{}, errors.New("admission enabled before RouterOS finalization")
				}
				// Apply may normalize compatibility fields before staging. Use
				// that exact target rather than assuming the caller's first hash.
				var revisionErr error
				desiredRevision, revisionErr = revisionFor(config)
				if revisionErr != nil {
					return routerOSApplyOutput{}, revisionErr
				}
				if condition == "commit-unpublished" {
					// Fault only the staged target, leaving the authoritative old
					// active generation readable for the real readiness endpoint.
					if err := os.Remove(filepath.Join(server.repository.generations, desiredRevision+".json")); err != nil {
						return routerOSApplyOutput{}, err
					}
				}
				finalizeErr := finalize(ctx, routeros.BackupRef{})
				atHousekeeping <- commitObservation{err: finalizeErr}
				select {
				case <-releaseHousekeeping:
				case <-ctx.Done():
					return routerOSApplyOutput{}, ctx.Err()
				}
				if finalizeErr != nil {
					return routerOSApplyOutput{}, finalizeErr
				}
				return routerOSApplyOutput{Kind: "delta"}, nil
			}
			waitedForTraffic := false
			server.waitApplyTraffic = func(context.Context, map[string]any, time.Time) error {
				waitedForTraffic = true
				return nil
			}
			type applyResult struct {
				value  map[string]any
				status int
				err    error
			}
			result := make(chan applyResult, 1)
			returned := make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer func() {
				release()
				cancel()
				select {
				case <-returned:
				case <-time.After(5 * time.Second):
					t.Error("Apply worker did not stop after releasing housekeeping")
				}
			}()
			go func() {
				defer close(returned)
				value, status, err := server.applyConfiguration(ctx, desired, "test")
				result <- applyResult{value, status, err}
			}()
			var observed commitObservation
			select {
			case observed = <-atHousekeeping:
			case early := <-result:
				t.Fatalf("Apply did not reach the commit boundary: status=%d err=%v", early.status, early.err)
			case <-ctx.Done():
				t.Fatal("Apply did not reach the controlled housekeeping barrier")
			}
			wantReady := condition == "committed"
			if (observed.err != nil) != (condition == "commit-unpublished") {
				t.Fatalf("unexpected finalization result: %v", observed.err)
			}
			if got := server.plannedRuntimeApply.Load(); got != wantReady {
				t.Errorf("while housekeeping is blocked, live admission=%t, want %t", got, wantReady)
			}
			checkReady := func(want int) {
				t.Helper()
				response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
				if response.Code != want {
					t.Errorf("traffic-ready during blocked housekeeping=%d, want %d: %s", response.Code, want, response.Body.String())
				}
			}
			wantStatus := http.StatusServiceUnavailable
			if wantReady {
				wantStatus = http.StatusOK
			}
			checkReady(wantStatus)
			if wantReady {
				// A live Apply allowance must not substitute for an actual lease.
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
				checkReady(http.StatusServiceUnavailable)
				if err := writeLease(); err != nil {
					t.Fatal(err)
				}
				checkReady(http.StatusOK)
			}
			select {
			case <-returned:
				t.Error("Apply response escaped the blocked synchronous housekeeping")
			default:
			}
			release()
			var completed applyResult
			select {
			case completed = <-result:
			case <-ctx.Done():
				t.Fatal("Apply did not return after housekeeping completed")
			}
			if server.plannedRuntimeApply.Load() {
				t.Error("live admission allowance survived Apply return")
			}
			if wantReady {
				if completed.err != nil || completed.status != http.StatusOK || completed.value["ok"] != true || !waitedForTraffic {
					t.Fatalf("successful committed Apply failed: status=%d err=%v trafficWait=%t", completed.status, completed.err, waitedForTraffic)
				}
			} else if completed.err == nil || completed.status != http.StatusConflict || waitedForTraffic {
				t.Fatalf("failed publication accepted: status=%d err=%v trafficWait=%t", completed.status, completed.err, waitedForTraffic)
			}
			committed, err := server.repository.activeRevision()
			if err != nil {
				t.Fatal(err)
			}
			wantRevision := desiredRevision
			if condition == "commit-unpublished" {
				wantRevision = revision
			}
			if committed != wantRevision {
				t.Fatalf("active commit=%s, want %s", committed, wantRevision)
			}
		})
	}
}
