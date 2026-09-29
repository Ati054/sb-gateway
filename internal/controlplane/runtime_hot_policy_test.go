package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const (
	hotPolicyOldPool = `{"health_policies":{"route":{"mode":"priority","candidates":["old"]}},"local_policy_ids":["route"]}`
	hotPolicyNewPool = `{"health_policies":{"route":{"mode":"priority","candidates":["new"]}},"local_policy_ids":["route"]}`
)

func hotPolicyFixture(t *testing.T) (*nativeRuntime, runtimeconfig.RuntimeCandidate, *recordingRuntimeController) {
	t.Helper()
	return hotPolicyFixtureWithPools(t, hotPolicyOldPool, hotPolicyNewPool)
}

func hotPolicyFixtureWithPools(t *testing.T, previousPool, targetPool string) (*nativeRuntime, runtimeconfig.RuntimeCandidate, *recordingRuntimeController) {
	t.Helper()
	root := t.TempDir()
	pool := filepath.Join(root, "pool.json")
	ready := filepath.Join(root, "ready")
	for path, body := range map[string]string{pool: previousPool, ready: "4321\n"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Separate the old generation even on filesystems with coarse timestamps.
	if err := os.Chtimes(pool, time.Unix(1000, 0), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "state"), map[string]string{"urltest-pool.json": pool})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.Prepare(strings.Repeat("e", 64), map[string][]byte{"urltest-pool.json": []byte(targetPool)})
	if err != nil {
		t.Fatal(err)
	}
	controller := &recordingRuntimeController{}
	runtime := &nativeRuntime{
		options: RuntimeOptions{XrayHealthPool: pool, XrayReadyFile: ready, XrayHotRuntimeReadyFile: filepath.Join(root, "hot-ready.json")},
		store:   store, controller: controller, validate: func(context.Context, runtimeconfig.RuntimeCandidate, []string) error { return nil },
	}
	return runtime, candidate, controller
}

func testPoolStamp(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime().UnixNano()
}

func waitTestPool(t *testing.T, path, expected string, previousStamp int64, activation ...<-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(activation) > 0 {
			select {
			case err := <-activation[0]:
				t.Fatalf("activation finished before the expected pool publication: %v", err)
			default:
			}
		}
		// On Windows, os.ReadFile holds a handle without FILE_SHARE_DELETE.
		// Polling the old destination can itself make atomic publication fail.
		// Stat does not hold it open; read only after the rename is complete.
		if info, err := os.Stat(path); err == nil && info.ModTime().UnixNano() != previousStamp {
			body, err := os.ReadFile(path)
			if err != nil || string(body) != expected {
				t.Fatalf("published pool differs from the expected generation: %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pool did not become %q", expected)
}

func acknowledgeTestPool(t *testing.T, runtime *nativeRuntime, overrides ...map[string]string) {
	t.Helper()
	digest, mtime, err := hashFileGeneration(runtime.options.XrayHealthPool)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := readHotPolicyPool(runtime.options.XrayHealthPool)
	if err != nil {
		t.Fatal(err)
	}
	selections := make(map[string]string)
	for id, policy := range pool.Policies {
		if len(policy.Candidates) > 0 {
			selections[id] = policy.Candidates[0]
		}
	}
	if len(overrides) > 0 {
		selections = overrides[0]
	}
	body, err := json.Marshal(map[string]any{
		"pool_sha256": digest, "pool_mtime_unix_nano": mtime, "xray_pid": 4321, "policy_selections": selections,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.options.XrayHotRuntimeReadyFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHotPolicyApplyWaitsForSelectorAndRollbackGeneration(t *testing.T) {
	runtime, candidate, controller := hotPolicyFixture(t)
	acknowledgeTestPool(t, runtime)
	type activation struct {
		receipt runtimeconfig.ActivationReceipt
		err     error
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan activation, 1)
	hookCalled := make(chan struct{}, 1)
	previousStamp := testPoolStamp(t, runtime.options.XrayHealthPool)
	go func() {
		receipt, err := runtime.activateWithHooks(ctx, candidate, func(context.Context) error {
			return errors.New("pool-only edit tried to restart Xray")
		}, func(context.Context) error {
			body, err := os.ReadFile(runtime.options.XrayHealthPool)
			if err != nil || string(body) != hotPolicyOldPool {
				return errors.New("hot readiness hook ran after publication")
			}
			hookCalled <- struct{}{}
			return nil
		})
		done <- activation{receipt, err}
	}()
	waitTestPool(t, runtime.options.XrayHealthPool, hotPolicyNewPool, previousStamp)
	select {
	case result := <-done:
		t.Fatalf("Apply returned before selector acknowledgement: %v", result.err)
	default:
	}
	acknowledgeTestPool(t, runtime)
	result := <-done
	if result.err != nil {
		t.Fatal(result.err)
	}
	select {
	case <-hookCalled:
	default:
		t.Fatal("pool-only publication did not arm live hot readiness")
	}
	rollbackDone := make(chan error, 1)
	previousStamp = testPoolStamp(t, runtime.options.XrayHealthPool)
	go func() { rollbackDone <- runtime.rollback(ctx, result.receipt) }()
	waitTestPool(t, runtime.options.XrayHealthPool, hotPolicyOldPool, previousStamp, rollbackDone)
	select {
	case err := <-rollbackDone:
		t.Fatalf("rollback reused candidate acknowledgement: %v", err)
	default:
	}
	acknowledgeTestPool(t, runtime)
	if err := <-rollbackDone; err != nil {
		t.Fatal(err)
	}
	if len(controller.restarts) != 0 || len(controller.probes) != 0 {
		t.Fatalf("hot transition restarted processes: %+v", controller)
	}
}

func TestHotPolicyApplyTimeoutReturnsRollbackReceipt(t *testing.T) {
	runtime, candidate, controller := hotPolicyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	receipt, err := runtime.activate(ctx, candidate)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || !hotPolicyChange(receipt.Changed()) {
		t.Fatalf("unconfirmed Apply succeeded or lost rollback receipt: %v %v", err, receipt.Changed())
	}
	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rollbackCancel()
	done := make(chan error, 1)
	previousStamp := testPoolStamp(t, runtime.options.XrayHealthPool)
	go func() { done <- runtime.rollback(rollbackCtx, receipt) }()
	waitTestPool(t, runtime.options.XrayHealthPool, hotPolicyOldPool, previousStamp, done)
	acknowledgeTestPool(t, runtime)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(controller.restarts) != 0 {
		t.Fatal("timeout rollback restarted the working Xray process")
	}
}
