package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func mixedHotFixture(t *testing.T, artifact string) (*nativeRuntime, runtimeconfig.RuntimeCandidate, *recordingRuntimeController) {
	t.Helper()
	runtime, _, controller := hotPolicyFixture(t)
	root := filepath.Dir(runtime.options.XrayHealthPool)
	extra := filepath.Join(root, artifact)
	if err := os.WriteFile(extra, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "mixed-state"), map[string]string{"urltest-pool.json": runtime.options.XrayHealthPool, artifact: extra})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.Prepare(strings.Repeat("f", 64), map[string][]byte{"urltest-pool.json": []byte(hotPolicyNewPool), artifact: []byte("new")})
	if err != nil {
		t.Fatal(err)
	}
	runtime.store = store
	runtime.options.ApplyGuardFile = filepath.Join(root, "apply-guard")
	acknowledgeTestPool(t, runtime)
	return runtime, candidate, controller
}

func TestMixedHotApplyRequiresSelectorAcknowledgement(t *testing.T) {
	for _, artifact := range []string{"nginx.conf", "policy-dns.json", "watchdog.env"} {
		t.Run(artifact, func(t *testing.T) {
			runtime, candidate, controller := mixedHotFixture(t, artifact)
			hooked := false
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			receipt, err := runtime.activateWithHooks(ctx, candidate, nil, func(context.Context) error { hooked = true; return nil }, nil)
			if !errors.Is(err, context.DeadlineExceeded) || !hooked || len(receipt.Changed()) != 2 {
				t.Fatalf("mixed edit acknowledged without selectors: err=%v hook=%t changed=%v", err, hooked, receipt.Changed())
			}
			if len(controller.restarts) != 1 || len(controller.probes) != 1 {
				t.Fatalf("companion program not activated: %+v", controller)
			}
			if _, err := os.Stat(runtime.options.ApplyGuardFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("guard prevents agent acknowledgement: %v", err)
			}
			rollback, cancelRollback := context.WithTimeout(context.Background(), time.Second)
			defer cancelRollback()
			if err := runtime.rollback(rollback, receipt); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("mixed rollback reused stale selector acknowledgement: %v", err)
			}
		})
	}
}

func TestMixedHotApplyAndRollbackReleaseGuardBeforeFreshAcknowledgement(t *testing.T) {
	for _, artifact := range []string{"nginx.conf", "policy-dns.json", "watchdog.env"} {
		t.Run(artifact, func(t *testing.T) {
			runtime, candidate, controller := mixedHotFixture(t, artifact)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type result struct {
				receipt runtimeconfig.ActivationReceipt
				err     error
			}
			done := make(chan result, 1)
			probed := make(chan struct{}, 1)
			controller.probeContext = func(context.Context) { probed <- struct{}{} }
			waitGuard := func() {
				t.Helper()
				select {
				case <-probed:
				case <-ctx.Done():
					t.Fatal("companion probe missing")
				}
				for {
					select {
					case r := <-done:
						t.Fatalf("completed without new acknowledgement: %v", r.err)
					default:
					}
					if _, err := os.Stat(runtime.options.ApplyGuardFile); errors.Is(err, os.ErrNotExist) {
						return
					}
					select {
					case <-ctx.Done():
						t.Fatal("guard blocked fresh agent acknowledgement")
					case <-time.After(time.Millisecond):
					}
				}
			}
			go func() { r, err := runtime.activate(ctx, candidate); done <- result{r, err} }()
			waitGuard()
			acknowledgeTestPool(t, runtime)
			applied := <-done
			if applied.err != nil {
				t.Fatal(applied.err)
			}
			go func() { done <- result{err: runtime.rollback(ctx, applied.receipt)} }()
			waitGuard()
			acknowledgeTestPool(t, runtime)
			if r := <-done; r.err != nil {
				t.Fatal(r.err)
			}
			if len(controller.restarts) != 2 || len(controller.probes) != 2 {
				t.Fatalf("unexpected process lifecycle: %+v", controller)
			}
			for _, programs := range controller.restarts {
				for _, p := range programs {
					if p == "xray" {
						t.Fatal("mixed hot edit restarted core")
					}
				}
			}
		})
	}
}
