package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type changingReloadRuntime struct {
	*fakeSelectorRuntime
	path       string
	calls      int
	failSecond bool
}

func (runtime *changingReloadRuntime) Reload() (healthPool, bool, error) {
	runtime.calls++
	if runtime.calls == 1 {
		if err := os.WriteFile(runtime.path, []byte("new generation"), 0o600); err != nil {
			return healthPool{}, false, err
		}
		return runtime.pool, true, nil
	}
	if runtime.calls == 2 && runtime.failSecond {
		return healthPool{}, false, errors.New("temporary reload failure")
	}
	return runtime.pool, false, nil
}

func TestResponsiveReloadRetainsResetAcrossGenerationYield(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "yield then success"
		if failure {
			name = "yield then error then success"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "generation")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			underlying := &changingReloadRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{pool: healthFixture(false)}, path: path, failSecond: failure}
			runtime := &responsiveSelectorRuntime{selectorRuntime: underlying, generationPaths: []string{path}}
			if _, _, err := runtime.Reload(); !errors.Is(err, errHealthYield) {
				t.Fatalf("changed file did not yield: %v", err)
			}
			if failure {
				if _, _, err := runtime.Reload(); err == nil {
					t.Fatal("temporary underlying failure was accepted")
				}
			}
			if pool, reset, err := runtime.Reload(); err != nil || !reset || len(pool.HealthPolicies) != 1 {
				t.Fatalf("successful wrapper retry lost reset: reset=%t err=%v", reset, err)
			}
			if _, reset, err := runtime.Reload(); err != nil || reset {
				t.Fatalf("wrapper delivered reset more than once: reset=%t err=%v", reset, err)
			}
		})
	}
}
