package agent

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestXrayReloadProcessHelper(t *testing.T) {
	if os.Getenv("SB_TEST_XRAY_RELOAD_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	_, _ = io.WriteString(os.Stdout, "ready\n")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func startReloadCoreProcess(t *testing.T) int {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray")
	if err := os.Link(executable, path); err != nil {
		source, openErr := os.Open(executable)
		if openErr != nil {
			t.Fatal(openErr)
		}
		defer source.Close()
		target, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, copyErr := io.Copy(target, source)
		if err := errors.Join(copyErr, target.Close()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	process := exec.CommandContext(ctx, path, "-test.run=^TestXrayReloadProcessHelper$")
	process.Env = append(os.Environ(), "SB_TEST_XRAY_RELOAD_HELPER=1")
	input, err := process.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := process.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = input.Close(); _ = process.Wait() })
	if ready, err := bufio.NewReader(output).ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatalf("start core PID fixture: ready=%q err=%v", ready, err)
	}
	return process.Process.Pid
}

type reloadInventoryState struct {
	sync.Mutex
	failures int
	calls    int
}

func reloadInventoryFixture(t *testing.T) (*xraySelectorRuntime, *reloadInventoryState) {
	t.Helper()
	root := t.TempDir()
	options := Options{StateRoot: root, HealthPoolFile: filepath.Join(root, "pool.json"), XrayReadyFile: filepath.Join(root, "xray.ready")}
	if err := writeJSONAtomic(options.HealthPoolFile, healthFixture(false)); err != nil {
		t.Fatal(err)
	}
	pid := startReloadCoreProcess(t)
	if err := os.WriteFile(options.XrayReadyFile, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	state := &reloadInventoryState{}
	client := controlRPCFixture(t, func(_ context.Context, method string, _ []byte) ([]byte, error) {
		state.Lock()
		defer state.Unlock()
		if !strings.HasSuffix(method, "/ListOutbounds") {
			return nil, errors.New("unexpected API operation before inventory")
		}
		state.calls++
		if state.failures > 0 {
			state.failures--
			return nil, errors.New("inventory temporarily unavailable")
		}
		return controlWireField(1, controlWireField(1, []byte("direct-wan"))), nil
	})
	runtime := newXraySelectorRuntime(options)
	runtime.control = client
	return runtime, state
}

func TestXrayReloadRetainsResetAfterInventoryFailure(t *testing.T) {
	for _, boundary := range []string{"PID", "contract"} {
		t.Run(boundary, func(t *testing.T) {
			runtime, inventory := reloadInventoryFixture(t)
			if _, reset, err := runtime.Reload(); err != nil || !reset {
				t.Fatalf("initial reload: reset=%t err=%v", reset, err)
			}
			if boundary == "PID" {
				pid := startReloadCoreProcess(t)
				if err := os.WriteFile(runtime.opts.XrayReadyFile, []byte(strconv.Itoa(pid)), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				pool := healthFixture(false)
				contract := pool.HealthPolicies["europe"]
				contract.Mode = "best"
				pool.HealthPolicies["europe"] = contract
				if err := writeJSONAtomic(runtime.opts.HealthPoolFile, pool); err != nil {
					t.Fatal(err)
				}
				// A contract may arrive while restart ownership inventory is pending.
				runtime.inventoryLoaded = false
			}
			inventory.Lock()
			inventory.failures = 1
			inventory.Unlock()
			if _, _, err := runtime.Reload(); err == nil {
				t.Fatal("failed inventory was accepted")
			}
			poolFile := runtime.opts.HealthPoolFile
			runtime.opts.HealthPoolFile = filepath.Join(t.TempDir(), "absent.json")
			if _, _, err := runtime.Reload(); err == nil {
				t.Fatal("missing pool was accepted")
			}
			runtime.opts.HealthPoolFile = poolFile
			pool, reset, err := runtime.Reload()
			if err != nil || !reset || len(pool.HealthPolicies) != 1 {
				t.Fatalf("successful retry lost the generation reset: reset=%t policies=%d err=%v", reset, len(pool.HealthPolicies), err)
			}
			if _, reset, err := runtime.Reload(); err != nil || reset {
				t.Fatalf("generation reset was delivered more than once: reset=%t err=%v", reset, err)
			}
			inventory.Lock()
			calls := inventory.calls
			inventory.Unlock()
			if calls != 3 {
				t.Fatalf("inventory retry count=%d, want initial/failure/success", calls)
			}
		})
	}
}

type reloadControllerRuntime struct {
	*fakeSelectorRuntime
	core *xraySelectorRuntime
}

func (runtime *reloadControllerRuntime) Reload() (healthPool, bool, error) {
	return runtime.core.Reload()
}

func (runtime *reloadControllerRuntime) hotRuntimeGeneration() hotRuntimeGeneration {
	return runtime.core.hotRuntimeGeneration()
}

func TestXrayReloadRetryReconcilesControllerStartup(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			core, inventory := reloadInventoryFixture(t)
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			pool.HealthPolicies["europe"] = contract
			if err := writeJSONAtomic(core.opts.HealthPoolFile, pool); err != nil {
				t.Fatal(err)
			}
			runtime := &reloadControllerRuntime{core: core, fakeSelectorRuntime: &fakeSelectorRuntime{
				pool: pool, current: map[string]string{"europe": "de"},
				probes: map[string]probeEvidence{"de": successfulEvidence(100), "nl": successfulEvidence(110)},
			}}
			controller := &healthController{opts: core.opts, runtime: runtime, warmStarted: make(map[string]bool)}
			if err := controller.Tick(time.Unix(1000, 0)); err != nil {
				t.Fatal(err)
			}
			oldReconciliation := controller.reconciled["europe"]
			controller.regularNext["europe"] = time.Unix(2000, 0)
			controller.state["europe"].AvailabilityFailures["de"] = 1
			runtime.probeCalls, runtime.availabilityCalls, runtime.selections = nil, nil, nil
			pid := startReloadCoreProcess(t)
			if err := os.WriteFile(core.opts.XrayReadyFile, []byte(strconv.Itoa(pid)), 0o600); err != nil {
				t.Fatal(err)
			}
			inventory.Lock()
			inventory.failures = 1
			inventory.Unlock()
			if err := controller.Tick(time.Unix(1010, 0)); err == nil {
				t.Fatal("failed inventory admitted a controller tick")
			}
			if !controller.warmStarted["europe"] || controller.reconciled["europe"] != oldReconciliation || len(runtime.probeCalls) != 0 || len(runtime.availabilityCalls) != 0 {
				t.Fatal("failed Reload unexpectedly consumed the old controller generation")
			}
			if err := controller.Tick(time.Unix(1012, 0)); err != nil {
				t.Fatal(err)
			}
			if strings.Join(runtime.probeCalls, ",") != "de,nl" || len(runtime.availabilityCalls) != 0 || len(runtime.selections) != 1 || controller.reconciled["europe"].Generation.XrayPID != pid {
				t.Fatalf("new core borrowed old startup state: quality=%v availability=%v selections=%v reconciliation=%+v", runtime.probeCalls, runtime.availabilityCalls, runtime.selections, controller.reconciled["europe"])
			}
			if _, reset, err := core.Reload(); err != nil || reset {
				t.Fatalf("controller did not consume the reset once: reset=%t err=%v", reset, err)
			}
		})
	}
}
