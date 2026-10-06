package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type coldSurveyRuntime struct {
	*fakeSelectorRuntime
	generation  hotRuntimeGeneration
	interrupt   func() error
	interrupted error
	batches     [][]string
	currentErr  error
	selectErr   error
}

func (runtime *coldSurveyRuntime) hotRuntimeGeneration() hotRuntimeGeneration {
	return runtime.generation
}

func (runtime *coldSurveyRuntime) Current(policy string) (string, error) {
	if runtime.currentErr != nil {
		return "", runtime.currentErr
	}
	return runtime.fakeSelectorRuntime.Current(policy)
}

func (runtime *coldSurveyRuntime) Select(policy, node string) error {
	if runtime.selectErr != nil {
		return runtime.selectErr
	}
	return runtime.fakeSelectorRuntime.Select(policy, node)
}

func (runtime *coldSurveyRuntime) ProbeQualityParallel(candidates []string) map[string]probeEvidence {
	runtime.batches = append(runtime.batches, append([]string(nil), candidates...))
	if interrupt := runtime.interrupt; interrupt != nil {
		runtime.interrupt = nil
		runtime.interrupted = interrupt()
		return nil
	}
	measured := make(map[string]probeEvidence, len(candidates))
	for _, candidate := range candidates {
		runtime.probeCalls = append(runtime.probeCalls, candidate)
		measured[candidate] = successfulEvidence(100)
	}
	return measured
}

func (runtime *coldSurveyRuntime) takeProbeInterruption() error {
	err := runtime.interrupted
	runtime.interrupted = nil
	return err
}

func coldSurveyFixture(t *testing.T, mode string) (*healthController, *coldSurveyRuntime) {
	t.Helper()
	controller, base, primary := callbackOrderFixture(t, mode)
	runtime := &coldSurveyRuntime{fakeSelectorRuntime: base, generation: hotRuntimeGeneration{PoolSHA256: "pool-1", XrayPID: 123}}
	controller.runtime = runtime
	runtime.reset = true
	runtime.probes["target"] = probeEvidence{Failure: probeFailureTimeout}
	runtime.probes["target-reserve"] = successfulEvidence(90)
	runtime.interrupt = func() error {
		now := time.Unix(1010, 0)
		signals := make(chan xrayFailureSignal, 1)
		signals <- callbackTargetHint(primary)
		joined := make(chan struct{})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		result := awaitProbeJobWithSignals(ctx, time.Hour, func() error {
			return controller.checkDuringProbe(now, runtime.pool)
		}, func(ctx context.Context) probeJobResult {
			defer close(joined)
			<-ctx.Done()
			return probeJobResult{err: ctx.Err()}
		}, signals, func(signal xrayFailureSignal) bool {
			return controller.acceptXrayFailureSignal(now, signal, primary)
		})
		select {
		case <-joined:
		default:
			t.Fatal("interrupted cold worker was not joined")
		}
		return result.err
	}
	return controller, runtime
}

func TestInterruptedColdSurveyKeepsReconciledPendingFastLane(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime := coldSurveyFixture(t, mode)
			controller.priorityPolicy = "z-target"
			item := controller.state["z-target"]
			// These fields are finalized only after the full survey succeeds.
			item.Mode, item.CandidateSignature = "", ""
			if err := controller.Tick(time.Unix(1009, 0)); err != nil {
				t.Fatal(err)
			}
			if !controller.yielded || controller.warmStarted["z-target"] || item.AvailabilityFailures["target"] != 1 || !item.RuntimeConfirmed {
				t.Fatalf("cold survey did not yield after its first proof: yielded=%t warm=%t failures=%d confirmed=%t", controller.yielded, controller.warmStarted["z-target"], item.AvailabilityFailures["target"], item.RuntimeConfirmed)
			}
			if _, exists := controller.reconciled["z-target"]; !exists || item.Mode != "" || item.CandidateSignature != "" {
				t.Fatal("successful prefix was not recorded separately from unfinished survey metadata")
			}
			if err := controller.Tick(time.Unix(1011, 0)); err != nil {
				t.Fatal(err)
			}
			if len(runtime.batches) != 2 || strings.Join(runtime.batches[1], ",") != "healthy,healthy-reserve" || strings.Join(runtime.availabilityCalls, ",") != "target" || item.AvailabilityFailures["target"] != 1 {
				t.Fatalf("retry cadence or other cold policy was bypassed: batches=%v availability=%v failures=%d", runtime.batches, runtime.availabilityCalls, item.AvailabilityFailures["target"])
			}
			if err := controller.Tick(time.Unix(1012, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "target-reserve" || !item.RuntimeConfirmed || len(runtime.batches) != 2 || strings.Join(runtime.availabilityCalls, ",") != "target,target,target-reserve" {
				t.Fatalf("confirmation restarted the interrupted warm batch: selected=%s batches=%v availability=%v", item.Selected, runtime.batches, runtime.availabilityCalls )
			}
		})
	}
}

func TestInterruptedStartupDoesNotBorrowOtherPolicyReconciliation(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime := coldSurveyFixture(t, mode)
			controller.reconciled = map[string]policyReconciliation{
				"z-target": {Generation: runtime.generation, CandidateSignature: "target\ntarget-reserve", Mode: mode, Selected: "target"},
			}
			if err := controller.Tick(time.Unix(1009, 0)); err != nil {
				t.Fatal(err)
			}
			if _, exists := controller.reconciled["z-target"]; exists || !controller.yielded || controller.state["z-target"].AvailabilityFailures["target"] != 1 {
				t.Fatal("runtime reset retained another policy's reconciliation before its startup prefix")
			}
			if err := controller.Tick(time.Unix(1011, 0)); err != nil {
				t.Fatal(err)
			}
			if len(runtime.batches) < 2 || strings.Join(runtime.batches[1], ",") != "target,target-reserve" || strings.Join(runtime.availabilityCalls, ",") != "target" {
				t.Fatalf("persisted confirmation bypassed unprocessed startup: batches=%v availability=%v", runtime.batches, runtime.availabilityCalls)
			}
			if len(runtime.selections) < 2 || runtime.selections[1] != [2]string{"z-target", "target"} {
				t.Fatalf("pending uninitialized policy skipped its startup Select: %v", runtime.selections)
			}
		})
	}
}

func TestPendingReconciliationRequiresCurrentContractAndActive(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, change := range []string{"new process", "runtime reset", "generation", "mode", "candidates", "active"} {
			t.Run(mode+"/"+change, func(t *testing.T) {
				controller, runtime, item := pendingFailureFixture(t, mode)
				controller.warmStarted["europe"] = false
				contract := runtime.pool.HealthPolicies["europe"]
				switch change {
				case "new process":
					controller.reconciled = nil
				case "runtime reset":
					runtime.reset = true
				case "generation":
					controller.runtime = &coldSurveyRuntime{fakeSelectorRuntime: runtime, generation: hotRuntimeGeneration{PoolSHA256: "changed", XrayPID: 456}}
				case "mode":
					contract.Mode = "priority"
					if mode == "priority" {
						contract.Mode = "best"
					}
				case "candidates":
					contract.Candidates = append(contract.Candidates, "fr")
					runtime.probes["fr"] = successfulEvidence(100)
				case "active":
					item.Selected, item.RuntimeSelected, runtime.current["europe"] = "nl", "nl", "nl"
				}
				runtime.pool.HealthPolicies["europe"] = contract
				item.AvailabilityFailures[item.Selected] = 1
				runtime.probes[item.Selected] = successfulEvidence(100)
				if err := controller.Tick(time.Unix(1012, 0)); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls) == 0 || len(runtime.availabilityCalls) != 0 {
					t.Fatalf("mismatched reconciliation bypassed startup: quality=%v availability=%v", runtime.probeCalls, runtime.availabilityCalls)
				}
			})
		}
	}
}

func TestStartupReconciliationRequiresSuccessfulPrefix(t *testing.T) {
	for _, failure := range []string{"readback", "select", "publication"} {
		t.Run(failure, func(t *testing.T) {
			controller, base, item := pendingFailureFixture(t, "best")
			runtime := &coldSurveyRuntime{fakeSelectorRuntime: base}
			controller.runtime = runtime
			controller.warmStarted["europe"] = false
			controller.reconciled = nil
			item.AvailabilityFailures["de"] = 1
			switch failure {
			case "readback":
				runtime.currentErr = errors.New("readback unavailable")
			case "select":
				runtime.selectErr = errors.New("selection unconfirmed")
			case "publication":
				path := filepath.Join(t.TempDir(), "not-a-directory")
				if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
					t.Fatal(err)
				}
				controller.opts.StateRoot = path
			}
			if err := controller.Tick(time.Unix(1012, 0)); err == nil {
				t.Fatal("failed startup prefix was reported successful")
			}
			if _, exists := controller.reconciled["europe"]; exists || item.RuntimeConfirmed || len(runtime.batches) != 0 || len(runtime.probeCalls) != 0 || len(runtime.availabilityCalls) != 0 {
				t.Fatalf("failed prefix admitted pending fast work: reconciled=%v confirmed=%t quality=%v availability=%v", controller.reconciled, item.RuntimeConfirmed, runtime.probeCalls, runtime.availabilityCalls)
			}
		})
	}
}
