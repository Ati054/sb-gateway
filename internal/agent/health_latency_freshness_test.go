package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSingleEmergencyCandidateRejectsReplacedGeneration(t *testing.T) {
	for _, change := range []string{"none", "before-probe", "during-probe", "cancel-during-probe", "local-failure"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "generation")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			primary := &observedTransitionRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{
				probes: map[string]probeEvidence{"reserve": successfulEvidence(100)},
			}}
			replace := func() {
				if err := os.WriteFile(path, []byte("replacement-generation"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			primary.beforeProbe = func(string) {
				if change == "during-probe" {
					replace()
				}
				if change == "cancel-during-probe" {
					cancel()
				}
			}
			if change == "local-failure" {
				primary.probes["reserve"] = probeEvidence{LocalFailure: true}
			}
			runtime := &responsiveSelectorRuntime{
				selectorRuntime: primary, ctx: ctx, enabled: true, parallelEnabled: true,
				generationPaths: []string{path},
			}
			runtime.generation = generationStamp(runtime.generationPaths)
			if change == "before-probe" {
				replace()
			}
			controller := &healthController{runtime: runtime}
			measured, selected, err := controller.probeEmergencyCandidates("route", []string{"reserve"}, effectivePolicySettings{batch: 1})
			if change == "none" {
				if err != nil || selected != "reserve" || !measured["reserve"].OK || len(primary.selections) != 1 {
					t.Fatalf("single-lane emergency did not recover immediately: selected=%q err=%v", selected, err)
				}
				return
			}
			wantErr := errHealthYield
			if change == "local-failure" {
				wantErr = errProbeSelectorUnavailable
			}
			if selected != "" || len(primary.selections) != 0 || !errors.Is(err, wantErr) {
				t.Fatalf("invalid single-lane result selected: selected=%q choices=%v err=%v", selected, primary.selections, err)
			}
			if change == "before-probe" && len(primary.availabilityCalls) != 0 {
				t.Fatal("old generation started a new availability probe")
			}
		})
	}
}

func TestLatencyConfirmationExpiresBeforeFreshPair(t *testing.T) {
	now := time.Unix(1120, 0)
	p := effectivePolicySettings{active: 60, improvement: 50}
	for _, tc := range []struct {
		name string
		at   string
		keep bool
	}{
		{"boundary", time.Unix(1000, 0).UTC().Format(time.RFC3339), true},
		{"expired", time.Unix(999, 0).UTC().Format(time.RFC3339), false},
		{"future", time.Unix(1121, 0).UTC().Format(time.RFC3339), false},
		{"missing", "", false},
		{"invalid", "not-a-time", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := newPolicyHealthState()
			item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "active", "reserve", 1
			item.OptimizationLastResult = &optimizationComparison{At: tc.at, Candidate: "reserve", Result: optimizationWin}
			comparison := compareOptimization(now, "active", "reserve", map[string]probeEvidence{
				"active": successfulEvidence(600), "reserve": successfulEvidence(500),
			}, true, true, p)
			desired, _ := gatePlannedOptimization(now, "active", "reserve", "meaningfully-faster", comparison, item, p)
			if tc.keep {
				if desired != "reserve" {
					t.Fatal("a fresh split-pair confirmation expired at its allowed boundary")
				}
			} else if desired != "active" || item.OptimizationChecks != 1 {
				t.Fatal("stale first win completed a fresh single comparison")
			}
		})
	}
}

func TestLatencyConfirmationAfterLongDeferralStartsAgain(t *testing.T) {
	controller, item, _ := stagedOptimizationController(t)
	for index, at := range []int64{1060, 5000, 5060} {
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if index < 2 && (item.Selected != "active" || item.OptimizationChecks != 1) {
			t.Fatalf("old latency win survived the pause at %d: selected=%q checks=%d", at, item.Selected, item.OptimizationChecks)
		}
	}
	if item.Selected != "reserve" {
		t.Fatal("two new latency confirmations did not switch")
	}
}

func TestRuntimeResetClearsPendingLatencyPairs(t *testing.T) {
	for _, fromDisk := range []bool{false, true} {
		name := "in-memory"
		if fromDisk {
			name = "restored"
		}
		t.Run(name, func(t *testing.T) {
			controller, item, runtime := stagedOptimizationController(t)
			item.OptimizationChecks = 1
			item.OptimizationLastResult = &optimizationComparison{At: time.Unix(1060, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
			if fromDisk {
				if err := writeJSONAtomic(statePath(controller.opts.StateRoot, "selector-health"), controller.state); err != nil {
					t.Fatal(err)
				}
				controller.state, controller.stateLoaded = nil, false
			}
			runtime.reset = true
			if err := controller.Tick(time.Unix(1120, 0)); err != nil {
				t.Fatal(err)
			}
			item = controller.state["europe"]
			if item.Selected != "active" || item.OptimizationChecks != 1 {
				t.Fatal("runtime reset inherited an old win instead of starting a new ordinary confirmation")
			}
			if !item.AvailabilityOK["active"] || item.Recoveries["reserve"] < 3 || len(item.Samples["active"]) == 0 {
				t.Fatal("pending reset erased availability or latency history")
			}
			for _, at := range []int64{1180, 1240} {
				if err := controller.Tick(time.Unix(at, 0)); err != nil {
					t.Fatal(err)
				}
			}
			if item.Selected != "reserve" {
				t.Fatal("reset blocked two new valid latency pairs")
			}
		})
	}
}
