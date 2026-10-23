package agent

import (
	"strings"
	"testing"
	"time"
)

func TestBestModeCompletesNomineeWhenFasterReservesTradePlaces(t *testing.T) {
	controller, item, runtime := jitterOptimizationController(t)
	for index, delays := range [][2]int{{350, 360}, {360, 350}} {
		runtime.probes["reserve"] = successfulEvidence(delays[0])
		runtime.probes["other"] = successfulEvidence(delays[1])
		before := len(runtime.probeCalls)
		if err := controller.Tick(time.Unix(int64(1060+60*index), 0)); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls)-before != 3 {
			t.Fatalf("confirmation changed the ordinary probe budget: %v", runtime.probeCalls[before:])
		}
		if index == 0 && (item.Selected != "active" || item.OptimizationCandidate != "reserve" || item.OptimizationChecks != 1) {
			t.Fatalf("first pair did not nominate the fastest reserve: selected=%s nominee=%s wins=%d", item.Selected, item.OptimizationCandidate, item.OptimizationChecks)
		}
	}
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatalf("reserve jitter erased an independently confirmed improvement: selected=%s nominee=%s wins=%d", item.Selected, item.OptimizationCandidate, item.OptimizationChecks)
	}
}

func TestBestModeReplacesInvalidOrExpiredNomineeWithoutInheritingWins(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence probeEvidence
		nextAt   int64
	}{
		{"below-margin", successfulEvidence(500), 1120},
		{"at-margin", successfulEvidence(453), 1120},
		{"failed", probeEvidence{Failure: probeFailureTimeout}, 1120},
		{"fallback-only", probeEvidence{OK: true, QualityUnmeasured: true, PrimaryQualityFailed: true}, 1120},
		{"expired", successfulEvidence(360), 1240},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, item, runtime := jitterOptimizationController(t)
			runtime.probes["reserve"], runtime.probes["other"] = successfulEvidence(350), successfulEvidence(360)
			if err := controller.Tick(time.Unix(1060, 0)); err != nil {
				t.Fatal(err)
			}
			runtime.probes["reserve"], runtime.probes["other"] = tc.evidence, successfulEvidence(350)
			if err := controller.Tick(time.Unix(tc.nextAt, 0)); err != nil {
				t.Fatal(err)
			}
			expected := "other"
			if tc.name == "expired" {
				// The fresh short median still favors this nominee, but its old
				// confirmation must expire independently of nomination ranking.
				expected = "reserve"
			}
			if item.Selected != "active" || item.OptimizationCandidate != expected || item.OptimizationChecks != 1 {
				t.Fatalf("replacement inherited an invalid nominee's win: selected=%s nominee=%s wins=%d", item.Selected, item.OptimizationCandidate, item.OptimizationChecks)
			}
			if err := controller.Tick(time.Unix(tc.nextAt+60, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != expected || item.LastSwitchReason != "meaningfully-faster" {
				t.Fatalf("replacement failed to qualify independently: selected=%s reason=%s", item.Selected, item.LastSwitchReason)
			}
		})
	}
}

func jitterOptimizationController(t *testing.T) (*healthController, *policyHealthState, *fakeSelectorRuntime) {
	t.Helper()
	controller, item, runtime := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.ProbeBatchSize = 3
	contract.Policy.SwitchImprovementMS = 155
	contract.Candidates = append(contract.Candidates, "other")
	contract.Nodes["other"] = healthNode{Label: "Other"}
	runtime.pool.HealthPolicies["europe"] = contract
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.AvailabilityOK["other"], item.QualityOK["other"] = true, true
	item.Recoveries["other"] = 3
	item.LastProbeAt["other"] = 1000
	initial := 360
	item.Samples["other"] = []healthSample{{At: 1000, OK: true, DelayMS: &initial}}
	runtime.probes["active"] = successfulEvidence(608)
	return controller, item, runtime
}
