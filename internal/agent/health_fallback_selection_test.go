package agent

import (
	"strings"
	"testing"
	"time"
)

func TestFallbackOnlyCandidateCannotMaskMeasuredWinner(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "new-nominee"
		if pending {
			name = "pending-nominee"
		}
		t.Run(name, func(t *testing.T) { testFallbackOnlyCandidateCannotMaskMeasuredWinner(t, pending) })
	}
}

func testFallbackOnlyCandidateCannotMaskMeasuredWinner(t *testing.T, pending bool) {
	t.Helper()
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.ProbeBatchSize = 3
	contract.Candidates = append(contract.Candidates, "good")
	contract.Nodes["good"] = healthNode{Label: "Good"}
	runtime.pool.HealthPolicies["europe"] = contract
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	clearOptimizationCandidate(item)
	if pending {
		item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "active", "reserve", 1
		item.OptimizationLastResult = &optimizationComparison{
			At: time.Unix(1000, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin,
		}
	}
	for node, delay := range map[string]int{"active": 500, "reserve": 100, "good": 300} {
		value := delay
		item.Samples[node] = []healthSample{{At: 1000, OK: true, DelayMS: &value}}
		item.LastProbeAt[node], item.Recoveries[node] = 1000, 3
		item.AvailabilityOK[node], item.QualityOK[node] = true, true
		runtime.probes[node] = successfulEvidence(delay)
	}
	runtime.probes["reserve"] = probeEvidence{OK: true, QualityUnmeasured: true}
	for _, at := range []int64{1060, 1120} {
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if !item.AvailabilityOK["reserve"] || item.AvailabilityFailures["reserve"] != 0 {
			t.Fatal("fallback availability was turned into a node outage")
		}
		if item.QualityOK["reserve"] || item.MedianDelayMS["reserve"] != nil {
			t.Fatal("fallback-only success retained an old ranking delay")
		}
		if at == 1060 && item.Selected != "active" {
			t.Fatal("one ordinary win bypassed anti-flapping confirmation")
		}
	}
	if item.Selected != "good" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatalf("fallback-only nominee masked the current winner: selected=%q comparison=%+v",
			item.Selected, item.OptimizationLastResult)
	}
}

func TestCachedNomineeCannotMaskFreshOrdinaryWinner(t *testing.T) {
	now := time.Unix(1000, 0)
	item := newPolicyHealthState()
	values := map[string]*int{}
	for node, delay := range map[string]int{"active": 500, "cached": 100, "fresh": 300} {
		value := delay
		values[node] = &value
		item.Samples[node] = []healthSample{{At: 980, OK: true, DelayMS: &value}}
		item.LastProbeAt[node], item.Recoveries[node] = 980, 3
	}
	measured := map[string]probeEvidence{
		"active": successfulEvidence(500), "fresh": successfulEvidence(300),
	}
	desired, reason := selectDesired(now, "best", "active", []string{"active", "cached", "fresh"},
		nil, nil, values, measured,
		map[string]bool{"cached": true, "fresh": true},
		map[string]bool{"active": true, "cached": true, "fresh": true}, item,
		effectivePolicySettings{active: 60, backup: 120, recoveryThreshold: 3, failureThreshold: 3, improvement: 50})
	if desired != "fresh" || reason != "meaningfully-faster" {
		t.Fatalf("unmeasured cached nominee masked this cycle's winner: %q %q", desired, reason)
	}
}

func TestSplitLatencyPairUsesQualitySampleTimeNotAvailabilityTime(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		name string
		at   float64
		want string
	}{
		{"fresh", 999, optimizationWin},
		{"boundary", 880, optimizationWin},
		{"stale", 879, optimizationInconclusive},
		{"missing", 0, optimizationInconclusive},
		{"future", 1001, optimizationInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := newPolicyHealthState()
			active := 500
			item.LastProbeAt["active"] = 1000
			item.Samples["active"] = []healthSample{{At: tc.at, OK: true, DelayMS: &active}}
			item.DailySamples["active"] = []healthSample{{At: 1000, OK: true}}
			comparison := regularOptimizationComparison(now, "active", "reserve",
				map[string]probeEvidence{"reserve": successfulEvidence(300)}, item, true, true,
				effectivePolicySettings{active: 60, improvement: 50})
			if comparison.Result != tc.want {
				t.Fatalf("availability timestamp made quality reusable: %+v", comparison)
			}
		})
	}
}

func TestPriorityReturnRequiresFreshQualityTimestamp(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, at := range []float64{0, 700, 1001, 999} {
		item := newPolicyHealthState()
		primary, backup := 100, 500
		item.Samples["primary"] = []healthSample{{At: at, OK: true, DelayMS: &primary}}
		item.LastProbeAt["primary"], item.Recoveries["primary"] = 1000, 3
		desired, _ := selectDesired(now, "priority", "backup", []string{"primary", "backup"},
			map[string]int{"primary": 0, "backup": 1}, nil,
			map[string]*int{"primary": &primary, "backup": &backup}, nil,
			map[string]bool{"primary": true}, map[string]bool{"primary": true, "backup": true}, item,
			effectivePolicySettings{active: 60, backup: 120, failureThreshold: 3, recoveryThreshold: 3})
		want := "backup"
		if at == 999 {
			want = "primary"
		}
		if desired != want {
			t.Fatalf("quality timestamp %v, fresh availability timestamp 1000: got %q want %q", at, desired, want)
		}
	}
}
