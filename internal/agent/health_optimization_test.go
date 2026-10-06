package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSingleProbeLaneRequiresTwoCompleteLatencyPairs(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.ProbeBatchSize = 1
	runtime.pool.HealthPolicies["europe"] = contract
	for _, at := range []int64{1_060, 1_120, 1_180, 1_240} {
		before := len(runtime.probeCalls)
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls)-before > 1 {
			t.Fatalf("single-lane tick at %d exceeded its batch", at)
		}
		if at < 1_240 && item.Selected != "active" {
			t.Fatalf("incomplete latency confirmation switched at %d", at)
		}
	}
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatalf("two complete pairs did not select reserve: selected=%q reason=%q", item.Selected, item.LastSwitchReason)
	}
}

func TestOrdinaryRotationDoesNotStopForOptimization(t *testing.T) {
	for _, batch := range []int{1, 2} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			controller, item, runtime := stagedOptimizationController(t)
			contract := runtime.pool.HealthPolicies["europe"]
			contract.Policy.ProbeBatchSize = batch
			contract.Candidates = append(contract.Candidates, "background1", "background2")
			for _, candidate := range []string{"background1", "background2"} {
				contract.Nodes[candidate] = healthNode{Label: candidate}
				runtime.probes[candidate] = successfulEvidence(700)
			}
			runtime.pool.HealthPolicies["europe"] = contract
			item.CandidateSignature = strings.Join(contract.Candidates, "\n")
			for at := int64(1060); at < 1300; at += 3 {
				before := len(runtime.probeCalls)
				if err := controller.Tick(time.Unix(at, 0)); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls)-before > batch {
					t.Fatal("budget exceeded")
				}
			}
			for _, candidate := range contract.Candidates {
				if !contains(runtime.probeCalls, candidate) {
					t.Fatalf("starved %s", candidate)
				}
			}
			if item.Selected != "reserve" {
				t.Fatal("ordinary rotation did not complete the confirmed improvement")
			}
		})
	}
}

func TestNewNomineeCannotInheritOrdinaryWins(t *testing.T) {
	item := newPolicyHealthState()
	item.OptimizationBaseline, item.OptimizationCandidate = "active", "reserve"
	item.OptimizationChecks = 1
	item.OptimizationLastResult = &optimizationComparison{At: time.Unix(1060, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
	p := effectivePolicySettings{active: 60, improvement: 50}
	for index, at := range []int64{1120, 1180} {
		now := time.Unix(at, 0)
		comparison := compareOptimization(now, "active", "better", map[string]probeEvidence{
			"active": successfulEvidence(600), "better": successfulEvidence(400),
		}, true, true, p)
		desired, _ := gatePlannedOptimization(now, "active", "better", "meaningfully-faster", comparison, item, p)
		if index == 0 && (desired != "active" || item.OptimizationChecks != 1) {
			t.Fatal("inherited another nominee's win")
		}
		if index == 1 && desired != "better" {
			t.Fatal("new nominee was not confirmed")
		}
	}
}

func TestRepeatedOrdinaryEvidenceIsNotAnotherWin(t *testing.T) {
	item := newPolicyHealthState()
	p := effectivePolicySettings{active: 60}
	now := time.Unix(1000, 0)
	comparison := &optimizationComparison{At: now.UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
	for repeat := 0; repeat < 3; repeat++ {
		desired, _ := gatePlannedOptimization(now, "active", "reserve", "meaningfully-faster", comparison, item, p)
		if desired != "active" || item.OptimizationChecks != 1 {
			t.Fatal("cached evidence counted again")
		}
	}
}

func TestLatencyOnlyComparisonRequiresFreshPairAndHysteresis(t *testing.T) {
	p := effectivePolicySettings{improvement: 50}
	for _, sample := range []struct {
		name                 string
		active, candidate    int
		missing, unavailable bool
		want                 string
	}{
		{name: "below-hysteresis", active: 500, candidate: 451, want: optimizationLoss},
		{name: "at-hysteresis", active: 500, candidate: 450, want: optimizationLoss},
		{name: "above-hysteresis", active: 500, candidate: 449, want: optimizationWin},
		{name: "slow-successful-candidate-still-improves", active: 2300, candidate: 2100, want: optimizationWin},
		{name: "missing-current-pair", active: 500, candidate: 100, missing: true, want: optimizationInconclusive},
		{name: "unavailable-reserve", active: 500, candidate: 100, unavailable: true, want: optimizationLoss},
		{name: "invalid-latency", active: 500, candidate: 0, want: optimizationLoss},
	} {
		t.Run(sample.name, func(t *testing.T) {
			measured := map[string]probeEvidence{"active": successfulEvidence(sample.active), "reserve": successfulEvidence(sample.candidate)}
			if sample.missing {
				delete(measured, "active")
			}
			comparison := compareOptimization(time.Unix(1000, 0), "active", "reserve", measured, true, !sample.unavailable, p)
			if comparison.Result != sample.want {
				t.Fatalf("comparison = %+v, want %s", comparison, sample.want)
			}
		})
	}
	p.improvement = 0
	if freshOptimizationWin("active", "reserve", map[string]probeEvidence{
		"active": successfulEvidence(500), "reserve": successfulEvidence(500),
	}, p) {
		t.Fatal("zero hysteresis must not turn equal latency into a switch")
	}
}

func TestLosingOrdinaryComparisonHasNoPenalty(t *testing.T) {
	item := newPolicyHealthState()
	p := effectivePolicySettings{active: 60, improvement: 50}
	for _, at := range []int64{1000, 1120, 1240} {
		item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "active", "reserve", 1
		comparison := &optimizationComparison{Candidate: "reserve", Result: optimizationLoss, Reason: "not-better"}
		desired, _ := gatePlannedOptimization(time.Unix(at, 0), "active", "reserve", "meaningfully-faster", comparison, item, p)
		if desired != "active" || item.OptimizationCandidate != "" {
			t.Fatal("loss retained confirmation or created penalty")
		}
	}
}

func TestLatencyPendingPairSurvivesDeferralButNotBaselineChange(t *testing.T) {
	p := effectivePolicySettings{active: 60, improvement: 50}
	for _, condition := range []string{"deferred", "legacy-cooldown", "baseline-changed"} {
		t.Run(condition, func(t *testing.T) {
			item := newPolicyHealthState()
			if condition == "legacy-cooldown" {
				if err := json.Unmarshal([]byte(`{"cooldown_until":1600}`), item); err != nil {
					t.Fatal(err)
				}
			}
			item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "active", "reserve", 1
			item.OptimizationLastResult = &optimizationComparison{At: time.Unix(940, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
			if condition == "baseline-changed" {
				item.OptimizationBaseline = "old-active"
			}
			desired, reason := gatePlannedOptimization(time.Unix(1000, 0), "active", "active", "", nil, item, p)
			if desired != "active" || reason != "" {
				t.Fatal("deferred or invalidated pair moved traffic")
			}
			if condition != "baseline-changed" && (item.OptimizationCandidate != "reserve" || item.OptimizationChecks != 1) {
				t.Fatal("budget deferral erased a completed confirmation")
			}
			if condition == "baseline-changed" && item.OptimizationCandidate != "" {
				t.Fatal("invalidated pending comparison survived")
			}
		})
	}
}

func TestLegacyPenaltyStateDoesNotHoldRecoveredPriorityCandidate(t *testing.T) {
	item := newPolicyHealthState()
	if err := json.Unmarshal([]byte(`{"cooldown_until":999999,"outage_penalty":{"primary":{"last_at":999,"count":3,"until":999999,"open":true}},"speed_probation":{"primary":{"until":999999,"count":2}}}`), item); err != nil {
		t.Fatal(err)
	}
	ensureHealthMaps(item)
	now := time.Unix(1000, 0)
	primaryDelay, backupDelay := 600, 100
	item.LastProbeAt["primary"], item.LastGoodAt["primary"], item.Recoveries["primary"] = 1000, 1000, 3
	item.Samples["primary"] = []healthSample{{At: 1000, OK: true, DelayMS: &primaryDelay}}
	desired, reason := selectDesired(now, "priority", "backup", []string{"primary", "backup"},
		map[string]int{"primary": 0, "backup": 1}, nil, map[string]*int{"primary": &primaryDelay, "backup": &backupDelay},
		nil, map[string]bool{"primary": true}, map[string]bool{"primary": true, "backup": true}, item,
		effectivePolicySettings{active: 60, backup: 300, failureThreshold: 3, recoveryThreshold: 3})
	if desired != "primary" || reason != "higher-priority-recovered" {
		t.Fatalf("legacy penalty or faster backup blocked recovered priority: %q %q", desired, reason)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "outage_penalty") || strings.Contains(string(encoded), "speed_probation") || strings.Contains(string(encoded), "cooldown_until") {
		t.Fatal("obsolete penalties survived state serialization")
	}
}
