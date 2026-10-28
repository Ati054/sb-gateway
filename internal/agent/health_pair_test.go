package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLegacyUnpairedConfirmationIsNotCarriedAcrossUpgrade(t *testing.T) {
	item := newPolicyHealthState()
	if err := json.Unmarshal([]byte(`{"selected":"active","optimization_baseline":"active","optimization_candidate":"reserve","optimization_checks":1,"optimization_last_result":{"at":"2026-10-26T00:00:00Z","active_sample_at":1000,"candidate_sample_at":1045},"samples":{"active":[{"at":1000,"ok":true,"delay_ms":600}],"reserve":[{"at":1045,"ok":true,"delay_ms":300}]}}`), item); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "active" || item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
		t.Fatal("upgrade retained an unpaired win or changed the saved route")
	}
}

func TestOptimizationRejectsSplitOrdinarySamples(t *testing.T) {
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	active := 1100
	item.Samples["active"] = []healthSample{{At: 1000, ObservedAt: 1000, OK: true, DelayMS: &active}}
	p := policySettings(healthPolicy{ActiveCheckSeconds: 60, SwitchImprovementMS: 200}, "best")
	comparison := regularOptimizationComparison(time.Unix(1045, 0), "active", "reserve", map[string]probeEvidence{"reserve": successfulEvidence(400)}, item, true, true, p)
	if comparison.Result != optimizationInconclusive || comparison.Reason != "pair-incomplete" {
		t.Fatalf("ordinary cached active confirmed a speed win: %+v", comparison)
	}
	desired, _ := gatePlannedOptimization(time.Unix(1045, 0), "active", "reserve", "meaningfully-faster", comparison, item, p)
	if desired != "active" || item.OptimizationCandidate != "reserve" || item.OptimizationChecks != 0 {
		t.Fatal("unpaired result must only nominate a paired check")
	}
	comparison = regularOptimizationComparison(time.Unix(1048, 0), "active", "reserve", map[string]probeEvidence{"reserve": successfulEvidence(400)}, item, true, true, p)
	if comparison.Result != optimizationInconclusive || comparison.Reason != "pair-skew" {
		t.Fatal("pending nomination allowed an old active sample")
	}
}

func TestOptimizationUsesObservationTimesInsideOneBatch(t *testing.T) {
	item := newPolicyHealthState()
	for _, skew := range []time.Duration{9 * time.Second, 11 * time.Second, 45 * time.Second} {
		now := time.Unix(1000, 0)
		active, reserve := successfulEvidence(1100), successfulEvidence(400)
		active.ObservedAt, reserve.ObservedAt = now, now.Add(skew)
		comparison := regularOptimizationComparison(now, "active", "reserve", map[string]probeEvidence{"active": active, "reserve": reserve}, item, true, true, policySettings(healthPolicy{SwitchImprovementMS: 200}, "best"))
		if (comparison.Result == optimizationWin) != (skew <= optimizationPairSkew) {
			t.Fatalf("wrong observation-time qualification for %s: %+v", skew, comparison)
		}
	}
}

func TestIncompleteNominationDoesNotConsumeFirstCompleteConfirmation(t *testing.T) {
	item := newPolicyHealthState()
	item.OptimizationBaseline, item.OptimizationCandidate = "active", "reserve"
	item.OptimizationLastResult = &optimizationComparison{At: time.Unix(1000, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationInconclusive, Reason: "pair-incomplete", ActiveSampleAt: 990, CandidateSampleAt: 1000}
	p := policySettings(healthPolicy{}, "best")
	first := &optimizationComparison{At: time.Unix(1004, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin, ActiveSampleAt: 1004, CandidateSampleAt: 1000}
	selected, _ := gatePlannedOptimization(time.Unix(1004, 0), "active", "reserve", "meaningfully-faster", first, item, p)
	if selected != "active" || item.OptimizationChecks != 1 {
		t.Fatal("an incomplete nomination suppressed the first complete confirmation")
	}
	selected, _ = gatePlannedOptimization(time.Unix(1005, 0), "active", "reserve", "meaningfully-faster", first, item, p)
	if selected != "active" || item.OptimizationChecks != 1 {
		t.Fatal("reusing the completed pair earned another win")
	}
	second := &optimizationComparison{At: time.Unix(1064, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin, ActiveSampleAt: 1060, CandidateSampleAt: 1064}
	selected, reason := gatePlannedOptimization(time.Unix(1064, 0), "active", "reserve", "meaningfully-faster", second, item, p)
	if selected != "reserve" || reason != "meaningfully-faster" {
		t.Fatal("the second independent complete pair did not finish switching")
	}
}

func TestNominatedPairCompletesAcrossOneSlotTicks(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.ProbeBatchSize = 1
	contract.Policy.SwitchImprovementMS = 50
	runtime.pool.HealthPolicies["europe"] = contract
	for at := int64(1060); at <= 1300; at += 3 {
		before := len(runtime.probeCalls)
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls)-before > 1 {
			t.Fatal("paired planning exceeded the one-slot budget")
		}
		if item.Selected == "reserve" {
			comparison := item.OptimizationLastResult
			if comparison == nil || comparison.CandidateSampleAt-comparison.ActiveSampleAt > optimizationPairSkew.Seconds() || comparison.CandidateSampleAt <= comparison.ActiveSampleAt {
				t.Fatalf("single-slot selection lacked close-time evidence: %+v", comparison)
			}
			return
		}
	}
	t.Fatalf("single-slot paired optimization starved: candidate=%q checks=%d probes=%v", item.OptimizationCandidate, item.OptimizationChecks, runtime.probeCalls)
}

func TestNominationDoesNotSpendAnotherWinOrLoopOnLongPair(t *testing.T) {
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	p := policySettings(healthPolicy{ActiveCheckSeconds: 60, ProbeBatchSize: 2}, "best")
	comparison := &optimizationComparison{At: time.Unix(1000, 0).UTC().Format(time.RFC3339), Candidate: "reserve", ActiveSampleAt: 1000, CandidateSampleAt: 1045, Result: optimizationInconclusive, Reason: "pair-skew"}
	gatePlannedOptimization(time.Unix(1000, 0), "active", "reserve", "meaningfully-faster", comparison, item, p)
	a, b := 1100, 400
	item.Samples["active"] = []healthSample{{At: 1000, ObservedAt: 1000, OK: true, DelayMS: &a}}
	item.Samples["reserve"] = []healthSample{{At: 1000, ObservedAt: 1045, OK: true, DelayMS: &b}}
	item.LastProbeAt["active"], item.LastProbeAt["reserve"] = 1000, 1000
	if targets := optimizationPairProbeTargets(time.Unix(1003, 0), "active", []string{"active", "reserve"}, item, p); len(targets) != 0 {
		t.Fatalf("slow pair started an immediate re-probe loop: %v", targets)
	}
	if item.OptimizationChecks != 0 {
		t.Fatal("inconclusive pair earned a win")
	}
}
