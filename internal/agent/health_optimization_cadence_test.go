package agent

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func completedCadenceState(t *testing.T) (*healthController, *policyHealthState, healthPolicyContract, time.Time) {
	t.Helper()
	base := time.Unix(1000, 0)
	contract := healthPolicyContract{Mode: "best", Candidates: []string{"a", "b", "c"}, Policy: healthPolicy{ActiveCheckSeconds: 60, ProbeBatchSize: 2, SwitchImprovementMS: 200}}
	p := policySettings(contract.Policy, contract.Mode)
	item := newPolicyHealthState()
	item.AvailabilityOK = map[string]bool{}
	item.QualityOK = map[string]bool{}
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "a", "a", true
	for _, node := range contract.Candidates {
		item.AvailabilityOK[node] = true
		item.QualityOK[node] = true
		item.Recoveries[node] = p.recoveryThreshold
	}
	pair := cadenceQualityWave(base, 1)
	for node, e := range pair {
		item.Samples[node] = []healthSample{{At: float64(e.ObservedAt.Unix()), ObservedAt: qualityObservationAt(base, e), OK: true, DelayMS: e.DelayMS}}
		item.LastProbeAt[node] = float64(e.ObservedAt.Unix())
	}
	comparison := regularOptimizationComparison(base.Add(time.Second), "a", "c", pair, item, true, true, p)
	selected, _ := gatePlannedOptimization(base.Add(time.Second), "a", "c", "meaningfully-faster", comparison, item, p)
	if selected != "a" || item.OptimizationChecks != 1 {
		t.Fatalf("first complete pair failed: selected=%s checks=%d comparison=%+v", selected, item.OptimizationChecks, comparison)
	}
	return &healthController{runtime: &concurrentCohortRuntime{}}, item, contract, base
}

func cadenceQualityWave(start time.Time, wave uint64) map[string]probeEvidence {
	active, candidate := successfulEvidence(900), successfulEvidence(400)
	active.QualityWave, candidate.QualityWave = wave, wave
	active.QualityStartedAt, candidate.QualityStartedAt = start, start
	active.ObservedAt, candidate.ObservedAt = start.Add(900*time.Millisecond), start.Add(400*time.Millisecond)
	return map[string]probeEvidence{"a": active, "c": candidate}
}

func refreshOtherReserveActive(item *policyHealthState, base time.Time) {
	ms := 900
	at := base.Add(3900 * time.Millisecond)
	item.Samples["a"] = append(item.Samples["a"], healthSample{At: float64(at.Unix()), ObservedAt: float64(at.UnixNano()) / 1e9, OK: true, DelayMS: &ms})
	item.LastProbeAt["a"] = float64(at.Unix())
	item.Samples["b"] = []healthSample{{At: float64(at.Unix()), ObservedAt: float64(at.UnixNano()) / 1e9, OK: true, DelayMS: &ms}}
	item.LastProbeAt["b"] = float64(at.Unix())
}

func TestOptimizationCadenceCompletedParallelPairDoesNotAccelerateFromOtherReserve(t *testing.T) {
	for _, count := range []int{3, 7, 10, 24} {
		t.Run(fmt.Sprintf("nodes%d", count), func(t *testing.T) {
			c, item, contract, base := completedCadenceState(t)
			for len(contract.Candidates) < count {
				contract.Candidates = append(contract.Candidates, fmt.Sprintf("extra-%d", len(contract.Candidates)))
			}
			refreshOtherReserveActive(item, base)
			now := base.Add(6 * time.Second)
			p := c.surveySettings(policySettings(contract.Policy, contract.Mode))
			targets := optimizationPairProbeTargets(now, "a", contract.Candidates, item, p)
			if len(targets) != 0 {
				t.Fatalf("completed pair resumed after 6 seconds instead of 60: targets=%v remaining=%v", targets, c.remainingProbeInterval(now, contract, item))
			}
			if c.remainingProbeInterval(now, contract, item) <= 0 || optimizationPairHalfPending(now, contract, item) {
				t.Fatal("completed proof promoted unrelated active refresh to urgent pair work")
			}
		})
	}
}

func TestOptimizationComparisonSeparatesRawPairAndMedians(t *testing.T) {
	item := newPolicyHealthState()
	makeSamples := func(values ...int) []healthSample {
		result := []healthSample{}
		for i, value := range values {
			ms := value
			result = append(result, healthSample{At: 998 + float64(i), ObservedAt: 998 + float64(i), OK: true, DelayMS: &ms})
		}
		return result
	}
	item.Samples["a"], item.Samples["c"] = makeSamples(1300, 1100, 900), makeSamples(600, 400, 200)
	firstAt := time.Unix(1000, 0)
	first := cadenceQualityWave(firstAt, 7)
	activeResponse, candidateResponse := 71, 91
	active := first["a"]
	active.ResponseDelayMS = &activeResponse
	first["a"] = active
	candidate := first["c"]
	candidate.DelayMS = item.Samples["c"][2].DelayMS
	candidate.ObservedAt = firstAt.Add(200 * time.Millisecond)
	first["c"] = candidate
	candidate = first["c"]
	candidate.ResponseDelayMS = &candidateResponse
	first["c"] = candidate
	p := policySettings(healthPolicy{ActiveCheckSeconds: 60, SwitchImprovementMS: 200}, "best")
	comparison := regularOptimizationComparison(firstAt.Add(time.Second), "a", "c", first, item, true, true, p)
	if comparison == nil || comparison.Result != optimizationWin || *comparison.ActiveDelayMS != 1100 || *comparison.CandidateDelayMS != 400 ||
		*comparison.ActiveRawDelayMS != 900 || *comparison.CandidateRawDelayMS != 200 || comparison.QualityWave != 7 ||
		comparison.ActiveStartedAt != 1000 || comparison.CandidateStartedAt != 1000 || *comparison.ActiveResponseMS != 71 || *comparison.CandidateResponseMS != 91 {
		t.Fatalf("mixed raw and smoothed diagnostic: %+v", comparison)
	}
	gatePlannedOptimization(firstAt.Add(time.Second), "a", "c", "meaningfully-faster", comparison, item, p)
	secondAt := firstAt.Add(61 * time.Second)
	second := cadenceQualityWave(secondAt, 8)
	next := regularOptimizationComparison(secondAt.Add(time.Second), "a", "c", second, item, true, true, p)
	selected, _ := gatePlannedOptimization(secondAt.Add(time.Second), "a", "c", "meaningfully-faster", next, item, p)
	if selected != "c" || next.FirstConfirmationAt != comparison.At || next.ConfirmationGapMS == nil || *next.ConfirmationGapMS != 61200 {
		t.Fatalf("confirmation spacing diagnostic lost: selected=%s comparison=%+v", selected, next)
	}
}

func TestOptimizationCadenceNextDueSingleSlotRoundCompletes(t *testing.T) {
	_, item, contract, base := completedCadenceState(t)
	contract.Policy.ProbeBatchSize = 1
	p := policySettings(contract.Policy, contract.Mode)
	item.Samples["c"][0].At = 1003
	item.Samples["c"][0].ObservedAt = 1003.4
	item.LastProbeAt["c"] = 1003
	item.OptimizationLastResult.CandidateSampleAt = 1003.4
	item.OptimizationLastResult.At = base.Add(4 * time.Second).UTC().Format(time.RFC3339)
	active := successfulEvidence(900)
	active.ObservedAt = base.Add(60900 * time.Millisecond)
	item.Samples["a"] = append(item.Samples["a"], healthSample{At: 1060, ObservedAt: 1060.9, OK: true, DelayMS: active.DelayMS})
	item.LastProbeAt["a"] = 1060
	early := base.Add(61 * time.Second)
	if got := optimizationPairProbeTargets(early, "a", contract.Candidates, item, p); len(got) != 0 {
		t.Fatalf("candidate resumed before its due time: %v", got)
	}
	due := base.Add(63 * time.Second)
	if got := optimizationPairProbeTargets(due, "a", contract.Candidates, item, p); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("due candidate starved behind refreshed active: %v", got)
	}
	if !optimizationPairHalfPending(due, contract, item) {
		t.Fatal("eligible single-slot half lost priority")
	}
	candidate := successfulEvidence(400)
	candidate.ObservedAt = due.Add(400 * time.Millisecond)
	item.Samples["c"] = append(item.Samples["c"], healthSample{At: 1063, ObservedAt: 1063.4, OK: true, DelayMS: candidate.DelayMS})
	item.LastProbeAt["c"] = 1063
	comparison := regularOptimizationComparison(due.Add(time.Second), "a", "c", map[string]probeEvidence{"c": candidate}, item, true, true, p)
	selected, reason := gatePlannedOptimization(due.Add(time.Second), "a", "c", "meaningfully-faster", comparison, item, p)
	if selected != "c" || reason != "meaningfully-faster" {
		t.Fatalf("due split confirmation did not complete: selected=%s comparison=%+v", selected, comparison)
	}
}

func TestOptimizationCadenceDueRoundWithFasterResponse(t *testing.T) {
	for _, interval := range []int{3, 30, 60} {
		t.Run((time.Duration(interval) * time.Second).String(), func(t *testing.T) {
			item := newPolicyHealthState()
			p := policySettings(healthPolicy{ActiveCheckSeconds: interval}, "best")
			first := &optimizationComparison{At: time.Unix(1001, 0).UTC().Format(time.RFC3339), Candidate: "c", Result: optimizationWin, ActiveSampleAt: 1000.95, CandidateSampleAt: 1000.9}
			gatePlannedOptimization(time.Unix(1001, 0), "a", "c", "meaningfully-faster", first, item, p)
			second := &optimizationComparison{At: time.Unix(1001+int64(interval), 0).UTC().Format(time.RFC3339), Candidate: "c", Result: optimizationWin, ActiveSampleAt: 1000.2 + float64(interval), CandidateSampleAt: 1000.1 + float64(interval)}
			selected, _ := gatePlannedOptimization(time.Unix(1001+int64(interval), 0), "a", "c", "meaningfully-faster", second, item, p)
			if selected != "c" {
				t.Fatal("whole-second due round rejected because its next request finished faster")
			}
		})
	}
}

func TestOptimizationCadenceOtherReserveCannotCauseActualSixSecondSwitch(t *testing.T) {
	c, item, contract, base := completedCadenceState(t)
	refreshOtherReserveActive(item, base)
	now := base.Add(6 * time.Second)
	p := c.surveySettings(policySettings(contract.Policy, contract.Mode))
	targets := optimizationPairProbeTargets(now, "a", contract.Candidates, item, p)
	if len(targets) == 0 {
		return
	}
	targets = c.withSurveyBaseline(now, "a", targets, item, p)
	if !reflect.DeepEqual(targets, []string{"a", "c"}) {
		t.Fatalf("unexpected second wave %v", targets)
	}
	measured := cadenceQualityWave(now, 3)
	for node, e := range measured {
		item.Samples[node] = append(item.Samples[node], healthSample{At: float64(e.ObservedAt.Unix()), ObservedAt: qualityObservationAt(now, e), OK: true, DelayMS: e.DelayMS})
	}
	desired, reason := selectDesired(now.Add(time.Second), "best", "a", contract.Candidates, map[string]int{}, item.DailyStats, sampleMedians(item.Samples, contract.Candidates), measured, item.QualityOK, item.AvailabilityOK, item, p)
	comparison := regularOptimizationComparison(now.Add(time.Second), "a", desired, measured, item, true, true, p)
	selected, _ := gatePlannedOptimization(now.Add(time.Second), "a", desired, reason, comparison, item, p)
	if selected != "a" {
		t.Fatalf("actual early switch=%s after six seconds, configured interval=60; comparison=%+v", selected, comparison)
	}
}

func TestOptimizationCadenceGateRejectsEarlyIndependentCompletePair(t *testing.T) {
	_, item, contract, base := completedCadenceState(t)
	now := base.Add(6 * time.Second)
	measured := cadenceQualityWave(now, 2)
	p := policySettings(contract.Policy, contract.Mode)
	comparison := regularOptimizationComparison(now.Add(time.Second), "a", "c", measured, item, true, true, p)
	selected, _ := gatePlannedOptimization(now.Add(time.Second), "a", "c", "meaningfully-faster", comparison, item, p)
	if selected != "a" || item.OptimizationChecks != 1 {
		t.Fatalf("early independent pair counted: selected=%s checks=%d", selected, item.OptimizationChecks)
	}
}

func TestOptimizationCadenceOtherReserveCannotStealPendingProof(t *testing.T) {
	_, item, contract, base := completedCadenceState(t)
	active, other := successfulEvidence(500), successfulEvidence(100)
	active.ObservedAt, other.ObservedAt = base.Add(3500*time.Millisecond), base.Add(3100*time.Millisecond)
	item.Samples["a"] = append(item.Samples["a"], healthSample{At: 1003, ObservedAt: 1003.5, OK: true, DelayMS: active.DelayMS})
	item.Samples["b"] = []healthSample{{At: 1003, ObservedAt: 1003.1, OK: true, DelayMS: other.DelayMS}}
	measured := map[string]probeEvidence{"a": active, "b": other}
	p := policySettings(contract.Policy, contract.Mode)
	now := base.Add(4 * time.Second)
	desired, reason := selectDesired(now, "best", "a", contract.Candidates, nil, item.DailyStats, sampleMedians(item.Samples, contract.Candidates), measured, item.QualityOK, item.AvailabilityOK, item, p)
	if desired != "c" {
		t.Fatalf("unpaired active refresh let %s steal candidate c", desired)
	}
	comparison := regularOptimizationComparison(now, "a", desired, measured, item, true, true, p)
	selected, _ := gatePlannedOptimization(now, "a", desired, reason, comparison, item, p)
	if selected != "a" || item.OptimizationCandidate != "c" || item.OptimizationChecks != 1 {
		t.Fatal("unrelated reserve changed or completed the pending proof")
	}
}

func TestOptimizationCadencePendingOwnPairCanLose(t *testing.T) {
	_, item, contract, base := completedCadenceState(t)
	now := base.Add(61 * time.Second)
	measured := cadenceQualityWave(now, 2)
	slow := successfulEvidence(1200)
	slow.QualityWave, slow.QualityStartedAt, slow.ObservedAt = 2, now, now.Add(1200*time.Millisecond)
	measured["c"] = slow
	item.Samples["c"] = append(item.Samples["c"], healthSample{At: 1062, ObservedAt: 1062.2, OK: true, DelayMS: slow.DelayMS})
	p := policySettings(contract.Policy, contract.Mode)
	desired, reason := selectDesired(now.Add(2*time.Second), "best", "a", contract.Candidates, nil, item.DailyStats, sampleMedians(item.Samples, contract.Candidates), measured, item.QualityOK, item.AvailabilityOK, item, p)
	comparisonNode := desired
	if desired == "a" {
		comparisonNode = item.OptimizationCandidate
	}
	comparison := regularOptimizationComparison(now.Add(2*time.Second), "a", comparisonNode, measured, item, true, true, p)
	selected, _ := gatePlannedOptimization(now.Add(2*time.Second), "a", desired, reason, comparison, item, p)
	if selected != "a" || item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
		t.Fatalf("pending candidate survived its own losing pair: %+v", comparison)
	}
}

func TestOptimizationCadencePendingProofDoesNotDelayFailure(t *testing.T) {
	_, item, contract, base := completedCadenceState(t)
	p := policySettings(contract.Policy, contract.Mode)
	item.AvailabilityFailures["a"] = p.failureThreshold
	measured := map[string]probeEvidence{"b": successfulEvidence(300)}
	now := base.Add(3 * time.Second)
	desired, reason := selectDesired(now, "best", "a", contract.Candidates, nil, item.DailyStats, sampleMedians(item.Samples, contract.Candidates), measured, item.QualityOK, item.AvailabilityOK, item, p)
	if desired != "b" || reason != "active-unavailable" {
		t.Fatalf("pending candidate delayed confirmed failure: selected=%s reason=%s", desired, reason)
	}
	selected, reason := gatePlannedOptimization(now, "a", desired, reason, nil, item, p)
	if selected != "b" || reason != "active-unavailable" || item.OptimizationCandidate != "" {
		t.Fatal("emergency switch waited for a planned confirmation")
	}
}
