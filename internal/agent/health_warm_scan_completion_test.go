package agent

import (
	"testing"
	"time"
)

func completedWarmScanFixture(now time.Time) (*policyHealthState, map[string]probeEvidence) {
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "a", "a", true
	item.WarmPlanningMarker, item.WarmPlanningSignature = string(qualityMeasurementWarm), "synthetic-context"
	a, b := 600, 100
	item.Samples["a"] = []healthSample{{At: 999, ObservedAt: 999, OK: true, DelayMS: &a}}
	item.Samples["b"] = []healthSample{{At: 1000, ObservedAt: 1000, OK: true, DelayMS: &b}}
	item.warmPlanningLatest = map[string]warmQualityEvidence{
		"a": {Measurement: qualityMeasurementWarm, StartedAt: now.Add(-2 * time.Second), ObservedAt: now.Add(-time.Second), DelayMS: &a},
		"b": {Measurement: qualityMeasurementWarm, StartedAt: now.Add(-100 * time.Millisecond), ObservedAt: now, DelayMS: &b},
	}
	item.warmPlanningCountedAt = map[string]time.Time{"a": now.Add(-time.Second), "b": now}
	item.warmScanPair = &warmScanContinuation{Baseline: "a", Candidate: "b", Next: "b", Signature: item.WarmPlanningSignature,
		ObservedAt: now.Add(-time.Second), CompletedAt: now}
	return item, map[string]probeEvidence{"b": {OK: true, DelayMS: &b, QualityStartedAt: now.Add(-100 * time.Millisecond), ObservedAt: now}}
}

func TestWarmPlanningCompletedScanTokenRequiresExactQualifiedPair(t *testing.T) {
	for _, shape := range []string{"valid", "missing-token", "unfinished", "context", "selection", "underlay", "availability",
		"expired", "first-time", "second-time", "future", "wrong-wave", "nonoverlapping-wave", "missing-first", "unknown-second", "failed-sample", "processed-watermark", "startless", "measured-delay-mismatch", "measured-start-mismatch"} {
		t.Run(shape, func(t *testing.T) {
			now := time.Unix(1000, 0)
			item, measured := completedWarmScanFixture(now)
			switch shape {
			case "missing-token":
				item.warmScanPair = nil
			case "unfinished":
				item.warmScanPair.CompletedAt = time.Time{}
			case "context":
				item.WarmPlanningSignature = "another-generation-or-origin"
			case "selection":
				item.Selected = "b"
			case "underlay":
				item.UnderlayFailure = "wan"
			case "availability":
				item.AvailabilityFailures["a"] = 1
			case "expired":
				now = now.Add(11 * time.Second)
			case "first-time":
				item.warmScanPair.ObservedAt = now.Add(-1500 * time.Millisecond)
			case "second-time":
				item.warmScanPair.CompletedAt = now.Add(-time.Millisecond)
			case "future":
				evidence := measured["b"]
				evidence.ObservedAt = now.Add(time.Second)
				measured["b"] = evidence
				warm := item.warmPlanningLatest["b"]
				warm.ObservedAt = evidence.ObservedAt
				item.warmPlanningLatest["b"] = warm
				item.Samples["b"][0].ObservedAt = 1001
				item.warmScanPair.CompletedAt = evidence.ObservedAt
			case "wrong-wave", "nonoverlapping-wave":
				warm := item.warmPlanningLatest["a"]
				warm.Wave = 10
				item.warmPlanningLatest["a"] = warm
				if shape == "nonoverlapping-wave" {
					warm = item.warmPlanningLatest["b"]
					warm.Wave = 10
					item.warmPlanningLatest["b"] = warm
					evidence := measured["b"]
					evidence.QualityWave = 10
					measured["b"] = evidence
				}
			case "missing-first":
				delete(item.warmPlanningLatest, "a")
			case "unknown-second", "startless":
				warm := item.warmPlanningLatest["b"]
				if shape == "unknown-second" {
					warm.Failed = true
				} else {
					warm.StartedAt = time.Time{}
				}
				item.warmPlanningLatest["b"] = warm
			case "failed-sample":
				item.Samples["a"][0].OK = false
			case "processed-watermark":
				item.warmPlanningCountedAt["a"] = now.Add(time.Millisecond)
			case "measured-delay-mismatch", "measured-start-mismatch":
				evidence := measured["b"]
				if shape == "measured-delay-mismatch" {
					different := 50
					evidence.DelayMS = &different
				} else {
					evidence.QualityStartedAt = now.Add(-50 * time.Millisecond)
				}
				measured["b"] = evidence
			}
			comparison := regularOptimizationComparison(now, "a", "b", measured, item, true, true, policySettings(healthPolicy{SwitchImprovementMS: 200}, "best"))
			if shape == "valid" {
				if comparison == nil || comparison.Result != optimizationWin || comparison.ActiveStartedAt != 998 || comparison.CandidateSampleAt != 1000 {
					t.Fatalf("completed initial scan did not retain the real pair: %+v", comparison)
				}
			} else if comparison != nil && comparison.Result == optimizationWin {
				t.Fatalf("invalid completion token authorized a proof: %+v", comparison)
			}
		})
	}
}

func TestWarmPlanningCompletedScanTokenCannotCountAgainOrHoldSlot(t *testing.T) {
	now := time.Unix(1000, 0)
	item, measured := completedWarmScanFixture(now)
	p := policySettings(healthPolicy{ActiveCheckSeconds: 60, SwitchImprovementMS: 200, ProbeBatchSize: 1}, "best")
	for _, at := range []time.Time{now, now, now.Add(time.Second)} {
		comparison := regularOptimizationComparison(at, "a", "b", measured, item, true, true, p)
		desired, _ := gatePlannedOptimization(at, "a", "b", "meaningfully-faster", comparison, item, p)
		if desired != "a" || item.OptimizationChecks != 1 {
			t.Fatal("reused pair became a new confirmation")
		}
	}
	if warmScanPairTarget(now, "a", []string{"a", "b"}, item) != "" {
		t.Fatal("completed token held a pending physical slot")
	}
	continueWarmScanPair(now.Add(time.Second), "a", []string{"a", "b"}, nil, item, p)
	if item.warmScanPair != nil {
		t.Fatal("completed token was retained into the next collection")
	}
}

func TestWarmPlanningCompletedScanTokenIsDiscardedByContextReset(t *testing.T) {
	item, _ := completedWarmScanFixture(time.Unix(1000, 0))
	resetWarmPlanning(item)
	if item.warmScanPair != nil {
		t.Fatal("context reset retained a completed comparison token")
	}
}

func TestWarmPlanningRetiredScanTokenPreservesNextPhysicalFirstHalf(t *testing.T) {
	now := time.Unix(1000, 0)
	item, _ := completedWarmScanFixture(now)
	previous := item.warmScanPair
	next := now.Add(time.Second)
	delay := 600
	warm := &warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: next.Add(-600 * time.Millisecond), ObservedAt: next, DelayMS: &delay}
	item.WarmPlanningLastProbeAt = map[string]float64{"a": 1001, "b": 1000}
	measured := map[string]probeEvidence{"a": {OK: true, Warm: warm}}
	p := policySettings(healthPolicy{ActiveCheckSeconds: 60, ProbeBatchSize: 1}, "best")
	continueWarmScanPair(next, "a", []string{"a", "b", "c"}, measured, item, p)
	if item.warmScanPair == nil || item.warmScanPair == previous || item.warmScanPair.Candidate != "c" ||
		item.warmScanPair.Next != "c" || !item.warmScanPair.ObservedAt.Equal(warm.ObservedAt) || !item.warmScanPair.CompletedAt.IsZero() {
		t.Fatal("retiring an earlier completion discarded the next physical first half")
	}
	if warmScanPairTarget(next, "a", []string{"a", "b", "c"}, item) != "c" || item.OptimizationChecks != 0 {
		t.Fatal("new continuation was lost or counted as a confirmation")
	}
}
