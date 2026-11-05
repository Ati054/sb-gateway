package agent

import (
	"testing"
	"time"
)

func warmParallelEvidence(value warmQualityEvidence) probeEvidence {
	return probeEvidence{OK: true, DelayMS: value.DelayMS, QualityStartedAt: value.StartedAt, ObservedAt: value.ObservedAt, QualityWave: value.Wave}
}

func warmParallelCompletionFixture(now time.Time, cached string) (*policyHealthState, map[string]probeEvidence) {
	a, c := 600, 300
	active := warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: now.Add(-700 * time.Millisecond),
		ObservedAt: now.Add(-100 * time.Millisecond), DelayMS: &a, Wave: 10}
	candidate := warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: now.Add(-699 * time.Millisecond),
		ObservedAt: now.Add(-399 * time.Millisecond), DelayMS: &c, Wave: 10}
	if cached == "candidate" {
		candidate.StartedAt, candidate.ObservedAt = now.Add(-399*time.Millisecond), now.Add(-99*time.Millisecond)
	}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "a", "a", true
	item.WarmPlanningMarker = string(qualityMeasurementWarm)
	item.OptimizationBaseline, item.OptimizationCandidate = "a", "c"
	item.warmPlanningLatest = map[string]warmQualityEvidence{"a": active, "c": candidate}
	item.warmPlanningCountedAt = map[string]time.Time{"a": active.ObservedAt, "c": candidate.ObservedAt}
	for node, warm := range item.warmPlanningLatest {
		item.Samples[node] = []healthSample{{At: float64(warm.ObservedAt.Unix()), ObservedAt: qualityObservationAt(now, warmParallelEvidence(warm)), OK: true, DelayMS: warm.DelayMS}}
	}
	freshNode, fresh := "c", candidate
	if cached == "candidate" {
		freshNode, fresh = "a", active
	}
	return item, map[string]probeEvidence{freshNode: warmParallelEvidence(fresh)}
}

func TestWarmPlanningCachedParallelCompletionOrderIsIndependent(t *testing.T) {
	for _, cached := range []string{"active", "candidate"} {
		for _, shape := range []string{"valid", "serial-reversed", "wrong-wave", "nonoverlapping", "future", "skew"} {
			t.Run(cached+"/"+shape, func(t *testing.T) {
				now := time.Unix(1000, 200*int64(time.Millisecond))
				item, measured := warmParallelCompletionFixture(now, cached)
				for node, warm := range item.warmPlanningLatest {
					_, fresh := measured[node]
					switch shape {
					case "serial-reversed", "skew":
						warm.Wave = 0
						if shape == "skew" && !fresh {
							warm.StartedAt, warm.ObservedAt = warm.StartedAt.Add(-11*time.Second), warm.ObservedAt.Add(-11*time.Second)
						}
					case "wrong-wave":
						if fresh {
							warm.Wave = 12
						}
					case "nonoverlapping":
						if fresh {
							warm.StartedAt, warm.ObservedAt = warm.StartedAt.Add(-time.Second), warm.ObservedAt.Add(-time.Second)
						}
					case "future":
						warm.StartedAt, warm.ObservedAt = warm.StartedAt.Add(time.Second), warm.ObservedAt.Add(time.Second)
					}
					item.warmPlanningLatest[node] = warm
					item.Samples[node] = []healthSample{{At: float64(warm.ObservedAt.Unix()), ObservedAt: qualityObservationAt(now, warmParallelEvidence(warm)), OK: true, DelayMS: warm.DelayMS}}
					if fresh {
						measured[node] = warmParallelEvidence(warm)
					}
				}
				comparison := regularOptimizationComparison(now, "a", "c", measured, item, true, true, policySettings(healthPolicy{SwitchImprovementMS: 200}, "best"))
				if shape == "valid" {
					if comparison == nil || comparison.Result != optimizationWin || comparison.QualityWave != 10 ||
						comparison.ActiveSampleAt != item.Samples["a"][0].ObservedAt || comparison.CandidateSampleAt != item.Samples["c"][0].ObservedAt {
						t.Fatalf("same overlapping physical wave was rejected because of completion/delivery order: %+v", comparison)
					}
				} else if comparison != nil && comparison.Result == optimizationWin {
					t.Fatalf("incompatible cached wave authorized a confirmation: %+v", comparison)
				}
			})
		}
	}
}

func TestWarmPlanningReorderedParallelPairStillNeedsTwoNewProofs(t *testing.T) {
	for _, cached := range []string{"active", "candidate"} {
		t.Run(cached, func(t *testing.T) {
			now := time.Unix(1000, 200*int64(time.Millisecond))
			item, measured := warmParallelCompletionFixture(now, cached)
			p := policySettings(healthPolicy{ActiveCheckSeconds: 60, SwitchImprovementMS: 200}, "best")
			for _, at := range []time.Time{now, now.Add(time.Millisecond)} {
				comparison := regularOptimizationComparison(at, "a", "c", measured, item, true, true, p)
				desired, _ := gatePlannedOptimization(at, "a", "c", "meaningfully-faster", comparison, item, p)
				if desired != "a" || item.OptimizationChecks != 1 {
					t.Fatal("delivery order or replay counted one physical wave twice")
				}
			}
			next := now.Add(61 * time.Second)
			freshItem, freshMeasured := warmParallelCompletionFixture(next, cached)
			freshItem.OptimizationBaseline, freshItem.OptimizationCandidate = item.OptimizationBaseline, item.OptimizationCandidate
			freshItem.OptimizationChecks, freshItem.OptimizationLastResult = item.OptimizationChecks, item.OptimizationLastResult
			for node, warm := range freshItem.warmPlanningLatest {
				warm.Wave = 12
				freshItem.warmPlanningLatest[node] = warm
				if _, exists := freshMeasured[node]; exists {
					freshMeasured[node] = warmParallelEvidence(warm)
				}
			}
			comparison := regularOptimizationComparison(next, "a", "c", freshMeasured, freshItem, true, true, p)
			desired, reason := gatePlannedOptimization(next, "a", "c", "meaningfully-faster", comparison, freshItem, p)
			if desired != "c" || reason != "meaningfully-faster" || comparison == nil || comparison.ConfirmationGapMS == nil || *comparison.ConfirmationGapMS != 61000 {
				t.Fatalf("two distinct interval-separated waves did not confirm: desired=%s reason=%s comparison=%+v", desired, reason, comparison)
			}
		})
	}
}
