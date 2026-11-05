package agent

import (
	"testing"
	"time"
)

func warmDisplayQualificationFixture(now time.Time, order string) (*policyHealthState, effectivePolicySettings, latencyComparison) {
	item, _ := warmParallelCompletionFixture(now, order)
	item.WarmPlanningSamples = item.Samples
	item.QualityOK, item.AvailabilityOK = map[string]bool{"a": true, "c": true}, map[string]bool{"a": true, "c": true}
	item.Recoveries["a"], item.Recoveries["c"] = 3, 3
	old := latencyComparison{Measurement: string(qualityMeasurementWarm), Active: "a", ActiveDelayMS: 500, CandidateDelayMS: 450,
		ActiveAt: 997, CandidateAt: 997.1, ExpiresAt: 1117}
	item.LastLatencyComparisons = map[string]latencyComparison{"c": old}
	return item, policySettings(healthPolicy{ActiveCheckSeconds: 60, SwitchImprovementMS: 200}, "best"), old
}

func TestWarmPlanningDisplayRejectsIncompatiblePhasesAndRetainsLastGood(t *testing.T) {
	for _, shape := range []string{"different-wave", "same-wave-without-overlap", "missing-metadata", "missing-start", "processed-watermark", "history-failed", "future"} {
		t.Run(shape, func(t *testing.T) {
			now := time.Unix(1000, 200*int64(time.Millisecond))
			item, p, old := warmDisplayQualificationFixture(now, "active")
			candidate := item.warmPlanningLatest["c"]
			switch shape {
			case "different-wave":
				candidate.Wave = 12
			case "same-wave-without-overlap":
				candidate.StartedAt, candidate.ObservedAt = candidate.StartedAt.Add(-time.Second), candidate.ObservedAt.Add(-time.Second)
				item.Samples["c"][0].At = float64(candidate.ObservedAt.Unix())
				item.Samples["c"][0].ObservedAt = qualityObservationAt(now, warmParallelEvidence(candidate))
			case "missing-start":
				candidate.StartedAt = time.Time{}
			case "processed-watermark":
				item.warmPlanningCountedAt = map[string]time.Time{"c": candidate.ObservedAt.Add(time.Millisecond)}
			case "history-failed":
				item.Samples["c"][0].OK = false
			case "future":
				candidate.StartedAt, candidate.ObservedAt = now.Add(-500*time.Millisecond), now.Add(50*time.Millisecond)
				item.Samples["c"][0].At = float64(candidate.ObservedAt.Unix())
				item.Samples["c"][0].ObservedAt = qualityObservationAt(now, warmParallelEvidence(candidate))
			}
			item.warmPlanningLatest["c"] = candidate
			if shape == "missing-metadata" {
				delete(item.warmPlanningLatest, "c")
			}
			item.LatencyComparisons = currentLatencyComparisons(now, warmPlanningView(item), []string{"a", "c"}, p)
			if current, exists := item.LatencyComparisons["c"]; exists {
				t.Errorf("unqualified phases invented a new paired display value: %+v", current)
			}
			rememberDisplayComparisons(item)
			if item.LastLatencyComparisons["c"] != old {
				t.Errorf("unqualified current value replaced last-good display history: %+v", item.LastLatencyComparisons["c"])
			}
		})
	}
}

func TestWarmPlanningDisplayAcceptsBothSerialAndParallelOrders(t *testing.T) {
	for _, order := range []string{"active", "candidate"} {
		for _, metric := range []string{"serial", "parallel"} {
			t.Run(order+"/"+metric, func(t *testing.T) {
				now := time.Unix(1000, 200*int64(time.Millisecond))
				item, p, _ := warmDisplayQualificationFixture(now, order)
				if metric == "serial" {
					for node, warm := range item.warmPlanningLatest {
						warm.Wave = 0
						item.warmPlanningLatest[node] = warm
					}
				}
				item.LatencyComparisons = currentLatencyComparisons(now, warmPlanningView(item), []string{"a", "c"}, p)
				pair, exists := item.LatencyComparisons["c"]
				if !exists || pair.ActiveDelayMS != 600 || pair.CandidateDelayMS != 300 {
					t.Fatalf("qualified phases lost the unchanged short-median display: %+v", item.LatencyComparisons)
				}
				rememberDisplayComparisons(item)
				if item.LastLatencyComparisons["c"] != pair {
					t.Fatal("new qualified pair did not replace old display numbers")
				}
			})
		}
	}
}

func TestWarmPlanningDisplayQualificationLeavesColdContractUnchanged(t *testing.T) {
	now := time.Unix(1000, 200*int64(time.Millisecond))
	item, p, _ := warmDisplayQualificationFixture(now, "active")
	item.WarmPlanningMarker, item.warmPlanningLatest = "", nil
	if pair, exists := currentLatencyComparisons(now, item, []string{"a", "c"}, p)["c"]; !exists || pair.ActiveDelayMS != 600 || pair.CandidateDelayMS != 300 {
		t.Fatal("cold timestamp-based display acquired a warm-metadata dependency")
	}
}

func TestWarmPlanningScanDistinguishesComparableAndIncompatibleDisplayPairs(t *testing.T) {
	for _, shape := range []string{"serial-active-last", "serial-candidate-last", "parallel", "different-wave", "nonoverlapping"} {
		t.Run(shape, func(t *testing.T) {
			now := time.Unix(1000, 200*int64(time.Millisecond))
			order := "active"
			if shape == "serial-candidate-last" {
				order = "candidate"
			}
			item, p, _ := warmDisplayQualificationFixture(now, order)
			item.OptimizationBaseline, item.OptimizationCandidate = "", ""
			p.batch = 1
			for node, warm := range item.warmPlanningLatest {
				if shape == "serial-active-last" || shape == "serial-candidate-last" {
					warm.Wave = 0
				}
				if node == "c" && shape == "different-wave" {
					warm.Wave = 12
				}
				if node == "c" && shape == "nonoverlapping" {
					warm.StartedAt, warm.ObservedAt = warm.StartedAt.Add(-time.Second), warm.ObservedAt.Add(-time.Second)
					item.Samples[node][0].At = float64(warm.ObservedAt.Unix())
					item.Samples[node][0].ObservedAt = qualityObservationAt(now, warmParallelEvidence(warm))
				}
				item.warmPlanningLatest[node] = warm
			}
			candidate := item.warmPlanningLatest["c"]
			continueWarmScanPair(now, "a", []string{"a", "c"}, map[string]probeEvidence{"c": {OK: true, Warm: &candidate}}, item, p)
			needsHalf := shape == "different-wave" || shape == "nonoverlapping"
			if (warmScanPairTarget(now, "a", []string{"a", "c"}, item) == "a") != needsHalf || item.OptimizationChecks != 0 {
				t.Fatal("scan qualification added an unnecessary half or accepted incompatible phases")
			}
		})
	}
}
