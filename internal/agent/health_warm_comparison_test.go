package agent

import (
	"fmt"
	"testing"
	"time"
)

func TestWarmPlanningCandidateFirstCompletesOneSlot(t *testing.T) {
	runWarmPlanningSingleSlotOrder(t, true)
}

func TestWarmPlanningInitialActiveFirstCompletesOneSlot(t *testing.T) {
	runWarmPlanningSingleSlotOrder(t, false)
}

func runWarmPlanningSingleSlotOrder(t *testing.T, candidateFirst bool) {
	runPairedPlanningSingleSlotOrder(t, candidateFirst, URLTestPlanningWarmPaired)
}

func runPairedPlanningSingleSlotOrder(t *testing.T, candidateFirst bool, mode URLTestPlanningMode) {
	t.Helper()
	requestsPerJob := 2
	if mode == URLTestPlanningFreshPaired {
		requestsPerJob = 1
	}
	for _, policies := range []int{1, 3, 6} {
		t.Run(fmt.Sprintf("policies%d", policies), func(t *testing.T) {
			controller, runtime, base := disjointWarmScanFixture(t, policies)
			controller.opts.URLTestPlanningMode = mode
			measurement := controller.opts.planningMeasurement()
			var switches []healthEvent
			controller.eventSink = func(event healthEvent) {
				if event.Event == "switch" {
					switches = append(switches, event)
				}
			}
			for id, item := range controller.state {
				contract := runtime.pool.HealthPolicies[id]
				controller.prepareWarmPlanning(contract, item)
				for index, name := range contract.Candidates {
					delay, ago := 600, 11*time.Second
					if index == 1 {
						delay, ago = 100, 61*time.Second
					}
					at := base.Add(-ago)
					runtime.warm[name] = delay
					if mode == URLTestPlanningFreshPaired {
						runtime.probes[name] = successfulEvidence(delay)
					}
					if !candidateFirst {
						continue // Start without any warm nomination or observation.
					}
					item.WarmPlanningSamples[name] = []healthSample{{At: float64(at.Unix()), ObservedAt: qualityObservationAt(at, probeEvidence{}), OK: true, DelayMS: &delay}}
					item.WarmPlanningLastProbeAt[name] = float64(at.Unix())
					item.warmPlanningLatest[name] = warmQualityEvidence{Measurement: measurement,
						StartedAt: at.Add(-time.Duration(delay) * time.Millisecond), ObservedAt: at, DelayMS: &delay}
					item.warmPlanningCountedAt[name] = at
				}
			}
			now := base
			for cycles := 0; len(runtime.probeCalls) < 2*policies && cycles < 16*policies; cycles++ {
				runtime.at = now
				before := len(runtime.probeCalls)
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls)-before > 1 {
					t.Fatal("one-slot physical budget exceeded")
				}
				now = runtime.at.Add(max(time.Millisecond, controller.nextIntervalAt(runtime.at)))
			}
			if len(runtime.probeCalls) != 2*policies {
				t.Fatalf("first comparison starved: %v", runtime.probeCalls)
			}
			if runtime.heads != 2*policies*requestsPerJob || len(switches) != 0 {
				t.Fatalf("first pair used extra primary requests or switched: jobs=%d requests=%d events=%v", len(runtime.probeCalls), runtime.heads, switches)
			}
			firstCandidateAt := make(map[string]float64, policies)
			for id, item := range controller.state {
				contract := runtime.pool.HealthPolicies[id]
				if item.OptimizationCandidate != contract.Candidates[1] || item.OptimizationChecks != 1 {
					t.Errorf("candidate-first complete fresh pair omitted first proof: policy=%s checks=%d pending=%s last=%+v calls=%v", id, item.OptimizationChecks, item.OptimizationCandidate, item.OptimizationLastResult, runtime.probeCalls)
				}
				if item.Selected != contract.Candidates[0] {
					t.Error("one pair switched without two confirmations")
				}
				if item.OptimizationLastResult != nil {
					firstCandidateAt[id] = item.OptimizationLastResult.CandidateSampleAt
					if (item.OptimizationLastResult.ActiveSampleAt > firstCandidateAt[id]) != candidateFirst ||
						item.OptimizationLastResult.ActiveSampleAt == firstCandidateAt[id] {
						t.Error("fixture did not preserve the requested endpoint order")
					}
				}
			}
			for cycles := 0; len(switches) < policies && cycles < 600 && now.Before(base.Add(3*time.Minute)); cycles++ {
				runtime.at = now
				before := len(runtime.probeCalls)
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls)-before > 1 {
					t.Fatal("confirmation exceeded the global one-slot budget")
				}
				now = runtime.at.Add(max(time.Millisecond, controller.nextIntervalAt(runtime.at)))
			}
			if len(switches) != policies || len(runtime.probeCalls) != 4*policies || runtime.heads != 4*policies*requestsPerJob {
				t.Fatalf("two pairs were not sufficient: switches=%v jobs=%d requests=%d", switches, len(runtime.probeCalls), runtime.heads)
			}
			for _, event := range switches {
				comparison := event.Comparison
				if event.Reason != "meaningfully-faster" || comparison == nil || comparison.ConfirmationGapMS == nil ||
					*comparison.ConfirmationGapMS < 60000 || *comparison.ConfirmationGapMS > 120000 || comparison.CandidateSampleAt < firstCandidateAt[event.Policy]+60 {
					t.Errorf("switch did not use two independent timely confirmations: %+v", event)
					continue
				}
				t.Logf("policies=%d policy=%s switch_elapsed=%.3fs gap_ms=%d quality_jobs=%d primary_requests=%d availability_calls=%d", policies, event.Policy,
					max(comparison.ActiveSampleAt, comparison.CandidateSampleAt)-qualityObservationAt(base, probeEvidence{}), *comparison.ConfirmationGapMS,
					len(runtime.probeCalls), runtime.heads, len(runtime.availabilityCalls))
			}
		})
	}
}

func TestWarmPlanningActiveCompletionIsStrictlyBounded(t *testing.T) {
	for _, shape := range []string{"valid", "not-nominated", "cold", "wrong-wave", "stale", "unknown", "failed", "future", "older-processed", "sample-failed", "newer-processed", "sample-missing", "sample-clock-missing", "startless", "start-after-observation"} {
		t.Run(shape, func(t *testing.T) {
			now := time.Unix(1000, 0)
			item := newPolicyHealthState()
			item.WarmPlanningMarker = string(qualityMeasurementWarm)
			item.OptimizationBaseline, item.OptimizationCandidate = "a", "b"
			a, b := 600, 100
			item.Samples["a"] = []healthSample{{At: 1000, ObservedAt: 1000, OK: true, DelayMS: &a}}
			item.Samples["b"] = []healthSample{{At: 999, ObservedAt: 999, OK: true, DelayMS: &b}}
			candidate := warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: now.Add(-2 * time.Second), ObservedAt: now.Add(-time.Second), DelayMS: &b}
			item.warmPlanningCountedAt = map[string]time.Time{"b": candidate.ObservedAt}
			active := probeEvidence{OK: true, DelayMS: &a, QualityStartedAt: now.Add(-time.Second), ObservedAt: now}
			switch shape {
			case "not-nominated":
				item.OptimizationCandidate = ""
			case "cold":
				item.WarmPlanningMarker = ""
			case "wrong-wave":
				candidate.Wave, active.QualityWave = 10, 12
			case "stale":
				candidate.StartedAt, candidate.ObservedAt = now.Add(-12*time.Second), now.Add(-11*time.Second)
			case "unknown":
				candidate.DelayMS = nil
			case "failed":
				candidate.Failed = true
			case "future":
				candidate.ObservedAt = now.Add(time.Second)
				item.Samples["b"][0].ObservedAt = 1001
			case "older-processed":
				item.warmPlanningCountedAt["b"] = now.Add(-2 * time.Second)
			case "sample-failed":
				item.Samples["b"][0].OK = false
			case "newer-processed":
				item.warmPlanningCountedAt["b"] = now
			case "sample-missing":
				delete(item.Samples, "b")
			case "sample-clock-missing":
				item.Samples["b"][0].ObservedAt = 0
			case "startless":
				candidate.StartedAt = time.Time{}
			case "start-after-observation":
				candidate.StartedAt = now
			}
			item.warmPlanningLatest = map[string]warmQualityEvidence{"b": candidate}
			comparison := regularOptimizationComparison(now, "a", "b", map[string]probeEvidence{"a": active}, item, true, true, policySettings(healthPolicy{SwitchImprovementMS: 200}, "best"))
			if shape == "valid" {
				if comparison == nil || comparison.Result != optimizationWin || comparison.CandidateSampleAt != 999 || comparison.ActiveSampleAt != 1000 {
					t.Fatalf("actual nominated candidate was not completed: %+v", comparison)
				}
			} else if comparison != nil && comparison.Result == optimizationWin {
				t.Fatalf("ineligible completion became fresh proof: %+v", comparison)
			}
		})
	}
}

func TestWarmPlanningCachedActivePreservesActualWaveAndStart(t *testing.T) {
	for _, shape := range []string{"serial-valid", "cached-parallel-active", "unmatched-observation", "missing-processed"} {
		t.Run(shape, func(t *testing.T) {
			now := time.Unix(1000, 0)
			item := newPolicyHealthState()
			item.WarmPlanningMarker = string(qualityMeasurementWarm)
			item.OptimizationBaseline, item.OptimizationCandidate = "a", "b"
			a, b := 600, 100
			item.Samples["a"] = []healthSample{{At: 999, ObservedAt: 999, OK: true, DelayMS: &a}}
			item.Samples["b"] = []healthSample{{At: 1000, ObservedAt: 1000, OK: true, DelayMS: &b}}
			cached := warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: now.Add(-2 * time.Second), ObservedAt: now.Add(-time.Second), DelayMS: &a}
			item.warmPlanningCountedAt = map[string]time.Time{"a": cached.ObservedAt}
			candidate := probeEvidence{OK: true, DelayMS: &b, QualityStartedAt: now.Add(-100 * time.Millisecond), ObservedAt: now}
			if shape == "cached-parallel-active" {
				cached.Wave = 10
			}
			if shape == "unmatched-observation" {
				cached.ObservedAt = now.Add(-2 * time.Second)
				cached.StartedAt = now.Add(-3 * time.Second)
			}
			item.warmPlanningLatest = map[string]warmQualityEvidence{"a": cached}
			if shape == "missing-processed" {
				delete(item.warmPlanningCountedAt, "a")
			}
			comparison := regularOptimizationComparison(now, "a", "b", map[string]probeEvidence{"b": candidate}, item, true, true, policySettings(healthPolicy{SwitchImprovementMS: 200}, "best"))
			if shape == "serial-valid" {
				if comparison == nil || comparison.Result != optimizationWin || comparison.ActiveStartedAt != 998 || comparison.ActiveSampleAt != 999 {
					t.Fatalf("cached active lost real phase metadata: %+v", comparison)
				}
			} else if comparison != nil && comparison.Result == optimizationWin {
				t.Fatalf("cached active invented compatible serial evidence: %+v", comparison)
			}
		})
	}
}

func TestWarmPlanningFailureDoesNotWaitForPair(t *testing.T) {
	for _, policies := range []int{1, 3, 6} {
		t.Run(fmt.Sprintf("policies%d", policies), func(t *testing.T) {
			controller, runtime, base := disjointWarmScanFixture(t, policies)
			for id, item := range controller.state {
				contract := runtime.pool.HealthPolicies[id]
				controller.prepareWarmPlanning(contract, item)
				active, candidate := contract.Candidates[0], contract.Candidates[1]
				item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = active, candidate, 1
				item.OptimizationLastResult = &optimizationComparison{At: base.UTC().Format(time.RFC3339), Candidate: candidate, Result: optimizationWin, ActiveSampleAt: 999, CandidateSampleAt: 999}
				runtime.probes[active] = probeEvidence{Failure: probeFailureTimeout}
			}
			var events []healthEvent
			controller.eventSink = func(event healthEvent) {
				if event.Event == "switch" {
					events = append(events, event)
				}
			}
			now := base
			for ticks := 0; ticks < 120 && now.Before(base.Add(time.Minute)); ticks++ {
				runtime.at = now
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				allRecovered := true
				for id, item := range controller.state {
					allRecovered = allRecovered && item.Selected == runtime.pool.HealthPolicies[id].Candidates[1]
				}
				if allRecovered {
					break
				}
				now = runtime.at.Add(max(time.Millisecond, controller.nextIntervalAt(runtime.at)))
			}
			for id, item := range controller.state {
				if item.Selected != runtime.pool.HealthPolicies[id].Candidates[1] {
					t.Errorf("failure waited for ordinary confirmation: %s %+v", id, item)
				}
			}
			if len(events) != policies {
				t.Fatalf("expected one emergency event per policy, got %+v", events)
			}
			for _, event := range events {
				if event.Reason != "active-unavailable" {
					t.Errorf("failure used planned branch: %+v", event)
				}
			}
			t.Logf("policies=%d emergency_elapsed=%.3fs availability_calls=%d quality_jobs=%d", policies, now.Sub(base).Seconds(), len(runtime.availabilityCalls), len(runtime.probeCalls))
		})
	}
}
