package agent

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func cadenceSample(at time.Time, delay int) healthSample {
	return healthSample{At: float64(at.Unix()), ObservedAt: float64(at.UnixNano()) / float64(time.Second), OK: true, DelayMS: &delay}
}

func TestQualityHistoryCadenceKeepsFirstEligibleNotBest(t *testing.T) {
	base := time.Unix(1000, 250000000)
	for _, interval := range []int{3, 30, 60} {
		p := effectivePolicySettings{mode: "best", active: interval, backup: 120}
		var samples []healthSample
		first := cadenceSample(base, 900)
		samples = appendQualityHistory(base, samples, first, p)
		for _, offset := range []time.Duration{time.Millisecond, time.Duration(interval)*time.Second - time.Millisecond} {
			at := base.Add(offset)
			samples = appendQualityHistory(at, samples, cadenceSample(at, 100), p)
			if len(samples) != 1 || *samples[0].DelayMS != 900 {
				t.Fatalf("interval=%d younger/better reference replaced accepted history: %+v", interval, samples)
			}
		}
		at := base.Add(time.Duration(interval) * time.Second)
		samples = appendQualityHistory(at, samples, cadenceSample(at, 700), p)
		if len(samples) != 2 || qualityHistoryAt(samples[1]) != qualityHistoryAt(cadenceSample(at, 700)) {
			t.Fatalf("interval=%d exact observation boundary was not admitted: %+v", interval, samples)
		}
	}
}

func TestQualityRawAdvancesWhenHistoryAdmissionDoesNot(t *testing.T) {
	base := time.Unix(1000, 0)
	p := effectivePolicySettings{mode: "best", active: 60, backup: 120}
	item := newPolicyHealthState()
	for _, offset := range []int{0, 3, 6, 59} {
		at := base.Add(time.Duration(offset) * time.Second)
		sample := cadenceSample(at, 450+offset)
		rememberQualityObservation(item, "node", sample)
		item.Samples["node"] = appendQualityHistory(at, item.Samples["node"], sample, p)
		latest, observed := latestQualityObservation(item, "node")
		if observed != qualityHistoryAt(sample) || *latest.DelayMS != 450+offset {
			t.Fatal("raw observation was replaced by admitted history")
		}
	}
	if len(item.Samples["node"]) != 1 || *item.Samples["node"][0].DelayMS != 450 {
		t.Fatal("dense references evicted the accepted first observation")
	}
	// Checkpoint/restart preserves the newer raw time without pretending it was
	// an additional median sample.
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var restored policyHealthState
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	_, at := latestQualityObservation(&restored, "node")
	if at != 1059 || len(restored.Samples["node"]) != 1 {
		t.Fatal("checkpoint merged raw and admitted evidence")
	}
}

func TestPairedPlanningCadencePreservesRawAndFailureWatermark(t *testing.T) {
	for _, metric := range []qualityMeasurement{qualityMeasurementWarm, qualityMeasurementFreshPaired} {
		t.Run(string(metric), func(t *testing.T) {
			item := newPolicyHealthState()
			item.WarmPlanningMarker = string(metric)
			item.WarmPlanningSamples = map[string][]healthSample{}
			item.WarmPlanningLastProbeAt = map[string]float64{}
			item.warmPlanningCountedAt = map[string]time.Time{}
			item.warmPlanningLatest = map[string]warmQualityEvidence{}
			p := effectivePolicySettings{mode: "best", active: 60, backup: 120}
			base := time.Unix(1000, 0)
			makeEvidence := func(at time.Time, delay int) probeEvidence {
				value := &warmQualityEvidence{Measurement: metric, StartedAt: at.Add(-time.Second), ObservedAt: at, DelayMS: &delay}
				e := successfulEvidence(delay)
				e.ObservedAt = at
				if metric == qualityMeasurementWarm {
					e.Warm = value
				} else {
					e.Planning = value
				}
				return e
			}
			for _, offset := range []int{0, 3, 6, 59} {
				at := base.Add(time.Duration(offset) * time.Second)
				collectWarmPlanning(at, []string{"node"}, map[string]probeEvidence{"node": makeEvidence(at, 400+offset)}, item, p)
			}
			if len(item.WarmPlanningSamples["node"]) != 1 {
				t.Fatal("paired history admitted dense references")
			}
			view := warmPlanningView(item)
			if _, at := latestQualityObservation(view, "node"); at != 1059 {
				t.Fatal("paired view returned admitted or cold time")
			}
			failedAt := base.Add(59500 * time.Millisecond)
			collectWarmPlanning(failedAt, []string{"node"}, map[string]probeEvidence{"node": {ObservedAt: failedAt}}, item, p)
			collectWarmPlanning(failedAt, []string{"node"}, map[string]probeEvidence{"node": makeEvidence(base.Add(59*time.Second), 50)}, item, p)
			if len(item.WarmPlanningSamples["node"]) != 0 {
				t.Fatal("late success resurrected a retired planning history")
			}
			recoveredAt := base.Add(59750 * time.Millisecond)
			collectWarmPlanning(recoveredAt, []string{"node"}, map[string]probeEvidence{"node": makeEvidence(recoveredAt, 350)}, item, p)
			if len(item.WarmPlanningSamples["node"]) != 1 || *item.WarmPlanningSamples["node"][0].DelayMS != 350 {
				t.Fatal("first recovery remained blocked by old admitted time")
			}
			before := item.WarmPlanningSamples["node"][0]
			collectWarmPlanning(recoveredAt, []string{"node"}, map[string]probeEvidence{"node": makeEvidence(recoveredAt, 10)}, item, p)
			if !reflect.DeepEqual(before, item.WarmPlanningSamples["node"][0]) {
				t.Fatal("duplicate changed accepted evidence")
			}
		})
	}
}

func TestQualityCadenceMigrationRetainsRawAndWorkingRoute(t *testing.T) {
	item := newPolicyHealthState()
	item.SampleCadenceSeconds = 0 // A checkpoint written before cadence admission.
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "node", "node", true
	item.Samples["node"] = []healthSample{cadenceSample(time.Unix(1000, 0), 500)}
	item.OptimizationCandidate, item.OptimizationChecks = "other", 1
	p := effectivePolicySettings{mode: "best", active: 60, backup: 120}
	ensureQualityHistoryCadence(item, p)
	if len(item.Samples) != 0 || item.SampleCadenceSeconds != 60 || item.OptimizationChecks != 0 {
		t.Fatal("old unqualified history or confirmation survived migration")
	}
	if _, at := latestQualityObservation(item, "node"); at != 1000 || item.Selected != "node" || !item.RuntimeConfirmed {
		t.Fatal("migration discarded raw health or working route")
	}
	item.Samples["node"] = []healthSample{cadenceSample(time.Unix(1060, 0), 400)}
	ensureQualityHistoryCadence(item, p)
	if len(item.Samples["node"]) != 1 {
		t.Fatal("unchanged cadence reset valid history")
	}
	p.active = 30
	ensureQualityHistoryCadence(item, p)
	if len(item.Samples) != 0 || item.SampleCadenceSeconds != 30 {
		t.Fatal("changed cadence reused incompatible median")
	}
}

func TestPlanningDisplayUsesFreshPhysicalClockWithOlderAdmittedHistory(t *testing.T) {
	now := time.Unix(1000, 200*int64(time.Millisecond))
	item, p, _ := warmDisplayQualificationFixture(now, "active")
	for node, samples := range item.WarmPlanningSamples {
		oldDelay := 300
		if node == "a" {
			oldDelay = 650
		}
		samples[0] = cadenceSample(now.Add(-30*time.Second), oldDelay)
	}
	pairs := currentLatencyComparisons(now, warmPlanningView(item), []string{"a", "c"}, p)
	pair, exists := pairs["c"]
	if !exists || pair.ActiveDelayMS != 650 || pair.CandidateDelayMS != 300 {
		t.Fatal("admitted median was lost when raw advanced")
	}
	if pair.ActiveAt != float64(item.warmPlanningLatest["a"].ObservedAt.UnixNano())/float64(time.Second) ||
		pair.CandidateAt != float64(item.warmPlanningLatest["c"].ObservedAt.UnixNano())/float64(time.Second) {
		t.Fatal("median time was substituted for physical pair time")
	}
}

func TestQualityCadenceSamplesAreImmutableAndPrunedWithNode(t *testing.T) {
	item := newPolicyHealthState()
	now := time.Unix(1000, 0)
	sample := cadenceSample(now, 500)
	p := effectivePolicySettings{mode: "best", active: 60, backup: 120}
	rememberQualityObservation(item, "node", sample)
	item.Samples["node"] = appendQualityHistory(now, nil, sample, p)
	*sample.DelayMS = 10
	if *item.LatestQuality["node"].DelayMS != 500 || *item.Samples["node"][0].DelayMS != 500 {
		t.Fatal("input mutation rewrote historical evidence")
	}
	pruneRemovedCandidateHealth(item, nil)
	if len(item.LatestQuality) != 0 || len(item.Samples) != 0 {
		t.Fatal("removed node retained cadence/raw state")
	}
}

func TestCadenceFreshPairBurstsAndPersistentDegradation(t *testing.T) {
	for _, steady := range []bool{false, true} {
		t.Run(fmt.Sprintf("steady%v", steady), func(t *testing.T) {
			base := time.Unix(2000, 0)
			p := policySettings(healthPolicy{ActiveCheckSeconds: 60, SwitchImprovementMS: 200}, "best")
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "a", "a", true
			item.WarmPlanningMarker = string(qualityMeasurementFreshPaired)
			item.WarmPlanningSamples = map[string][]healthSample{}
			item.WarmPlanningLastProbeAt = map[string]float64{}
			item.warmPlanningLatest = map[string]warmQualityEvidence{}
			item.warmPlanningCountedAt = map[string]time.Time{}
			selected, switchAt, maxChecks := "a", -1, 0
			for second := -180; second <= 180; second += 6 {
				activeDelay := 450
				if steady && second >= 0 || !steady && (second >= -6 && second <= 0 || second >= 54 && second <= 60) {
					activeDelay = 1000
				}
				start := base.Add(time.Duration(second) * time.Second)
				makeEvidence := func(delay int) probeEvidence {
					e := successfulEvidence(delay)
					e.ObservedAt = start.Add(time.Duration(delay) * time.Millisecond)
					e.Planning = &planningQualityEvidence{Measurement: qualityMeasurementFreshPaired, StartedAt: start, ObservedAt: e.ObservedAt, DelayMS: e.DelayMS, Wave: uint64(second + 181)}
					return e
				}
				measured := map[string]probeEvidence{"a": makeEvidence(activeDelay)}
				if second%60 == 0 {
					measured["b"] = makeEvidence(400)
				}
				now := start.Add(time.Second)
				collectWarmPlanning(now, []string{"a", "b"}, measured, item, p)
				if second < 0 || second%60 != 0 {
					continue
				}
				comparison := planningComparison(now, "a", "b", measured, item, true, true, p)
				desired, reason := "a", ""
				if comparison != nil && comparison.Result == optimizationWin {
					desired, reason = "b", "meaningfully-faster"
				}
				selected, _ = gatePlannedOptimization(now, "a", desired, reason, comparison, item, p)
				maxChecks = max(maxChecks, item.OptimizationChecks)
				if selected == "b" {
					switchAt = second
					break
				}
			}
			if steady && switchAt != 120 {
				t.Fatalf("persistent degradation delayed or reused a proof: switched at %d", switchAt)
			}
			if !steady && (switchAt >= 0 || maxChecks > 1) {
				t.Fatalf("dense short bursts confirmed a switch: at=%d checks=%d", switchAt, maxChecks)
			}
		})
	}
}

func TestCadenceColdFailureRecoveryAndUncertaintyRemainImmediate(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, item := livenessFixture(t, mode)
			contract := runtime.pool.HealthPolicies["europe"]
			for i, e := range []probeEvidence{{Failure: probeFailureTransient}, successfulEvidence(110), successfulEvidence(120)} {
				now := time.Unix(1003+int64(i)*3, 0)
				item.LastProbeAt["de"], item.LastProbeAt["nl"] = 0, float64(now.Unix())
				controller.probeBudget = nil // A new outer Tick owns a new batch budget.
				runtime.probes["de"] = e
				if err := controller.tickPolicy(now, "europe", contract, item); err != nil {
					t.Fatal(err)
				}
				latest, at := latestQualityObservation(item, "de")
				if at != float64(now.Unix()) || latest.OK != e.OK {
					t.Fatalf("cold raw outcome was rate limited: step=%d at=%v want=%v latest=%+v calls=%v", i, at, now.Unix(), latest, runtime.probeCalls)
				}
				if i == 0 && (item.AvailabilityFailures["de"] != 1 || item.QualityOK["de"]) {
					t.Fatal("failure waited for median history")
				}
				if i > 0 && (item.AvailabilityFailures["de"] != 0 || item.Failures["de"] != 0 || !item.QualityOK["de"] || item.Recoveries["de"] != i) {
					t.Fatalf("recovery counters depended on history admission: recovery=%d", item.Recoveries["de"])
				}
			}
			before, at := latestQualityObservation(item, "de")
			item.LastProbeAt["de"], item.LastProbeAt["nl"] = 0, 1012
			controller.probeBudget = nil
			runtime.probes["de"] = probeEvidence{LocalFailure: true, Failure: probeFailureTransient}
			if err := controller.tickPolicy(time.Unix(1012, 0), "europe", contract, item); err != errProbeSelectorUnavailable {
				t.Fatalf("unexpected local uncertainty result: %v", err)
			}
			after, nextAt := latestQualityObservation(item, "de")
			if nextAt != at || !reflect.DeepEqual(before, after) || item.AvailabilityFailures["de"] != 0 {
				t.Fatal("local uncertainty became remote failure/raw evidence")
			}
		})
	}
}

func TestCadenceMigratedRawRejectsReplayWithoutAdmittedHistory(t *testing.T) {
	for _, good := range []bool{false, true} {
		item := newPolicyHealthState()
		sample := cadenceSample(time.Unix(1000, 0), 400)
		sample.OK = good
		rememberQualityObservation(item, "node", sample)
		body, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		var loaded policyHealthState
		if err = json.Unmarshal(body, &loaded); err != nil {
			t.Fatal(err)
		}
		if len(loaded.Samples) != 0 || loaded.qualityCountedAt != nil {
			t.Fatal("fixture did not cover missing persisted admission/watermark")
		}
		for _, at := range []float64{999, 1000} {
			if freshQualityEvidence(&loaded, "node", at) {
				t.Fatalf("raw good=%v accepted older/equal replay %v", good, at)
			}
		}
		if !freshQualityEvidence(&loaded, "node", 1001) || freshQualityEvidence(&loaded, "node", 1001) {
			t.Fatal("new physical observation did not advance exactly once")
		}
	}
}
