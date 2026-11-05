package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPlanningModeEnvironmentAndStartupValidation(t *testing.T) {
	for _, test := range []struct {
		mode   string
		legacy string
		want   qualityMeasurement
	}{
		{"", "", qualityMeasurementCold}, {"", "1", qualityMeasurementWarm},
		{"legacy", "1", qualityMeasurementCold}, {"warm-paired", "0", qualityMeasurementWarm},
		{"fresh-paired", "1", qualityMeasurementFreshPaired}, {"fresh-paired", "0", qualityMeasurementFreshPaired},
	} {
		t.Run(test.mode+"/"+test.legacy, func(t *testing.T) {
			t.Setenv("SB_URLTEST_PLANNING_MODE", test.mode)
			t.Setenv("SB_URLTEST_WARM_COMPARE", test.legacy)
			opts := OptionsFromEnvironment()
			if err := opts.validatePlanningMode(); err != nil || opts.planningMeasurement() != test.want {
				t.Fatalf("mode=%q legacy=%q measurement=%s err=%v", test.mode, test.legacy, opts.planningMeasurement(), err)
			}
		})
	}
	for _, bad := range []URLTestPlanningMode{"fresh", "FRESH-PAIRED", " fresh-paired", "unknown"} {
		// Validation must precede opening any API connection or starting workers.
		err := Run(context.Background(), Options{URLTestPlanningMode: bad, XrayAPIServer: "invalid"})
		if err == nil || !strings.Contains(err.Error(), "SB_URLTEST_PLANNING_MODE") {
			t.Fatalf("invalid mode did not fail before API initialization: %v", err)
		}
	}
}

func TestFreshPlanningMetricIsolationAndContextReset(t *testing.T) {
	controller, _, base := warmControllerFixture(t, 2, 2, 2)
	contract, item := controller.runtime.(*warmPlanningTestRuntime).pool.HealthPolicies["route"], controller.state["route"]
	controller.prepareWarmPlanning(contract, item)
	oldKey := controller.probeKey("route", "node-00", contract)
	oldSignature := item.WarmPlanningSignature
	item.OptimizationCandidate, item.OptimizationBaseline, item.OptimizationChecks = "node-01", item.Selected, 1
	item.OptimizationLastResult = &optimizationComparison{Result: optimizationWin, At: base.Format(time.RFC3339)}
	selected, cold := item.Selected, item.Samples["node-00"][0]
	controller.opts.URLTestPlanningMode = URLTestPlanningFreshPaired
	controller.prepareWarmPlanning(contract, item)
	if item.WarmPlanningMarker != string(qualityMeasurementFreshPaired) || oldSignature == item.WarmPlanningSignature ||
		oldKey == controller.probeKey("route", "node-00", contract) || item.OptimizationChecks != 0 || item.OptimizationLastResult != nil ||
		item.Selected != selected || item.Samples["node-00"][0].At != cold.At {
		t.Fatal("mode transition mixed proof/cache identity or lost working route/cold history")
	}
	delay := 100
	value := &planningQualityEvidence{Measurement: qualityMeasurementFreshPaired, StartedAt: base, ObservedAt: base.Add(time.Second), DelayMS: &delay}
	if validWarmQuality(value) || !validPlanningQuality(value, qualityMeasurementFreshPaired) || validPlanningQuality(value, qualityMeasurementWarm) {
		t.Fatal("fresh observation was relabelled as strict same-connection quality")
	}
	for _, wrong := range []qualityMeasurement{qualityMeasurementWarm, qualityMeasurementCold, "unknown"} {
		copy := *value
		copy.Measurement = wrong
		collectWarmPlanning(base.Add(time.Second), []string{"node-00"}, map[string]probeEvidence{"node-00": {OK: true, Planning: &copy}}, item, policySettings(contract.Policy, contract.Mode))
		if len(item.WarmPlanningSamples["node-00"]) != 0 {
			t.Fatal("foreign metric entered planning history")
		}
	}
	controller.opts.URLTestPlanningMode = URLTestPlanningLegacy
	controller.prepareWarmPlanning(contract, item)
	if item.WarmPlanningMarker != "" || item.Selected != selected || len(item.Samples["node-00"]) == 0 {
		t.Fatal("legacy transition retained planning evidence or discarded cold history")
	}
}

func TestFreshPlanningDisjointOneSlotFairness(t *testing.T) {
	for _, policies := range []int{3, 6} {
		t.Run(fmt.Sprint(policies), func(t *testing.T) {
			controller, runtime, base := disjointWarmScanFixture(t, policies)
			controller.opts.URLTestPlanningMode = URLTestPlanningFreshPaired
			now := base
			for cycles := 0; len(runtime.probeCalls) < 2*policies && cycles < 8*policies; cycles++ {
				runtime.at = now
				before := len(runtime.probeCalls)
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls)-before > 1 {
					t.Fatal("fresh pair escaped one-slot budget")
				}
				now = runtime.at.Add(controller.nextIntervalAt(runtime.at))
			}
			if len(runtime.probeCalls) != 2*policies || runtime.heads != 2*policies {
				t.Fatalf("fresh survey stalled or added HTTP: jobs=%d primary=%d", len(runtime.probeCalls), runtime.heads)
			}
			for id, item := range controller.state {
				contract := runtime.pool.HealthPolicies[id]
				pairs := currentLatencyComparisons(now, warmPlanningView(item), contract.Candidates, policySettings(contract.Policy, contract.Mode))
				if len(pairs) != 1 {
					t.Fatalf("policy %s did not finish its first qualified pair", id)
				}
			}
		})
	}
}

func TestFreshPlanningTwoIndependentProductionCadenceProofs(t *testing.T) {
	t.Setenv("SB_OUTBOUND_HEALTH_INTERVAL", "")
	for _, lanes := range []int{1, 2} {
		t.Run(fmt.Sprint(lanes), func(t *testing.T) {
			controller, runtime, base := warmControllerFixture(t, 2, lanes, lanes)
			controller.opts.URLTestPlanningMode = URLTestPlanningFreshPaired
			controller.opts.HealthInterval = OptionsFromEnvironment().HealthInterval
			if controller.opts.HealthInterval != time.Minute {
				t.Fatal("production health-loop default changed; update this cadence fixture explicitly")
			}
			runtime.advanceClock = true
			runtime.probes["node-00"], runtime.probes["node-01"] = successfulEvidence(900), successfulEvidence(100)
			var switches []healthEvent
			controller.eventSink = func(event healthEvent) {
				if event.Event == "switch" {
					switches = append(switches, event)
				}
			}
			now := base
			for cycles := 0; now.Before(base.Add(180*time.Second)) && cycles < 180; cycles++ {
				runtime.at = now
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				if now.Before(base.Add(time.Minute)) && controller.state["route"].Selected != "node-00" {
					t.Fatal("early proof switched route")
				}
				now = runtime.at.Add(controller.nextIntervalAt(runtime.at))
			}
			if len(switches) != 1 || controller.state["route"].Selected != "node-01" {
				t.Fatalf("fresh planning failed to converge: %+v", switches)
			}
			comparison := switches[0].Comparison
			if comparison == nil || comparison.Measurement != string(qualityMeasurementFreshPaired) || comparison.ConfirmationGapMS == nil || *comparison.ConfirmationGapMS < 60000 {
				t.Fatalf("fresh proof reused data or ignored full cadence: %+v", comparison)
			}
			if runtime.heads != len(runtime.probeCalls) {
				t.Fatal("fresh mode issued a hidden second planning request")
			}
		})
	}
}

// The same scheduler/clock contract covers both endpoint orders, three/six
// independent policies, and both confirmations rather than only the first pair.
func TestFreshPlanningSingleSlotAllPoliciesReachSecondProof(t *testing.T) {
	for _, mode := range []URLTestPlanningMode{URLTestPlanningWarmPaired, URLTestPlanningFreshPaired} {
		for _, candidateFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/candidateFirst%v", mode, candidateFirst), func(t *testing.T) {
				runPairedPlanningSingleSlotOrder(t, candidateFirst, mode)
			})
		}
	}
}

func TestFreshPlanningSharedEarlyPairAndCachedHalves(t *testing.T) {
	t.Run("full-pair-before60s", func(t *testing.T) { runPlanningSharedEarlyPair(t, URLTestPlanningFreshPaired) })
	t.Run("shared-fingerprint-coherent-pair", func(t *testing.T) { runPlanningEarlyCoherentCache(t, URLTestPlanningFreshPaired) })
	t.Run("single-slot-early-half", func(t *testing.T) { runPlanningSingleSlotEarlyCandidateCache(t, URLTestPlanningFreshPaired) })
}

func TestFreshPlanningEmergencyPreemptsHalfAndJoinsWorkers(t *testing.T) {
	t.Run("in-flight-worker-join", func(t *testing.T) { runParallelQualitySignalJoinsWorkers(t, qualityMeasurementFreshPaired) })
	t.Run("own-partial-token-reset", func(t *testing.T) {
		controller, runtime, base := disjointWarmScanFixture(t, 1)
		controller.opts.URLTestPlanningMode = URLTestPlanningFreshPaired
		if err := controller.Tick(base); err != nil {
			t.Fatal(err)
		}
		item, contract := controller.state["disjoint-0"], runtime.pool.HealthPolicies["disjoint-0"]
		if item.warmScanPair == nil || len(runtime.probeCalls) != 1 {
			t.Fatal("fresh pair did not start")
		}
		item.AvailabilityFailures[item.Selected] = 3
		runtime.probes[item.Selected] = probeEvidence{Failure: probeFailureTimeout}
		runtime.at = runtime.at.Add(controller.nextIntervalAt(runtime.at))
		if err := controller.Tick(runtime.at); err != nil {
			t.Fatal(err)
		}
		if item.Selected != contract.Candidates[1] || item.LastSwitchReason != "active-unavailable" || item.warmScanPair != nil || item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
			t.Fatalf("emergency retained the partial proof or waited for planning: selected=%s reason=%s token=%+v pending=%s checks=%d", item.Selected, item.LastSwitchReason, item.warmScanPair, item.OptimizationCandidate, item.OptimizationChecks)
		}
		if runtime.at.Sub(base) >= time.Minute || len(runtime.probeCalls) != 1 {
			t.Fatal("emergency waited for the 60s pair or issued another planning HEAD")
		}
	})
}

func TestFreshPlanningRejectsIncompatiblePhysicalPairAndRetainsDisplay(t *testing.T) {
	for _, shape := range []string{"valid", "wrong-marker", "different-wave", "future", "missing-start"} {
		t.Run(shape, func(t *testing.T) {
			now := time.Unix(1000, 200*int64(time.Millisecond))
			item, p, previous := warmDisplayQualificationFixture(now, "active")
			item.WarmPlanningMarker = string(qualityMeasurementFreshPaired)
			previous.Measurement = item.WarmPlanningMarker
			item.LastLatencyComparisons["c"] = previous
			for node, observation := range item.warmPlanningLatest {
				observation.Measurement = qualityMeasurementFreshPaired
				item.warmPlanningLatest[node] = observation
			}
			candidate := item.warmPlanningLatest["c"]
			switch shape {
			case "wrong-marker":
				candidate.Measurement = qualityMeasurementWarm
			case "different-wave":
				candidate.Wave++
			case "future":
				candidate.ObservedAt = now.Add(time.Second)
			case "missing-start":
				candidate.StartedAt = time.Time{}
			}
			item.warmPlanningLatest["c"] = candidate
			item.LatencyComparisons = currentLatencyComparisons(now, warmPlanningView(item), []string{"a", "c"}, p)
			pair, valid := item.LatencyComparisons["c"]
			if (shape == "valid") != valid {
				t.Fatalf("physical qualification mismatch: %+v", item.LatencyComparisons)
			}
			rememberDisplayComparisons(item)
			if valid {
				if pair.Measurement != item.WarmPlanningMarker || item.LastLatencyComparisons["c"] != pair {
					t.Fatal("valid fresh pair was not published")
				}
			} else if item.LastLatencyComparisons["c"] != previous {
				t.Fatal("incomplete pair erased last qualified display")
			}
		})
	}
}

func TestFreshAndPriorityUseDistinctSharedCacheEntries(t *testing.T) {
	controller, runtime, _ := warmControllerFixture(t, 2, 2, 4)
	controller.opts.URLTestPlanningMode = URLTestPlanningFreshPaired
	runtime.at = time.Now()
	controller.warmStarted = map[string]bool{"best": true, "priority": true}
	controller.beginProbeBudget(healthPool{ProbeBudget: 4}, []string{"best", "priority"})
	contract := runtime.pool.HealthPolicies["route"]
	for repeat := 0; repeat < 2; repeat++ {
		for _, mode := range []string{"best", "priority"} {
			contract.Mode = mode
			evidence := controller.sharedQualityProbe(mode, "node-00", contract)
			if !evidence.OK {
				t.Fatal("shared synthetic request failed")
			}
			if mode == "best" && !validPlanningQuality(evidence.Planning, qualityMeasurementFreshPaired) {
				t.Fatal("fresh cache returned priority evidence")
			}
			if mode == "priority" && evidence.Planning != nil {
				t.Fatal("priority cache returned fresh planning evidence")
			}
		}
	}
	if runtime.heads != 2 || len(runtime.probeCalls) != 2 || len(controller.probeBudget.Quality) != 2 {
		t.Fatalf("cache identity/cost mismatch: heads=%d jobs=%v", runtime.heads, runtime.probeCalls)
	}
}
