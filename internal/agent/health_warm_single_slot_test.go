package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Three physically distinct policies must complete their initial pairs using
// the scheduler's returned wake interval, including both HTTP durations. Shared
// endpoint fingerprints or fixed clock steps would hide an expired first side.
func disjointWarmScanFixture(t *testing.T, policies int) (*healthController, *warmPlanningTestRuntime, time.Time) {
	t.Helper()
	controller, runtime, base := warmControllerFixture(t, 2, 1, 1)
	controller.opts.HealthInterval = time.Minute
	runtime.advanceClock = true
	template := runtime.pool.HealthPolicies["route"]
	seed, _ := json.Marshal(controller.state["route"])
	controller.state, controller.warmStarted = healthState{}, map[string]bool{}
	runtime.pool.HealthPolicies, runtime.current = map[string]healthPolicyContract{}, map[string]string{}
	runtime.probes, runtime.warm = map[string]probeEvidence{}, map[string]int{}
	for policy := 0; policy < policies; policy++ {
		id := fmt.Sprintf("disjoint-%d", policy)
		contract := template
		contract.Candidates = make([]string, 2)
		contract.Nodes = map[string]healthNode{}
		for node, original := range template.Candidates {
			name := id + "-" + original
			contract.Candidates[node] = name
			contract.Nodes[name] = healthNode{Fingerprint: "synthetic-" + name, Protocol: "vless", Transport: "ws"}
			runtime.probes[name], runtime.warm[name] = successfulEvidence(200+node*200), 75+node*50
		}
		item := newPolicyHealthState()
		if err := json.Unmarshal(seed, item); err != nil {
			t.Fatal(err)
		}
		item.Selected, item.RuntimeSelected = contract.Candidates[0], contract.Candidates[0]
		item.CandidateSignature, item.CandidateNodes = strings.Join(contract.Candidates, "\n"), contract.Nodes
		item.Samples = prefixWarmModelMap(item.Samples, id+"-")
		item.LastProbeAt = prefixWarmModelMap(item.LastProbeAt, id+"-")
		item.Recoveries = prefixWarmModelMap(item.Recoveries, id+"-")
		item.QualityOK = prefixWarmModelMap(item.QualityOK, id+"-")
		item.AvailabilityOK = prefixWarmModelMap(item.AvailabilityOK, id+"-")
		controller.state[id], controller.warmStarted[id] = item, true
		runtime.pool.HealthPolicies[id], runtime.current[id] = contract, item.Selected
	}
	return controller, runtime, base
}

func TestWarmPlanningDisjointOneSlotCompletesFirstSurveyWithoutExtraRequests(t *testing.T) {
	for _, policies := range []int{3, 6} {
		t.Run(fmt.Sprintf("policies%d", policies), func(t *testing.T) {
			controller, runtime, base := disjointWarmScanFixture(t, policies)
			now := base
			for cycles := 0; len(runtime.probeCalls) < 2*policies && cycles < 8*policies; cycles++ {
				runtime.at = now
				before := len(runtime.probeCalls)
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls)-before > 1 {
					t.Fatal("initial pair escaped the one-slot global budget")
				}
				now = runtime.at.Add(controller.nextIntervalAt(runtime.at))
			}
			if len(runtime.probeCalls) != 2*policies || runtime.heads != 4*policies {
				t.Fatalf("first survey used extra requests: jobs=%d primary=%d", len(runtime.probeCalls), runtime.heads)
			}
			for id, item := range controller.state {
				contract := runtime.pool.HealthPolicies[id]
				view := warmPlanningView(item)
				pairs := currentLatencyComparisons(now, view, contract.Candidates, policySettings(contract.Policy, contract.Mode))
				if len(pairs) != 1 {
					_, activeAt := latestQualityObservation(view, contract.Candidates[0])
					_, candidateAt := latestQualityObservation(view, contract.Candidates[1])
					t.Errorf("first survey did not complete %s: active=%f candidate=%f gap=%f requests=%v", id, activeAt, candidateAt, candidateAt-activeAt, runtime.probeCalls)
				}
			}
			for pair := 0; pair < policies; pair++ {
				if strings.Split(runtime.probeCalls[pair*2], "-node-")[0] != strings.Split(runtime.probeCalls[pair*2+1], "-node-")[0] {
					t.Fatalf("one finished pair did not precede the next policy: %v", runtime.probeCalls)
				}
			}
		})
	}
}

func TestWarmPlanningSingleSlotScanContinuationExpiresOrResets(t *testing.T) {
	for _, change := range []string{"expired-observation", "selection", "fingerprint", "metric", "warm-error"} {
		t.Run(change, func(t *testing.T) {
			controller, runtime, base := disjointWarmScanFixture(t, 1)
			if err := controller.Tick(base); err != nil {
				t.Fatal(err)
			}
			item, contract := controller.state["disjoint-0"], runtime.pool.HealthPolicies["disjoint-0"]
			pair := item.warmScanPair
			if pair == nil || item.OptimizationChecks != 0 || item.OptimizationCandidate != "" {
				t.Fatal("initial scan did not create a separate non-proof continuation")
			}
			now := pair.ObservedAt.Add(time.Second)
			switch change {
			case "expired-observation":
				now = pair.ObservedAt.Add(11 * time.Second) // A delayed callback cannot renew its timestamp.
			case "selection":
				item.Selected = contract.Candidates[1]
			case "fingerprint":
				metadata := contract.Nodes[contract.Candidates[0]]
				metadata.Fingerprint = "synthetic-new-endpoint"
				contract.Nodes[contract.Candidates[0]] = metadata
				controller.prepareWarmPlanning(contract, item)
			case "metric":
				item.WarmPlanningMarker = ""
			case "warm-error":
				invalidateWarmNode(item, contract.Candidates[1])
			}
			if target := warmScanPairTarget(now, item.Selected, contract.Candidates, item); target != "" || item.warmScanPair != nil {
				t.Fatal("invalid scan retained priority or renewed itself")
			}
			if len(runtime.probeCalls) != 1 || controller.nextIntervalAt(now) <= 0 {
				t.Fatal("expired scan caused extra HTTP or an immediate retry loop")
			}
		})
	}
}

func TestWarmPlanningSingleSlotBadPeerReleasesOtherPolicies(t *testing.T) {
	controller, runtime, base := disjointWarmScanFixture(t, 3)
	bad := runtime.pool.HealthPolicies["disjoint-0"].Candidates[1]
	runtime.blocked[bad] = true
	now := base
	for cycles := 0; len(runtime.probeCalls) < 6 && cycles < 30; cycles++ {
		runtime.at = now
		if err := controller.Tick(now); err != nil {
			t.Fatal(err)
		}
		now = runtime.at.Add(controller.nextIntervalAt(runtime.at))
	}
	if len(runtime.attempts[bad]) != 1 || controller.state["disjoint-0"].warmScanPair != nil {
		t.Fatal("bad peer retained the slot or retried before its normal interval")
	}
	for _, id := range []string{"disjoint-1", "disjoint-2"} {
		contract := runtime.pool.HealthPolicies[id]
		if pairs := currentLatencyComparisons(now, warmPlanningView(controller.state[id]), contract.Candidates, policySettings(contract.Policy, contract.Mode)); len(pairs) != 1 {
			t.Fatalf("bad peer starved the next route: %s jobs=%v", id, runtime.probeCalls)
		}
	}
}

func TestWarmPlanningSingleSlotOutagePrecedesScanContinuation(t *testing.T) {
	controller, runtime, base := disjointWarmScanFixture(t, 3)
	if err := controller.Tick(base); err != nil {
		t.Fatal(err)
	}
	if controller.state["disjoint-0"].warmScanPair == nil {
		t.Fatal("fixture did not start a scan continuation")
	}
	failed := controller.state["disjoint-2"]
	failed.AvailabilityFailures[failed.Selected] = 3
	runtime.probes[failed.Selected] = probeEvidence{Failure: probeFailureTimeout}
	warmJobsAtOutage := -1
	controller.eventSink = func(event healthEvent) {
		if event.Event == "switch" && event.Policy == "disjoint-2" && event.Reason == "active-unavailable" {
			warmJobsAtOutage = len(runtime.probeCalls)
		}
	}
	runtime.at = runtime.at.Add(controller.nextIntervalAt(runtime.at))
	if err := controller.Tick(runtime.at); err != nil {
		t.Fatal(err)
	}
	if failed.Selected != runtime.pool.HealthPolicies["disjoint-2"].Candidates[1] || warmJobsAtOutage != 1 {
		t.Fatal("an unrelated scan continuation ran before the confirmed outage")
	}
}

func TestWarmPlanningSingleSlotOnlyAdmittedQualityCompletesScan(t *testing.T) {
	for _, kind := range []string{"not-admitted", "availability-only", "cold-failed", "warm-deferred", "warm-failed", "warm-success"} {
		t.Run(kind, func(t *testing.T) {
			controller, runtime, base := disjointWarmScanFixture(t, 1)
			if err := controller.Tick(base); err != nil {
				t.Fatal(err)
			}
			item, contract := controller.state["disjoint-0"], runtime.pool.HealthPolicies["disjoint-0"]
			pair := item.warmScanPair
			if pair == nil {
				t.Fatal("missing first scan half")
			}
			now := pair.ObservedAt.Add(time.Second)
			evidence := probeEvidence{OK: true}
			switch kind {
			case "not-admitted":
				evidence = probeEvidence{Deferred: true}
			case "availability-only":
				evidence.QualityUnmeasured = true
			case "cold-failed":
				evidence.OK, evidence.QualityStartedAt, evidence.Failure = false, now, probeFailureTimeout
			case "warm-deferred":
				evidence.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, Deferred: true, ObservedAt: now}
			case "warm-failed":
				evidence.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, Failed: true, ObservedAt: now}
			case "warm-success":
				delay := 125
				evidence.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: now.Add(-125 * time.Millisecond), ObservedAt: now, DelayMS: &delay}
			}
			continueWarmScanPair(now, item.Selected, contract.Candidates, map[string]probeEvidence{pair.Next: evidence}, item, policySettings(contract.Policy, contract.Mode))
			retained := kind == "not-admitted" || kind == "availability-only"
			pending := warmScanPairTarget(now, item.Selected, contract.Candidates, item) != ""
			if pending != retained || item.OptimizationChecks != 0 || len(runtime.probeCalls) != 1 {
				t.Fatal("scan confused admission, a switch proof, or availability with a completed quality half")
			}
			if kind == "warm-success" && (item.warmScanPair == nil || !item.warmScanPair.CompletedAt.Equal(evidence.Warm.ObservedAt)) {
				t.Fatal("successful scan lost the exact completion token before selection")
			}
		})
	}
}

func TestWarmPlanningSingleSlotScanWakeDoesNotWaitForLongLivenessInterval(t *testing.T) {
	controller, runtime, base := disjointWarmScanFixture(t, 1)
	contract := runtime.pool.HealthPolicies["disjoint-0"]
	contract.Policy.ActiveLivenessSeconds = 30
	runtime.pool.HealthPolicies["disjoint-0"] = contract
	if err := controller.Tick(base); err != nil {
		t.Fatal(err)
	}
	wait := controller.nextIntervalAt(runtime.at)
	if wait > optimizationPairSkew-qualityProbeTimeout {
		t.Fatal("an admitted half waited beyond the comparison window for liveness")
	}
	runtime.at = runtime.at.Add(wait)
	if err := controller.Tick(runtime.at); err != nil {
		t.Fatal(err)
	}
	item := controller.state["disjoint-0"]
	if pairs := currentLatencyComparisons(runtime.at, warmPlanningView(item), contract.Candidates, policySettings(contract.Policy, contract.Mode)); len(pairs) != 1 || len(runtime.probeCalls) != 2 {
		t.Fatal("long liveness setting prevented a two-job initial comparison")
	}
}

func TestWarmPlanningSingleSlotEarlyCandidateCacheCannotPostponeProof(t *testing.T) {
	runPlanningSingleSlotEarlyCandidateCache(t, URLTestPlanningWarmPaired)
}

func runPlanningSingleSlotEarlyCandidateCache(t *testing.T, mode URLTestPlanningMode) {
	t.Helper()
	for _, attempted := range []bool{false, true} {
		t.Run(fmt.Sprintf("attempted%t", attempted), func(t *testing.T) {
			controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
			controller.opts.URLTestPlanningMode = mode
			measurement := controller.opts.planningMeasurement()
			if mode == URLTestPlanningFreshPaired {
				for node, delay := range runtime.warm {
					runtime.probes[node] = successfulEvidence(500 + delay)
				}
			}
			controller.opts.HealthInterval = time.Minute
			runtime.advanceClock = true
			if err := controller.Tick(base); err != nil {
				t.Fatal(err)
			}
			item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
			if item.OptimizationChecks != 1 {
				t.Fatal("missing initial physical proof")
			}
			a, b := contract.Candidates[0], contract.Candidates[1]
			previousClock := item.WarmPlanningLastProbeAt[b]
			contract.Policy.ProbeBatchSize, runtime.lanes = 1, 1
			runtime.pool.HealthPolicies["route"] = contract
			// Two earlier logical consumers use the same physical lane. The
			// candidate completes too early; the subsequent active job advances
			// this Tick beyond the pending policy's own candidate due time.
			runtime.at = base.Add(59*time.Second + 300*time.Millisecond)
			early := runtime.ProbeWithQualityRequest(b, qualityProbeRequest{Measurement: measurement})
			runtime.at = base.Add(60 * time.Second)
			active := runtime.ProbeWithQualityRequest(a, qualityProbeRequest{Measurement: measurement})
			now := runtime.at
			collectWarmPlanning(now, contract.Candidates, map[string]probeEvidence{a: active}, item, policySettings(contract.Policy, contract.Mode))
			wrapper := &warmCacheInjectionRuntime{warmPlanningTestRuntime: runtime}
			wrapper.inject = func() {
				key := controller.probeKey("route", b, contract)
				controller.probeBudget.Quality[key] = sharedProbeResult{At: time.Now(), Evidence: early}
				controller.probeBudget.QualityAttempted[key] = attempted
				if attempted {
					controller.probeBudget.Used[key] = true
				}
			}
			controller.runtime = wrapper
			before := len(runtime.probeCalls)
			if err := controller.Tick(now); err != nil {
				t.Fatal(err)
			}
			if attempted {
				if len(runtime.probeCalls) != before || item.WarmPlanningLastProbeAt[b] != previousClock || item.OptimizationChecks != 1 {
					t.Fatal("one-node early cache repeated HTTP or postponed the first proof")
				}
				runtime.at = runtime.at.Add(controller.nextIntervalAt(runtime.at))
				if err := controller.Tick(runtime.at); err != nil {
					t.Fatal(err)
				}
			}
			if item.Selected != b || item.LastSwitchReason != "meaningfully-faster" || len(runtime.probeCalls)-before != 1 || len(controller.probeBudget.Used) != 1 {
				t.Fatal("single due producer waited for another full interval or escaped its one-job budget")
			}
		})
	}
}
