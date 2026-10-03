package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func budgetContract(nodes ...string) healthPolicyContract {
	contract := healthPolicyContract{Nodes: map[string]healthNode{}}
	for _, node := range nodes {
		contract.Nodes[node] = healthNode{Fingerprint: "endpoint-" + node}
	}
	return contract
}

func TestSharedProbesBelongToOneTickAndConcreteEndpoint(t *testing.T) {
	runtime := &fakeSelectorRuntime{probes: map[string]probeEvidence{"a": successfulEvidence(500)}, speeds: map[string]int64{"a": 10_000_000}}
	controller := &healthController{runtime: runtime}
	pool := healthPool{ProbeBudget: 5}
	contract := budgetContract("a")
	controller.beginProbeBudget(pool, []string{"first", "second"})
	for _, id := range []string{"first", "second"} {
		controller.sharedQualityProbe(id, "a", contract)
		controller.sharedSpeedProbe(id, "a", contract, defaultSpeedBytes)
	}
	if len(runtime.probeCalls) != 1 || len(runtime.throughputCalls) != 1 {
		t.Fatal("overlapping policies downloaded twice")
	}
	controller.beginProbeBudget(pool, []string{"first", "second"})
	controller.sharedQualityProbe("first", "a", contract)
	controller.sharedSpeedProbe("first", "a", contract, defaultSpeedBytes)
	if len(runtime.probeCalls) != 2 || len(runtime.throughputCalls) != 2 {
		t.Fatal("same probe became another Tick's confirmation")
	}
	changed := budgetContract("a")
	changed.Nodes["a"] = healthNode{Fingerprint: "new-endpoint"}
	controller.sharedQualityProbe("second", "a", changed)
	if len(runtime.probeCalls) != 3 {
		t.Fatal("replacement inherited old evidence")
	}
	controller.sharedSpeedProbe("second", "a", contract, defaultSpeedBytes*2)
	if len(runtime.throughputCalls) != 3 {
		t.Fatal("different byte limits shared incompatible speeds")
	}
}

func TestSharedBudgetCountsUniqueEndpointsAndDefersWithoutFailure(t *testing.T) {
	controller := &healthController{}
	controller.beginProbeBudget(healthPool{ProbeBudget: 5}, nil)
	contract := budgetContract("a", "b", "c", "d", "e", "f")
	accepted, deferred := controller.claimProbeTargets("first", contract, []string{"a", "b", "c", "d", "e"}, 0, false)
	if len(accepted) != 5 || len(deferred) != 0 {
		t.Fatal("first batch not admitted")
	}
	accepted, deferred = controller.claimProbeTargets("second", contract, []string{"b", "d", "f"}, 0, false)
	if strings.Join(accepted, ",") != "b,d" || strings.Join(deferred, ",") != "f" || len(controller.probeBudget.Used) != 5 {
		t.Fatal("shared budget charged repeated endpoint or exceeded limit")
	}
}

type observedQualityRuntime struct{ *fakeSelectorRuntime }

func (runtime *observedQualityRuntime) ProbeQualityParallel(nodes []string) map[string]probeEvidence {
	result := map[string]probeEvidence{}
	for _, node := range nodes {
		result[node] = runtime.Probe(node)
	}
	return result
}

func TestSharedQualityDoesNotRefreshCompletedParallelSample(t *testing.T) {
	evidence := successfulEvidence(100)
	evidence.ObservedAt = time.Now().Add(-sharedProbeLifetime - time.Second)
	runtime := &observedQualityRuntime{&fakeSelectorRuntime{probes: map[string]probeEvidence{"a": evidence, "b": successfulEvidence(100)}}}
	controller := &healthController{runtime: runtime}
	controller.beginProbeBudget(healthPool{ProbeBudget: 5}, nil)
	controller.sharedQualityBatch("first", budgetContract("a", "b"), []string{"a", "b"})
	deferred := controller.sharedQualityProbe("second", "a", budgetContract("a"))
	controller.sharedQualityProbe("second", "b", budgetContract("b"))
	if len(runtime.probeCalls) != 2 || !deferred.Deferred {
		t.Fatal("waiting for a slow parallel peer refreshed an expired result")
	}
}

func TestSharedSpeedRechecksAttemptedAfterAdmission(t *testing.T) {
	runtime := &fakeSelectorRuntime{speeds: map[string]int64{"a": 10_000_000, "b": 20_000_000}}
	controller := &healthController{runtime: runtime}
	controller.beginProbeBudget(healthPool{ProbeBudget: 2}, nil)
	contract := budgetContract("a", "b")
	controller.sharedSpeedProbe("first", "b", contract, defaultSpeedBytes)
	accepted, deferred := controller.claimProbeTargets("second", contract, []string{"a", "b"}, defaultSpeedBytes, true)
	if len(accepted) != 2 || len(deferred) != 0 {
		t.Fatal("fresh pair was not admitted")
	}
	controller.sharedSpeedProbe("second", "a", contract, defaultSpeedBytes)
	key := fmt.Sprintf("endpoint-b:%d", defaultSpeedBytes)
	cached := controller.probeBudget.Speed[key]
	cached.At = time.Now().Add(-sharedProbeLifetime - time.Second)
	controller.probeBudget.Speed[key] = cached
	_, err := controller.sharedSpeedProbe("second", "b", contract, defaultSpeedBytes)
	if err != errSharedProbeDeferred || len(runtime.throughputCalls) != 2 {
		t.Fatal("expiry between admission and execution repeated a download")
	}
}

func TestLocalSelectorFailureDoesNotPenalizeActiveOrReserve(t *testing.T) {
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{"de": {LocalFailure: true, Failure: probeFailureTimeout}, "nl": {LocalFailure: true, Failure: probeFailureTimeout}},
	}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.AvailabilityOK, item.QualityOK = map[string]bool{}, map[string]bool{}
	item.AvailabilityOK["de"], item.QualityOK["de"], item.Recoveries["de"] = true, true, 3
	controller := &healthController{runtime: runtime, state: healthState{"europe": item}, livenessAt: map[string]time.Time{}, forceLiveness: map[string]bool{}}
	_, err := controller.checkActiveAvailability(time.Unix(10000, 0), "europe", contract, item, false)
	if err != errProbeSelectorUnavailable || item.AvailabilityFailures["de"] != 0 || item.Recoveries["de"] != 3 {
		t.Fatal("local API error became an active-node outage")
	}
	_, _, err = controller.probeEmergencyCandidates("europe", []string{"nl"}, policySettings(contract.Policy, contract.Mode))
	if err != errProbeSelectorUnavailable || len(runtime.selections) != 0 {
		t.Fatal("local API error was accepted as a reserve probe")
	}
}

func TestSharedProbeInterruptionInvalidatesPartialEvidence(t *testing.T) {
	runtime := &interruptedTestRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{}, interrupted: true}
	controller := &healthController{runtime: runtime}
	controller.beginProbeBudget(healthPool{ProbeBudget: 5}, nil)
	controller.probeBudget.Quality["endpoint-a"] = sharedProbeResult{At: time.Now(), Evidence: successfulEvidence(100)}
	controller.probeBudget.Speed["endpoint-a:1"] = sharedSpeedResult{At: time.Now(), BPS: 10_000_000}
	if controller.takeSharedProbeInterruption() == nil || len(controller.probeBudget.Quality) != 0 || len(controller.probeBudget.Speed) != 0 {
		t.Fatal("interrupted generation left reusable endpoint evidence")
	}
}

func TestSharedBudgetAtomicallyDefersComparisonPair(t *testing.T) {
	controller := &healthController{}
	controller.beginProbeBudget(healthPool{ProbeBudget: 5}, nil)
	contract := budgetContract("a", "b", "c", "d", "active", "reserve")
	controller.claimProbeTargets("first", contract, []string{"a", "b", "c", "d"}, 0, false)
	accepted, deferred := controller.claimProbeTargets("second", contract, []string{"active", "reserve"}, 0, true)
	if len(accepted) != 0 || len(deferred) != 2 || len(controller.probeBudget.Used) != 4 {
		t.Fatal("half a comparison consumed the last slot")
	}
}

func TestSharedBudgetRotatesDisjointPoliciesAndPreservesManualCounts(t *testing.T) {
	for _, limit := range []int{2, 5, 6, 7, 8, 9, 10} {
		controller := &healthController{}
		seen := map[string]bool{}
		for tick := 0; tick < 3; tick++ {
			ids := []string{"a", "b", "c"}
			controller.beginProbeBudget(healthPool{ProbeBudget: limit}, ids)
			seen[ids[0]] = true
			nodes := []string{}
			for i := 0; i < limit+1; i++ {
				nodes = append(nodes, fmt.Sprint(i))
			}
			accepted, deferred := controller.claimProbeTargets(ids[0], budgetContract(nodes...), nodes, 0, false)
			if len(accepted) != limit || len(deferred) != 1 {
				t.Fatalf("manual limit %d not honored", limit)
			}
			controller.probeBudget.Cursor++
		}
		if len(seen) != 3 {
			t.Fatal("disjoint policies starved")
		}
	}
}

func TestSharedBudgetDoesNotRepeatFailedOrExpiredAttempts(t *testing.T) {
	runtime := &fakeSelectorRuntime{probes: map[string]probeEvidence{"a": failedEvidence(), "b": successfulEvidence(100)}, speeds: map[string]int64{}}
	controller := &healthController{runtime: runtime}
	controller.beginProbeBudget(healthPool{ProbeBudget: 2}, nil)
	contract := budgetContract("a", "b")
	controller.sharedQualityProbe("first", "a", contract)
	controller.sharedQualityProbe("first", "b", contract)
	controller.probeBudget.Quality["endpoint-b"] = sharedProbeResult{At: time.Now().Add(-sharedProbeLifetime - time.Second), Evidence: successfulEvidence(100)}
	accepted, deferred := controller.claimProbeTargets("second", contract, []string{"a", "b"}, 0, false)
	if len(accepted) != 0 || len(deferred) != 2 {
		t.Fatal("failed or expired attempt repeated in the same Tick")
	}
	controller.sharedSpeedProbe("first", "a", contract, defaultSpeedBytes)
	accepted, deferred = controller.claimProbeTargets("second", contract, []string{"a", "b"}, defaultSpeedBytes, true)
	if len(accepted) != 0 || len(deferred) != 2 {
		t.Fatal("half of an attempted speed pair admitted")
	}
}

func TestSharedBudgetManualOneAdmitsRoutineSpeedRotation(t *testing.T) {
	controller := &healthController{}
	controller.beginProbeBudget(healthPool{ProbeBudget: 1}, nil)
	accepted, deferred := controller.claimProbeTargets("first", budgetContract("a", "b"), []string{"a", "b"}, defaultSpeedBytes, false)
	if strings.Join(accepted, ",") != "a" || strings.Join(deferred, ",") != "b" {
		t.Fatal("routine rotation treated as an atomic comparison")
	}
}

func TestSharedBudgetDoesNotStarveSlowerDuePolicy(t *testing.T) {
	base := healthFixture(false).HealthPolicies["europe"]
	pool := healthPool{Version: 4, ProbeBudget: 2, HealthPolicies: map[string]healthPolicyContract{}}
	runtime := &fakeSelectorRuntime{current: map[string]string{}, probes: map[string]probeEvidence{}}
	controller := &healthController{
		opts:    Options{StateRoot: t.TempDir(), HealthInterval: time.Minute},
		runtime: runtime, stateLoaded: true, state: healthState{},
		warmStarted: map[string]bool{},
	}
	const start int64 = 10000
	for index, id := range []string{"a", "b"} {
		interval := 30 * (index + 1)
		active, reserve := id+"-active", id+"-reserve"
		contract := base
		contract.Mode, contract.Groups = "best", nil
		contract.Candidates = []string{active, reserve}
		contract.Nodes = budgetContract(active, reserve).Nodes
		contract.Policy.MaxActiveCandidates, contract.Policy.ProbeBatchSize = 2, 2
		contract.Policy.ActiveCheckSeconds, contract.Policy.BackupCheckSeconds = interval, interval
		contract.Policy.FullScanSeconds = 1800
		pool.HealthPolicies[id] = contract
		item := newPolicyHealthState()
		ensureHealthMaps(item)
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = active, active, true
		item.CandidateSignature = strings.Join(contract.Candidates, "\n")
		item.NextFullScanAt = float64(start + 1800)
		item.AvailabilityOK, item.QualityOK = map[string]bool{}, map[string]bool{}
		item.MedianDelayMS = map[string]*int{}
		for nodeIndex, node := range contract.Candidates {
			delay := 400 + nodeIndex*100
			item.Samples[node] = []healthSample{{OK: true, DelayMS: &delay}}
			item.AvailabilityOK[node], item.QualityOK[node], item.Recoveries[node] = true, true, 3
			item.MedianDelayMS[node] = &delay
			item.LastProbeAt[node], item.LastGoodAt[node] = float64(start-120), float64(start-120)
			runtime.probes[node] = successfulEvidence(delay)
		}
		controller.state[id], controller.warmStarted[id] = item, true
		runtime.current[id] = active
	}
	runtime.pool = pool
	countB := 0
	for offset := int64(0); offset <= 300; offset += 3 {
		runtime.probeCalls = nil
		if err := controller.Tick(time.Unix(start+offset, 0)); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls) > 2 {
			t.Fatalf("manual2 exceeded at %ds: %v", offset, runtime.probeCalls)
		}
		if offset%30 != 0 && len(runtime.probeCalls) != 0 {
			t.Fatal("deferred work accelerated the configured cadence")
		}
		for _, node := range runtime.probeCalls {
			if strings.HasPrefix(node, "b-") {
				countB++
			}
		}
	}
	if countB < 2 {
		t.Fatalf("slower due policy starved: B full probes=%d", countB)
	}
	if len(runtime.selections) != 0 {
		t.Fatal("budget scheduling changed live selection")
	}
}
