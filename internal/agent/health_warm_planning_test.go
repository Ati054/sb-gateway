package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type warmPlanningTestRuntime struct {
	*fakeSelectorRuntime
	at           time.Time
	lanes        int
	warm         map[string]int
	warmFailures map[string]bool
	measurements []qualityMeasurement
	heads        int
	wave         uint64
	blocked      map[string]bool
	batches      [][]string
	attempts     map[string][]time.Time
	advanceClock bool
}

func (runtime *warmPlanningTestRuntime) qualityLaneCount() int { return runtime.lanes }

func (runtime *warmPlanningTestRuntime) Probe(node string) probeEvidence {
	return runtime.ProbeWithQualityRequest(node, qualityProbeRequest{Measurement: qualityMeasurementCold})
}

func (runtime *warmPlanningTestRuntime) ProbeWithQualityRequest(node string, request qualityProbeRequest) probeEvidence {
	runtime.probeCalls = append(runtime.probeCalls, node)
	runtime.measurements = append(runtime.measurements, request.Measurement)
	runtime.heads++
	if runtime.attempts != nil {
		runtime.attempts[node] = append(runtime.attempts[node], runtime.at)
	}
	evidence := runtime.probes[node]
	evidence.QualityStartedAt, evidence.ObservedAt = runtime.at, runtime.at.Add(500*time.Millisecond)
	if runtime.blocked[node] {
		// A timed-out primary HEAD followed by one successful availability GET.
		runtime.heads++
		evidence.PrimaryQualityFailed, evidence.QualityUnmeasured, evidence.DelayMS = false, true, nil
		evidence.ObservedAt = runtime.at.Add(5 * time.Second)
		if request.Measurement == qualityMeasurementWarm {
			evidence.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, ObservedAt: evidence.ObservedAt, Failed: true}
		}
		if request.Measurement == qualityMeasurementFreshPaired {
			evidence.Planning = &planningQualityEvidence{Measurement: qualityMeasurementFreshPaired, ObservedAt: evidence.ObservedAt, Failed: true}
		}
		return runtime.finishModelObservation(evidence)
	}
	if request.Measurement == qualityMeasurementFreshPaired {
		delay := *evidence.DelayMS
		evidence.ObservedAt = runtime.at.Add(time.Duration(delay) * time.Millisecond)
		evidence.Planning = &planningQualityEvidence{Measurement: qualityMeasurementFreshPaired, StartedAt: runtime.at,
			ObservedAt: evidence.ObservedAt, DelayMS: &delay}
	}
	if request.Measurement == qualityMeasurementWarm {
		runtime.heads++
		delay := runtime.warm[node]
		warm := &warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: runtime.at.Add(500 * time.Millisecond),
			ObservedAt: runtime.at.Add(time.Duration(500+delay) * time.Millisecond), DelayMS: &delay, Failed: runtime.warmFailures[node]}
		if warm.Failed {
			warm.DelayMS = nil
		}
		evidence.Warm = warm
	}
	return runtime.finishModelObservation(evidence)
}

func (runtime *warmPlanningTestRuntime) finishModelObservation(evidence probeEvidence) probeEvidence {
	if runtime.advanceClock {
		if evidence.ObservedAt.After(runtime.at) {
			runtime.at = evidence.ObservedAt
		}
		if quality := evidence.planningQuality(); quality != nil && quality.ObservedAt.After(runtime.at) {
			runtime.at = quality.ObservedAt
		}
	}
	return evidence
}

func (runtime *warmPlanningTestRuntime) ProbeQualityParallel(nodes []string) map[string]probeEvidence {
	return runtime.ProbeQualityParallelWithMeasurement(nodes, qualityMeasurementCold)
}

func (runtime *warmPlanningTestRuntime) ProbeQualityParallelWithMeasurement(nodes []string, metric qualityMeasurement) map[string]probeEvidence {
	result := make(map[string]probeEvidence)
	runtime.batches = append(runtime.batches, append([]string(nil), nodes...))
	started := runtime.at
	runtime.wave += 2
	for _, node := range nodes {
		if runtime.advanceClock && runtime.lanes > 1 {
			runtime.at = started
		}
		evidence := runtime.ProbeWithQualityRequest(node, qualityProbeRequest{Measurement: metric})
		if runtime.lanes > 1 {
			evidence.QualityWave = runtime.wave
			if evidence.Warm != nil {
				evidence.Warm.Wave = runtime.wave + 1
			}
			if evidence.Planning != nil {
				evidence.Planning.Wave = runtime.wave
			}
		}
		result[node] = evidence
	}
	failedPeer := false
	finished := started
	for node, evidence := range result {
		failedPeer = failedPeer || runtime.blocked[node]
		if evidence.ObservedAt.After(finished) {
			finished = evidence.ObservedAt
		}
	}
	if metric == qualityMeasurementWarm && failedPeer && runtime.lanes > 1 {
		for node, evidence := range result {
			if !runtime.blocked[node] && evidence.Warm != nil {
				runtime.heads-- // The peer abort prevents the second HTTP request.
				evidence.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, ObservedAt: finished, Deferred: true, Wave: runtime.wave + 1}
				result[node] = evidence
			}
		}
	}
	if runtime.advanceClock {
		runtime.at = started
		for _, evidence := range result {
			runtime.finishModelObservation(evidence)
		}
	}
	return result
}

func warmControllerFixture(t *testing.T, count, lanes, budget int) (*healthController, *warmPlanningTestRuntime, time.Time) {
	t.Helper()
	base := time.Unix(1000, 0)
	nodes, metadata := make([]string, count), make(map[string]healthNode)
	probes, warm := make(map[string]probeEvidence), make(map[string]int)
	for i := range nodes {
		node := fmt.Sprintf("node-%02d", i)
		nodes[i], metadata[node] = node, healthNode{Fingerprint: "test-endpoint-" + node, Protocol: "vless", Transport: "ws"}
		probes[node], warm[node] = successfulEvidence(200), 900
	}
	probes[nodes[1]], warm[nodes[1]] = successfulEvidence(400), 100
	contract := healthPolicyContract{Mode: "best", Candidates: nodes, Nodes: metadata,
		Policy: healthPolicy{LatencyMeasurement: latencyMeasurement, ActiveCheckSeconds: 60, ActiveLivenessSeconds: 3, ProbeBatchSize: budget, SwitchImprovementMS: 200}}
	pool := healthPool{Version: 4, ProbeBudget: budget, ProbeLanes: lanes, HealthPolicies: map[string]healthPolicyContract{"route": contract}}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = nodes[0], nodes[0], true
	item.Mode, item.LatencyMeasurement, item.CandidateSignature = "best", latencyMeasurement, strings.Join(nodes, "\n")
	item.CandidateNodes, item.AvailabilityOK, item.QualityOK = metadata, map[string]bool{}, map[string]bool{}
	for _, node := range nodes {
		value := *probes[node].DelayMS
		item.Samples[node] = []healthSample{{At: 998, ObservedAt: 998, OK: true, DelayMS: &value}}
		item.LastProbeAt[node], item.Recoveries[node], item.AvailabilityOK[node], item.QualityOK[node] = 935, 3, true, true
	}
	runtime := &warmPlanningTestRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{pool: pool, current: map[string]string{"route": nodes[0]}, probes: probes},
		at: base, lanes: lanes, warm: warm, warmFailures: map[string]bool{}, blocked: map[string]bool{}, attempts: map[string][]time.Time{}}
	controller := &healthController{opts: Options{StateRoot: t.TempDir(), URLTestWarmCompare: true}, runtime: runtime, stateLoaded: true,
		state: healthState{"route": item}, warmStarted: map[string]bool{"route": true}, processedPool: pool}
	return controller, runtime, base
}

func TestWarmPlanningOptInUsesWarmOnlyForOrdinaryBest(t *testing.T) {
	for _, count := range []int{7, 10, 24} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			controller, runtime, base := warmControllerFixture(t, count, 2, 10)
			item := controller.state["route"]
			var switches []healthEvent
			controller.eventSink = func(event healthEvent) {
				if event.Event == "switch" {
					switches = append(switches, event)
				}
			}
			for second := 0; second <= 150; second += 3 {
				runtime.at = base.Add(time.Duration(second) * time.Second)
				before := len(runtime.probeCalls)
				if err := controller.Tick(runtime.at); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls)-before > 10 {
					t.Fatal("quality budget exceeded")
				}
				if second < 60 && item.Selected != "node-00" {
					t.Fatal("accepted an early warm proof")
				}
			}
			if item.Selected != "node-01" || len(switches) != 1 {
				t.Fatalf("warm improvement did not converge: selected=%s switches=%+v", item.Selected, switches)
			}
			comparison := switches[0].Comparison
			if comparison == nil || comparison.Measurement != string(qualityMeasurementWarm) || comparison.ConfirmationGapMS == nil || *comparison.ConfirmationGapMS < 60_000 {
				t.Fatalf("missing independent warm confirmations: %+v", comparison)
			}
			if *item.MedianDelayMS["node-00"] != 200 || *item.MedianDelayMS["node-01"] != 400 || item.LatencyMeasurement != latencyMeasurement {
				t.Fatal("warm ranking changed cold metrics")
			}
			for node, samples := range item.WarmPlanningSamples {
				if len(samples) > 3 {
					t.Fatalf("unbounded history for %s", node)
				}
			}
		})
	}
}

func TestWarmPlanningDefaultAndStartupRemainCold(t *testing.T) {
	for _, startup := range []bool{false, true} {
		controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
		controller.opts.URLTestWarmCompare = startup
		if startup {
			controller.warmStarted["route"] = false
		}
		if err := controller.Tick(base); err != nil {
			t.Fatal(err)
		}
		for _, metric := range runtime.measurements {
			if metric != qualityMeasurementCold {
				t.Fatal("default or startup used warm requests")
			}
		}
		if runtime.heads != len(runtime.probeCalls) || controller.state["route"].Selected != "node-00" {
			t.Fatal("cold first batch changed")
		}
	}
	for _, value := range []string{"", "0", "false", "invalid", "1", "true"} {
		t.Run("env-"+value, func(t *testing.T) {
			t.Setenv("SB_URLTEST_WARM_COMPARE", value)
			want := value == "1" || value == "true"
			if OptionsFromEnvironment().URLTestWarmCompare != want {
				t.Fatal("unexpected image opt-in")
			}
		})
	}
}

func TestWarmPlanningMixedMetricsHaveSeparateCacheAndHonestHeadBound(t *testing.T) {
	for _, order := range [][]string{{"best", "priority"}, {"priority", "best"}} {
		t.Run(strings.Join(order, "-"), func(t *testing.T) {
			controller, runtime, _ := warmControllerFixture(t, 2, 2, 4)
			runtime.at = time.Now()
			controller.warmStarted = map[string]bool{"best": true, "priority": true}
			controller.beginProbeBudget(healthPool{ProbeBudget: 4}, order)
			contract := runtime.pool.HealthPolicies["route"]
			for _, id := range order {
				c := contract
				c.Mode = id
				controller.sharedQualityProbe(id, "node-00", c)
			}
			if runtime.heads != 3 || len(runtime.probeCalls) != 2 || len(controller.probeBudget.Quality) != 2 {
				t.Fatalf("cold/warm cache collided or cost hidden: heads=%d calls=%v", runtime.heads, runtime.probeCalls)
			}
			for _, id := range order {
				c := contract
				c.Mode = id
				controller.sharedQualityProbe(id, "node-00", c)
			}
			if runtime.heads != 3 {
				t.Fatal("same logical metric was queried twice")
			}
		})
	}
}

func TestWarmPlanningUnknownAndStaleEvidenceDoNotChangeColdState(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
	item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
	controller.prepareWarmPlanning(contract, item)
	p := policySettings(contract.Policy, "best")
	evidence := runtime.ProbeWithQualityRequest("node-00", qualityProbeRequest{Measurement: qualityMeasurementWarm})
	now := base.Add(2 * time.Second)
	collectWarmPlanning(now, contract.Candidates, map[string]probeEvidence{"node-00": evidence}, item, p)
	clock := item.WarmPlanningLastProbeAt["node-00"]
	item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "node-00", "node-01", 1
	coldBefore, _ := json.Marshal(item.Samples)
	for _, failed := range []bool{false, true} {
		old := evidence
		w := *evidence.Warm
		w.StartedAt = w.StartedAt.Add(-time.Second)
		w.ObservedAt = w.ObservedAt.Add(-time.Second)
		w.Failed = failed
		old.Warm = &w
		collectWarmPlanning(now, contract.Candidates, map[string]probeEvidence{"node-00": old}, item, p)
		if item.OptimizationChecks != 1 || item.WarmPlanningLastProbeAt["node-00"] != clock || len(item.WarmPlanningSamples["node-00"]) != 1 {
			t.Fatal("stale warm evidence rewound or invalidated current planning")
		}
	}
	availability := probeEvidence{OK: true, QualityUnmeasured: true, ObservedAt: now}
	collectWarmPlanning(now, contract.Candidates, map[string]probeEvidence{"node-00": availability}, item, p)
	if item.OptimizationChecks != 1 {
		t.Fatal("ordinary liveness became a warm failure")
	}
	unknown := evidence
	w := *evidence.Warm
	w.ObservedAt = now.Add(time.Second)
	w.Failed = true
	w.DelayMS = nil
	unknown.Warm = &w
	collectWarmPlanning(now.Add(time.Second), contract.Candidates, map[string]probeEvidence{"node-00": unknown}, item, p)
	if item.OptimizationChecks != 0 || len(item.WarmPlanningSamples["node-00"]) != 0 || item.AvailabilityFailures["node-00"] != 0 || item.Failures["node-00"] != 0 || item.Recoveries["node-00"] != 3 {
		t.Fatal("unknown warm retained proof or changed cold availability")
	}
	coldAfter, _ := json.Marshal(item.Samples)
	if string(coldAfter) != string(coldBefore) {
		t.Fatal("warm collector modified cold samples")
	}
	// Empty old QualityOK must not suppress a newly measured warm node.
	item.QualityOK = nil
	w = *evidence.Warm
	w.ObservedAt = now.Add(2 * time.Second)
	evidence.Warm = &w
	collectWarmPlanning(now.Add(2*time.Second), contract.Candidates, map[string]probeEvidence{"node-00": evidence}, item, p)
	if !warmPlanningView(item).QualityOK["node-00"] {
		t.Fatal("new warm node waited for old public QualityOK map")
	}
}

func TestWarmPlanningResetPreservesColdHistory(t *testing.T) {
	for _, change := range []string{"node", "target", "runtime", "disabled", "restore"} {
		t.Run(change, func(t *testing.T) {
			controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
			item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
			controller.prepareWarmPlanning(contract, item)
			e := runtime.ProbeWithQualityRequest("node-00", qualityProbeRequest{Measurement: qualityMeasurementWarm})
			collectWarmPlanning(base.Add(2*time.Second), contract.Candidates, map[string]probeEvidence{"node-00": e}, item, policySettings(contract.Policy, "best"))
			cold := append([]healthSample(nil), item.Samples["node-00"]...)
			item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "node-00", "node-01", 1
			switch change {
			case "node":
				n := contract.Nodes["node-01"]
				n.Fingerprint = "replacement"
				contract.Nodes["node-01"] = n
			case "target":
				controller.opts.ProbeURL = "http://127.0.0.1:19999"
			case "runtime":
				controller.processedGeneration.XrayPID = 99
			case "disabled":
				controller.opts.URLTestWarmCompare = false
			case "restore":
				body, _ := json.Marshal(item)
				var restored policyHealthState
				if err := json.Unmarshal(body, &restored); err != nil {
					t.Fatal(err)
				}
				item = &restored
			}
			controller.prepareWarmPlanning(contract, item)
			if item.OptimizationChecks != 0 || len(item.WarmPlanningSamples) != 0 || !reflect.DeepEqual(item.Samples["node-00"], cold) || item.Recoveries["node-00"] != 3 {
				t.Fatal("planning reset erased cold state or kept old proof")
			}
		})
	}
}

func TestWarmPlanningRepeatedUnknownRetainsColdTrafficAndCanRecover(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
	item := controller.state["route"]
	runtime.warmFailures["node-00"] = true
	for _, second := range []int{0, 63, 126, 189} {
		runtime.at = base.Add(time.Duration(second) * time.Second)
		if err := controller.Tick(runtime.at); err != nil {
			t.Fatal(err)
		}
		if item.Selected != "node-00" || item.Failures["node-00"] != 0 || item.AvailabilityFailures["node-00"] != 0 || item.OptimizationChecks != 0 {
			t.Fatal("unknown second HEAD became cold degradation or retained a proof")
		}
	}
	if item.DailyStats["node-00"].Failures != 0 || *item.MedianDelayMS["node-00"] != 200 {
		t.Fatal("unknown warm polluted cold history")
	}
	runtime.warmFailures["node-00"] = false
	for _, second := range []int{252, 315} {
		runtime.at = base.Add(time.Duration(second) * time.Second)
		if err := controller.Tick(runtime.at); err != nil {
			t.Fatal(err)
		}
	}
	if item.Selected != "node-01" {
		t.Fatal("warm planning did not recover after two fresh good rounds")
	}
}

func TestWarmPlanningNewQualityAndNoOpContractDoNotNeedAnotherCycle(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
	item := controller.state["route"]
	item.QualityOK = nil
	if err := controller.Tick(base); err != nil {
		t.Fatal(err)
	}
	if item.OptimizationChecks != 1 {
		t.Fatalf("new valid warm node lost first confirmation: %+v", item.OptimizationLastResult)
	}
	proof, samples := item.OptimizationLastResult, item.WarmPlanningSamples["node-00"]
	controller.processedGeneration.PoolMTimeUnixNano++
	controller.prepareWarmPlanning(runtime.pool.HealthPolicies["route"], item)
	if item.OptimizationChecks != 1 || item.OptimizationLastResult != proof || !reflect.DeepEqual(item.WarmPlanningSamples["node-00"], samples) {
		t.Fatal("unchanged contract/target/runtime reset warm evidence")
	}
}

func TestWarmPlanningOppositeColdAndWarmOrdering(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
	item := controller.state["route"]
	for node, value := range map[string]int{"node-00": 700, "node-01": 800} {
		runtime.probes[node] = successfulEvidence(value)
		ms := value
		item.Samples[node] = []healthSample{{At: 998, ObservedAt: 998, OK: true, DelayMS: &ms}}
	}
	runtime.warm["node-00"], runtime.warm["node-01"] = 600, 100
	for _, second := range []int{0, 63} {
		runtime.at = base.Add(time.Duration(second) * time.Second)
		if err := controller.Tick(runtime.at); err != nil {
			t.Fatal(err)
		}
	}
	if item.Selected != "node-01" || *item.MedianDelayMS["node-00"] != 700 || *item.MedianDelayMS["node-01"] != 800 {
		t.Fatal("cold ordering filtered the better ordinary warm candidate or cold history changed")
	}
}

func TestWarmPlanningCheckpointCannotBecomeLegacyColdConfirmation(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
	item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
	if err := controller.Tick(base); err != nil {
		t.Fatal(err)
	}
	if item.OptimizationChecks != 1 {
		t.Fatal("fixture did not create first warm proof")
	}
	item.LatencyComparisons = map[string]latencyComparison{"node-01": {Active: "node-00", Measurement: string(qualityMeasurementWarm), ActiveDelayMS: 900, CandidateDelayMS: 100}}
	item.LastLatencyComparisons = item.LatencyComparisons
	proof := item.OptimizationLastResult
	path := statePath(t.TempDir(), "selector-health")
	if err := publishHealthState(path, healthState{"route": item}); err != nil {
		t.Fatal(err)
	}
	checkpoint, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policies map[string]json.RawMessage
	if err := json.Unmarshal(checkpoint, &policies); err != nil {
		t.Fatal(err)
	}
	body := policies["route"]
	if item.OptimizationChecks != 1 || item.OptimizationLastResult != proof || len(item.LatencyComparisons) != 1 {
		t.Fatal("serialization mutated live planning state")
	}
	// This reader deliberately knows only the pre-experiment JSON fields.
	var legacy struct {
		LatencyMeasurement     string                       `json:"latency_measurement"`
		Selected               string                       `json:"selected"`
		Samples                map[string][]healthSample    `json:"samples"`
		OptimizationBaseline   string                       `json:"optimization_baseline"`
		OptimizationCandidate  string                       `json:"optimization_candidate"`
		OptimizationChecks     int                          `json:"optimization_checks"`
		OptimizationLastResult *optimizationComparison      `json:"optimization_last_result"`
		LatencyComparisons     map[string]latencyComparison `json:"latency_comparisons"`
		LastLatencyComparisons map[string]latencyComparison `json:"last_latency_comparisons"`
	}
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.LatencyMeasurement != latencyMeasurement || legacy.Selected != item.Selected || !reflect.DeepEqual(legacy.Samples, item.Samples) ||
		legacy.OptimizationBaseline != "" || legacy.OptimizationCandidate != "" || legacy.OptimizationChecks != 0 || legacy.OptimizationLastResult != nil || len(legacy.LatencyComparisons) != 0 || len(legacy.LastLatencyComparisons) != 0 {
		t.Fatal("legacy checkpoint received warm planning or lost cold state")
	}
	var public map[string]json.RawMessage
	if err := json.Unmarshal(body, &public); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"warm_planning_marker", "warm_latency_comparisons", "warm_last_latency_comparisons", "warm_optimization_last_result"} {
		if len(public[key]) == 0 {
			t.Fatalf("missing explicit warm diagnostic %s", key)
		}
	}
	old := newPolicyHealthState()
	old.Selected, old.Samples = legacy.Selected, legacy.Samples
	at := base.Add(63 * time.Second)
	a, b := successfulEvidence(900), successfulEvidence(400)
	a.QualityStartedAt, b.QualityStartedAt = at, at
	a.ObservedAt, b.ObservedAt = at.Add(900*time.Millisecond), at.Add(400*time.Millisecond)
	measured := map[string]probeEvidence{"node-00": a, "node-01": b}
	for node, e := range measured {
		old.Samples[node] = []healthSample{{At: float64(e.ObservedAt.Unix()), ObservedAt: qualityObservationAt(at, e), OK: true, DelayMS: e.DelayMS}}
	}
	p := policySettings(contract.Policy, "best")
	comparison := regularOptimizationComparison(at.Add(time.Second), "node-00", "node-01", measured, old, true, true, p)
	selected, _ := gatePlannedOptimization(at.Add(time.Second), "node-00", "node-01", "meaningfully-faster", comparison, old, p)
	if selected != "node-00" || old.OptimizationChecks != 1 {
		t.Fatal("warm checkpoint supplied a legacy cold confirmation")
	}
	var restored policyHealthState
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.OptimizationChecks != 0 || restored.WarmPlanningMarker != "" || !reflect.DeepEqual(restored.Samples, item.Samples) {
		t.Fatal("new agent restored a session-bound warm proof")
	}
}

func TestWarmPlanningOneSlotThreePoliciesAndFastOutage(t *testing.T) {
	controller, runtime, base := disjointWarmScanFixture(t, 3)
	for i, interval := range []int{3, 30, 60} {
		id := fmt.Sprintf("disjoint-%d", i)
		contract := runtime.pool.HealthPolicies[id]
		contract.Policy.ActiveCheckSeconds = interval
		runtime.pool.HealthPolicies[id] = contract
		runtime.warm[contract.Candidates[0]], runtime.warm[contract.Candidates[1]] = 900, 100
	}
	now := base
	for cycles := 0; now.Before(base.Add(240 * time.Second)); cycles++ {
		if cycles > 300 {
			t.Fatal("actual one-slot scheduler stopped advancing")
		}
		runtime.at = now
		before := len(runtime.probeCalls)
		if err := controller.Tick(runtime.at); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls)-before > 1 {
			t.Fatal("one slot budget exceeded")
		}
		now = runtime.at.Add(controller.nextIntervalAt(runtime.at))
	}
	for id, item := range controller.state {
		if item.Selected != runtime.pool.HealthPolicies[id].Candidates[1] {
			t.Fatalf("one slot starved %s: selected=%s", id, item.Selected)
		}
	}
	item := controller.state["disjoint-2"]
	item.AvailabilityFailures[item.Selected] = 3
	runtime.probes[item.Selected] = probeEvidence{Failure: probeFailureTimeout}
	runtime.at = now.Add(3 * time.Second)
	if err := controller.Tick(runtime.at); err != nil {
		t.Fatal(err)
	}
	if item.Selected != runtime.pool.HealthPolicies["disjoint-2"].Candidates[0] || item.LastSwitchReason != "active-unavailable" {
		t.Fatal("warm planning delayed cold emergency")
	}
}

func TestWarmPlanningCohortsHaveIndependentBarriersAndNoSingleLaneDeadlock(t *testing.T) {
	queues := probeLaneJobsWithMeasurement([]string{"a", "b", "c"}, 2, true, func() {}, qualityMeasurementWarm)
	a, b := <-queues[0], <-queues[1]
	if a.start.barrier != b.start.barrier || a.warmStart.barrier != b.warmStart.barrier || a.start.barrier == a.warmStart.barrier {
		t.Fatal("cold/warm cohort identity is not independent")
	}
	a.start.arrive()
	b.start.arrive()
	a.warmStart.arrive()
	b.warmStart.arrive()
	last := <-queues[0]
	last.start.arrive()
	last.warmStart.arrive()
	select {
	case <-last.warmStart.barrier.ready:
	default:
		t.Fatal("singleton final wave waited for another peer")
	}
	single := probeLaneJobsWithMeasurement([]string{"a", "b"}, 1, true, func() {}, qualityMeasurementWarm)
	for job := range single[0] {
		if job.start != nil || job.warmStart != nil {
			t.Fatal("single lane has a multi-peer barrier")
		}
	}
}

func TestWarmPlanningPublicationKeepsColdGraphAndAvoidsPolicyMarshalAllocations(t *testing.T) {
	cold := newPolicyHealthState()
	cold.CandidateLabels = map[string]string{"node": strings.Repeat("history", 100000)}
	state := healthState{"cold": cold, "absent": nil}
	var projected any
	allocations := testing.AllocsPerRun(100, func() { projected = healthCheckpointProjection(state) })
	if allocations != 0 {
		t.Fatalf("cold publication projection allocated %.1f objects", allocations)
	}
	if _, ok := projected.(healthState); !ok {
		t.Fatal("cold-only publication wrapped the original state")
	}
	if _, ok := any(cold).(json.Marshaler); ok {
		t.Fatal("per-policy custom marshaler returned")
	}
	controller, runtime, _ := warmControllerFixture(t, 2, 2, 2)
	warm := controller.state["route"]
	controller.prepareWarmPlanning(runtime.pool.HealthPolicies["route"], warm)
	warm.OptimizationChecks = 1
	state["warm"] = warm
	wire, ok := healthCheckpointProjection(state).(map[string]any)
	if !ok || wire["cold"] != cold {
		t.Fatal("mixed projection copied or encoded cold history")
	}
	view, ok := wire["warm"].(warmPolicyCheckpoint)
	if !ok || view.OptimizationChecks != 0 || warm.OptimizationChecks != 1 || !reflect.DeepEqual(view.Samples, warm.Samples) {
		t.Fatal("wire view changed live state or dropped cold samples")
	}
}

func TestWarmPlanningHistoryContainsOnlyRecentMeasuredNodes(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 24, 2, 10)
	item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
	controller.prepareWarmPlanning(contract, item)
	e := runtime.ProbeWithQualityRequest("node-00", qualityProbeRequest{Measurement: qualityMeasurementWarm})
	p := policySettings(contract.Policy, "best")
	collectWarmPlanning(base.Add(2*time.Second), contract.Candidates, map[string]probeEvidence{"node-00": e}, item, p)
	if len(item.WarmPlanningSamples) != 1 {
		t.Fatal("unmeasured inventory created empty planning histories")
	}
	collectWarmPlanning(base.Add(300*time.Second), contract.Candidates, nil, item, p)
	if len(item.WarmPlanningSamples) != 0 || len(item.warmPlanningLatest) != 0 {
		t.Fatal("expired planning samples retained history/map entries")
	}
}
