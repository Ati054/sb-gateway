package agent

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSurveyBaselineRespectsSharedSlotsAndFailureCadence(t *testing.T) {
	for _, name := range []string{"refresh", "fresh", "serial-wave", "single-batch", "one-shared-slot", "one-slot-left", "failure", "failed-primary", "underlay", "unconfirmed", "pending", "empty"} {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
			delay := 600
			item.Samples["active"] = []healthSample{{At: 980, ObservedAt: 980, OK: true, DelayMS: &delay}}
			p := policySettings(healthPolicy{ProbeBatchSize: 2}, "best")
			controller := &healthController{probeBudget: &healthProbeBudget{Limit: 2, Used: map[string]bool{}}}
			targets := []string{"a", "b"}
			switch name {
			case "fresh":
				item.Samples["active"][0].ObservedAt = 996
			case "serial-wave":
				item.Samples["active"][0].ObservedAt = 996
				controller.processedPool.ProbeLanes = 1
			case "single-batch":
				p.batch = 1
				targets = targets[:1]
			case "one-shared-slot":
				controller.probeBudget.Limit = 1
			case "one-slot-left":
				controller.probeBudget.Used["other-policy"] = true
			case "failure":
				item.AvailabilityFailures["active"] = 1
			case "failed-primary":
				item.Samples["active"][0].OK = false
			case "underlay":
				item.UnderlayFailure = "wan"
			case "unconfirmed":
				item.RuntimeConfirmed = false
			case "pending":
				item.OptimizationCandidate, item.OptimizationBaseline = "a", "active"
				item.OptimizationLastResult = &optimizationComparison{At: now.UTC().Format(time.RFC3339), Candidate: "a"}
			case "empty":
				targets = nil
			}
			want := append([]string(nil), targets...)
			if name == "refresh" || name == "serial-wave" {
				want = []string{"active", "a"}
			}
			got := controller.withSurveyBaseline(now, "active", targets, item, p)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("targets=%v want=%v", got, want)
			}
			if (name == "refresh" || name == "serial-wave") && !reflect.DeepEqual(item.ScanQueue, []string{"b"}) {
				t.Fatal("displaced reserve was not requeued")
			}
		})
	}
}

func TestSurveySettingsUsesActualLaneCount(t *testing.T) {
	for _, lanes := range []int{1, 2, 10} {
		controller := &healthController{processedPool: healthPool{ProbeBudget: 10, ProbeLanes: lanes}}
		p := controller.surveySettings(policySettings(healthPolicy{ProbeBatchSize: 10}, "best"))
		if p.batch != min(10, 2*lanes) {
			t.Fatalf("lanes=%d batch=%d", lanes, p.batch)
		}
	}
	controller := &healthController{processedPool: healthPool{ProbeBudget: 10, ProbeLanes: 10}, runtime: &responsiveSelectorRuntime{parallelEnabled: true, backgrounds: make([]*xraySelectorRuntime, 1)}}
	if got := controller.surveySettings(policySettings(healthPolicy{ProbeBatchSize: 10}, "best")).batch; got != 2 {
		t.Fatal("rendered count overrode the actual single runtime lane")
	}
}

// Virtual time drives the real controller and wake schedule. Parallel primary
// probes may be slow without failing; every member must still acquire a close
// comparison to the unchanged active route after a restart.
type surveyBaselineRuntime struct {
	*fakeSelectorRuntime
	clock    *time.Time
	duration time.Duration
	started  []time.Time
}

func (r *surveyBaselineRuntime) Probe(node string) probeEvidence {
	r.started = append(r.started, *r.clock)
	evidence := r.fakeSelectorRuntime.Probe(node)
	*r.clock = r.clock.Add(r.duration)
	evidence.ObservedAt = *r.clock
	return evidence
}

func (r *surveyBaselineRuntime) ProbeQualityParallel(nodes []string) map[string]probeEvidence {
	result := make(map[string]probeEvidence)
	started := *r.clock
	for _, node := range nodes {
		r.started = append(r.started, started)
		evidence := r.fakeSelectorRuntime.Probe(node)
		duration := r.duration
		if node == "active" {
			duration = min(duration, 600*time.Millisecond)
		}
		evidence.ObservedAt = started.Add(duration)
		result[node] = evidence
	}
	*r.clock = started.Add(r.duration)
	return result
}

func TestSurveyComparisonCoversWholeInventoryAfterRestart(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, duration := range []time.Duration{time.Second, 4500 * time.Millisecond} {
			t.Run(fmt.Sprintf("%s/%s", mode, duration), func(t *testing.T) {
				controller, item, base := stagedOptimizationController(t)
				contract := base.pool.HealthPolicies["europe"]
				contract.Mode, contract.Groups = mode, nil
				contract.Candidates = []string{"active"}
				contract.Nodes = map[string]healthNode{"active": {Label: "Active"}}
				for n := 1; n < 24; n++ {
					id := fmt.Sprintf("reserve-%02d", n)
					contract.Candidates = append(contract.Candidates, id)
					contract.Nodes[id] = healthNode{Label: id}
					base.probes[id] = successfulEvidence(4500)
					item.Recoveries[id] = 3
				}
				base.probes["active"] = successfulEvidence(600)
				contract.Policy.ProbeBatchSize = 10
				contract.Policy.ActiveCheckSeconds = 60
				contract.Policy.ActiveLivenessSeconds = 3
				contract.Policy.SwitchImprovementMS = 200
				base.pool.HealthPolicies["europe"], base.pool.ProbeBudget = contract, 10
				item.CandidateSignature = strings.Join(contract.Candidates, "\n")
				item.Selected, item.RuntimeSelected = "active", "active"
				item.Samples = map[string][]healthSample{}
				item.LastProbeAt = map[string]float64{}
				now := time.Unix(1060, 0)
				runtime := &surveyBaselineRuntime{fakeSelectorRuntime: base, clock: &now, duration: duration}
				controller.runtime = runtime
				end := now.Add(20 * time.Minute)
				cycles, restartAt := 0, now.Add(10*time.Minute)
				restarted := false
				for now.Before(end) && cycles < 1000 {
					cycles++
					before := len(base.probeCalls)
					if err := controller.Tick(now); err != nil {
						t.Fatal(err)
					}
					if len(base.probeCalls)-before > 10 {
						t.Fatal("survey exceeded the shared cycle budget")
					}
					item = controller.state["europe"]
					if item.Selected != "active" {
						t.Fatal("display survey changed the active route")
					}
					if !restarted && !now.Before(restartAt) {
						controller.stateLoaded, base.reset = false, true
						restarted = true
					}
					now = now.Add(max(time.Millisecond, controller.nextIntervalAt(now)))
				}
				seen, activeProbes := map[string]int{}, 0
				for _, node := range base.probeCalls {
					seen[node]++
					if node == "active" {
						activeProbes++
					}
				}
				peak := 0
				for i, at := range runtime.started {
					j := i
					for j < len(runtime.started) && runtime.started[j].Sub(at) < time.Minute {
						j++
					}
					peak = max(peak, j-i)
				}
				t.Logf("members=%d display=%d quality_requests=%d active_requests=%d rolling_minute_peak=%d cycles=%d", len(seen), len(item.LastLatencyComparisons), len(base.probeCalls), activeProbes, peak, cycles)
				if peak > 40 || len(base.probeCalls) > 28*20 {
					t.Fatal("baseline refresh accelerated the survey beyond its bounded cadence")
				}
				for _, node := range contract.Candidates[1:] {
					pair, ok := item.LastLatencyComparisons[node]
					if seen[node] < 2 || !ok || pair.CandidateAt < float64(restartAt.Unix()) {
						t.Fatalf("reserve lacks repeated current-baseline comparisons: %s probes=%d pair=%+v", node, seen[node], pair)
					}
					if pair.Active != "active" || pair.ActiveAt-pair.CandidateAt > 10 || pair.CandidateAt-pair.ActiveAt > 10 {
						t.Fatal("survey weakened the paired observation window")
					}
				}
			})
		}
	}
}

func TestSingleQualityLaneBoundsLargeSurveyAndPopulatesDelta(t *testing.T) {
	controller, item, base := stagedOptimizationController(t)
	contract := base.pool.HealthPolicies["europe"]
	contract.Candidates, contract.Groups = []string{"active"}, nil
	contract.Nodes = map[string]healthNode{"active": {Label: "Active"}}
	for n := 1; n < 24; n++ {
		id := fmt.Sprintf("reserve-%02d", n)
		contract.Candidates = append(contract.Candidates, id)
		contract.Nodes[id] = healthNode{Label: id}
		base.probes[id] = successfulEvidence(4500)
		item.Recoveries[id] = 3
	}
	contract.Policy.ProbeBatchSize, contract.Policy.ActiveCheckSeconds, contract.Policy.ActiveLivenessSeconds = 10, 60, 3
	base.pool.HealthPolicies["europe"], base.pool.ProbeBudget, base.pool.ProbeLanes = contract, 10, 1
	base.probes["active"] = successfulEvidence(600)
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.Samples, item.LastProbeAt = map[string][]healthSample{}, map[string]float64{}
	clearOptimizationCandidate(item)
	now := time.Unix(1060, 0)
	controller.runtime = &timedPairTestRuntime{base, &now, 4500 * time.Millisecond}
	end, restartAt := now.Add(20*time.Minute), now.Add(10*time.Minute)
	restarted := false
	for cycles := 0; now.Before(end) && cycles < 1000; cycles++ {
		before := len(base.probeCalls)
		if err := controller.Tick(now); err != nil {
			t.Fatal(err)
		}
		if count := len(base.probeCalls) - before; count > 2 {
			t.Fatalf("one quality lane queued %d sequential probes in one batch", count)
		}
		item = controller.state["europe"]
		if item.Selected != "active" {
			t.Fatal("bounded survey changed the active route")
		}
		if !restarted && !now.Before(restartAt) {
			controller.stateLoaded, base.reset, restarted = false, true, true
		}
		now = now.Add(max(time.Millisecond, controller.nextIntervalAt(now)))
	}
	for _, node := range contract.Candidates[1:] {
		pair, ok := item.LastLatencyComparisons[node]
		if !ok || pair.CandidateAt < float64(restartAt.Unix()) || pair.ActiveAt-pair.CandidateAt > 10 || pair.CandidateAt-pair.ActiveAt > 10 {
			t.Fatalf("single lane did not refresh a close-time comparison: %s pair=%+v", node, pair)
		}
	}
	t.Logf("members=24 display=%d quality_requests=%d physical_lanes=1 configured_batch=10", len(item.LastLatencyComparisons), len(base.probeCalls))
}
