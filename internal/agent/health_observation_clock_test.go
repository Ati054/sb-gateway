package agent

import (
	"fmt"
	"testing"
	"time"
)

func TestSixPolicyCycleKeepsEachObservationInterval(t *testing.T) {
	controller, first, base := stagedOptimizationController(t)
	contract := base.pool.HealthPolicies["europe"]
	base.pool.HealthPolicies, controller.state, controller.warmStarted = map[string]healthPolicyContract{}, healthState{}, map[string]bool{}
	base.current = map[string]string{}
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("route-%d", i)
		item := first
		if i > 0 {
			_, item, _ = stagedOptimizationController(t)
		}
		clearOptimizationCandidate(item)
		controller.state[id], controller.warmStarted[id], base.current[id] = item, true, "active"
		base.pool.HealthPolicies[id] = contract
	}
	base.pool.ProbeBudget = 0 // Independent legacy endpoints; no shared evidence.
	started := time.Unix(1060, 0)
	clock := started
	controller.runtime = &timedPairTestRuntime{base, &clock, 4 * time.Second}
	if err := controller.Tick(started); err != nil {
		t.Fatal(err)
	}
	if len(base.probeCalls) != 12 {
		t.Fatalf("six complete pairs did not run: calls=%v", base.probeCalls)
	}
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("route-%d", i)
		observed := started.Add(time.Duration(i*8+4) * time.Second)
		if at := controller.state[id].LastProbeAt["active"]; at != float64(observed.Unix()) {
			t.Fatalf("%s lost its actual observation date: got=%v want=%v", id, at, observed.Unix())
		}
		if next := controller.regularNext[id]; next.Before(observed.Add(time.Minute)) {
			t.Fatalf("%s second pair scheduled from common cycle start: next=%v observed=%v", id, next, observed)
		}
	}
	clock = started.Add(time.Minute)
	if err := controller.Tick(clock); err != nil {
		t.Fatal(err)
	}
	if len(base.probeCalls) != 12 {
		t.Fatalf("late policies were remeasured before their intervals elapsed: calls=%v", base.probeCalls)
	}
}

type delayedObservationRuntime struct {
	*fakeSelectorRuntime
	observedAt time.Time
}

func (runtime *delayedObservationRuntime) Probe(node string) probeEvidence {
	evidence := runtime.fakeSelectorRuntime.Probe(node)
	evidence.ObservedAt = runtime.observedAt
	return evidence
}

func TestDelayedQualityResultsUseObservationDates(t *testing.T) {
	controller, item, base := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	started := time.Unix(1060, 0)
	observed := started.Add(52 * time.Second)
	runtime := &delayedObservationRuntime{fakeSelectorRuntime: base, observedAt: observed}
	controller.runtime = runtime
	if err := controller.Tick(started); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"active", "reserve"} {
		if item.LastProbeAt[node] != float64(observed.Unix()) || item.LastGoodAt[node] != float64(observed.Unix()) {
			t.Fatalf("%s observation dated from the old cycle: probe=%v good=%v want=%v", node, item.LastProbeAt[node], item.LastGoodAt[node], observed.Unix())
		}
		samples, daily := item.Samples[node], item.DailySamples[node]
		if samples[len(samples)-1].At != float64(observed.Unix()) || daily[len(daily)-1].At != float64(observed.Unix()) {
			t.Fatalf("%s fresh sample/history aged before completion: samples=%v daily=%v", node, samples, daily)
		}
	}
	if next := controller.regularNext["europe"]; next.Before(observed.Add(time.Minute)) {
		t.Fatalf("next quality cycle starts before its observation interval: next=%v observed=%v", next, observed)
	}
}

func TestSlowCycleCannotCompressIndependentConfirmationInterval(t *testing.T) {
	controller, item, base := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	started := time.Unix(1060, 0)
	observed := started.Add(52 * time.Second)
	runtime := &delayedObservationRuntime{fakeSelectorRuntime: base, observedAt: observed}
	controller.runtime = runtime
	if err := controller.Tick(started); err != nil {
		t.Fatal(err)
	}
	before := len(base.probeCalls)
	runtime.observedAt = observed.Add(8 * time.Second)
	if err := controller.Tick(runtime.observedAt); err != nil {
		t.Fatal(err)
	}
	if len(base.probeCalls) != before || item.Selected != "active" || item.OptimizationChecks != 1 {
		t.Fatalf("slow cycle manufactured a rapid second confirmation: probes=%v selected=%s confirmations=%d", base.probeCalls, item.Selected, item.OptimizationChecks)
	}
	runtime.observedAt = observed.Add(time.Minute)
	if err := controller.Tick(runtime.observedAt); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "reserve" {
		t.Fatalf("properly spaced fresh confirmation did not switch: selected=%s", item.Selected)
	}
}

func TestHistoryKeepsSharedObservationAge(t *testing.T) {
	now := time.Unix(1120, 0)
	item := newPolicyHealthState()
	evidence := successfulEvidence(100)
	evidence.ObservedAt = now.Add(-10 * time.Second)
	updateHistories(item, []string{"node"}, map[string]probeEvidence{"node": evidence}, now)
	if at := item.DailySamples["node"][0].At; at != float64(evidence.ObservedAt.Unix()) {
		t.Fatalf("shared history refreshed old evidence: at=%v want=%v", at, evidence.ObservedAt.Unix())
	}
}
