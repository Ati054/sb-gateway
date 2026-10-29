package agent

import (
	"strings"
	"testing"
	"time"
)

func TestURLTestDefersIncoherentSharedQualityBatch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		lanes    int
		ages     map[string]time.Duration
		targets  []string
		deferred bool
		requests int
	}{
		{"skewed_cache", "best", 10, map[string]time.Duration{"active": 12 * time.Second, "reserve": 0}, []string{"active", "reserve"}, true, 0},
		{"coherent_old_cache", "best", 10, map[string]time.Duration{"active": 13 * time.Second, "reserve": 11 * time.Second}, []string{"active", "reserve"}, false, 0},
		{"cached_side_and_two_waves", "best", 2, map[string]time.Duration{"active": 2 * time.Second}, []string{"active", "reserve", "other", "last"}, true, 0},
		{"cached_side_and_one_wave", "best", 3, map[string]time.Duration{"active": 2 * time.Second}, []string{"active", "reserve", "other", "last"}, false, 3},
		{"all_fresh_two_waves", "best", 2, nil, []string{"active", "reserve", "other", "last"}, false, 4},
		{"priority_keeps_raw_sharing", "priority", 10, map[string]time.Duration{"active": 12 * time.Second, "reserve": 0}, []string{"active", "reserve"}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := &fakeSelectorRuntime{probes: map[string]probeEvidence{}}
			contract := budgetContract(tc.targets...)
			contract.Mode = tc.mode
			for _, node := range tc.targets {
				base.probes[node] = successfulEvidence(100)
			}
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
			controller := &healthController{runtime: &observedQualityRuntime{base}, state: healthState{"route": item}, processedPool: healthPool{ProbeLanes: tc.lanes}}
			controller.beginProbeBudget(healthPool{ProbeBudget: 10}, []string{"route"})
			for node, age := range tc.ages {
				at := time.Now().Add(-age)
				evidence := successfulEvidence(100)
				evidence.ObservedAt = at
				key := controller.probeKey("route", node, contract)
				controller.probeBudget.Quality[key] = sharedProbeResult{At: at, Evidence: evidence}
				controller.probeBudget.QualityAttempted[key], controller.probeBudget.Used[key] = true, true
			}
			accepted, deferred := controller.claimProbeTargets("route", contract, tc.targets, false)
			if len(deferred) != 0 || strings.Join(accepted, ",") != strings.Join(tc.targets, ",") {
				t.Fatalf("fixture did not admit the batch: accepted=%v deferred=%v", accepted, deferred)
			}
			measured := controller.sharedQualityBatch("route", contract, accepted)
			for _, node := range tc.targets {
				if measured[node].Deferred != tc.deferred {
					t.Fatalf("incoherent cache admitted or valid work postponed for %s: %+v", node, measured[node])
				}
			}
			if len(base.probeCalls) != tc.requests {
				t.Fatalf("unnecessary HTTPS work: got %v want %d", base.probeCalls, tc.requests)
			}
			if !tc.deferred {
				return
			}
			if controller.probeBudget.DeferredPolicies["route"].IsZero() || len(controller.probeBudget.Used) != len(tc.ages) {
				t.Fatal("deferred pair lost fairness or retained unstarted reservations")
			}
			// The next ordinary budget can complete the pair. The old cached
			// result is neither a failure nor another comparison confirmation.
			controller.beginProbeBudget(healthPool{ProbeBudget: 10}, []string{"route"})
			measured = controller.sharedQualityBatch("route", contract, tc.targets)
			for _, node := range tc.targets {
				if measured[node].Deferred || !measured[node].OK {
					t.Fatalf("pair did not resume: %s %+v", node, measured[node])
				}
			}
			if len(base.probeCalls) != len(tc.targets) {
				t.Fatal("deferred pair repeated or lost requests")
			}
		})
	}
}
