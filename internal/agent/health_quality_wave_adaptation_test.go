package agent

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestConcurrentSurveyRefreshesRecentAndPendingActive(t *testing.T) {
	for _, pending := range []bool{false, true} {
		now := time.Unix(1000, 100000000)
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
		ms := 900
		item.Samples["active"] = []healthSample{{At: 999, ObservedAt: 999, OK: true, DelayMS: &ms}}
		if pending {
			item.OptimizationBaseline, item.OptimizationCandidate = "active", "reserve"
			item.OptimizationChecks = 1
			item.OptimizationLastResult = &optimizationComparison{At: now.UTC().Format(time.RFC3339), Candidate: "reserve"}
		}
		controller := &healthController{runtime: &concurrentCohortRuntime{}, probeBudget: &healthProbeBudget{Limit: 2}}
		got := controller.withSurveyBaseline(now, "active", []string{"reserve", "other"}, item, effectivePolicySettings{mode: "best", batch: 2})
		if !reflect.DeepEqual(got, []string{"active", "reserve"}) || !reflect.DeepEqual(item.ScanQueue, []string{"other"}) {
			t.Fatalf("pending=%v targets=%v deferred=%v", pending, got, item.ScanQueue)
		}
	}
}

func TestParallelSurveyUsesPhysicalAndGlobalCapacity(t *testing.T) {
	for _, tc := range []struct{ lanes, budget, want int }{{2, 10, 2}, {10, 10, 10}, {1, 10, 2}, {2, 1, 1}} {
		controller := &healthController{runtime: &responsiveSelectorRuntime{parallelEnabled: true, backgrounds: make([]*xraySelectorRuntime, tc.lanes)}}
		controller.beginProbeBudget(healthPool{ProbeBudget: tc.budget}, nil)
		got := controller.surveySettings(effectivePolicySettings{mode: "best", batch: 10})
		if got.batch != tc.want {
			t.Fatalf("physical=%d global=%d batch=%d want=%d", tc.lanes, tc.budget, got.batch, tc.want)
		}
	}
}

func TestSingleWorkerDoesNotClaimConcurrentWave(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	queues := probeLaneJobs([]string{"active", "reserve"}, 1, true, cancel)
	for job := range queues[0] {
		if job.start != nil {
			t.Fatal("one physical worker tagged sequential jobs as a parallel wave")
		}
	}
}

type singlePhysicalQualityRuntime struct{ *timedPairTestRuntime }

func (*singlePhysicalQualityRuntime) qualityLaneCount() int { return 1 }

func (r *singlePhysicalQualityRuntime) ProbeQualityParallel(nodes []string) map[string]probeEvidence {
	result := map[string]probeEvidence{}
	for _, node := range nodes {
		result[node] = r.Probe(node)
	}
	return result
}

func TestSinglePhysicalLaneStillCompletesPlannedSwitch(t *testing.T) {
	for _, budget := range []int{1, 10} {
		controller, item, base := stagedOptimizationController(t)
		contract := base.pool.HealthPolicies["europe"]
		contract.Policy.ProbeBatchSize = 10
		base.pool.HealthPolicies["europe"], base.pool.ProbeBudget, base.pool.ProbeLanes = contract, budget, 1
		now := time.Unix(1060, 173000000)
		controller.runtime = &singlePhysicalQualityRuntime{&timedPairTestRuntime{base, &now, 375 * time.Millisecond}}
		end := now.Add(4 * time.Minute)
		for cycles := 0; cycles < 300 && now.Before(end); cycles++ {
			before := len(base.probeCalls)
			if err := controller.Tick(now); err != nil {
				t.Fatal(err)
			}
			if len(base.probeCalls)-before > min(budget, 2) {
				t.Fatal("single-line work exceeded its effective budget")
			}
			if item.Selected == "reserve" {
				break
			}
			now = now.Add(max(time.Millisecond, controller.nextIntervalAt(now)))
		}
		if item.Selected != "reserve" {
			t.Fatalf("budget=%d single-line comparison starved: %+v", budget, item.OptimizationLastResult)
		}
	}
}

func TestBusySharedBudgetDefersWholeConcurrentPair(t *testing.T) {
	c := &healthController{runtime: &concurrentCohortRuntime{}}
	c.beginProbeBudget(healthPool{ProbeBudget: 2}, []string{"first", "second"})
	c.claimProbeTargets("first", budgetContract("other"), []string{"other"}, false)
	accepted, deferred := c.claimProbeTargets("second", budgetContract("active", "reserve"), []string{"active", "reserve"}, true)
	if len(accepted) != 0 || len(deferred) != 2 || len(c.probeBudget.Used) != 1 {
		t.Fatalf("partial pair consumed remaining shared slot: accepted=%v deferred=%v", accepted, deferred)
	}
	c.beginProbeBudget(healthPool{ProbeBudget: 2}, []string{"first", "second"})
	accepted, deferred = c.claimProbeTargets("second", budgetContract("active", "reserve"), []string{"active", "reserve"}, true)
	if len(accepted) != 2 || len(deferred) != 0 {
		t.Fatal("deferred pair did not resume with the next complete budget")
	}
}
