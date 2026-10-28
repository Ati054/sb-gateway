package agent

import (
	"fmt"
	"testing"
	"time"
)

type timedPairTestRuntime struct {
	*fakeSelectorRuntime
	clock    *time.Time
	duration time.Duration
}

func (runtime *timedPairTestRuntime) Probe(candidate string) probeEvidence {
	evidence := runtime.fakeSelectorRuntime.Probe(candidate)
	*runtime.clock = runtime.clock.Add(runtime.duration)
	evidence.ObservedAt = *runtime.clock
	return evidence
}

func TestSingleSlotPairUsesActualControllerWakeSchedule(t *testing.T) {
	for _, liveness := range []int{3, 30} {
		for _, latency := range []time.Duration{time.Second, 5 * time.Second} {
			t.Run(fmt.Sprintf("liveness%d/probe%s", liveness, latency), func(t *testing.T) {
				controller, item, base := stagedOptimizationController(t)
				contract := base.pool.HealthPolicies["europe"]
				contract.Policy.ProbeBatchSize, contract.Policy.ActiveLivenessSeconds = 1, liveness
				base.pool.HealthPolicies["europe"] = contract
				base.pool.ProbeBudget = 1
				now := time.Unix(1060, 0)
				controller.runtime = &timedPairTestRuntime{base, &now, latency}
				deadline := now.Add(4 * time.Minute)
				for cycles := 0; cycles < 300 && now.Before(deadline); cycles++ {
					before := len(base.probeCalls)
					if err := controller.Tick(now); err != nil {
						t.Fatal(err)
					}
					if len(base.probeCalls)-before > 1 {
						t.Fatal("one-slot quality budget exceeded")
					}
					if item.Selected == "reserve" {
						return
					}
					now = now.Add(controller.nextIntervalAt(now))
				}
				t.Fatalf("actual wake scheduling starved planned switching: checks=%d last=%+v next=%v calls=%v", item.OptimizationChecks, item.OptimizationLastResult, controller.regularNext, base.probeCalls)
			})
		}
	}
}

func TestOverduePairCoolsAndResumesWhenProbeTimingRecovers(t *testing.T) {
	controller, item, base := stagedOptimizationController(t)
	contract := base.pool.HealthPolicies["europe"]
	contract.Policy.ProbeBatchSize, contract.Policy.ActiveLivenessSeconds = 1, 30
	base.pool.HealthPolicies["europe"] = contract
	base.pool.ProbeBudget = 1
	now := time.Unix(1060, 0)
	runtime := &timedPairTestRuntime{base, &now, 15 * time.Second}
	controller.runtime = runtime
	slowUntil := now.Add(3 * time.Minute)
	for cycles := 0; now.Before(slowUntil); cycles++ {
		if cycles > 30 {
			t.Fatal("expired pair caused a tight retry loop")
		}
		if err := controller.Tick(now); err != nil {
			t.Fatal(err)
		}
		if item.Selected != "active" || item.OptimizationChecks != 0 {
			t.Fatal("overdue pair earned a win")
		}
		now = now.Add(controller.nextIntervalAt(now))
	}
	if len(base.probeCalls) > 10 {
		t.Fatal("slow-pair retries exceeded normal quality cadence")
	}
	runtime.duration = time.Second
	until := now.Add(4 * time.Minute)
	for cycles := 0; cycles < 100 && now.Before(until); cycles++ {
		if err := controller.Tick(now); err != nil {
			t.Fatal(err)
		}
		if item.Selected == "reserve" {
			return
		}
		now = now.Add(controller.nextIntervalAt(now))
	}
	t.Fatal("timing recovery left planned switching stuck")
}

func TestSharedSingleSlotCompletesPairsWithoutStarvingOtherPolicies(t *testing.T) {
	for _, mixedIntervals := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixedIntervals=%t", mixedIntervals), func(t *testing.T) {
			controller, first, base := stagedOptimizationController(t)
			contract := base.pool.HealthPolicies["europe"]
			contract.Policy.ProbeBatchSize, contract.Policy.ActiveLivenessSeconds = 1, 30
			base.pool.HealthPolicies = map[string]healthPolicyContract{}
			controller.state, controller.warmStarted = healthState{}, map[string]bool{}
			for i := 0; i < 3; i++ {
				id := fmt.Sprintf("route-%d", i)
				item := first
				if i > 0 {
					_, item, _ = stagedOptimizationController(t)
				}
				controller.state[id], controller.warmStarted[id] = item, true
				ownContract := contract
				if mixedIntervals {
					ownContract.Policy.ActiveCheckSeconds = []int{3, 30, 60}[i]
				}
				base.pool.HealthPolicies[id] = ownContract
				base.current[id] = "active"
			}
			base.pool.ProbeBudget = 1
			now := time.Unix(1060, 0)
			controller.runtime = &timedPairTestRuntime{base, &now, 4 * time.Second}
			until := now.Add(5 * time.Minute)
			for cycles := 0; cycles < 300 && now.Before(until); cycles++ {
				before := len(base.probeCalls)
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				if len(base.probeCalls)-before > 1 {
					t.Fatal("shared one-slot budget exceeded")
				}
				complete := true
				for _, item := range controller.state {
					complete = complete && item.Selected == "reserve"
				}
				if complete {
					return
				}
				now = now.Add(controller.nextIntervalAt(now))
			}
			t.Fatal("shared slot starved a policy's paired comparison")
		})
	}
}

func TestPairContinuationDoesNotAccelerateFailurePolling(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, underlay := range []bool{false, true} {
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
		item.OptimizationBaseline, item.OptimizationCandidate = "active", "reserve"
		item.ProbeLimits.LivenessSeconds, item.ProbeLimits.FailureRetrySeconds = 30, 2
		if underlay {
			item.UnderlayFailure = "wan"
		} else {
			item.AvailabilityFailures["active"] = 1
		}
		controller := &healthController{opts: Options{HealthInterval: time.Minute}, state: healthState{"route": item}, regularNext: map[string]time.Time{"route": now.Add(-time.Second)}}
		if got := controller.nextIntervalAt(now); got != 2*time.Second {
			t.Fatalf("failure polling interval=%s", got)
		}
	}
}
