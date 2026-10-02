package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSingleProbeLaneRetriesMissingCandidateSpeed(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.ProbeBatchSize = 1
	runtime.pool.HealthPolicies["europe"] = contract
	delete(runtime.speeds, "reserve")

	tick := func(at int64) {
		t.Helper()
		probes, downloads := len(runtime.probeCalls), len(runtime.throughputCalls)
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls)-probes > 1 || len(runtime.throughputCalls)-downloads > 1 {
			t.Fatalf("single-lane tick at %d exceeded its batch", at)
		}
	}
	tick(1_060)
	tick(1_120)
	if item.Selected != "active" || item.OptimizationCandidate != "reserve" || item.OptimizationIncomplete != 1 ||
		item.OptimizationNextAt != 1_240 || item.OptimizationRetryAfter != 0 ||
		item.OptimizationLastResult == nil || item.OptimizationLastResult.Reason != "candidate-speed-missing" ||
		item.OptimizationLastResult.CandidateSpeedBPS != nil {
		t.Fatalf("missing candidate speed was treated as a measured loss: %+v", item.OptimizationLastResult)
	}
	if len(item.SpeedSamplesBPS["reserve"]) != 1 || item.SpeedSamplesBPS["reserve"][0] != 16_000 {
		t.Fatal("failed download changed historical speed")
	}

	runtime.speeds["reserve"] = 16_000
	for _, at := range []int64{1_240, 1_300, 1_360} {
		tick(at)
		if item.Selected != "active" {
			t.Fatalf("incomplete confirmation switched at %d", at)
		}
	}
	tick(1_420)
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatalf("two complete pairs did not select reserve: selected=%q reason=%q", item.Selected, item.LastSwitchReason)
	}
}

func TestPlannedComparisonPreservesUnprobedScanCandidates(t *testing.T) {
	for _, batch := range []int{1, 2} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			controller, item, runtime := stagedOptimizationController(t)
			contract := runtime.pool.HealthPolicies["europe"]
			contract.Policy.ProbeBatchSize = batch
			contract.Candidates = append(contract.Candidates, "background1", "background2")
			for _, candidate := range []string{"background1", "background2"} {
				contract.Nodes[candidate] = healthNode{Label: candidate}
				runtime.probes[candidate] = successfulEvidence(700)
			}
			runtime.pool.HealthPolicies["europe"] = contract
			item.CandidateSignature = strings.Join(contract.Candidates, "\n")
			item.ScanQueue = []string{"background1", "background2"}
			item.ProbeLane = 3

			if err := controller.Tick(time.Unix(1_060, 0)); err != nil {
				t.Fatal(err)
			}
			if strings.Join(item.ScanQueue, ",") != "background1,background2" {
				t.Fatalf("optimization discarded unprobed scan candidates: %v", item.ScanQueue)
			}
			if item.ProbeLane != 3 {
				t.Fatalf("optimization advanced unused regular lanes: %d", item.ProbeLane)
			}
			if len(runtime.probeCalls) != batch || contains(runtime.probeCalls, "background1") || contains(runtime.probeCalls, "background2") {
				t.Fatalf("optimization escaped its bounded pair: %v", runtime.probeCalls)
			}

			clearOptimizationCandidate(item)
			item.CooldownUntil = 2_000
			for _, at := range []int64{1_120, 1_180, 1_240, 1_300} {
				if err := controller.Tick(time.Unix(at, 0)); err != nil {
					t.Fatal(err)
				}
			}
			for _, candidate := range []string{"background1", "background2"} {
				if item.LastProbeAt[candidate] == 0 {
					t.Fatalf("%s waited for the next full scan", candidate)
				}
			}
		})
	}
}

func TestPlannedComparisonReconsidersBetterFreshNomineeBeforeSwitch(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Candidates = append(contract.Candidates, "better")
	contract.Nodes["better"] = healthNode{Label: "Better"}
	runtime.pool.HealthPolicies["europe"] = contract
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	betterDelay := 400
	item.Samples["better"] = []healthSample{{OK: true, DelayMS: &betterDelay}, {OK: true, DelayMS: &betterDelay}, {OK: true, DelayMS: &betterDelay}}
	item.AvailabilityOK["better"], item.QualityOK["better"] = true, true
	item.Recoveries["better"] = 3
	item.LastProbeAt["better"], item.LastSpeedProbeAt["better"] = 1_000, 1_000
	item.LastSpeedSuccessAt["better"] = 1_000
	item.SpeedSamplesBPS["reserve"] = []int64{20_000_000}
	item.SpeedSamplesBPS["active"] = []int64{12_000_000}
	item.SpeedSamplesBPS["better"] = []int64{18_000_000}
	runtime.speeds["active"], runtime.speeds["reserve"], runtime.speeds["better"] = 12_000_000, 15_000_000, 18_000_000
	runtime.probes["reserve"], runtime.probes["better"] = successfulEvidence(520), successfulEvidence(betterDelay)

	if err := controller.Tick(time.Unix(1_000, 0)); err != nil {
		t.Fatal(err)
	}
	if item.OptimizationCandidate != "reserve" {
		t.Fatalf("historical speed leader was not nominated: %q", item.OptimizationCandidate)
	}
	for _, at := range []int64{1_060, 1_120, 1_180, 1_240} {
		probes, downloads := len(runtime.probeCalls), len(runtime.throughputCalls)
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls)-probes > 2 || len(runtime.throughputCalls)-downloads > 2 {
			t.Fatalf("reconsideration exceeded the original paired batch at %d", at)
		}
		if hasSelection(runtime.selections, "europe", "reserve") {
			t.Fatalf("selected intermediate reserve despite a better fresh nominee at %d: %v", at, runtime.selections)
		}
		if at == 1_120 && (item.Selected != "active" || item.OptimizationCandidate != "better" || item.OptimizationChecks != 0) {
			t.Fatal("new nominee inherited confirmations or switched before its own comparison")
		}
		if at == 1_180 && (item.Selected != "active" || item.OptimizationChecks != 1) {
			t.Fatal("new nominee did not wait for its second successful pair")
		}
	}
	if item.Selected != "better" || len(runtime.selections) != 1 {
		t.Fatalf("better reserve was not confirmed without an intermediate hop: %v", runtime.selections)
	}
}

func TestMinorNomineeLeadDoesNotRestartConfirmedComparison(t *testing.T) {
	item := newPolicyHealthState()
	item.OptimizationCandidate, item.OptimizationBaseline = "reserve", "active"
	item.OptimizationChecks = 1
	activeDelay, reserveDelay, otherDelay := 600, 520, 500
	activeSpeed, reserveSpeed, otherSpeed := int64(12_000_000), int64(15_000_000), int64(16_000_000)
	comparison := &optimizationComparison{
		Candidate: "reserve", Result: optimizationWin, Reason: "better",
		ActiveDelayMS: &activeDelay, CandidateDelayMS: &reserveDelay,
		ActiveSpeedBPS: &activeSpeed, CandidateSpeedBPS: &reserveSpeed,
	}
	settings := effectivePolicySettings{active: 60, cooldown: 600, improvement: 50, speedEnabled: true, speedImprovement: 25}
	reconsiderPlannedOptimization("active", "other", "meaningfully-faster", comparison, item,
		map[string]*int{"other": &otherDelay}, map[string]*int64{"other": &otherSpeed}, settings)
	desired, reason := gatePlannedOptimization(time.Unix(1_120, 0), "active", "other", "meaningfully-faster", comparison, item, settings)
	if desired != "reserve" || reason != "meaningfully-faster" {
		t.Fatalf("minor lead restarted a confirmed comparison: %q %q", desired, reason)
	}
}
