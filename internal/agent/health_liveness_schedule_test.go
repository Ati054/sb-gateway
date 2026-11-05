package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type scheduledLivenessRuntime struct {
	*fakeSelectorRuntime
	clock  *time.Time
	proofs []time.Time
}

func (runtime *scheduledLivenessRuntime) Probe(node string) probeEvidence {
	evidence := runtime.fakeSelectorRuntime.Probe(node)
	evidence.QualityStartedAt = *runtime.clock
	*runtime.clock = runtime.clock.Add(425 * time.Millisecond)
	evidence.ObservedAt = *runtime.clock
	if node == "active" && evidence.OK {
		runtime.proofs = append(runtime.proofs, *runtime.clock)
	}
	return evidence
}

func (runtime *scheduledLivenessRuntime) ProbeAvailability(node string) probeEvidence {
	evidence := runtime.fakeSelectorRuntime.ProbeAvailability(node)
	*runtime.clock = runtime.clock.Add(425 * time.Millisecond)
	evidence.ObservedAt = *runtime.clock
	if node == "active" && evidence.OK {
		runtime.proofs = append(runtime.proofs, *runtime.clock)
	}
	return evidence
}

func scheduledLivenessFixture(t *testing.T) (*healthController, *policyHealthState, *scheduledLivenessRuntime) {
	t.Helper()
	controller, item, base := stagedOptimizationController(t)
	contract := base.pool.HealthPolicies["europe"]
	contract.Candidates = []string{"active"}
	contract.Nodes = map[string]healthNode{"active": {Label: "Active"}}
	for i := 1; i < 24; i++ {
		node := fmt.Sprintf("reserve-%02d", i)
		contract.Candidates = append(contract.Candidates, node)
		contract.Nodes[node] = healthNode{Label: node}
	}
	contract.Policy.ProbeBatchSize, contract.Policy.ActiveLivenessSeconds = 1, 3
	contract.Policy.SwitchImprovementMS = 200
	base.pool.ProbeBudget, base.pool.ProbeLanes = 1, 1
	base.pool.HealthPolicies["europe"] = contract
	base.underlay = underlayEvidence{Known: true, WANOK: true, DNSOK: true}
	clearOptimizationCandidate(item)
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.CandidateNodes = contract.Nodes
	item.ScanQueue = append([]string(nil), contract.Candidates...)
	now := time.Unix(1060, 0)
	start := now
	delay := 500
	for _, node := range contract.Candidates {
		base.probes[node] = successfulEvidence(delay)
		item.AvailabilityOK[node], item.QualityOK[node] = true, true
		item.LastProbeAt[node], item.Recoveries[node] = 1000, 3
		item.Samples[node] = []healthSample{{At: float64(start.Unix()), OK: true, DelayMS: &delay}}
	}
	runtime := &scheduledLivenessRuntime{fakeSelectorRuntime: base, clock: &now, proofs: []time.Time{start}}
	controller.runtime = runtime
	return controller, item, runtime
}

func TestSingleSlotSurveyDoesNotStarveActiveLivenessAtActualWake(t *testing.T) {
	controller, _, runtime := scheduledLivenessFixture(t)
	base := runtime.fakeSelectorRuntime
	now := runtime.clock
	start := *now
	deadline := start.Add(40 * time.Second)
	for cycles := 0; cycles < 80 && now.Before(deadline); cycles++ {
		before := len(base.probeCalls)
		if err := controller.Tick(*now); err != nil {
			t.Fatal(err)
		}
		if len(base.probeCalls)-before > 1 {
			t.Fatal("one-slot quality budget exceeded")
		}
		if gap := now.Sub(runtime.proofs[len(runtime.proofs)-1]); gap > 6*time.Second {
			t.Fatalf("short survey jobs starved active proof: gap=%s quality=%v availability=%v", gap, base.probeCalls, base.availabilityCalls)
		}
		*now = now.Add(controller.nextIntervalAt(*now))
	}
	seen := map[string]bool{}
	for _, node := range base.probeCalls {
		seen[node] = true
	}
	if len(seen) < 6 {
		t.Fatalf("liveness displaced quality progress: %v", base.probeCalls)
	}
}

func TestSingleSlotShortSurveyDetectsActiveOutageWithoutFailureSignal(t *testing.T) {
	controller, item, runtime := scheduledLivenessFixture(t)
	now := runtime.clock
	start := *now
	var failedAt time.Time
	for cycles := 0; cycles < 100 && now.Sub(start) < time.Minute; cycles++ {
		if failedAt.IsZero() && now.Sub(start) >= 15*time.Second {
			failedAt = *now
			runtime.probes["active"] = probeEvidence{Failure: probeFailureTimeout}
		}
		if err := controller.Tick(*now); err != nil {
			t.Fatal(err)
		}
		if item.Selected != "active" {
			if failedAt.IsZero() || now.Sub(failedAt) > 15*time.Second || item.LastSwitchReason != "active-unavailable" {
				t.Fatalf("outage was delayed or quality changed route: selected=%s reason=%s elapsed=%s", item.Selected, item.LastSwitchReason, now.Sub(failedAt))
			}
			return
		}
		*now = now.Add(controller.nextIntervalAt(*now))
	}
	t.Fatalf("active outage waited for the quality sweep: quality=%v availability=%v", runtime.probeCalls, runtime.availabilityCalls)
}
