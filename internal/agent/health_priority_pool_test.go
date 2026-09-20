package agent

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestPriorityPoolFollowsFullRuntimeSelectionNotSavedURLTestLimit(t *testing.T) {
	pool := healthFixture(true)
	contract := pool.HealthPolicies["europe"]
	contract.Policy.MaxActiveCandidates = 1
	contract.Policy.MaxProbeCandidates = 1
	contract.Policy.ProbeBatchSize = 3
	contract.Groups = nil
	runtime := &fakeSelectorRuntime{pool: pool, probes: map[string]probeEvidence{}}
	controller := &healthController{opts: Options{StateRoot: t.TempDir()}, runtime: runtime, warmStarted: map[string]bool{}}
	second := int64(1000)
	// More than the old schema cap, subscription growth, then removal. No
	// manual edit to max_active_candidates is needed for any generation.
	for _, count := range []int{12, 16, 4} {
		contract.Candidates = nil
		for index := 0; index < count; index++ {
			id := fmt.Sprintf("node-%02d", index)
			contract.Candidates = append(contract.Candidates, id)
			runtime.probes[id] = successfulEvidence(500 - index)
		}
		runtime.pool.HealthPolicies["europe"] = contract
		for tick := 0; tick < 100; tick++ {
			before := len(runtime.probeCalls)
			if err := controller.Tick(time.Unix(second, 0)); err != nil {
				t.Fatal(err)
			}
			second++
			if len(runtime.probeCalls)-before > 3 {
				t.Fatal("full priority queue increased probe batch")
			}
		}
		item := controller.state["europe"]
		if item.ProbeLimits.Shortlist != count || !reflect.DeepEqual(item.Shortlist, contract.Candidates) {
			t.Fatalf("count=%d: effective limit=%d pool=%v", count, item.ProbeLimits.Shortlist, item.Shortlist)
		}
		if item.Selected != "node-00" || runtime.speedCalls != 0 {
			t.Fatal("priority order or disabled speed checks changed")
		}
	}
	contract.Mode = "best"
	runtime.pool.HealthPolicies["europe"] = contract
	if err := controller.Tick(time.Unix(second, 0)); err != nil {
		t.Fatal(err)
	}
	if got := controller.state["europe"]; got.ProbeLimits.Shortlist != 1 || len(got.Shortlist) != 1 {
		t.Fatalf("return to URLTest must restore its saved limit: %+v", got.ProbeLimits)
	}
}
