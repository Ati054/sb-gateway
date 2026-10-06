package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLatencyOnlyStateUpgradePreservesAvailabilityAndDropsCooldown(t *testing.T) {
	legacy := []byte(`{"selected":"active","cooldown_until":10600,"recoveries":{"active":3},"availability_failures":{"reserve":2},"samples":{"active":[{"ok":true,"delay_ms":400}]},"speed_samples_bps":{},"outage_penalty":{"reserve":{"count":3,"until":999999}},"optimization_candidate":"reserve","optimization_baseline":"active","optimization_checks":2,"optimization_next_at":999999,"optimization_backoff":{"reserve":999999}}`)
	var item policyHealthState
	if err := json.Unmarshal(legacy, &item); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "active" || item.Recoveries["active"] != 3 || item.AvailabilityFailures["reserve"] != 2 || len(item.Samples["active"]) != 1 {
		t.Fatal("upgrade lost availability or history")
	}
	if item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
		t.Fatal("legacy speed comparison became a latency confirmation")
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cooldown_until", "speed_", "outage_penalty", "optimization_backoff", "optimization_next_at", "optimization_active_ms", "probe_lane", "next_full_scan_at"} {
		if strings.Contains(string(encoded), key) {
			t.Fatalf("legacy field survived publication: %s", key)
		}
	}
	item.OptimizationCandidate, item.OptimizationBaseline, item.OptimizationChecks = "reserve", "active", 1
	encoded, _ = json.Marshal(item)
	var restored policyHealthState
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.OptimizationCandidate != "reserve" || restored.OptimizationChecks != 1 {
		t.Fatal("new latency comparison was discarded on restart")
	}
}

func TestProbeLanesBoundedByEligibleInventory(t *testing.T) {
	for _, requested := range []int{1, 5, 10, 64, 100} {
		for _, inventory := range []int{0, 1, 5, 100} {
			pool := healthPool{ProbeBudget: requested, HealthPolicies: map[string]healthPolicyContract{}}
			contract := healthPolicyContract{}
			for i := 0; i < inventory; i++ {
				contract.Candidates = append(contract.Candidates, fmt.Sprint(i))
			}
			pool.HealthPolicies["first"], pool.HealthPolicies["second"] = contract, contract
			want := maxInt(1, minInt(64, minInt(requested, inventory)))
			if got := healthProbeLaneCount(pool); got != want {
				t.Fatalf("request=%d inventory=%d overlapping lists: lanes=%d want=%d", requested, inventory, got, want)
			}
		}
	}
}

func TestProbeLaneAllocationStableAcrossHotEligibilityEdit(t *testing.T) {
	pool := healthPool{ProbeBudget: 64, Outbounds: map[string]json.RawMessage{"a": {}, "b": {}}, HealthPolicies: map[string]healthPolicyContract{"route": {Candidates: []string{"a", "b"}}}}
	before := healthProbeLaneCount(pool)
	pool.HealthPolicies["route"] = healthPolicyContract{Candidates: []string{"a"}}
	if before != 2 || healthProbeLaneCount(pool) != before {
		t.Fatal("hot membership edit resized the core probe contract")
	}
}

func TestProbeLaneCountUsesRenderedContractForStaticCandidates(t *testing.T) {
	pool := healthPool{ProbeBudget: 10, ProbeLanes: 3, Outbounds: map[string]json.RawMessage{"dynamic": {}}}
	if got := healthProbeLaneCount(pool); got != 3 {
		t.Fatalf("static lanes were lost: got %d", got)
	}
	pool.ProbeBudget = 2
	if got := healthProbeLaneCount(pool); got != 2 {
		t.Fatalf("declared lanes bypassed manual budget: got %d", got)
	}
}
