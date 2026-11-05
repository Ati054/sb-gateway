package agent

import (
	"testing"
	"time"
)

func TestURLTestTransientWANJitterDoesNotMoveWorkingRoute(t *testing.T) {
	for _, scenario := range []struct {
		name            string
		active, reserve []int
		wantSwitch      bool
	}{
		{"single-spike", []int{1500, 300, 300, 300}, []int{300, 300, 300, 300}, false},
		{"recurring-short-spikes", []int{1500, 300, 1700, 300, 1400, 300}, []int{300, 300, 300, 300, 300, 300}, false},
		{"shared-wan-queue", []int{1500, 1700, 1400, 300}, []int{1450, 1650, 1350, 300}, false},
		{"sustained-node-degradation", []int{1500, 1500, 1500, 1500}, []int{300, 300, 300, 300}, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			controller, item, runtime := stagedOptimizationController(t)
			contract := runtime.pool.HealthPolicies["europe"]
			contract.Policy.SwitchImprovementMS = 200
			runtime.pool.HealthPolicies["europe"] = contract
			for _, id := range contract.Candidates {
				delay := 300
				item.Samples[id] = []healthSample{{At: 995, OK: true, DelayMS: &delay}, {At: 998, OK: true, DelayMS: &delay}, {At: 1000, OK: true, DelayMS: &delay}}
			}
			for round, active := range scenario.active {
				runtime.probes["active"] = successfulEvidence(active)
				runtime.probes["reserve"] = successfulEvidence(scenario.reserve[round])
				if err := controller.Tick(time.Unix(1060+int64(round)*60, 0)); err != nil {
					t.Fatal(err)
				}
				if !scenario.wantSwitch && item.Selected != "active" {
					t.Fatalf("transient/shared delay moved a working route at round %d: %s", round, item.Selected)
				}
			}
			if scenario.wantSwitch && (item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster") {
				t.Fatalf("sustained degradation was hidden: selected=%s reason=%s", item.Selected, item.LastSwitchReason)
			}
		})
	}
}
