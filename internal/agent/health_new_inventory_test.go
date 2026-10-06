package agent

import (
	"testing"
	"time"
)

func TestAddedSubscriptionNodeRequiresFreshWinsOnlyInURLTest(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, item, runtime := stagedOptimizationController(t)
			contract := runtime.pool.HealthPolicies["europe"]
			contract.Mode = mode
			contract.Policy.SwitchImprovementMS = 200
			contract.Policy.ProbeBatchSize = 3
			contract.Candidates = append(contract.Candidates, "new-subscription")
			contract.Nodes["new-subscription"] = healthNode{SubscriptionID: "new", Label: "new"}
			runtime.pool.HealthPolicies["europe"] = contract
			item.Mode = mode
			runtime.probes["active"], runtime.probes["reserve"] = successfulEvidence(500), successfulEvidence(600)
			runtime.probes["new-subscription"] = successfulEvidence(100)
			for _, at := range []int64{1060, 1120, 1180, 1240} {
				if err := controller.Tick(time.Unix(at, 0)); err != nil {
					t.Fatal(err)
				}
				if (at < 1240 || mode == "priority") && item.Selected != "active" {
					t.Fatalf("mode=%s switched prematurely at %d to %s", mode, at, item.Selected)
				}
			}
			if mode == "best" && (item.Selected != "new-subscription" || item.LastSwitchReason != "meaningfully-faster") {
				t.Fatalf("fresh added-node wins did not select the faster node: %+v", item.OptimizationLastResult)
			}
		})
	}
}

func TestAddedSubscriptionNodeDoesNotBypassURLTestTolerance(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.SwitchImprovementMS = 200
	contract.Policy.ProbeBatchSize = 3
	contract.Candidates = append(contract.Candidates, "new-subscription")
	contract.Nodes["new-subscription"] = healthNode{SubscriptionID: "new"}
	runtime.pool.HealthPolicies["europe"] = contract
	runtime.probes["active"], runtime.probes["reserve"] = successfulEvidence(500), successfulEvidence(600)
	runtime.probes["new-subscription"] = successfulEvidence(300)
	for at := int64(1060); at <= 1360; at += 60 {
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if item.Selected != "active" {
			t.Fatal("adding a subscription bypassed the strict improvement threshold")
		}
	}
}
