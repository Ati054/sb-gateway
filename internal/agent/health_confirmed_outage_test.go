package agent

import (
	"fmt"
	"testing"
	"time"
)

func TestConfirmedOutageBypassesQualityAndActiveRetryDeadlines(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, warm := range []bool{false, true} {
			for _, forced := range []bool{false, true} {
				for _, extra := range []int{0, 1} {
					t.Run(fmt.Sprintf("%s/warm=%t/forced=%t/extra=%d", mode, warm, forced, extra), func(t *testing.T) {
						controller, runtime, now := warmControllerFixture(t, 2, 1, 1)
						contract := runtime.pool.HealthPolicies["route"]
						contract.Mode = mode
						runtime.pool.HealthPolicies["route"] = contract
						controller.opts.URLTestWarmCompare = warm
						item := controller.state["route"]
						item.Mode = mode
						active, reserve := contract.Candidates[0], contract.Candidates[1]
						// An already confirmed failure can be observed between ordinary
						// quality turns. Neither deadline grants it another active retry.
						item.AvailabilityFailures[active] = policySettings(contract.Policy, mode).failureThreshold + extra
						item.FailureClass[active] = string(probeFailureTimeout)
						item.LastProbeAt[active] = float64(now.Unix())
						controller.regularNext = map[string]time.Time{"route": now.Add(time.Hour)}
						controller.livenessAt = map[string]time.Time{"route": now}
						controller.forceLiveness = map[string]bool{"route": forced}
						runtime.probes[active] = probeEvidence{Failure: probeFailureTimeout}

						if err := controller.Tick(now); err != nil {
							t.Fatal(err)
						}
						if item.Selected != reserve || item.LastSwitchReason != "active-unavailable" {
							t.Fatalf("confirmed outage waited for another deadline: selected=%s reason=%s", item.Selected, item.LastSwitchReason)
						}
						for _, node := range runtime.availabilityCalls {
							if node == active {
								t.Fatal("already confirmed active failure consumed another availability request")
							}
						}
						if len(runtime.measurements) != 0 {
							t.Fatal("emergency dispatch performed a planned quality measurement")
						}
					})
				}
			}
		}
	}
}

func TestUnconfirmedOutageStillWaitsForIndependentActiveRetry(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, warm := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/warm=%t", mode, warm), func(t *testing.T) {
				controller, runtime, now := warmControllerFixture(t, 2, 1, 1)
				contract := runtime.pool.HealthPolicies["route"]
				contract.Mode = mode
				runtime.pool.HealthPolicies["route"] = contract
				controller.opts.URLTestWarmCompare = warm
				item := controller.state["route"]
				item.Mode = mode
				active := item.Selected
				item.AvailabilityFailures[active] = 1
				item.FailureClass[active] = string(probeFailureTimeout)
				item.LastProbeAt[active] = float64(now.Unix())
				controller.regularNext = map[string]time.Time{"route": now.Add(time.Hour)}
				controller.livenessAt = map[string]time.Time{"route": now}
				runtime.probes[active] = probeEvidence{Failure: probeFailureTimeout}
				if err := controller.Tick(now); err != nil {
					t.Fatal(err)
				}
				if item.Selected != active || item.AvailabilityFailures[active] != 1 || len(runtime.availabilityCalls) != 0 || len(runtime.measurements) != 0 {
					t.Fatalf("unconfirmed failure bypassed its retry: selected=%s availability=%v quality=%v", item.Selected, runtime.availabilityCalls, runtime.measurements)
				}
			})
		}
	}
}
