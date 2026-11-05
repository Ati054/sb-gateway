package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCadenceFreshPlanningSingleSlotPoolProgress(t *testing.T) {
	for _, nodes := range []int{7, 10, 24} {
		for _, policies := range []int{1, 6} {
			for _, shared := range []bool{false, true} {
				t.Run(fmt.Sprintf("nodes%d/policies%d/shared%v", nodes, policies, shared), func(t *testing.T) {
					controller, runtime, base := disjointWarmScanFixture(t, policies)
					controller.opts.URLTestPlanningMode = URLTestPlanningFreshPaired
					for id, contract := range runtime.pool.HealthPolicies {
						item := controller.state[id]
						for n := 2; n < nodes; n++ {
							name := fmt.Sprintf("%s-node-%02d", id, n)
							contract.Candidates = append(contract.Candidates, name)
							contract.Nodes[name] = healthNode{Fingerprint: "synthetic-" + name, Protocol: "vless", Transport: "ws"}
							runtime.probes[name] = successfulEvidence(400)
							item.LastProbeAt[name], item.Recoveries[name], item.AvailabilityOK[name], item.QualityOK[name] = 935, 3, true, true
						}
						item.CandidateSignature, item.CandidateNodes = strings.Join(contract.Candidates, "\n"), contract.Nodes
						runtime.pool.HealthPolicies[id] = contract
					}
					if shared {
						first := runtime.pool.HealthPolicies["disjoint-0"]
						body, _ := json.Marshal(controller.state["disjoint-0"])
						for id := range runtime.pool.HealthPolicies {
							var item policyHealthState
							if err := json.Unmarshal(body, &item); err != nil {
								t.Fatal(err)
							}
							runtime.pool.HealthPolicies[id], controller.state[id], runtime.current[id] = first, &item, item.Selected
						}
					}
					observed := map[string]time.Time{}
					counts := map[string]int{}
					now := base
					done, throttled := false, false
					for tick := 0; tick < 10000 && now.Before(base.Add(20*time.Minute)); tick++ {
						runtime.at = now
						before := len(runtime.probeCalls)
						if err := controller.Tick(now); err != nil {
							t.Fatal(err)
						}
						if len(runtime.probeCalls)-before > 1 {
							t.Fatal("quality jobs escaped the shared one-slot budget")
						}
						done = true
						for id, item := range controller.state {
							contract := runtime.pool.HealthPolicies[id]
							if item.Selected != contract.Candidates[0] {
								t.Fatal("slower reserve changed the working route")
							}
							for _, node := range contract.Candidates {
								key := id + "/" + node
								at := item.warmPlanningCountedAt[node]
								if at.After(observed[key]) {
									observed[key] = at
									counts[key]++
								}
								if counts[key] < 2 {
									done = false
								}
								samples := item.WarmPlanningSamples[node]
								if len(samples) > 3 {
									t.Fatal("planning ring grew beyond three samples")
								}
								for n := 1; n < len(samples); n++ {
									if qualityHistoryAt(samples[n])-qualityHistoryAt(samples[n-1]) < 60 {
										t.Fatal("dense references displaced minute history")
									}
								}
								if len(samples) > 0 && float64(at.UnixNano())/float64(time.Second) > qualityHistoryAt(samples[len(samples)-1]) {
									throttled = true
								}
							}
						}
						if done {
							break
						}
						now = runtime.at.Add(max(time.Millisecond, controller.nextIntervalAt(runtime.at)))
					}
					if !done || !throttled {
						t.Fatalf("lost progress or no dense-reference coverage: done=%v throttled=%v virtual=%s", done, throttled, now.Sub(base))
					}
					if runtime.heads != len(runtime.probeCalls) || runtime.heads > 12*nodes*policies {
						t.Fatalf("hidden/repeated planning requests: heads=%d jobs=%d", runtime.heads, len(runtime.probeCalls))
					}
					t.Logf("fresh HEAD requests=%d virtual sweep=%s", runtime.heads, now.Sub(base))
				})
			}
		}
	}
}
