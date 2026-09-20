package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestReadyReservesNotStarvedByFailedNodesAndFullScan(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			contract.Candidates = []string{"active", "reserve1", "reserve2", "dead1", "dead2", "dead3"}
			for i := 0; i < 9; i++ {
				contract.Candidates = append(contract.Candidates, fmt.Sprintf("extra%d", i))
			}
			contract.Policy.MaxActiveCandidates, contract.Policy.ProbeBatchSize = 3, 2
			contract.Policy.ActiveCheckSeconds, contract.Policy.BackupCheckSeconds, contract.Policy.FullScanSeconds = 60, 300, 1800
			pool.HealthPolicies["europe"] = contract
			item := newPolicyHealthState()
			ensureHealthMaps(item)
			item.AvailabilityOK, item.QualityOK = map[string]bool{}, map[string]bool{}
			item.MedianDelayMS = map[string]*int{}
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
			item.CandidateSignature, item.NextFullScanAt = strings.Join(contract.Candidates, "\n"), 2800
			item.ScanQueue = append([]string(nil), contract.Candidates...)
			runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "active"}, probes: map[string]probeEvidence{}}
			for i, candidate := range contract.Candidates {
				runtime.probes[candidate] = successfulEvidence(500 + i*10)
				item.LastProbeAt[candidate] = 1000
				if i < 3 {
					delay := 500 + i*10
					item.Samples[candidate] = []healthSample{{OK: true, DelayMS: &delay}}
					item.AvailabilityOK[candidate], item.QualityOK[candidate] = true, true
					item.Recoveries[candidate] = 3
					item.MedianDelayMS[candidate] = &delay
				} else if i < 6 {
					runtime.probes[candidate] = failedEvidence()
					item.Samples[candidate] = []healthSample{{OK: false}}
					item.AvailabilityFailures[candidate] = 3
				}
			}
			controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime, warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item}}
			for second := int64(1060); second <= 2200; second += 60 {
				runtime.probeCalls = nil
				if err := controller.Tick(time.Unix(second, 0)); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls) > 2 {
					t.Fatal("exceeded configured probe batch")
				}
				for _, candidate := range []string{"reserve1", "reserve2"} {
					if mode == "best" && float64(second)-item.LastProbeAt[candidate] > 420 {
						t.Fatalf("ready %s starved: last=%v now=%d", candidate, item.LastProbeAt[candidate], second)
					}
				}
			}
			for _, candidate := range contract.Candidates {
				if item.LastProbeAt[candidate] <= 1000 {
					t.Fatalf("%s never probed", candidate)
				}
			}
			if item.Selected != "active" {
				t.Fatal("scheduler caused an unnecessary switch")
			}
		})
	}
}

func TestRegularProbeLanesMakeProgressWithinBatch(t *testing.T) {
	for _, batch := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			item := newPolicyHealthState()
			ensureHealthMaps(item)
			candidates := []string{"active", "reserve", "dead"}
			item.Samples["dead"] = []healthSample{{OK: false}}
			for i := 0; i < 40; i++ {
				id := fmt.Sprintf("unknown-%d", i)
				candidates = append(candidates, id)
				item.ScanQueue = append(item.ScanQueue, id)
			}
			seen := map[string]int{}
			p := effectivePolicySettings{batch: batch, active: 60, backup: 300, recoveryThreshold: 3}
			for tick := 0; tick < 200; tick++ {
				now := time.Unix(int64(1000+tick*60), 0)
				targets := regularProbeTargets(now, "active", candidates, []string{"active", "reserve"}, item, p)
				if len(targets) > batch || len(uniqueCandidates(targets)) != len(targets) {
					t.Fatalf("invalid batch: %v", targets)
				}
				for _, id := range targets {
					seen[id]++
					item.LastProbeAt[id] = float64(now.Unix())
				}
				// Restart after every batch must not reset scheduling fairness.
				encoded, err := json.Marshal(item)
				if err != nil {
					t.Fatal(err)
				}
				item = newPolicyHealthState()
				if err := json.Unmarshal(encoded, item); err != nil {
					t.Fatal(err)
				}
			}
			for _, id := range candidates {
				if seen[id] == 0 {
					t.Fatalf("starved lane/member: %s", id)
				}
			}
			for _, id := range candidates[:3] {
				if seen[id] < 20 {
					t.Fatalf("insufficient repeated service for %s: %d", id, seen[id])
				}
			}
		})
	}
}
