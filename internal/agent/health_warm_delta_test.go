package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWarmProbeFailureRetainsDisplayButWithdrawsPlanning(t *testing.T) {
	for _, node := range []string{"node-00", "node-01"} {
		for _, outcome := range []string{"failed", "missing", "deferred"} {
			t.Run(node+"/"+outcome, func(t *testing.T) {
				controller, runtime, now := warmControllerFixture(t, 3, 2, 3)
				item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
				controller.prepareWarmPlanning(contract, item)
				item.LatencyComparisons = make(map[string]latencyComparison)
				for _, candidate := range contract.Candidates[1:] {
					item.LatencyComparisons[candidate] = latencyComparison{Active: "node-00", Measurement: string(qualityMeasurementWarm),
						ActiveDelayMS: 100, CandidateDelayMS: 80, ActiveAt: 995, CandidateAt: 996, ExpiresAt: 1115}
				}
				rememberDisplayComparisons(item)
				saved := make(map[string]latencyComparison)
				for candidate, pair := range item.LastLatencyComparisons {
					saved[candidate] = pair
				}
				item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "node-00", "node-01", 1
				evidence := successfulEvidence(200)
				if outcome != "missing" {
					evidence.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: now.Add(-time.Second), ObservedAt: now,
						Failed: outcome == "failed", Deferred: outcome == "deferred"}
				}
				collectWarmPlanning(now, contract.Candidates, map[string]probeEvidence{node: evidence}, item, policySettings(contract.Policy, contract.Mode))
				if item.Selected != "node-00" || item.RuntimeSelected != "node-00" || !item.RuntimeConfirmed {
					t.Fatal("fixture changed the active route")
				}
				for candidate, pair := range saved {
					if item.LastLatencyComparisons[candidate] != pair {
						t.Fatal("unsuccessful warm probe erased the last displayed comparison")
					}
				}
				if _, exists := item.LatencyComparisons["node-01"]; exists || item.OptimizationChecks != 0 || item.OptimizationCandidate != "" {
					t.Fatal("failed quality remained usable for a planned switch")
				}
				path := statePath(t.TempDir(), "selector-health")
				if err := publishHealthState(path, healthState{"route": item}); err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var wire map[string]struct {
					Last map[string]latencyComparison `json:"warm_last_latency_comparisons"`
				}
				if err := json.Unmarshal(body, &wire); err != nil || len(wire["route"].Last) != len(saved) {
					t.Fatalf("retained display values missing from public checkpoint: %v", err)
				}
			})
		}
	}
}

// An equal, healthy inventory never nominates an optimization candidate. It
// must nevertheless publish display comparisons during the ordinary sweep.
func TestWarmHealthySweepPublishesDeltaWithoutOptimization(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 24, 10, 10)
	controller.opts.HealthInterval = time.Minute
	for node := range runtime.warm {
		runtime.warm[node] = 75
	}
	runtime.advanceClock = true
	// The fixture advances probe/scheduler time without sleeping. Durable
	// checkpoint deadlines must use that same clock rather than real seconds.
	controller.checkpointNow = func() time.Time { return runtime.at }
	seen := map[string]bool{}
	now := base
	for cycle := 0; now.Before(base.Add(130 * time.Second)); cycle++ {
		if cycle > 200 {
			item := controller.state["route"]
			t.Fatalf("healthy sweep failed to advance: elapsed=%s next=%s calls=%d warm=%d seen=%d queue=%v probes=%v", now.Sub(base), controller.nextIntervalAt(now), len(runtime.probeCalls), len(item.WarmPlanningSamples), len(seen), item.ScanQueue, item.ProbedCandidates)
		}
		runtime.at = now
		if err := controller.Tick(now); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(controller.opts.StateRoot, "selector-health.json"))
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]struct {
			Comparisons map[string]latencyComparison `json:"warm_latency_comparisons"`
			Last        map[string]latencyComparison `json:"warm_last_latency_comparisons"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		for node, pair := range wire["route"].Last {
			if pair.Active != "node-00" || pair.Measurement != string(qualityMeasurementWarm) || pair.ActiveDelayMS != 75 || pair.CandidateDelayMS != 75 {
				t.Fatalf("invalid published warm pair: %+v", pair)
			}
			seen[node] = true
		}
		now = runtime.at.Add(controller.nextIntervalAt(runtime.at))
	}
	if item := controller.state["route"]; item.Selected != "node-00" || item.OptimizationChecks != 0 || item.OptimizationLastResult != nil {
		t.Fatal("equal healthy inventory nominated a planned switch")
	}
	if len(seen) != 23 {
		t.Fatalf("healthy nodes missing published Delta: got %d of 23", len(seen))
	}
}
