package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWarmBarrierAbortNeverCancelsColdOrDoubleCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	barrier := &qualityStartBarrier{id: 301, ready: make(chan struct{}), cancel: cancel}
	barrier.left.Store(2)
	a, b := &qualityStartTicket{barrier: barrier}, &qualityStartTicket{barrier: barrier}
	b.abortWarm()
	b.abortWarm()
	b.arrive()
	if err := a.waitWarm(ctx); !errors.Is(err, errWarmPeerFailed) {
		t.Fatalf("failed peer opened a warm HTTP phase: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("warm abort shortened cold deadline")
	}
	a.arrive()
	a.abortWarm()
	if barrier.left.Load() != 0 {
		t.Fatal("tickets arrived more than once")
	}
	expired, expire := context.WithCancel(context.Background())
	expire()
	if err := (*qualityStartTicket)(nil).waitWarm(expired); !errors.Is(err, context.Canceled) {
		t.Fatal("single lane started an expired warm phase")
	}
}

func TestWarmBarrierExpiredWaitWithdrawsOnlyWarmPhase(t *testing.T) {
	cold, cancelCold := context.WithCancel(context.Background())
	defer cancelCold()
	barrier := &qualityStartBarrier{id: 302, ready: make(chan struct{}), cancel: cancelCold}
	barrier.left.Store(2)
	a, b := &qualityStartTicket{barrier: barrier}, &qualityStartTicket{barrier: barrier}
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	if a.waitWarm(expired) == nil {
		t.Fatal("expired warm wait succeeded")
	}
	if !errors.Is(b.waitWarm(cold), errWarmPeerFailed) || cold.Err() != nil {
		t.Fatal("warm wait canceled cold peer or allowed second request")
	}
}

func TestWarmPlanningFractionalCompletionDoesNotStartNextProducerEarly(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
	contract := runtime.pool.HealthPolicies["route"]
	item := controller.state["route"]
	controller.prepareWarmPlanning(contract, item)
	measured := map[string]probeEvidence{}
	for _, node := range contract.Candidates {
		delay := 100
		measured[node] = probeEvidence{OK: true, ObservedAt: base.Add(500 * time.Millisecond), Warm: &warmQualityEvidence{
			Measurement: qualityMeasurementWarm, StartedAt: base.Add(800 * time.Millisecond), ObservedAt: base.Add(900 * time.Millisecond), DelayMS: &delay}}
	}
	p := policySettings(contract.Policy, contract.Mode)
	collectWarmPlanning(base.Add(time.Second), contract.Candidates, measured, item, p)
	view := warmPlanningScheduleView(item)
	if view.LastProbeAt[contract.Candidates[0]] != 1001 {
		t.Fatal("fractional completion was rounded down")
	}
	if targets := regularProbeTargets(time.Unix(1060, 0), item.Selected, contract.Candidates, nil, item, p); len(targets) != 0 {
		t.Fatalf("producer became due in less than sixty real seconds: %v", targets)
	}
	if targets := regularProbeTargets(time.Unix(1061, 0), item.Selected, contract.Candidates, nil, item, p); len(targets) != 2 {
		t.Fatalf("conservative rounding postponed a due pair: %v", targets)
	}
}

func TestWarmPlanningSharedEarlyPairCannotCountAsSecondProof(t *testing.T) {
	runPlanningSharedEarlyPair(t, URLTestPlanningWarmPaired)
}

func runPlanningSharedEarlyPair(t *testing.T, mode URLTestPlanningMode) {
	t.Helper()
	controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
	controller.opts.URLTestPlanningMode = mode
	contract := runtime.pool.HealthPolicies["route"]
	item := controller.state["route"]
	controller.prepareWarmPlanning(contract, item)
	a, b := contract.Candidates[0], contract.Candidates[1]
	p := policySettings(contract.Policy, contract.Mode)
	item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = a, b, 1
	item.OptimizationLastResult = &optimizationComparison{At: base.Add(time.Second).UTC().Format(time.RFC3339), Candidate: b, Result: optimizationWin, ActiveSampleAt: 1000.9, CandidateSampleAt: 1000.9}
	comparison := &optimizationComparison{At: time.Unix(1061, 0).UTC().Format(time.RFC3339), Candidate: b, Result: optimizationWin, ActiveSampleAt: 1060.8, CandidateSampleAt: 1060.8}
	if desired, _ := gatePlannedOptimization(time.Unix(1061, 0), a, b, "meaningfully-faster", comparison, item, p); desired != a || item.OptimizationChecks != 1 {
		t.Fatal("fresh shared pair bypassed this policy's sixty-second proof interval")
	}
	cold := *item
	cold.WarmPlanningMarker = ""
	if !optimizationCandidateIntervalElapsed(&cold, comparison.CandidateSampleAt, p) {
		t.Fatal("warm experiment changed legacy cold cadence")
	}
	comparison.ActiveSampleAt, comparison.CandidateSampleAt = 1061, 1061
	if desired, _ := gatePlannedOptimization(time.Unix(1061, 0), a, b, "meaningfully-faster", comparison, item, p); desired != b {
		t.Fatal("a second genuinely due pair failed to complete the proof")
	}
}

type warmCacheInjectionRuntime struct {
	*warmPlanningTestRuntime
	inject func()
}

func (runtime *warmCacheInjectionRuntime) Current(selector string) (string, error) {
	if inject := runtime.inject; inject != nil {
		runtime.inject = nil
		inject()
	}
	return runtime.warmPlanningTestRuntime.Current(selector)
}

func TestWarmPlanningEarlyCoherentCacheCannotPostponePendingProof(t *testing.T) {
	runPlanningEarlyCoherentCache(t, URLTestPlanningWarmPaired)
}

func runPlanningEarlyCoherentCache(t *testing.T, mode URLTestPlanningMode) {
	t.Helper()
	for _, attempted := range []bool{false, true} {
		t.Run(fmt.Sprintf("attempted%t", attempted), func(t *testing.T) {
			controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
			controller.opts.URLTestPlanningMode = mode
			measurement := controller.opts.planningMeasurement()
			if mode == URLTestPlanningFreshPaired {
				// Match the warm control's physical job durations, while measuring
				// the full fresh request rather than its setup-free second phase.
				for node, delay := range runtime.warm {
					runtime.probes[node] = successfulEvidence(500 + delay)
				}
			}
			runtime.advanceClock = true
			if err := controller.Tick(base); err != nil {
				t.Fatal(err)
			}
			item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
			if item.OptimizationChecks != 1 {
				t.Fatal("initial physical pair did not establish a first proof")
			}
			a, b := contract.Candidates[0], contract.Candidates[1]
			previousClock := item.WarmPlanningLastProbeAt[b]
			runtime.at = base.Add(59*time.Second + 900*time.Millisecond)
			// A preceding policy completes a valid shared wave just before the
			// candidate's own sixty-second confirmation interval has elapsed.
			shared := runtime.ProbeQualityParallelWithMeasurement([]string{a, b}, measurement)
			if shared[b].planningQuality().ObservedAt.Sub(time.Unix(0, int64(item.OptimizationLastResult.CandidateSampleAt*1e9))) >= time.Minute {
				t.Fatal("fixture did not supply an early shared candidate")
			}
			now := base.Add(61*time.Second + 400*time.Millisecond)
			runtime.at = now
			wrapper := &warmCacheInjectionRuntime{warmPlanningTestRuntime: runtime}
			controller.warmStarted["physical-peer"] = true
			if controller.probeKey("route", b, contract) != controller.probeKey("physical-peer", b, contract) {
				t.Fatal("identical physical endpoint did not share its metric/context key")
			}
			wrapper.inject = func() {
				for node, evidence := range shared {
					key := controller.probeKey("physical-peer", node, contract)
					controller.probeBudget.Quality[key] = sharedProbeResult{At: time.Now(), Evidence: evidence}
					controller.probeBudget.QualityAttempted[key] = attempted
				}
			}
			controller.runtime = wrapper
			before := len(runtime.probeCalls)
			if err := controller.Tick(now); err != nil {
				t.Fatal(err)
			}
			if attempted {
				if len(runtime.probeCalls) != before || item.OptimizationChecks != 1 || item.WarmPlanningLastProbeAt[b] != previousClock {
					t.Fatal("rejected same-tick shared pair repeated HTTP or postponed the pending proof")
				}
				runtime.at = now.Add(3 * time.Second)
				if err := controller.Tick(runtime.at); err != nil {
					t.Fatal(err)
				}
			}
			if item.Selected != b || item.LastSwitchReason != "meaningfully-faster" || len(runtime.probeCalls)-before != 2 || len(controller.probeBudget.Used) != 2 {
				t.Fatal("a genuinely due physical pair waited for a new full interval or escaped its budget")
			}
		})
	}
}

func TestWarmPlanningCapKeepsStartupAndPriorityWidths(t *testing.T) {
	for _, mode := range []string{"ordinary", "startup", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, base := warmControllerFixture(t, 10, 10, 10)
			want := 2
			if mode == "startup" {
				controller.warmStarted["route"] = false
				want = 10
			}
			if mode == "priority" {
				contract := runtime.pool.HealthPolicies["route"]
				contract.Mode = "priority"
				runtime.pool.HealthPolicies["route"] = contract
				want = 10
			}
			if err := controller.Tick(base); err != nil {
				t.Fatal(err)
			}
			if len(runtime.probeCalls) != want {
				t.Fatalf("%s width=%d want%d", mode, len(runtime.probeCalls), want)
			}
		})
	}
}

func TestWarmPlanningDeferredPreservesProofButDoesNotHideLateRealFailure(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 3, 10, 10)
	item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
	controller.prepareWarmPlanning(contract, item)
	p := policySettings(contract.Policy, "best")
	first := runtime.ProbeQualityParallelWithMeasurement([]string{"node-00", "node-01"}, qualityMeasurementWarm)
	collectWarmPlanning(base.Add(2*time.Second), contract.Candidates, first, item, p)
	comparison := planningComparison(base.Add(2*time.Second), "node-00", "node-01", first, item, true, true, p)
	gatePlannedOptimization(base.Add(2*time.Second), "node-00", "node-01", "meaningfully-faster", comparison, item, p)
	if item.OptimizationChecks != 1 {
		t.Fatal("missing first good proof")
	}
	watermark := item.warmPlanningCountedAt["node-00"]
	runtime.blocked["node-02"] = true
	runtime.at = base.Add(3 * time.Second)
	blocked := runtime.ProbeQualityParallelWithMeasurement([]string{"node-00", "node-02"}, qualityMeasurementWarm)
	collectWarmPlanning(base.Add(8*time.Second), contract.Candidates, blocked, item, p)
	if item.OptimizationChecks != 1 || item.warmPlanningCountedAt["node-00"] != watermark || len(item.WarmPlanningSamples["node-00"]) != 1 || item.WarmPlanningLastProbeAt["node-00"] != 1008 {
		t.Fatal("unstarted second phase invalidated quality or failed to date attempt")
	}
	// The skipped attempt at8s must not mask an actual network error at4s.
	failure := first["node-00"]
	failure.ObservedAt = base.Add(4 * time.Second)
	failure.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: base.Add(3500 * time.Millisecond), ObservedAt: base.Add(4 * time.Second), Failed: true}
	collectWarmPlanning(base.Add(9*time.Second), contract.Candidates, map[string]probeEvidence{"node-00": failure}, item, p)
	if item.OptimizationChecks != 0 || len(item.WarmPlanningSamples["node-00"]) != 0 || item.WarmPlanningLastProbeAt["node-00"] != 1008 {
		t.Fatal("deferred watermark hid real failure or rewound attempts")
	}
	value := 100
	if validWarmQuality(&warmQualityEvidence{Measurement: qualityMeasurementWarm, StartedAt: base, ObservedAt: base.Add(time.Second), DelayMS: &value, Deferred: true}) {
		t.Fatal("deferred evidence became measured quality")
	}
}

func TestWarmPlanningGoodNomineeSurvivesDeferredOtherPeerUntilSecondProof(t *testing.T) {
	controller, runtime, base := warmControllerFixture(t, 3, 10, 10)
	item, contract := controller.state["route"], runtime.pool.HealthPolicies["route"]
	controller.prepareWarmPlanning(contract, item)
	p := policySettings(contract.Policy, "best")
	first := runtime.ProbeQualityParallelWithMeasurement([]string{"node-00", "node-01"}, qualityMeasurementWarm)
	collectWarmPlanning(base.Add(2*time.Second), contract.Candidates, first, item, p)
	comparison := planningComparison(base.Add(2*time.Second), "node-00", "node-01", first, item, true, true, p)
	gatePlannedOptimization(base.Add(2*time.Second), "node-00", "node-01", "meaningfully-faster", comparison, item, p)
	runtime.blocked["node-02"] = true
	runtime.at = base.Add(20 * time.Second)
	collectWarmPlanning(base.Add(25*time.Second), contract.Candidates, runtime.ProbeQualityParallelWithMeasurement([]string{"node-00", "node-02"}, qualityMeasurementWarm), item, p)
	runtime.at = base.Add(63 * time.Second)
	second := runtime.ProbeQualityParallelWithMeasurement([]string{"node-00", "node-01"}, qualityMeasurementWarm)
	collectWarmPlanning(base.Add(65*time.Second), contract.Candidates, second, item, p)
	next := planningComparison(base.Add(65*time.Second), "node-00", "node-01", second, item, true, true, p)
	selected, reason := gatePlannedOptimization(base.Add(65*time.Second), "node-00", "node-01", "meaningfully-faster", next, item, p)
	if selected != "node-01" || reason != "meaningfully-faster" {
		t.Fatal("bad unrelated peer destroyed good pending proof")
	}
}

func TestWarmPlanningRefreshesOnlyUnattemptedIncoherentCache(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		t.Run(fmt.Sprint(attempted), func(t *testing.T) {
			controller, runtime, _ := warmControllerFixture(t, 3, 10, 10)
			contract := runtime.pool.HealthPolicies["route"]
			runtime.at = time.Now().Add(-2 * time.Second)
			old := runtime.ProbeWithQualityRequest("node-00", qualityProbeRequest{Measurement: qualityMeasurementWarm})
			old.Warm.Wave = 901
			runtime.probeCalls = nil
			runtime.heads = 0
			controller.beginProbeBudget(runtime.pool, []string{"route"})
			key := controller.probeKey("route", "node-00", contract)
			controller.probeBudget.Quality[key] = sharedProbeResult{At: time.Now().Add(-time.Second), Evidence: old}
			if attempted {
				controller.probeBudget.QualityAttempted[key] = true
				controller.probeBudget.Used[key] = true
			}
			nodes := []string{"node-00", "node-02"}
			accepted, deferred := controller.claimProbeTargets("route", contract, nodes, true)
			if len(deferred) != 0 {
				t.Fatal("fixture did not admit cached half")
			}
			measured := controller.sharedQualityBatch("route", contract, accepted)
			if attempted {
				if len(runtime.probeCalls) != 0 || !measured["node-00"].Deferred || len(controller.probeBudget.Used) != 1 {
					t.Fatal("same-Tick executed side ran again")
				}
				controller.beginProbeBudget(runtime.pool, []string{"route"})
				accepted, _ = controller.claimProbeTargets("route", contract, nodes, true)
				measured = controller.sharedQualityBatch("route", contract, accepted)
			}
			if len(runtime.probeCalls) != 2 || len(controller.probeBudget.Used) != 2 || !validWarmQuality(measured["node-00"].Warm) || measured["node-00"].Warm.Wave != measured["node-02"].Warm.Wave {
				t.Fatal("fresh pair waited for TTL or escaped budget")
			}
		})
	}
}

func TestWarmPlanningFailedAndDeferredResultsNeverEnterQualityCache(t *testing.T) {
	controller, runtime, _ := warmControllerFixture(t, 3, 10, 10)
	runtime.blocked["node-02"] = true
	controller.beginProbeBudget(runtime.pool, []string{"route"})
	contract := runtime.pool.HealthPolicies["route"]
	measured := controller.sharedQualityBatch("route", contract, []string{"node-00", "node-02"})
	if !measured["node-00"].Warm.Deferred || len(controller.probeBudget.Quality) != 0 {
		t.Fatal("unmeasured result poisoned shared quality cache")
	}
	before := len(runtime.probeCalls)
	if !controller.sharedQualityProbe("route", "node-00", contract).Deferred || len(runtime.probeCalls) != before {
		t.Fatal("unknown result triggered same-Tick retry")
	}
}

func prefixWarmModelMap[T any](values map[string]T, prefix string) map[string]T {
	result := make(map[string]T, len(values))
	for key, value := range values {
		result[prefix+key] = value
	}
	return result
}

// This model runs the actual scheduler and advances its virtual clock by both
// request duration and nextIntervalAt. It reports requests/publication changes,
// not hardware CPU or independent physical-network measurements.
func TestWarmPlanningLateFastCandidateAndBadPeersAreFairAcrossPolicies(t *testing.T) {
	for _, nodes := range []int{7, 10, 24} {
		for _, policies := range []int{1, 2, 6} {
			for _, lanes := range []int{10, 1} {
				if lanes == 1 && (nodes != 7 || policies != 6) {
					continue
				}
				t.Run(fmt.Sprintf("nodes%d/policies%d/lanes%d", nodes, policies, lanes), func(t *testing.T) {
					controller, runtime, base := warmControllerFixture(t, nodes, lanes, 10)
					controller.opts.HealthInterval = time.Minute
					runtime.advanceClock = true
					template := runtime.pool.HealthPolicies["route"]
					initial := controller.state["route"]
					body, _ := json.Marshal(initial)
					controller.state = healthState{}
					controller.warmStarted = map[string]bool{}
					runtime.pool.HealthPolicies = map[string]healthPolicyContract{}
					runtime.current = map[string]string{}
					oldProbes, oldWarm := runtime.probes, runtime.warm
					runtime.probes = map[string]probeEvidence{}
					runtime.warm = map[string]int{}
					firstSwitch := map[string]float64{}
					switchCounts := map[string]int{}
					controller.eventSink = func(event healthEvent) {
						if event.Event == "switch" {
							at, _ := time.Parse(time.RFC3339, event.At)
							firstSwitch[event.Policy] = at.Sub(base).Seconds()
							switchCounts[event.Policy]++
							if event.Reason != "meaningfully-faster" {
								t.Errorf("unexpected switch %s", event.Reason)
							}
							if event.Comparison == nil || event.Comparison.ConfirmationGapMS == nil || *event.Comparison.ConfirmationGapMS < 60_000 || *event.Comparison.ConfirmationGapMS > 120_000 {
								encoded, _ := json.Marshal(event.Comparison)
								t.Errorf("nominee did not get two timely fresh proofs: %s", encoded)
							}
						}
					}
					for policy := 0; policy < policies; policy++ {
						id := fmt.Sprintf("p%d", policy)
						prefix := id + "-"
						contract := template
						contract.Candidates = make([]string, len(template.Candidates))
						contract.Nodes = map[string]healthNode{}
						for i, node := range template.Candidates {
							name := prefix + node
							contract.Candidates[i] = name
							metadata := template.Nodes[node]
							metadata.Fingerprint = prefix + metadata.Fingerprint
							contract.Nodes[name] = metadata
							runtime.probes[name], runtime.warm[name] = oldProbes[node], oldWarm[node]
							runtime.warm[name] = 900
							if i > 1 && i < nodes-1 && i%6 == 3 {
								runtime.blocked[name] = true
							}
						}
						runtime.warm[contract.Candidates[nodes-1]] = 100
						item := newPolicyHealthState()
						if err := json.Unmarshal(body, item); err != nil {
							t.Fatal(err)
						}
						item.Selected, item.RuntimeSelected = contract.Candidates[0], contract.Candidates[0]
						item.CandidateSignature = strings.Join(contract.Candidates, "\n")
						item.CandidateNodes = contract.Nodes
						item.Samples = prefixWarmModelMap(item.Samples, prefix)
						item.LastProbeAt = prefixWarmModelMap(item.LastProbeAt, prefix)
						item.Recoveries = prefixWarmModelMap(item.Recoveries, prefix)
						item.QualityOK = prefixWarmModelMap(item.QualityOK, prefix)
						item.AvailabilityOK = prefixWarmModelMap(item.AvailabilityOK, prefix)
						controller.state[id] = item
						controller.warmStarted[id] = true
						runtime.pool.HealthPolicies[id] = contract
						runtime.current[id] = contract.Candidates[0]
					}
					now := base
					end := base.Add(12 * time.Minute)
					idleSpins, persistedChanges := 0, 0
					var previousHash [32]byte
					for now.Before(end) {
						runtime.at = now
						before := len(runtime.probeCalls)
						if err := controller.Tick(now); err != nil {
							t.Fatal(err)
						}
						if len(runtime.probeCalls)-before > 10 {
							t.Fatal("global work budget exceeded")
						}
						if saved, err := os.ReadFile(statePath(controller.opts.StateRoot, "selector-health")); err == nil {
							hash := sha256.Sum256(saved)
							if hash != previousHash {
								persistedChanges++
								previousHash = hash
							}
						}
						completed := runtime.at
						wait := controller.nextIntervalAt(completed)
						if !completed.After(now) && wait <= 0 {
							idleSpins++
							if idleSpins > policies+2 {
								t.Fatal("scheduler spins without network work")
							}
						} else {
							idleSpins = 0
						}
						now = completed.Add(wait)
					}
					lastFirstProbe := 0.0
					maxSwitchSeconds := float64(360)
					if policies == 6 {
						maxSwitchSeconds = 600 // Inventory sweep includes 144 endpoints and cold timeouts.
					}
					for id, item := range controller.state {
						want := fmt.Sprintf("%s-node-%02d", id, nodes-1)
						if item.Selected != want || firstSwitch[id] <= 0 || firstSwitch[id] > maxSwitchSeconds || switchCounts[id] != 1 {
							t.Fatalf("late faster candidate starved or oscillated in %s: selected=%s switch=%v", id, item.Selected, firstSwitch)
						}
						for _, node := range runtime.pool.HealthPolicies[id].Candidates {
							attempts := runtime.attempts[node]
							if len(attempts) == 0 {
								t.Fatalf("node %s never checked", node)
							}
							lastFirstProbe = max(lastFirstProbe, attempts[0].Sub(base).Seconds())
							for i := 1; i < len(attempts); i++ {
								if node != item.Selected && runtime.blocked[node] && attempts[i].Sub(attempts[i-1]) < 60*time.Second {
									t.Fatalf("bad peer %s retried early", node)
								}
							}
						}
					}
					for _, batch := range runtime.batches {
						if len(batch) > 2 {
							t.Fatal("ordinary warm admitted more than a physical pair")
						}
					}
					elapsed := now.Sub(base).Seconds()
					metrics := map[string]any{"nodes": nodes, "policies": policies, "lanes": lanes, "virtual_seconds": elapsed, "quality_primary_requests": runtime.heads, "quality_requests_per_minute": float64(runtime.heads) * 60 / elapsed, "availability_checks": len(runtime.availabilityCalls),
						"persisted_snapshot_change_ticks": persistedChanges, "snapshot_changes_per_minute": float64(persistedChanges) * 60 / elapsed, "first_sweep_seconds": lastFirstProbe, "switch_seconds": firstSwitch, "scope": "virtual actual controller; no hardware CPU claim; fallback is one successful GET"}
					encoded, _ := json.Marshal(metrics)
					t.Log("WARM_PAIR_MODEL " + string(encoded))
				})
			}
		}
	}
}
