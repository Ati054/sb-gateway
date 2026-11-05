package agent

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHEADRecoveryOnSameOriginDoesNotDegradeWorkingRoute(t *testing.T) {
	original := healthTargets
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	t.Cleanup(func() { healthTargets = original })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else if r.URL.Path == "/gstatic-204" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	e := runtime.Probe("direct-wan")
	if !e.OK || !e.QualityUnmeasured || e.DelayMS != nil || e.PrimaryQualityFailed {
		t.Fatalf("a successful GET to the same origin must not cause a quality-failure switch: %+v", e)
	}
	controller, item, fake := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	e.ObservedAt = time.Time{}
	fake.probes["active"] = e
	for cycle := int64(0); cycle < 30; cycle++ {
		at := 1060 + cycle*60
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if item.Selected != "active" || item.Failures["active"] != 0 {
			t.Fatalf("HEAD-specific failure displaced a working route at %d: selected=%s failures=%d", at, item.Selected, item.Failures["active"])
		}
	}
}

func TestDegradedRouteDoesNotUseUnpairedCachedReserve(t *testing.T) {
	for _, stale := range []string{"reserve", "active"} {
		t.Run(stale, func(t *testing.T) {
			_, item, _ := stagedOptimizationController(t)
			clearOptimizationCandidate(item)
			p := policySettings(healthPolicy{}, "best")
			item.Failures["active"], item.Recoveries["reserve"] = p.failureThreshold, p.recoveryThreshold
			delay := 400
			item.Samples["active"] = []healthSample{{At: 1060, OK: true, PrimaryQualityFailed: true}}
			item.Samples["reserve"] = []healthSample{{At: 1060, OK: true, DelayMS: &delay}}
			item.Samples[stale][0].At = 1000
			measured := map[string]probeEvidence{}
			if stale == "reserve" {
				measured["active"] = probeEvidence{OK: true, QualityUnmeasured: true, PrimaryQualityFailed: true}
			} else {
				measured["reserve"] = successfulEvidence(delay)
			}
			selected, reason := selectDesired(time.Unix(1060, 0), "best", "active", []string{"active", "reserve"}, nil, nil,
				map[string]*int{"reserve": &delay}, measured, map[string]bool{"reserve": true}, map[string]bool{"active": true, "reserve": true}, item, p)
			if selected != "active" {
				t.Fatalf("%s old proof moved working traffic: selected=%s reason=%s", stale, selected, reason)
			}
		})
	}
}

func TestSingleLanePrimaryDegradationStillChecksReserve(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) { singleLaneDegradedReserve(t, mode) })
	}
}

func singleLaneDegradedReserve(t *testing.T, mode string) {
	controller, item, runtime := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Mode, item.Mode = mode, mode
	contract.Policy.ProbeBatchSize = 1
	runtime.pool.HealthPolicies["europe"] = contract
	runtime.probes["active"] = probeEvidence{OK: true, QualityUnmeasured: true, PrimaryQualityFailed: true}
	for _, at := range []int64{1060, 1061, 1120, 1121, 1180, 1181, 1240, 1241} {
		before := len(runtime.probeCalls)
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		if len(runtime.probeCalls)-before > 1 {
			t.Fatal("single-slot comparison exceeded its existing request budget")
		}
	}
	if !contains(runtime.probeCalls, "reserve") || item.Selected != "reserve" {
		t.Fatalf("primary failures monopolized the only slot: calls=%v selected=%s", runtime.probeCalls, item.Selected)
	}
}

func TestPrimaryGETRecoveryClearsDegradationWithoutInventingQuality(t *testing.T) {
	for _, primary := range []bool{false, true} {
		c, runtime, item := livenessFixture(t, "best")
		item.Failures["de"] = 2
		item.QualityOK["de"] = false
		item.Samples["de"] = []healthSample{{At: 1000, OK: true, PrimaryQualityFailed: true}}
		label := healthTargets[1].label
		if primary {
			label = healthTargets[0].label
		}
		delay := 100
		runtime.probes["de"] = probeEvidence{OK: true, QualityUnmeasured: true, Targets: map[string]*int{label: &delay}}
		if _, err := c.tickActiveAvailability(time.Unix(1009, 0), "europe", runtime.pool.HealthPolicies["europe"], item); err != nil {
			t.Fatal(err)
		}
		want := 2
		if primary {
			want = 0
		}
		if item.Failures["de"] != want || item.QualityOK["de"] || item.Samples["de"][0].DelayMS != nil || item.Selected != "de" {
			t.Fatalf("primary=%t: failure streak or HEAD ranking was fabricated: failures=%d quality=%t", primary, item.Failures["de"], item.QualityOK["de"])
		}
	}
}

func TestRepeatedQualityProofDoesNotConfirmPrimaryFailure(t *testing.T) {
	c, item, runtime := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	runtime.probes["active"] = probeEvidence{OK: true, QualityUnmeasured: true, PrimaryQualityFailed: true, ObservedAt: time.Unix(1060, 0)}
	for _, at := range []int64{1060, 1120, 1180} {
		if err := c.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if item.Failures["active"] != 1 || item.Selected != "active" {
		t.Fatalf("same failed proof counted repeatedly: failures=%d selected=%s", item.Failures["active"], item.Selected)
	}
}

func TestRepeatedQualityProofDoesNotConfirmRecovery(t *testing.T) {
	c, item, runtime := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Mode, item.Mode = "priority", "priority"
	contract.Candidates = []string{"reserve", "active"}
	runtime.pool.HealthPolicies["europe"] = contract
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.Recoveries["reserve"] = 0
	evidence := successfulEvidence(500)
	evidence.ObservedAt = time.Unix(1060, 0)
	runtime.probes["reserve"] = evidence
	for _, at := range []int64{1060, 1120, 1180} {
		if err := c.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if !contains(runtime.probeCalls, "reserve") || item.Recoveries["reserve"] != 1 || item.Selected != "active" {
		t.Fatalf("same success counted as several recovery confirmations: recovery=%d selected=%s calls=%v", item.Recoveries["reserve"], item.Selected, runtime.probeCalls)
	}
}

func TestDegradedPairChecksFreshnessAndRecovery(t *testing.T) {
	for _, scenario := range []string{"boundary", "expired", "future", "recovered", "unavailable", "unknown-old-state"} {
		t.Run(scenario, func(t *testing.T) {
			item := newPolicyHealthState()
			item.Failures["a"] = 3
			delay := 400
			item.Samples["a"] = []healthSample{{At: 1000, OK: true, PrimaryQualityFailed: true}}
			item.Samples["b"] = []healthSample{{At: 1010, OK: true, DelayMS: &delay}}
			now := time.Unix(1010, 0)
			switch scenario {
			case "expired":
				now = now.Add(time.Millisecond)
			case "future":
				item.Samples["b"][0].At = 1011
			case "recovered":
				item.Failures["a"] = 0
			case "unavailable":
				item.Samples["a"][0].OK = false
			case "unknown-old-state":
				item.Samples["a"][0].PrimaryQualityFailed = false
			}
			if closeDegradedPair(now, item, "a", "b") != (scenario == "boundary") {
				t.Fatal("invalid degradation comparison", scenario)
			}
		})
	}
}

func TestSixDegradedListsShareOneQualitySlot(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, interval := range []int{3, 30, 60} {
			t.Run(fmt.Sprintf("%s/%d", mode, interval), func(t *testing.T) {
				base := healthFixture(false).HealthPolicies["europe"]
				pool := healthPool{Version: 4, ProbeBudget: 1, HealthPolicies: map[string]healthPolicyContract{}}
				runtime := &fakeSelectorRuntime{current: map[string]string{}, probes: map[string]probeEvidence{}}
				controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: 30 * time.Second}, runtime: runtime, stateLoaded: true, state: healthState{}, warmStarted: map[string]bool{}}
				for n := 0; n < 6; n++ {
					id := fmt.Sprintf("list-%d", n)
					active, reserve := id+"-active", id+"-reserve"
					contract := base
					contract.Mode, contract.Groups = mode, nil
					contract.Candidates = []string{active, reserve}
					contract.Nodes = budgetContract(active, reserve).Nodes
					contract.Policy.ActiveCheckSeconds, contract.Policy.ActiveLivenessSeconds, contract.Policy.ProbeBatchSize = interval, 30, 1
					pool.HealthPolicies[id] = contract
					item := newPolicyHealthState()
					item.Mode = mode
					item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = active, active, true
					item.CandidateSignature, item.CandidateNodes = strings.Join(contract.Candidates, "\n"), contract.Nodes
					item.AvailabilityOK = map[string]bool{active: true, reserve: true}
					item.QualityOK = map[string]bool{reserve: true}
					item.Failures[active], item.Recoveries[reserve] = 3, 3
					item.LastProbeAt[active], item.LastProbeAt[reserve] = 800, 800
					delay := 400
					item.Samples[active] = []healthSample{{At: 800, OK: true, PrimaryQualityFailed: true}}
					item.Samples[reserve] = []healthSample{{At: 800, OK: true, DelayMS: &delay}}
					runtime.probes[active] = probeEvidence{OK: true, QualityUnmeasured: true, PrimaryQualityFailed: true}
					runtime.probes[reserve] = successfulEvidence(delay)
					runtime.current[id], controller.state[id], controller.warmStarted[id] = active, item, true
				}
				runtime.pool = pool
				now := time.Unix(1000, 0)
				for tick := 0; tick < 240 && now.Before(time.Unix(1180, 0)); tick++ {
					runtime.probeCalls = nil
					if err := controller.Tick(now); err != nil {
						t.Fatal(err)
					}
					if len(runtime.probeCalls) > 1 {
						t.Fatalf("shared quality slot exceeded: %v", runtime.probeCalls)
					}
					done := true
					for id, item := range controller.state {
						done = done && item.Selected == id+"-reserve"
					}
					if done {
						return
					}
					pause := controller.nextIntervalAt(now)
					if pause <= 0 {
						pause = time.Second
					}
					now = now.Add(pause)
				}
				for id, item := range controller.state {
					if item.Selected != id+"-reserve" {
						t.Errorf("%s starved: selected=%s pending=%+v", id, item.Selected, item.degradedPair)
					}
				}
			})
		}
	}
}
