package agent

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEmergencyFallbackBranchesUseCurrentProofAndLatestPrimary(t *testing.T) {
	for _, selected := range []string{"active", "block"} {
		for _, mode := range []string{"best", "priority"} {
			t.Run(mode+"/"+selected, func(t *testing.T) {
				item := newPolicyHealthState()
				fast, slow, oldFast, oldSlow, availability := 400, 640, 900, 300, 7
				item.Samples["fast"] = []healthSample{{At: 999, ObservedAt: 999.5, OK: true, DelayMS: &fast}}
				item.Samples["slow"] = []healthSample{{At: 999, ObservedAt: 999.5, OK: true, DelayMS: &slow}}
				item.Recoveries["fast"], item.Recoveries["slow"] = 0, 3
				item.AvailabilityFailures["active"], item.AvailabilityFailures["fast"] = 3, 3
				item.LastProbeAt["slow"] = 999
				measured := map[string]probeEvidence{"fast": {OK: true, QualityUnmeasured: true, DelayMS: &availability}, "slow": {OK: true, QualityUnmeasured: true}}
				quality, available := map[string]bool{"slow": true}, map[string]bool{"slow": true}
				p := policySettings(healthPolicy{}, mode)
				desired, reason := selectDesired(time.Unix(1000, 0), mode, selected, []string{"active", "slow", "fast"}, map[string]int{"fast": 0, "slow": 1}, nil,
					map[string]*int{"fast": &oldFast, "slow": &oldSlow}, measured, quality, available, item, p)
				wantReason := "active-unavailable"
				if selected == "block" {
					wantReason = "fresh-path-available"
				}
				if desired != "fast" || reason != wantReason {
					t.Fatalf("old recovery/flags/median displaced current best success: %s %s", desired, reason)
				}
				measured["fast"] = failedEvidence()
				desired, _ = selectDesired(time.Unix(1000, 0), mode, selected, []string{"active", "slow", "fast"}, map[string]int{"fast": 0, "slow": 1}, nil,
					map[string]*int{"fast": &oldFast, "slow": &oldSlow}, measured, quality, available, item, p)
				if desired != "slow" {
					t.Fatal("failed current reserve reused cached speed")
				}
			})
		}
	}
}

func TestEmergencyPlanDoesNotTreatOldFlagsAsCurrentProof(t *testing.T) {
	item := newPolicyHealthState()
	fast, slow := 400, 640
	item.Samples["fast"] = []healthSample{{At: 999, OK: true, DelayMS: &fast}}
	item.Samples["slow"] = []healthSample{{At: 999, OK: true, DelayMS: &slow}}
	item.AvailabilityOK = map[string]bool{"slow": true}
	item.QualityOK = map[string]bool{"slow": true}
	item.AvailabilityFailures["fast"] = 3
	item.Recoveries["slow"] = 3
	item.MedianDelayMS = map[string]*int{"fast": &fast, "slow": &slow}
	targets, preferred := emergencyProbePlan(time.Unix(1000, 0), "active", []string{"slow"}, []string{"fast", "slow"}, nil, item, policySettings(healthPolicy{ProbeBatchSize: 1}, "best"))
	if !reflect.DeepEqual(targets, []string{"fast"}) || !reflect.DeepEqual(preferred, []string{"fast"}) {
		t.Fatalf("old flags hid fresh fast reserve: %v %v", targets, preferred)
	}
}

func TestEmergencyAvailabilityDelayCannotInventPrimaryRanking(t *testing.T) {
	for _, selected := range []string{"active", "block"} {
		t.Run(selected, func(t *testing.T) {
			item := newPolicyHealthState()
			known, unknownOld, availabilityDelay := 640, 1, 5
			item.AvailabilityFailures["active"] = 3
			item.Samples["known"] = []healthSample{{At: 999, ObservedAt: 999.5, OK: true, DelayMS: &known}}
			measured := map[string]probeEvidence{"unknown": {OK: true, QualityUnmeasured: true, DelayMS: &availabilityDelay}, "known": {OK: true, QualityUnmeasured: true}}
			desired, _ := selectDesired(time.Unix(1000, 0), "best", selected, []string{"active", "unknown", "known"}, nil, nil, map[string]*int{"unknown": &unknownOld, "known": &known}, measured, nil, nil, item, policySettings(healthPolicy{}, "best"))
			if desired != "known" {
				t.Fatalf("availability/old aggregate invented a primary ranking: %s", desired)
			}
			measured["known"] = failedEvidence()
			desired, _ = selectDesired(time.Unix(1000, 0), "best", selected, []string{"active", "unknown", "known"}, nil, nil, nil, measured, nil, nil, item, policySettings(healthPolicy{}, "best"))
			if desired != "unknown" {
				t.Fatal("missing ranking prevented recovery through a currently available node")
			}
		})
	}
}

func TestEmergencyAvailabilityPreservesPrimaryObservationThroughPolicyTick(t *testing.T) {
	for _, tc := range []struct {
		withDelay bool
		batch     int
	}{{false, 1}, {true, 1}, {false, 3}, {true, 3}} {
		t.Run(fmt.Sprintf("delay=%t/batch=%d", tc.withDelay, tc.batch), func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode, contract.Candidates, contract.Groups = "best", []string{"active", "fast"}, nil
			contract.Policy.ActiveCheckSeconds, contract.Policy.ProbeBatchSize = 60, tc.batch
			item := newPolicyHealthState()
			item.Mode, item.LatencyMeasurement = "best", latencyMeasurement
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
			item.CandidateSignature = strings.Join(contract.Candidates, "\n")
			item.AvailabilityFailures["active"] = 3
			delay, availabilityDelay := 400, 9
			original := healthSample{At: 999, ObservedAt: 999.5, OK: true, DelayMS: &delay}
			item.Samples["fast"] = []healthSample{original}
			item.MedianDelayMS = map[string]*int{"fast": &delay}
			item.AvailabilityOK, item.QualityOK = map[string]bool{"fast": true}, map[string]bool{"fast": true}
			item.Recoveries["fast"] = 3
			evidence := probeEvidence{OK: true, QualityUnmeasured: true}
			if tc.withDelay {
				evidence.DelayMS = &availabilityDelay
				evidence.QualityUnmeasured = false
			}
			runtime := &fakeSelectorRuntime{current: map[string]string{"europe": "active"}, probes: map[string]probeEvidence{"active": failedEvidence(), "fast": evidence}}
			controller := &healthController{opts: Options{StateRoot: t.TempDir()}, runtime: runtime, state: healthState{"europe": item}, warmStarted: map[string]bool{"europe": true}}
			if err := controller.tickPolicy(time.Unix(1000, 0), "europe", contract, item); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "fast" {
				t.Fatalf("did not recover: %s", item.Selected)
			}
			if len(item.Samples["fast"]) != 1 || !reflect.DeepEqual(item.Samples["fast"][0], original) || item.Recoveries["fast"] != 0 || !item.QualityOK["fast"] || item.Failures["fast"] != 0 {
				t.Fatalf("availability replaced primary sample/counters: samples=%+v recovery=%d quality=%t failures=%d", item.Samples["fast"], item.Recoveries["fast"], item.QualityOK["fast"], item.Failures["fast"])
			}
		})
	}
}
