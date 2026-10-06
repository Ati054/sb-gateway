package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func callbackOrderFixture(t *testing.T, mode string) (*healthController, *fakeSelectorRuntime, *xraySelectorRuntime) {
	t.Helper()
	base := healthFixture(false).HealthPolicies["europe"]
	base.Mode = mode
	base.Policy.ActiveCheckSeconds = 60
	base.Groups = nil
	pool := healthPool{
		Version:        4,
		HealthPolicies: make(map[string]healthPolicyContract),
		Outbounds:      make(map[string]json.RawMessage),
	}
	state := make(healthState)
	for _, entry := range []struct{ policy, node string }{{"a-healthy", "healthy"}, {"z-target", "target"}} {
		contract := base
		contract.Candidates = []string{entry.node, entry.node + "-reserve"}
		pool.HealthPolicies[entry.policy] = contract
		pool.Outbounds[entry.node] = json.RawMessage(`{"protocol":"freedom"}`)
		item := newPolicyHealthState()
		ensureHealthMaps(item)
		item.Mode = mode
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = entry.node, entry.node, true
		item.CandidateSignature = strings.Join(contract.Candidates, "\n")
		item.AvailabilityOK = map[string]bool{entry.node: true}
		item.QualityOK = map[string]bool{entry.node: true}
		item.Recoveries[entry.node], item.LastProbeAt[entry.node] = 3, 1000
		state[entry.policy] = item
	}
	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"a-healthy": "healthy", "z-target": "target"},
		probes:   map[string]probeEvidence{"healthy": successfulEvidence(100), "target": successfulEvidence(100)},
		underlay: underlayEvidence{Known: true, WANOK: true, DNSOK: true},
	}
	controller := &healthController{
		opts: Options{StateRoot: t.TempDir()}, runtime: runtime, state: state, stateLoaded: true,
		warmStarted: map[string]bool{"a-healthy": true, "z-target": true},
		regularNext: map[string]time.Time{"a-healthy": time.Unix(1060, 0), "z-target": time.Unix(1060, 0)},
		livenessAt:  map[string]time.Time{"a-healthy": time.Unix(1000, 0), "z-target": time.Unix(1000, 0)},
	}
	primary := newXraySelectorRuntime(Options{})
	primary.pool, primary.xrayPID = pool, 123
	return controller, runtime, primary
}

func callbackTargetHint(primary *xraySelectorRuntime) xrayFailureSignal {
	return xrayFailureSignal{Version: 1, PID: primary.xrayPID, Tag: primary.policyRuntimeTag("z-target", "target"), Stage: "dial"}
}

func TestBackgroundHintChecksSignalledPolicyBeforeOtherDuePolicies(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, primary := callbackOrderFixture(t, mode)
			runtime.probes["target"] = probeEvidence{Failure: probeFailureTimeout}
			now := time.Unix(1010, 0)
			signals := make(chan xrayFailureSignal, 1)
			signals <- callbackTargetHint(primary)
			joined := make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result := awaitProbeJobWithSignals(ctx, time.Hour, func() error {
				return controller.checkDuringProbe(now, runtime.pool)
			}, func(ctx context.Context) probeJobResult {
				defer close(joined)
				<-ctx.Done()
				return probeJobResult{err: ctx.Err()}
			}, signals, func(signal xrayFailureSignal) bool {
				return controller.acceptXrayFailureSignal(now, signal, primary)
			})
			if !errors.Is(result.err, errHealthYield) {
				t.Fatalf("accepted hint did not yield the worker after a failed proof: %v", result.err)
			}
			select {
			case <-joined:
			default:
				t.Fatal("background worker was not joined")
			}
			item := controller.state["z-target"]
			if item.AvailabilityFailures["target"] != 1 || item.Selected != "target" || len(runtime.selections) != 0 || len(runtime.probeCalls) != 0 {
				t.Fatalf("hint changed proof or selection semantics: failures=%d selected=%s selections=%v quality=%v", item.AvailabilityFailures["target"], item.Selected, runtime.selections, runtime.probeCalls)
			}
			if got := strings.Join(runtime.availabilityCalls, ","); got != "target" {
				t.Fatalf("accepted hint waited behind unrelated due work: availability=%s, want target", got)
			}
		})
	}
}

func TestBackgroundHintPreservesHealthyCallbackFairness(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, primary := callbackOrderFixture(t, mode)
			for _, second := range []int64{1010, 1014, 1018} {
				now := time.Unix(second, 0)
				if !controller.acceptXrayFailureSignal(now, callbackTargetHint(primary), primary) {
					t.Fatal("current active hint was rejected")
				}
				runtime.availabilityCalls = nil
				if err := controller.checkDuringProbe(now, runtime.pool); err != nil {
					t.Fatal(err)
				}
				if len(runtime.availabilityCalls) != 2 || !contains(runtime.availabilityCalls, "healthy") || !contains(runtime.availabilityCalls, "target") || controller.forceLiveness["z-target"] {
					t.Fatalf("healthy repeated hints starved due work or retained force: calls=%v forced=%t", runtime.availabilityCalls, controller.forceLiveness["z-target"])
				}
			}
			controller.priorityPolicy = "z-target"
			runtime.availabilityCalls = nil
			if err := controller.checkDuringProbe(time.Unix(1022, 0), runtime.pool); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(runtime.availabilityCalls, ","); got != "healthy,target" {
				t.Fatalf("stale priority without urgency displaced normal order: %s", got)
			}
			if len(runtime.selections) != 0 || len(runtime.probeCalls) != 0 {
				t.Fatalf("healthy hints started non-liveness work: selections=%v quality=%v", runtime.selections, runtime.probeCalls)
			}
		})
	}
}

func TestBackgroundPendingFailureKeepsPriorityAndRetryInterval(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, elapsed := range []time.Duration{time.Second, failureRetryInterval} {
			t.Run(mode+"/"+elapsed.String(), func(t *testing.T) {
				controller, runtime, _ := callbackOrderFixture(t, mode)
				runtime.probes["target"] = probeEvidence{Failure: probeFailureTimeout}
				item := controller.state["z-target"]
				first := time.Unix(1009, 0)
				changed, err := controller.checkActiveAvailability(first, "z-target", runtime.pool.HealthPolicies["z-target"], item, false)
				if err != nil || !changed || item.AvailabilityFailures["target"] != 1 {
					t.Fatalf("failed to establish an independent pending proof: changed=%t failures=%d err=%v", changed, item.AvailabilityFailures["target"], err)
				}
				controller.priorityPolicy = "a-healthy"
				runtime.availabilityCalls = nil
				err = controller.checkDuringProbe(first.Add(elapsed), runtime.pool)
				if elapsed < failureRetryInterval {
					if err != nil || strings.Join(runtime.availabilityCalls, ",") != "healthy" || item.AvailabilityFailures["target"] != 1 {
						t.Fatalf("pending priority bypassed retry cadence: calls=%v failures=%d err=%v", runtime.availabilityCalls, item.AvailabilityFailures["target"], err)
					}
				} else {
					p := policySettings(runtime.pool.HealthPolicies["z-target"].Policy, mode)
					if !errors.Is(err, errHealthYield) || item.AvailabilityFailures["target"] != p.failureThreshold {
						t.Fatalf("due independent proof did not confirm failure: failures=%d err=%v", item.AvailabilityFailures["target"], err)
					}
					if got := strings.Join(runtime.availabilityCalls, ","); got != "target" {
						t.Fatalf("pending confirmation waited behind unrelated due work: availability=%s, want target", got)
					}
				}
				if len(runtime.selections) != 0 || len(runtime.probeCalls) != 0 {
					t.Fatalf("callback took ownership of recovery or routine work: selections=%v quality=%v", runtime.selections, runtime.probeCalls)
				}
			})
		}
	}
}
