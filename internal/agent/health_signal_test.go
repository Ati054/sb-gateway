package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestXrayFailureSignalOnlyWakesCurrentActiveHandler(t *testing.T) {
	primary := newXraySelectorRuntime(Options{})
	primary.xrayPID = 123
	primary.pool = healthPool{
		HealthPolicies: map[string]healthPolicyContract{"route": {Candidates: []string{"active", "reserve"}}},
		PolicyPrefixes: map[string]string{"route": "sb-urltest-route-"},
		Outbounds: map[string]json.RawMessage{
			"active":  json.RawMessage(`{"tag":"active","protocol":"vless"}`),
			"reserve": json.RawMessage(`{"tag":"reserve","protocol":"vless"}`),
		},
	}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
	controller := &healthController{state: healthState{"route": item}}
	now := time.Unix(1000, 0)
	activeTag := primary.policyRuntimeTag("route", "active")
	valid := xrayFailureSignal{Version: 1, PID: 123, Tag: activeTag, Stage: "dial"}
	for _, rejected := range []xrayFailureSignal{
		{Version: 1, PID: 122, Tag: activeTag, Stage: "dial"},
		{Version: 1, PID: 123, Tag: "outbound-health-background-active", Stage: "dial"},
		{Version: 1, PID: 123, Tag: activeTag, Stage: "site-error"},
		{Version: 1, PID: 123, Tag: "old-generation", Stage: "dial"},
	} {
		if controller.acceptXrayFailureSignal(now, rejected, primary) {
			t.Fatalf("stale/probe/site signal was accepted: %+v", rejected)
		}
	}
	if !controller.acceptXrayFailureSignal(now, valid, primary) || !controller.forceLiveness["route"] || controller.priorityPolicy != "route" {
		t.Fatal("active VLESS server failure did not wake its route")
	}
	if controller.acceptXrayFailureSignal(now.Add(100*time.Millisecond), valid, primary) {
		t.Fatal("repeated failures bypassed one-second coalescing")
	}
	item.Selected, item.RuntimeSelected = "reserve", "reserve"
	if controller.acceptXrayFailureSignal(now.Add(2*time.Second), valid, primary) {
		t.Fatal("retired handler woke the new active path")
	}
	valid.Tag = primary.policyRuntimeTag("route", "reserve")
	if !controller.acceptXrayFailureSignal(now.Add(2*time.Second), valid, primary) {
		t.Fatal("new active handler was not recognized")
	}
}

func TestXrayFailureSignalBypassesLivenessTimerButStillProbes(t *testing.T) {
	for _, next := range []int64{1000, 1060} {
		t.Run(time.Unix(next, 0).String(), func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			selected := contract.Candidates[0]
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = selected, selected, true
			item.CandidateSignature = selected
			item.LastProbeAt[selected] = 1000
			runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": selected}, probes: map[string]probeEvidence{selected: successfulEvidence(20)}}
			controller := &healthController{
				opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
				warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item},
				regularNext:   map[string]time.Time{"europe": time.Unix(next, 0)},
				livenessAt:    map[string]time.Time{"europe": time.Unix(1000, 0)},
				forceLiveness: map[string]bool{"europe": true},
			}
			if err := controller.Tick(time.Unix(1001, 0)); err != nil {
				t.Fatal(err)
			}
			if len(runtime.availabilityCalls) != 1 || runtime.availabilityCalls[0] != selected || len(runtime.selections) != 0 {
				t.Fatalf("signal must probe, not switch: probes=%v selections=%v", runtime.availabilityCalls, runtime.selections)
			}
		})
	}
}

func TestSignalDrivenFailoverRequiresProbeAndHealthyUnderlay(t *testing.T) {
	for _, wanOK := range []bool{true, false} {
		t.Run(map[bool]string{true: "wan-up", false: "wan-down"}[wanOK], func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			selected, reserve := contract.Candidates[0], contract.Candidates[1]
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = selected, selected, true
			item.CandidateSignature = selected + "\n" + reserve
			item.LastProbeAt[selected] = 1000
			runtime := &fakeSelectorRuntime{
				pool: pool, current: map[string]string{"europe": selected},
				probes:   map[string]probeEvidence{selected: {Failure: probeFailureFatal}, reserve: successfulEvidence(30)},
				underlay: underlayEvidence{Known: true, WANOK: wanOK, DNSOK: true},
			}
			controller := &healthController{
				opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
				warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item},
				regularNext:   map[string]time.Time{"europe": time.Unix(1060, 0)},
				livenessAt:    map[string]time.Time{"europe": time.Unix(1000, 0)},
				forceLiveness: map[string]bool{"europe": true},
			}
			if err := controller.Tick(time.Unix(1001, 0)); err != nil {
				t.Fatal(err)
			}
			if len(runtime.availabilityCalls) == 0 || runtime.availabilityCalls[0] != selected {
				t.Fatalf("active path was not verified: %v", runtime.availabilityCalls)
			}
			if wanOK {
				if item.Selected != reserve || len(runtime.availabilityCalls) < 2 || runtime.availabilityCalls[1] != reserve {
					t.Fatalf("healthy reserve was not confirmed: selected=%s probes=%v", item.Selected, runtime.availabilityCalls)
				}
			} else if item.Selected != selected || len(runtime.availabilityCalls) != 1 || len(runtime.selections) != 0 {
				t.Fatalf("WAN outage caused a node hop: selected=%s probes=%v selections=%v", item.Selected, runtime.availabilityCalls, runtime.selections)
			}
		})
	}
}

func TestHealthWakeIgnoresInvalidSignalsWithoutResettingCadence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	signals := make(chan xrayFailureSignal, 2)
	signals <- xrayFailureSignal{Tag: "stale"}
	signals <- xrayFailureSignal{Tag: "active"}
	start := time.Now()
	if !waitForHealthWake(ctx, 500*time.Millisecond, nil, time.Second, signals, func(signal xrayFailureSignal) bool { return signal.Tag == "active" }) {
		t.Fatal("valid signal did not wake the health loop")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("health loop waited for its timer despite a valid signal")
	}
}

func TestXrayFailureSignalInterruptsBackgroundProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	signals := make(chan xrayFailureSignal, 1)
	joined := make(chan struct{})
	signals <- xrayFailureSignal{Tag: "active"}
	forced := false
	result := awaitProbeJobWithSignals(ctx, time.Hour, func() error {
		if forced {
			return errHealthYield
		}
		return nil
	}, func(ctx context.Context) probeJobResult {
		defer close(joined)
		<-ctx.Done()
		return probeJobResult{err: ctx.Err()}
	}, signals, func(signal xrayFailureSignal) bool {
		forced = signal.Tag == "active"
		return forced
	})
	if !errors.Is(result.err, errHealthYield) {
		t.Fatalf("active failure did not interrupt the background probe: %+v", result)
	}
	select {
	case <-joined:
	default:
		t.Fatal("background probe was not joined after the signal")
	}
}

func TestXrayFailureSocketReceivesBoundedSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unixgram is validated on the Linux target")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "failure.sock")
	signals, closeSocket, err := listenXrayFailureSignals(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSocket()
	connection, err := net.Dial("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(`{"v":1,"pid":123,"tag":"active","stage":"dial"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case signal := <-signals:
		if signal.PID != 123 || signal.Tag != "active" || signal.Stage != "dial" {
			t.Fatalf("unexpected signal: %+v", signal)
		}
	case <-time.After(time.Second):
		t.Fatal("local signal was not received")
	}
	closeSocket()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket was not removed: %v", err)
	}
}
