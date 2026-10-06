package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestParallelQualitySignalWakesCheckAndJoinsWorkers(t *testing.T) {
	accepted := false
	runtime, _ := delayedAvailabilityRuntime(t, time.Second, func() error {
		if accepted {
			return errHealthYield
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	runtime.ctx = ctx
	signals := make(chan xrayFailureSignal, 1)
	runtime.signals = signals
	runtime.acceptSignal = func(signal xrayFailureSignal) bool {
		accepted = validXrayFailureSignal(signal) && signal.Tag == "active"
		return accepted
	}
	started, canceled := make(chan struct{}, 2), make(chan struct{}, 2)
	release := make(chan struct{})
	finishCleanup := sync.OnceFunc(func() { close(release) })
	for _, lane := range runtime.backgrounds {
		lane.command = func(ctx context.Context, _ time.Duration, _ string, _ ...string) ([]byte, error) {
			started <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			<-release
			return nil, ctx.Err()
		}
	}
	done := make(chan map[string]probeEvidence, 1)
	completed := false
	t.Cleanup(func() {
		cancel()
		finishCleanup()
		if !completed {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("parallel workers did not stop during cleanup")
			}
		}
	})
	go func() { done <- runtime.ProbeQualityParallel([]string{"a", "b"}) }()
	for range 2 {
		waitAgentWorkerSignal(t, started)
	}
	signals <- xrayFailureSignal{Version: 1, PID: 123, Tag: "active", Stage: "dial"}
	for range 2 {
		waitAgentWorkerSignal(t, canceled)
	}
	select {
	case <-done:
		completed = true
		t.Fatal("signal interruption returned before both workers released their lanes")
	case <-time.After(50 * time.Millisecond):
	}
	finishCleanup()
	select {
	case measured := <-done:
		completed = true
		if len(measured) != 0 || !errors.Is(runtime.takeProbeInterruption(), errHealthYield) {
			t.Fatalf("signal did not interrupt the routine batch safely: %+v", measured)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("joined parallel batch did not return")
	}
}

func TestParallelQualityIgnoresRejectedAndClosedSignals(t *testing.T) {
	for _, closed := range []bool{false, true} {
		name := "rejected"
		if closed {
			name = "closed"
		}
		t.Run(name, func(t *testing.T) {
			runtime, _ := delayedAvailabilityRuntime(t, 20*time.Millisecond, func() error { return nil })
			signals := make(chan xrayFailureSignal, 1)
			if closed {
				close(signals)
			} else {
				signals <- xrayFailureSignal{Tag: "retired"}
			}
			runtime.signals = signals
			acceptedCalls := 0
			runtime.acceptSignal = func(xrayFailureSignal) bool {
				acceptedCalls++
				return false
			}
			measured := runtime.ProbeQualityParallel([]string{"a", "b"})
			wantCalls := 1
			if closed {
				wantCalls = 0
			}
			if acceptedCalls != wantCalls || len(measured) != 2 || !measured["a"].OK || !measured["b"].OK || runtime.takeProbeInterruption() != nil {
				t.Fatalf("rejected/closed signal interfered with work: accept calls=%d results=%+v", acceptedCalls, measured)
			}
		})
	}
}

func TestEmergencyParallelIgnoresSignalStorm(t *testing.T) {
	checks, accepts := 0, 0
	runtime, _ := delayedAvailabilityRuntime(t, 80*time.Millisecond, func() error {
		checks++
		return errHealthYield
	})
	signals := make(chan xrayFailureSignal, 32)
	signal := xrayFailureSignal{Version: 1, PID: 123, Tag: "active", Stage: "dial"}
	for range cap(signals) {
		signals <- signal
	}
	runtime.signals = signals
	runtime.acceptSignal = func(xrayFailureSignal) bool {
		accepts++
		return true
	}
	ctx, stop := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case signals <- signal:
				default:
				}
			}
		}
	}()
	defer func() { stop(); <-stopped }()
	controller := &healthController{runtime: runtime}
	measured, selected, err := controller.probeEmergencyCandidates("route", []string{"a", "b"}, effectivePolicySettings{})
	if err != nil || selected == "" || !measured[selected].OK || checks != 0 || accepts != 0 {
		t.Fatalf("hint storm preempted emergency recovery: selected=%q checks=%d accepts=%d err=%v", selected, checks, accepts, err)
	}
}
