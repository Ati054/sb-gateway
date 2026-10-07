package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func delayedAvailabilityRuntime(t *testing.T, delay time.Duration, check func() error) (*responsiveSelectorRuntime, string) {
	t.Helper()
	oldTargets := healthTargets
	healthTargets = append(healthTargets[:0:0], oldTargets[0])
	healthTargets[0].url = "http://probe.invalid/generate_204"
	t.Cleanup(func() { healthTargets = oldTargets })
	pool := healthFixture(false)
	pool.Version = 4
	pool.BaseOutboundTags = []string{"a", "b"}
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	lanes := make([]*xraySelectorRuntime, 0, 2)
	for _, lag := range []time.Duration{delay, delay + 300*time.Millisecond} {
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			select {
			case <-request.Context().Done():
				return
			case <-time.After(lag):
				w.WriteHeader(http.StatusNoContent)
			}
		}))
		t.Cleanup(proxy.Close)
		lane := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: proxy.URL})
		lane.probeSelector = "outbound-health-background"
		selected := ""
		lane.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[1] == "bo" {
				selected = args[len(args)-1]
				return nil, nil
			}
			return selectorInfo(selected), nil
		}
		lanes = append(lanes, lane)
	}
	runtime := &responsiveSelectorRuntime{
		selectorRuntime: &fakeSelectorRuntime{}, backgrounds: lanes, ctx: context.Background(),
		enabled: true, parallelEnabled: true, generationPaths: []string{path}, check: check,
	}
	runtime.generation = generationStamp(runtime.generationPaths)
	return runtime, path
}

func TestConfirmedEmergencyDoesNotYieldToUnrelatedPolicyCheck(t *testing.T) {
	checks := 0
	runtime, _ := delayedAvailabilityRuntime(t, 1200*time.Millisecond, func() error {
		checks++
		return errHealthYield
	})
	controller := &healthController{runtime: runtime}
	measured, selected, err := controller.probeEmergencyCandidates("route", []string{"a", "b"}, effectivePolicySettings{})
	if err != nil || selected == "" || !measured[selected].OK || checks != 0 {
		t.Fatalf("confirmed emergency was preempted: selected=%q checks=%d err=%v", selected, checks, err)
	}
}

func TestOrdinaryParallelAvailabilityStillYieldsToActivePolicyCheck(t *testing.T) {
	checks := 0
	runtime, _ := delayedAvailabilityRuntime(t, 1200*time.Millisecond, func() error {
		checks++
		return errHealthYield
	})
	measured := runtime.ProbeAvailabilityParallel([]string{"a", "b"}, nil)
	if checks == 0 || len(measured) != 0 || !errors.Is(runtime.takeProbeInterruption(), errHealthYield) {
		t.Fatalf("routine probing failed to yield: checks=%d results=%d", checks, len(measured))
	}
}

func TestEmergencyRejectsGenerationChangedBeforeFirstResult(t *testing.T) {
	runtime, path := delayedAvailabilityRuntime(t, 250*time.Millisecond, func() error { return nil })
	changed := make(chan error, 1)
	timer := time.AfterFunc(50*time.Millisecond, func() {
		changed <- os.WriteFile(path, []byte("new-generation"), 0600)
	})
	defer timer.Stop()
	controller := &healthController{runtime: runtime}
	_, selected, err := controller.probeEmergencyCandidates("route", []string{"a", "b"}, effectivePolicySettings{})
	if changeErr := <-changed; changeErr != nil {
		t.Fatal(changeErr)
	}
	if selected != "" || !errors.Is(err, errHealthYield) {
		t.Fatalf("stale emergency result selected after generation change: selected=%q err=%v", selected, err)
	}
}

func TestEmergencyCancellationJoinsWorkersWithoutSelection(t *testing.T) {
	runtime, _ := delayedAvailabilityRuntime(t, 1200*time.Millisecond, func() error { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	runtime.ctx = ctx
	controller := &healthController{runtime: runtime}
	_, selected, err := controller.probeEmergencyCandidates("route", []string{"a", "b"}, effectivePolicySettings{})
	if selected != "" || !errors.Is(err, errHealthYield) {
		t.Fatalf("cancelled emergency selected a route: selected=%q err=%v", selected, err)
	}
}

func TestEmergencyCallbackCannotPublishAcrossApply(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		for _, change := range []string{"generation", "cancellation"} {
			t.Run(fmt.Sprintf("parallel=%t/%s", parallel, change), func(t *testing.T) {
				runtime, path := delayedAvailabilityRuntime(t, time.Millisecond, nil)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				runtime.ctx = ctx
				candidates := []string{"a", "b"}
				if !parallel {
					runtime.selectorRuntime = &fakeSelectorRuntime{probes: map[string]probeEvidence{"a": successfulEvidence(1)}}
					candidates = candidates[:1]
				}
				calls := 0
				runtime.ProbeEmergencyAvailabilityParallel(candidates, func(string, probeEvidence) bool {
					calls++
					// Select can overlap the atomic publication of a new Apply pool.
					if change == "generation" {
						if err := os.WriteFile(path, []byte("replacement-generation"), 0600); err != nil {
							t.Fatal(err)
						}
					} else {
						cancel()
					}
					return true
				})
				if calls != 1 || !errors.Is(runtime.takeProbeInterruption(), errHealthYield) {
					t.Fatal("callback accepted evidence from a replaced or cancelled runtime")
				}
			})
		}
	}
}
