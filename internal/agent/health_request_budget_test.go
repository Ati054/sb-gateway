package agent

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestProductionAvailabilityBudgetAcceptsFourSecondResponse(t *testing.T) {
	if availabilityProbeTimeout != 5*time.Second || availabilityFallbackTimeout != 5*time.Second {
		t.Fatal("availability must have a five-second round budget")
	}
	originalTargets := healthTargets
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	t.Cleanup(func() { healthTargets = originalTargets })
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "primary", true: "fallback"}[fallback], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fallback && r.URL.Path == "/gstatic-204" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				select {
				case <-time.After(4 * time.Second):
				case <-r.Context().Done():
					return
				}
				if r.URL.Path == "/gstatic-204" {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
			runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
			evidence := runtime.ProbeAvailability("direct-wan")
			if !evidence.OK || evidence.LocalFailure || !evidence.QualityUnmeasured {
				t.Fatalf("four-second availability response rejected: %+v", evidence)
			}
			for _, mode := range []string{"best", "urltest", "priority", "fallback", "reverse"} {
				t.Run(mode, func(t *testing.T) {
					controller, item, fake := stagedOptimizationController(t)
					contract := fake.pool.HealthPolicies["europe"]
					contract.Mode = mode
					fake.probes["active"] = evidence
					item.AvailabilityFailures["active"] = 1
					controller.livenessAt = map[string]time.Time{}
					controller.forceLiveness = map[string]bool{"europe": true}
					if _, err := controller.checkActiveAvailability(time.Unix(1001, 0), "europe", contract, item, true); err != nil {
						t.Fatal(err)
					}
					if item.Selected != "active" || item.AvailabilityFailures["active"] != 0 || len(fake.selections) != 0 {
						t.Fatalf("reachable active caused a switch: selected=%s failures=%d selections=%v", item.Selected, item.AvailabilityFailures["active"], fake.selections)
					}
				})
			}
		})
	}
}

func TestAvailabilityHedgeKeepsFastPathAndBoundsSilence(t *testing.T) {
	if availabilityFallbackDelay != 2*time.Second {
		t.Fatal("alternatives must wait two seconds for a pending primary")
	}
	originalTargets := healthTargets
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	t.Cleanup(func() { healthTargets = originalTargets })
	for _, outcome := range []string{"within-two-seconds", "hedged-success", "silent"} {
		t.Run(outcome, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if outcome == "silent" || outcome == "hedged-success" && r.URL.Path == "/gstatic-204" {
					<-r.Context().Done()
					return
				}
				if outcome == "within-two-seconds" {
					time.Sleep(1200 * time.Millisecond)
				}
				if r.URL.Path == "/gstatic-204" {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
			runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
			at := time.Now()
			evidence := runtime.ProbeAvailability("direct-wan")
			elapsed := time.Since(at)
			switch outcome {
			case "within-two-seconds":
				if !evidence.OK || calls.Load() != 1 {
					t.Fatalf("ordinary latency expanded fanout: %+v calls=%d", evidence, calls.Load())
				}
			case "hedged-success":
				if !evidence.OK || elapsed < 2*time.Second || elapsed > 3*time.Second || len(evidence.TargetFailures) != 0 {
					t.Fatalf("hedge canceled primary early or ran late: %+v elapsed=%s", evidence, elapsed)
				}
			case "silent":
				if evidence.OK || evidence.Failure != probeFailureTimeout || len(evidence.TargetFailures) != 3 || calls.Load() != 3 || elapsed < 4800*time.Millisecond || elapsed > 6*time.Second {
					t.Fatalf("silent round did not retain one five-second deadline: %+v elapsed=%s calls=%d", evidence, elapsed, calls.Load())
				}
			}
		})
	}
}
