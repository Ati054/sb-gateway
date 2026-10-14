package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestReverseRecoveryUsesActiveRequestContract(t *testing.T) {
	originalTargets := healthTargets
	originalPrimary, originalFallback := availabilityProbeTimeout, availabilityFallbackTimeout
	originalDelay := availabilityFallbackDelay
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	availabilityProbeTimeout, availabilityFallbackTimeout = 150*time.Millisecond, 150*time.Millisecond
	availabilityFallbackDelay = 60 * time.Millisecond
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	t.Cleanup(func() {
		healthTargets = originalTargets
		availabilityProbeTimeout, availabilityFallbackTimeout = originalPrimary, originalFallback
		availabilityFallbackDelay = originalDelay
	})
	for _, outcome := range []string{"healthy", "head-only", "slow-get"} {
		t.Run(outcome, func(t *testing.T) {
			var heads, gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					heads.Add(1)
				} else {
					gets.Add(1)
					if outcome == "head-only" {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
					if outcome == "slow-get" {
						select {
						case <-time.After(450 * time.Millisecond):
						case <-r.Context().Done():
							return
						}
					}
				}
				if r.URL.Path == "/gstatic-204" {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
			runtime.pool = healthPool{HealthPolicies: map[string]healthPolicyContract{
				"route": {Nodes: map[string]healthNode{"reverse-vless-test": {Protocol: "xray-reverse"}}},
			}}
			runtime.selectorMembers["outbound-health-probe"] = "reverse-vless-test"
			runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
				if args[1] != "statsonline" {
					t.Fatalf("unexpected command: %v", args)
				}
				return []byte(`{"stat":{"name":"user>>>reverse-vless-test>>>online","value":1}}`), nil
			}
			quality, active := runtime.Probe("reverse-vless-test"), runtime.ProbeAvailability("reverse-vless-test")
			if quality.OK != active.OK || quality.OK != (outcome == "healthy") {
				t.Fatalf("different recovery/active result: quality=%+v active=%+v", quality, active)
			}
			if heads.Load() != 0 || gets.Load() == 0 {
				t.Fatalf("Reverse used a different request method: heads=%d gets=%d", heads.Load(), gets.Load())
			}
			if outcome == "healthy" && (gets.Load() != 2 || quality.DelayMS == nil || quality.QualityUnmeasured) {
				t.Fatalf("healthy Reverse duplicated qualification requests: %+v gets=%d", quality, gets.Load())
			}
			if outcome == "slow-get" {
				if len(active.TargetStages) != len(healthTargets) {
					t.Fatalf("timeout stages missing from evidence: %+v", active)
				}
				for _, stage := range active.TargetStages {
					if stage != "response-headers" {
						t.Fatalf("slow GET assigned wrong stage: %+v", active)
					}
				}
			}
		})
	}
}
