package agent

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSingleOriginQualityHEADAndFallback(t *testing.T) {
	original := healthTargets
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	t.Cleanup(func() { healthTargets = original })
	for _, outcome := range []string{"healthy", "head-rejected", "origin-failed", "all-failed"} {
		t.Run(outcome, func(t *testing.T) {
			var calls, heads atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method == http.MethodHead {
					heads.Add(1)
				}
				if outcome == "all-failed" || r.URL.Path == "/gstatic-204" &&
					(outcome == "origin-failed" || outcome == "head-rejected" && r.Method == http.MethodHead) {
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
			evidence := runtime.Probe("direct-wan")
			if heads.Load() != 1 {
				t.Fatalf("quality must use one HEAD: %d", heads.Load())
			}
			if outcome == "healthy" {
				if !evidence.OK || evidence.DelayMS == nil || calls.Load() != 1 || len(evidence.Targets) != 1 || evidence.QualityUnmeasured || evidence.PrimaryQualityFailed {
					t.Fatalf("healthy HEAD queried other origins: %+v calls=%d", evidence, calls.Load())
				}
			} else {
				if evidence.OK != (outcome != "all-failed") || evidence.DelayMS != nil || !evidence.QualityUnmeasured || !evidence.PrimaryQualityFailed {
					t.Fatalf("fallback supplied ranking latency or wrong availability: %+v", evidence)
				}
				if calls.Load() > 4 {
					t.Fatal("fallback fanout exceeded its bound")
				}
			}
		})
	}
}

func TestHEADMeasurementDoesNotWaitForBody(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Error("not HEAD")
		}
		w.Header().Set("Content-Length", "10000000")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
	}))
	defer server.Close()
	defer close(release)
	started := time.Now()
	_, err := requestThroughProxyContext(t.Context(), server.URL, "http://probe.invalid/", http.MethodHead, time.Second, 0, 200)
	if err != nil || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("HEAD waited for a body: %v", err)
	}
}

func TestColdChoiceIgnoresToleranceButRestartKeepsWorkingLeaf(t *testing.T) {
	for _, restart := range []bool{false, true} {
		controller, item, runtime := stagedOptimizationController(t)
		controller.warmStarted["europe"] = false
		contract := runtime.pool.HealthPolicies["europe"]
		contract.Policy.SwitchImprovementMS = 200
		runtime.pool.HealthPolicies["europe"] = contract
		runtime.probes["active"], runtime.probes["reserve"] = successfulEvidence(500), successfulEvidence(490)
		if !restart {
			item.Selected, item.LastWorkingSelection, item.Samples = "", nil, nil
		}
		if err := controller.Tick(time.Unix(1060, 0)); err != nil {
			t.Fatal(err)
		}
		want := "reserve"
		if restart {
			want = "active"
		}
		if item.Selected != want {
			t.Fatalf("restart=%t selected=%s want=%s", restart, item.Selected, want)
		}
	}
}

func TestLatencyOriginMigrationKeepsWorkingSelectionAndRequiresFreshQuality(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.LatencyMeasurement = "gstatic-head-v1"
	runtime.pool.HealthPolicies["europe"] = contract
	controller.warmStarted["europe"] = false
	item.OptimizationChecks = 1
	old := 30000
	item.Samples["active"] = []healthSample{{OK: true, DelayMS: &old}}
	if err := controller.Tick(time.Unix(1060, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "active" || item.OptimizationChecks != 0 ||
		len(item.Samples["active"]) != 1 || *item.Samples["active"][0].DelayMS != 600 ||
		item.LatencyMeasurement != "gstatic-head-v1" {
		t.Fatal("old-origin quality influenced migrated selection")
	}
}

func TestReachableFallbackIsNotHistoricalPacketLoss(t *testing.T) {
	item := newPolicyHealthState()
	updateHistories(item, []string{"active"}, map[string]probeEvidence{"active": {OK: true}}, time.Unix(1000, 0))
	stats := summarizeSamples(item.DailySamples["active"])
	if stats.Successes != 1 || stats.Failures != 0 || stats.MedianMS != nil || *stats.AvailabilityPercent != 100 {
		t.Fatalf("reachable unranked fallback recorded as failure: %+v", stats)
	}
}
