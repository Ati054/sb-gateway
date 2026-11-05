package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWarmRuntimeStalledThirdPeerDoesNotStarveHealthyPair(t *testing.T) {
	original := healthTargets
	healthTargets = append(healthTargets[:0:0], original[0])
	healthTargets[0].url = "http://probe.invalid/generate_204"
	t.Cleanup(func() { healthTargets = original })
	pool := healthFixture(false)
	pool.Version, pool.BaseOutboundTags = 4, []string{"a", "b", "c"}
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	seen := map[string]*atomic.Int32{"a": {}, "b": {}, "c": {}}
	lanes := make([]*xraySelectorRuntime, 3)
	for index := range lanes {
		var selected atomic.Value
		selected.Store("")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen[selected.Load().(string)].Add(1)
			if selected.Load().(string) == "c" && r.Method == http.MethodHead {
				<-r.Context().Done() // Consume the full ordinary cold deadline.
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(server.Close)
		selector := fmt.Sprintf("warm-stall-%d", index)
		lane := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: server.URL})
		lane.probeSelector = selector
		lane.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[1] == "bo" {
				selected.Store(args[len(args)-1])
				return nil, nil
			}
			return selectorInfo(selected.Load().(string)), nil
		}
		lanes[index] = lane
	}
	runtime := &responsiveSelectorRuntime{selectorRuntime: &fakeSelectorRuntime{}, backgrounds: lanes,
		ctx: ctx, check: func() error { return nil }, enabled: true, parallelEnabled: true, generationPaths: []string{path}}
	runtime.generation = generationStamp(runtime.generationPaths)
	measured := runtime.ProbeQualityParallelWithMeasurement([]string{"a", "b", "c"}, qualityMeasurementWarm)
	t.Logf("HTTP requests a=%d b=%d c=%d interruption=%v", seen["a"].Load(), seen["b"].Load(), seen["c"].Load(), runtime.interrupted)
	if seen["a"].Load() == 0 || seen["b"].Load() == 0 || seen["c"].Load() == 0 {
		t.Fatal("fixture failed before exercising all three real HTTP peers")
	}
	for _, node := range []string{"a", "b"} {
		if !measured[node].OK || !validWarmQuality(measured[node].Warm) {
			t.Fatalf("stalled unrelated peer poisoned healthy %s: %+v", node, measured[node])
		}
	}
	if measured["a"].Warm.Wave == 0 || measured["a"].Warm.Wave != measured["b"].Warm.Wave {
		t.Fatal("healthy pair did not retain one physical warm wave")
	}
}

func TestWarmRuntimeKeepsColdFailureAndFallbackContracts(t *testing.T) {
	original := healthTargets
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	t.Cleanup(func() { healthTargets = original })
	for _, scenario := range []string{"legacy", "warm-ok", "warm-failed", "cold-failed"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("SB_HEALTH_STAGE_TRACE", "1")
			var traces bytes.Buffer
			writer := log.Writer()
			log.SetOutput(&traces)
			defer log.SetOutput(writer)
			var heads, gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					call := heads.Add(1)
					if scenario == "cold-failed" && call == 1 || scenario == "warm-failed" && call == 2 {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
				} else {
					gets.Add(1)
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
			var evidence probeEvidence
			if scenario == "legacy" {
				evidence = runtime.Probe("direct-wan")
			} else {
				evidence = runtime.ProbeWithQualityRequest("direct-wan", qualityProbeRequest{Measurement: qualityMeasurementWarm})
			}
			requests := 0
			for _, line := range strings.Split(traces.String(), "\n") {
				_, body, ok := strings.Cut(line, "agent: health-stage ")
				var stage healthStageRecord
				if ok && json.Unmarshal([]byte(body), &stage) == nil && stage.Stage == "https" {
					requests++
				}
			}
			if int32(requests) != heads.Load()+gets.Load() {
				t.Fatalf("HTTP trace hid physical requests: traces=%d HEAD=%d GET=%d", requests, heads.Load(), gets.Load())
			}
			if !evidence.OK || evidence.PrimaryQualityFailed || evidence.LocalFailure || evidence.ObservedAt.IsZero() {
				t.Fatalf("ordinary availability changed: %+v", evidence)
			}
			if scenario == "legacy" {
				if heads.Load() != 1 || gets.Load() != 0 || evidence.Warm != nil || evidence.DelayMS == nil {
					t.Fatalf("default cold path changed: %+v heads=%d gets=%d", evidence, heads.Load(), gets.Load())
				}
				return
			}
			if evidence.Warm == nil {
				t.Fatal("requested warm quality has no explicit observation")
			}
			if scenario == "cold-failed" {
				if heads.Load() != 1 || gets.Load() != 1 || !evidence.QualityUnmeasured || evidence.DelayMS != nil || !evidence.Warm.Failed {
					t.Fatalf("cold fallback changed or retried warm: %+v heads=%d gets=%d", evidence, heads.Load(), gets.Load())
				}
				return
			}
			if heads.Load() != 2 || gets.Load() != 0 || evidence.QualityUnmeasured || evidence.DelayMS == nil {
				t.Fatalf("successful cold response gained availability fallback: %+v heads=%d gets=%d", evidence, heads.Load(), gets.Load())
			}
			if evidence.Warm.Failed != (scenario == "warm-failed") || (evidence.Warm.DelayMS == nil) != (scenario == "warm-failed") {
				t.Fatalf("wrong warm quality classification: %+v", evidence)
			}
			if evidence.Warm.StartedAt.Before(evidence.ObservedAt) || evidence.Warm.ObservedAt.After(time.Now()) {
				t.Fatalf("cold and warm boundaries mixed: %+v", evidence)
			}
		})
	}
}
