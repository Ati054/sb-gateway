package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLegacyCooldownDoesNotDelayFreshLatencyWins(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	for node, delay := range map[string]int{"active": 805, "reserve": 300} {
		value := delay
		item.Samples[node] = []healthSample{{At: 1000, OK: true, DelayMS: &value}}
		runtime.probes[node] = successfulEvidence(delay)
	}
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["cooldown_until"] = json.RawMessage(`999999`)
	legacy["quality_thresholds"] = json.RawMessage(`{"max_latency_ms":2000,"cooldown_seconds":600}`)
	if err := writeJSONAtomic(statePath(controller.opts.StateRoot, "selector-health"), map[string]any{"europe": legacy}); err != nil {
		t.Fatal(err)
	}
	controller.state, controller.stateLoaded = nil, false
	for index, at := range []int64{1060, 1120} {
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
		item = controller.state["europe"]
		if index == 0 && (item.Selected != "active" || item.OptimizationChecks != 1 || hasSelection(runtime.selections, "europe", "reserve")) {
			t.Fatal("first fresh win bypassed confirmation")
		}
	}
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" || len(runtime.probeCalls) != 4 {
		t.Fatalf("legacy cooldown delayed two fresh pairs: selected=%s reason=%s probes=%v", item.Selected, item.LastSwitchReason, runtime.probeCalls)
	}
	body, err = json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"cooldown_until", "cooldown_seconds", "max_latency_ms"} {
		if strings.Contains(string(body), retired) {
			t.Fatalf("retired field survived publication: %s", retired)
		}
	}
}

func TestTransientLatencyWinDoesNotSwitch(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	clearOptimizationCandidate(item)
	runtime.probes["active"] = successfulEvidence(805)
	for index, delay := range []int{300, 790, 300, 300} {
		runtime.probes["reserve"] = successfulEvidence(delay)
		if err := controller.Tick(time.Unix(int64(1060+60*index), 0)); err != nil {
			t.Fatal(err)
		}
		if index < 3 && (item.Selected != "active" || hasSelection(runtime.selections, "europe", "reserve")) {
			t.Fatalf("transient or inherited win moved traffic at step %d", index)
		}
		if index == 1 && (item.OptimizationChecks != 0 || item.OptimizationCandidate != "") {
			t.Fatal("loss did not erase the first transient win")
		}
		if index == 2 && item.OptimizationChecks != 1 {
			t.Fatal("new win inherited the earlier comparison")
		}
	}
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatal("two new independent wins did not switch after a loss")
	}
}

func TestFallbackOnlyActiveYieldsToFreshQualityReserve(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, reserveQuality := range []bool{false, true} {
			name := mode + "/fallback-reserve"
			if reserveQuality {
				name = mode + "/quality-reserve"
			}
			t.Run(name, func(t *testing.T) {
				controller, item, runtime := stagedOptimizationController(t)
				contract := runtime.pool.HealthPolicies["europe"]
				contract.Mode = mode
				runtime.pool.HealthPolicies["europe"] = contract
				item.Mode = mode
				clearOptimizationCandidate(item)
				fallback := probeEvidence{OK: true, QualityUnmeasured: true, PrimaryQualityFailed: true}
				runtime.probes["active"] = fallback
				if !reserveQuality {
					runtime.probes["reserve"] = fallback
				}
				for index, at := range []int64{1060, 1120, 1180} {
					if err := controller.Tick(time.Unix(at, 0)); err != nil {
						t.Fatal(err)
					}
					if !item.AvailabilityOK["active"] || item.AvailabilityFailures["active"] != 0 || item.QualityOK["active"] || item.Failures["active"] != index+1 {
						t.Fatalf("primary failure corrupted fallback availability: failures=%d availability=%t quality=%t", item.Failures["active"], item.AvailabilityOK["active"], item.QualityOK["active"])
					}
					if index < 2 && (item.Selected != "active" || hasSelection(runtime.selections, "europe", "reserve")) {
						t.Fatal("unconfirmed primary-quality failure moved traffic")
					}
				}
				if reserveQuality {
					if item.Selected != "reserve" || item.LastSwitchReason != "active-degraded" {
						t.Fatalf("confirmed primary failure did not yield to a qualified reserve: selected=%s reason=%s", item.Selected, item.LastSwitchReason)
					}
				} else if item.Selected != "active" || len(runtime.selections) != 0 {
					t.Fatalf("unqualified reserve displaced a working fallback path: %v", runtime.selections)
				}
				if hasSelection(runtime.selections, "europe", "block") {
					t.Fatal("primary-origin failure blocked usable fallback availability")
				}
			})
		}
	}
}

func TestAvailabilityProbeDoesNotInventPrimaryQualityFailure(t *testing.T) {
	original := healthTargets
	healthTargets = append(healthTargets[:0:0], original...)
	for index := range healthTargets {
		healthTargets[index].url = "http://probe.invalid/" + healthTargets[index].label
	}
	t.Cleanup(func() { healthTargets = original })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("availability attempted a quality HEAD")
		}
		if r.URL.Path == "/gstatic-204" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	for _, mode := range []string{"routine", "emergency"} {
		t.Run(mode, func(t *testing.T) {
			runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
			runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
			var evidence probeEvidence
			if mode == "emergency" {
				evidence = runtime.ProbeEmergencyAvailability("direct-wan")
			} else {
				evidence = runtime.ProbeAvailability("direct-wan")
			}
			if !evidence.OK || evidence.PrimaryQualityFailed {
				t.Fatalf("availability-only fallback invented primary HEAD failure: %+v", evidence)
			}
		})
	}
}
