package agent

import (
	"testing"
	"time"
)

// These are controller decision regressions with synthetic observations, not
// network benchmarks or a replica of sing-box's transport-dependent clock.
// In particular, a fresh request and a reused request answer different questions.
func TestURLTestFreshAndWarmMeasurementTradeoffs(t *testing.T) {
	for _, scenario := range []struct {
		name                        string
		activeFresh, reserveFresh   int
		activeWarm, reserveWarm     int
		transient                   bool
		freshSelected, warmSelected string
	}{
		{"slow-setup-fast-reuse", 1000, 450, 80, 90, false, "node-01", "node-00"},
		{"persistent-response-delay", 1000, 450, 550, 100, false, "node-01", "node-01"},
		{"single-setup-spike", 1000, 450, 80, 90, true, "node-00", "node-00"},
	} {
		for _, warm := range []bool{false, true} {
			mode, want := "fresh", scenario.freshSelected
			if warm {
				mode, want = "warm", scenario.warmSelected
			}
			t.Run(scenario.name+"/"+mode, func(t *testing.T) {
				controller, runtime, base := warmControllerFixture(t, 2, 2, 2)
				controller.opts.URLTestWarmCompare = warm
				item := controller.state["route"]
				seed := scenario.activeFresh
				if scenario.transient {
					seed = 400
				}
				for node, delay := range map[string]int{"node-00": seed, "node-01": scenario.reserveFresh} {
					value := delay
					item.Samples[node] = []healthSample{{At: 998, ObservedAt: 998, OK: true, DelayMS: &value}}
				}
				runtime.warm["node-00"], runtime.warm["node-01"] = scenario.activeWarm, scenario.reserveWarm
				runtime.probes["node-01"] = successfulEvidence(scenario.reserveFresh)
				var switches []healthEvent
				controller.eventSink = func(event healthEvent) {
					if event.Event == "switch" {
						switches = append(switches, event)
					}
				}
				for second := 0; second <= 150; second += 3 {
					delay := scenario.activeFresh
					if scenario.transient && second >= 10 {
						delay = 400
					}
					runtime.probes["node-00"] = successfulEvidence(delay)
					runtime.at = base.Add(time.Duration(second) * time.Second)
					if err := controller.Tick(runtime.at); err != nil {
						t.Fatal(err)
					}
					if second < 60 && item.Selected != "node-00" {
						t.Fatalf("selection changed before an independent second confirmation at %ds", second)
					}
				}
				if item.Selected != want {
					t.Fatalf("%s selected %s, want %s; switches=%+v", mode, item.Selected, want, switches)
				}
				wantSwitches := 0
				if want == "node-01" {
					wantSwitches = 1
				}
				if len(switches) != wantSwitches {
					t.Fatalf("got %d switches, want %d: %+v", len(switches), wantSwitches, switches)
				}
				for _, event := range switches {
					comparison := event.Comparison
					if event.Reason != "meaningfully-faster" || comparison == nil || comparison.ConfirmationGapMS == nil || *comparison.ConfirmationGapMS < 60_000 {
						t.Fatalf("switch lacks independently spaced quality evidence: %+v", event)
					}
					metric := latencyMeasurement
					if warm {
						metric = string(qualityMeasurementWarm)
					}
					if comparison.Measurement != metric {
						t.Fatalf("reported %q for %s comparison", comparison.Measurement, mode)
					}
				}
				t.Logf("synthetic %s: selected=%s switches=%d jobs=%d primary-requests=%d", mode, item.Selected, len(switches), len(runtime.probeCalls), runtime.heads)
			})
		}
	}
}
