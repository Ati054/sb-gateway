package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHealthJournalRecordsFailureAndConfirmedSwitch(t *testing.T) {
	controller, runtime, item := livenessFixture(t, "priority")
	reserveDelay := 90
	item.AvailabilityOK["nl"] = true
	item.QualityOK["nl"] = true
	item.Recoveries["nl"] = 3
	item.MedianDelayMS["nl"] = &reserveDelay
	item.LastProbeAt["nl"] = 1000
	runtime.probes["de"] = probeEvidence{
		Failure: probeFailureTimeout,
		Targets: map[string]*int{"gstatic-204": nil, "cloudflare-trace": nil},
		TargetFailures: map[string]probeFailureClass{
			"gstatic-204": probeFailureTimeout, "cloudflare-trace": probeFailureTimeout,
		},
	}
	events := []healthEvent{}
	controller.eventSink = func(event healthEvent) { events = append(events, event) }
	if err := controller.Tick(time.Unix(1010, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "de" || len(events) != 1 || events[0].Event != "probe-failed" ||
		events[0].Count != 1 || events[0].Threshold != 2 || events[0].Targets["gstatic-204"] != "timeout" ||
		events[0].Targets["cloudflare-trace"] != "timeout" {
		t.Fatalf("first failed probe/journal = selected %q, events %#v", item.Selected, events)
	}
	if err := controller.Tick(time.Unix(1012, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "nl" || len(events) != 3 || events[1].Event != "probe-failed" ||
		events[1].Count != 2 || events[2].Event != "switch" || events[2].From != "de" ||
		events[2].To != "nl" || events[2].Reason != "active-unavailable" || events[2].Failure != probeFailureTimeout {
		t.Fatalf("confirmed switch/journal = selected %q, events %#v", item.Selected, events)
	}
}

func TestProbeTargetResultsNeverIncludeRawEndpoint(t *testing.T) {
	delay := 24
	results := probeTargetResults(probeEvidence{
		Targets:        map[string]*int{"gstatic-204": nil, "cloudflare-trace": &delay},
		TargetFailures: map[string]probeFailureClass{"gstatic-204": probeFailureTLS},
	})
	if results["gstatic-204"] != "fatal-tls" || results["cloudflare-trace"] != "ok" || len(results) != 2 {
		t.Fatalf("unexpected sanitized targets: %#v", results)
	}
}

func TestDegradedSwitchJournalIncludesOnlyNumericDecisionEvidence(t *testing.T) {
	item := newPolicyHealthState()
	from, to := 2500, 500
	item.MedianDelayMS = map[string]*int{"active": &from, "reserve": &to}
	item.PacketLossPercent = map[string]float64{"active": 40, "reserve": 0}
	item.Failures["active"] = 3
	item.LastProbeAt["reserve"] = 970
	quality := switchQualityEvidence(time.Unix(1000, 0), item, "active", "reserve", "active-degraded")
	if quality == nil || quality.FromBadProbes != 3 || quality.ToProbeAgeSeconds != 30 ||
		*quality.FromMedianMS != from || *quality.ToMedianMS != to {
		t.Fatalf("missing switch evidence: %+v", quality)
	}
	body, err := json.Marshal(healthEvent{Event: "switch", Quality: quality})
	if err != nil || !strings.Contains(string(body), `"from_loss_percent":40`) ||
		strings.Contains(string(body), "candidate_nodes") {
		t.Fatalf("unsafe or incomplete event: %s (%v)", body, err)
	}
	if switchQualityEvidence(time.Unix(1000, 0), item, "active", "reserve", "active-unavailable") != nil {
		t.Fatal("outage switch gained unrelated quality payload")
	}
}

func TestOptimizationSwitchJournalIncludesFreshComparison(t *testing.T) {
	controller, item, _ := stagedOptimizationController(t)
	var events []healthEvent
	controller.eventSink = func(event healthEvent) { events = append(events, event) }
	for _, at := range []int64{1_060, 1_120} {
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if len(events) != 1 || events[0].Event != "switch" || events[0].Reason != "meaningfully-faster" {
		t.Fatalf("expected one confirmed optimization event: %+v", events)
	}
	comparison := events[0].Comparison
	if comparison == nil || comparison.Result != optimizationWin || comparison.Reason != "better" ||
		comparison.Candidate != events[0].To || comparison.At != events[0].At ||
		comparison.ActiveDelayMS == nil || *comparison.ActiveDelayMS != 600 ||
		comparison.CandidateDelayMS == nil || *comparison.CandidateDelayMS != 500 {
		t.Fatalf("switch lost its paired decision evidence: %+v", comparison)
	}
	body, err := json.Marshal(events[0])
	if err != nil || !strings.Contains(string(body), `"candidate_delay_ms":500`) || strings.Contains(string(body), "speed_bps") ||
		strings.Contains(string(body), "candidate_nodes") || strings.Contains(string(body), "https://") {
		t.Fatalf("unsafe or incomplete optimization event: %s (%v)", body, err)
	}
	if switchOptimizationEvidence(item, "reserve", "active-unavailable") != nil ||
		switchOptimizationEvidence(item, "other", "meaningfully-faster") != nil {
		t.Fatal("another switch reused optimization evidence")
	}
	item.LastSwitchAt = time.Unix(1_180, 0).UTC().Format(time.RFC3339)
	if switchOptimizationEvidence(item, "reserve", "meaningfully-faster") != nil {
		t.Fatal("later switch reused old optimization evidence")
	}
}
