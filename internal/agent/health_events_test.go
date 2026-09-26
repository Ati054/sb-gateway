package agent

import (
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
