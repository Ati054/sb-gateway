package agent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func pendingFailureFixture(t *testing.T, mode string) (*healthController, *fakeSelectorRuntime, *policyHealthState) {
	t.Helper()
	controller, runtime, item := livenessFixture(t, mode)
	reserveDelay := 90
	item.AvailabilityOK["nl"], item.QualityOK["nl"] = true, true
	item.Recoveries["nl"], item.MedianDelayMS["nl"] = 3, &reserveDelay
	runtime.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
	runtime.probeCalls, runtime.availabilityCalls = nil, nil
	return controller, runtime, item
}

func TestPendingActiveFailureKeepsFastLaneWhenQualityIsDue(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, outcome := range []struct {
			name       string
			evidence   probeEvidence
			underlay   underlayEvidence
			selected   string
			marker     string
			probeCalls string
		}{
			{name: "confirmed timeout", evidence: probeEvidence{Failure: probeFailureTimeout}, selected: "nl", probeCalls: "de,de,nl"},
			{name: "active recovered", evidence: successfulEvidence(100), selected: "de", probeCalls: "de,de"},
			{name: "WAN failed", evidence: probeEvidence{Failure: probeFailureTimeout}, underlay: underlayEvidence{Known: true}, selected: "de", marker: "wan", probeCalls: "de,de"},
			{name: "DNS failed", evidence: probeEvidence{Failure: probeFailureTimeout}, underlay: underlayEvidence{Known: true, WANOK: true}, selected: "de", marker: "dns", probeCalls: "de,de"},
		} {
			t.Run(mode+"/"+outcome.name, func(t *testing.T) {
				controller, runtime, item := pendingFailureFixture(t, mode)
				if err := controller.Tick(time.Unix(1058, 0)); err != nil {
					t.Fatal(err)
				}
				if item.Selected != "de" || item.AvailabilityFailures["de"] != 1 {
					t.Fatalf("first failure bypassed confirmation: selected=%s failures=%d", item.Selected, item.AvailabilityFailures["de"])
				}
				controller.regularNext["europe"] = time.Unix(1059, 0)
				if err := controller.Tick(time.Unix(1059, 0)); err != nil {
					t.Fatal(err)
				}
				if item.Selected != "de" || item.AvailabilityFailures["de"] != 1 || len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != "de" {
					t.Fatalf("due quality bypassed the failure retry interval: selected=%s failures=%d quality=%v availability=%v", item.Selected, item.AvailabilityFailures["de"], runtime.probeCalls, runtime.availabilityCalls)
				}
				runtime.probes["de"], runtime.underlay = outcome.evidence, outcome.underlay
				if err := controller.Tick(time.Unix(1060, 0)); err != nil {
					t.Fatal(err)
				}
				if item.Selected != outcome.selected || item.UnderlayFailure != outcome.marker || !item.RuntimeConfirmed {
					t.Fatalf("wrong fast confirmation outcome: selected=%s marker=%s confirmed=%t", item.Selected, item.UnderlayFailure, item.RuntimeConfirmed)
				}
				if len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != outcome.probeCalls {
					t.Fatalf("pending failure entered routine work: quality=%v availability=%v", runtime.probeCalls, runtime.availabilityCalls)
				}
				if outcome.selected == "de" && item.AvailabilityFailures["de"] != 0 {
					t.Fatalf("recovery/underlay suppression retained failure count: %d", item.AvailabilityFailures["de"])
				}
				if outcome.name == "active recovered" {
					if err := controller.Tick(time.Unix(1061, 0)); err != nil {
						t.Fatal(err)
					}
					if strings.Join(runtime.probeCalls, ",") != "de,nl" {
						t.Fatalf("recovered active did not resume due quality work: %v", runtime.probeCalls)
					}
				}
			})
		}
	}
}

func TestResponsiveFailureResumesFastConfirmation(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, item := pendingFailureFixture(t, mode)
			controller.forceLiveness = map[string]bool{"europe": true}
			if err := controller.checkDuringProbe(time.Unix(1010, 0), runtime.pool); !errors.Is(err, errHealthYield) {
				t.Fatalf("first failure did not yield background work: %v", err)
			}
			if item.AvailabilityFailures["de"] != 1 || controller.forceLiveness["europe"] || !controller.regularNext["europe"].IsZero() {
				t.Fatalf("unexpected responsive retry state: failures=%d forced=%t next=%v", item.AvailabilityFailures["de"], controller.forceLiveness["europe"], controller.regularNext["europe"])
			}
			if err := controller.Tick(time.Unix(1012, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "nl" || len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != "de,de,nl" {
				t.Fatalf("yield resumed routine work instead of fast confirmation: selected=%s quality=%v availability=%v", item.Selected, runtime.probeCalls, runtime.availabilityCalls)
			}
		})
	}
}

func TestConfirmedResponsiveFailureDoesNotWaitForAnotherActiveProbe(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, item := pendingFailureFixture(t, mode)
			for _, second := range []int64{1010, 1012} {
				if err := controller.checkDuringProbe(time.Unix(second, 0), runtime.pool); !errors.Is(err, errHealthYield) {
					t.Fatalf("failed proof did not yield background work: %v", err)
				}
			}
			p := policySettings(runtime.pool.HealthPolicies["europe"].Policy, mode)
			if item.AvailabilityFailures["de"] != p.failureThreshold {
				t.Fatalf("second proof did not confirm outage: %d", item.AvailabilityFailures["de"])
			}
			if err := controller.Tick(time.Unix(1012, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "nl" || len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != "de,de,nl" {
				t.Fatalf("confirmed outage waited for another active proof: selected=%s quality=%v availability=%v", item.Selected, runtime.probeCalls, runtime.availabilityCalls)
			}
		})
	}
}

func TestPendingFailureDoesNotBypassStartup(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, item := pendingFailureFixture(t, mode)
			item.AvailabilityFailures["de"] = 1
			runtime.probes["de"] = successfulEvidence(100)
			runtime.reset = true
			if err := controller.Tick(time.Unix(1012, 0)); err != nil {
				t.Fatal(err)
			}
			if len(runtime.probeCalls) == 0 || runtime.probeCalls[0] != "de" || len(runtime.availabilityCalls) != 0 || !item.RuntimeConfirmed {
				t.Fatalf("pending failure bypassed startup reconciliation: quality=%v availability=%v confirmed=%t", runtime.probeCalls, runtime.availabilityCalls, item.RuntimeConfirmed)
			}
		})
	}
}

func TestInterruptedWarmSurveyDoesNotRestartBeforeFastConfirmation(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, item := pendingFailureFixture(t, mode)
			if err := controller.Tick(time.Unix(1058, 0)); err != nil {
				t.Fatal(err)
			}
			if item.AvailabilityFailures["de"] != 1 || !item.RuntimeConfirmed {
				t.Fatal("first proof did not establish a confirmed active pending failure")
			}
			// A yielded cold survey has not completed quality initialization, but
			// its live active selector is already reconciled in this generation.
			controller.warmStarted["europe"] = false
			if err := controller.Tick(time.Unix(1059, 0)); err != nil {
				t.Fatal(err)
			}
			if item.AvailabilityFailures["de"] != 1 || len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != "de" {
				t.Fatalf("warm restart bypassed retry cadence: quality=%v availability=%v", runtime.probeCalls, runtime.availabilityCalls)
			}
			if err := controller.Tick(time.Unix(1060, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "nl" || !item.RuntimeConfirmed || len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != "de,de,nl" {
				t.Fatalf("pending cold survey restarted routine work: selected=%s quality=%v availability=%v", item.Selected, runtime.probeCalls, runtime.availabilityCalls)
			}
		})
	}
}
