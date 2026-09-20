package agent

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func livenessFixture(t *testing.T, mode string) (*healthController, *fakeSelectorRuntime, *policyHealthState) {
	t.Helper()
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = mode
	contract.Policy.ActiveCheckSeconds, contract.Policy.BackupCheckSeconds = 60, 300
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.CandidateSignature, item.NextFullScanAt = "de", "de\nnl", 2800
	item.LastProbeAt["de"], item.LastProbeAt["nl"] = 940, 1000
	runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{"de": successfulEvidence(100), "nl": successfulEvidence(90)}}
	c := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
		warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item}}
	if err := c.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	return c, runtime, item
}

func TestHealthyFastLaneDoesNotRescoreScanOrWriteHistory(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			c, runtime, item := livenessFixture(t, mode)
			path := statePath(c.opts.StateRoot, "selector-health")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			stamp := time.Unix(10, 0)
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			recoveries := item.Recoveries["de"]
			for _, second := range []int64{1009, 1010, 1020, 1030, 1040, 1050} {
				if err := c.Tick(time.Unix(second, 0)); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || !info.ModTime().Equal(stamp) {
				t.Fatal("healthy fast lane rewrote persisted history")
			}
			if strings.Join(runtime.probeCalls, ",") != "de" || strings.Join(runtime.availabilityCalls, ",") != "de,de,de,de,de" {
				t.Fatalf("unexpected quality/availability probes: %v / %v", runtime.probeCalls, runtime.availabilityCalls)
			}
			if item.Recoveries["de"] != recoveries || runtime.speedCalls != 0 {
				t.Fatal("fast lane accelerated scoring or speed test")
			}
			if err := c.Tick(time.Unix(1060, 0)); err != nil {
				t.Fatal(err)
			}
			if strings.Join(runtime.probeCalls, ",") != "de,de" {
				t.Fatal("normal quality cadence lost")
			}
		})
	}
}

func TestInitialFailureDetectedBeforeMinuteWithConfirmedReserve(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			c, runtime, item := livenessFixture(t, mode)
			reserveDelay := 90
			item.Recoveries["nl"] = 3
			item.Samples["nl"] = []healthSample{{OK: true, DelayMS: &reserveDelay}, {OK: true, DelayMS: &reserveDelay}, {OK: true, DelayMS: &reserveDelay}}
			runtime.probes["de"] = failedEvidence()
			for _, second := range []int64{1010, 1015} {
				if err := c.Tick(time.Unix(second, 0)); err != nil {
					t.Fatal(err)
				}
				if item.Selected != "de" || c.nextInterval() != failureRetryInterval {
					t.Fatal("failure confirmations bypassed")
				}
			}
			if err := c.Tick(time.Unix(1020, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "nl" || !item.RuntimeConfirmed || item.LastSwitchReason != "active-unavailable" {
				t.Fatal("reserve not selected before regular tick")
			}
			if strings.Join(runtime.probeCalls, ",") != "de" || strings.Join(runtime.availabilityCalls, ",") != "de,de,de,nl" {
				t.Fatalf("unexpected emergency probes: quality=%v availability=%v", runtime.probeCalls, runtime.availabilityCalls)
			}
		})
	}
}

func TestFailureClassControlsActivePathConfirmation(t *testing.T) {
	for _, test := range []struct {
		name       string
		failure    probeFailureClass
		first      int64
		second     int64
		wantFirst  string
		wantSecond string
	}{
		{name: "fatal network switches immediately", failure: probeFailureFatal, first: 1010, wantFirst: "nl", wantSecond: "nl"},
		{name: "fatal TLS switches immediately", failure: probeFailureTLS, first: 1010, wantFirst: "nl", wantSecond: "nl"},
		{name: "timeout needs immediate confirmation", failure: probeFailureTimeout, first: 1010, wantFirst: "nl", wantSecond: "nl"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, runtime, item := livenessFixture(t, "priority")
			reserveDelay := 90
			item.AvailabilityOK["nl"] = true
			item.QualityOK["nl"] = true
			item.Recoveries["nl"] = 3
			item.MedianDelayMS["nl"] = &reserveDelay
			item.LastProbeAt["nl"] = 1000
			runtime.probes["de"] = probeEvidence{Failure: test.failure}

			if err := c.Tick(time.Unix(test.first, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != test.wantFirst {
				t.Fatalf("first decision selected %q, want %q", item.Selected, test.wantFirst)
			}
			if test.failure == probeFailureTimeout && strings.Join(runtime.availabilityCalls, ",") != "de,de" {
				t.Fatalf("timeout was not independently confirmed before failover: %v", runtime.availabilityCalls)
			}
			if test.second == 0 {
				return
			}
			if err := c.Tick(time.Unix(test.second, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != test.wantSecond {
				t.Fatalf("confirmed decision selected %q, want %q", item.Selected, test.wantSecond)
			}
		})
	}
}

func TestSharedUnderlayFailureSuppressesNodeHopping(t *testing.T) {
	for _, test := range []struct {
		name     string
		failure  probeFailureClass
		underlay underlayEvidence
		marker   string
	}{
		{name: "WAN outage", failure: probeFailureFatal, underlay: underlayEvidence{Known: true, WANOK: false, DNSOK: false}, marker: "wan"},
		{name: "DNS outage", failure: probeFailureDNS, underlay: underlayEvidence{Known: true, WANOK: true, DNSOK: false}, marker: "dns"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, runtime, item := livenessFixture(t, "priority")
			runtime.underlay = test.underlay
			runtime.probes["de"] = probeEvidence{Failure: test.failure}
			if err := c.Tick(time.Unix(1010, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "de" || item.AvailabilityFailures["de"] != 0 || item.UnderlayFailure != test.marker {
				t.Fatalf("shared outage changed node: selected=%q failures=%d marker=%q", item.Selected, item.AvailabilityFailures["de"], item.UnderlayFailure)
			}
			if hasSelection(runtime.selections, "europe", "nl") {
				t.Fatalf("shared outage hopped to reserve: %#v", runtime.selections)
			}
		})
	}
}
