package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfirmedFailureProbesReserveWithoutBackupWait(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		for _, batch := range []int{1, 3} {
			t.Run(fmt.Sprintf("%s/batch=%d", mode, batch), func(t *testing.T) {
				pool := healthFixture(true)
				contract := pool.HealthPolicies["europe"]
				contract.Mode = mode
				contract.Policy.ActiveCheckSeconds = 60
				contract.Policy.BackupCheckSeconds = 300
				contract.Policy.ProbeBatchSize = batch
				pool.HealthPolicies["europe"] = contract
				item := newPolicyHealthState()
				item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
				item.CandidateSignature = "de\nnl"
				item.NextFullScanAt, item.CooldownUntil = 2800, 9000
				item.LastProbeAt["de"], item.LastProbeAt["nl"] = 940, 1000
				// A reserve that recently failed is retried immediately. With no
				// maintained alternative, a current usable response restores service.
				item.Samples["nl"] = []healthSample{{OK: false}}
				runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"},
					probes: map[string]probeEvidence{"de": failedEvidence(), "nl": successfulEvidence(500)}}
				controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute},
					runtime: runtime, warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item}}
				for _, second := range []int64{1000, 1000 + int64(failureRetryInterval/time.Second)} {
					if err := controller.Tick(time.Unix(second, 0)); err != nil {
						t.Fatal(err)
					}
					if item.Selected != "de" || controller.nextInterval() != failureRetryInterval {
						t.Fatal("confirmation/cadence violated")
					}
				}
				for second := int64(1000 + 2*int64(failureRetryInterval/time.Second)); second <= 1030 && item.Selected != "nl"; second += int64(failureRetryInterval / time.Second) {
					if err := controller.Tick(time.Unix(second, 0)); err != nil {
						t.Fatal(err)
					}
				}
				if item.Selected != "nl" || item.LastSwitchReason != "active-unavailable" || !item.RuntimeConfirmed {
					t.Fatalf("reserve not restored promptly: selected=%s reason=%s probes=%v", item.Selected, item.LastSwitchReason, runtime.probeCalls)
				}
				if item.CooldownUntil <= 1000 {
					t.Fatalf("recovered reserve has no anti-flap cooldown: %.0f", item.CooldownUntil)
				}
				if runtime.speedCalls != 0 || controller.nextInterval() != activeLivenessInterval {
					t.Fatal("outage download or continued fast polling")
				}
				if strings.Join(runtime.probeCalls, ",") != "de" || strings.Join(runtime.availabilityCalls, ",") != "de,de,nl" {
					t.Fatalf("unexpected probes: %v / %v", runtime.probeCalls, runtime.availabilityCalls)
				}
			})
		}
	}
}

func TestSingleFailureDoesNotSwitchAndRestoresNormalCadence(t *testing.T) {
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Policy.ActiveCheckSeconds, contract.Policy.BackupCheckSeconds = 60, 300
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.CandidateSignature, item.NextFullScanAt = "de", "de\nnl", 2800
	item.LastProbeAt["nl"] = 1000
	runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"}, probes: map[string]probeEvidence{"de": failedEvidence()}}
	c := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
		warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item}}
	if err := c.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	runtime.probes["de"] = successfulEvidence(100)
	if err := c.Tick(time.Unix(1005, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "de" || c.nextInterval() != activeLivenessInterval || hasSelection(runtime.selections, "europe", "nl") {
		t.Fatal("transient failure caused flapping")
	}
}

func TestConfirmedFailureIsSuppressedWhenUnderlayDropsBeforeSwitch(t *testing.T) {
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Policy.SwitchCooldownSeconds = 600
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.CandidateSignature = "de\nnl"
	item.AvailabilityFailures["de"] = contract.Policy.FailureThreshold
	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"europe": "de"},
		probes:   map[string]probeEvidence{"de": failedEvidence(), "nl": successfulEvidence(90)},
		underlay: underlayEvidence{Known: true, WANOK: false, DNSOK: false},
	}
	controller := &healthController{
		opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
		warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item},
	}
	if err := controller.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "de" || item.AvailabilityFailures["de"] != 0 || item.UnderlayFailure != "wan" {
		t.Fatalf("underlay race changed route: selected=%s failures=%d underlay=%s", item.Selected, item.AvailabilityFailures["de"], item.UnderlayFailure)
	}
	if hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("underlay race selected reserve: %#v", runtime.selections)
	}
}

func TestRecoveredUnderlayRechecksActiveBeforeSwitching(t *testing.T) {
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.CandidateSignature = "de\nnl"
	item.AvailabilityFailures["de"] = contract.Policy.FailureThreshold
	item.UnderlayFailure = "wan"
	item.UnderlayCheckedAt = time.Unix(995, 0).UTC().Format(time.RFC3339Nano)
	item.AvailabilityOK = map[string]bool{"nl": true}
	item.QualityOK = map[string]bool{"nl": true}
	item.Recoveries["nl"] = contract.Policy.RecoveryThreshold
	item.LastProbeAt["nl"] = 999
	reserveDelay := 90
	item.MedianDelayMS = map[string]*int{"nl": &reserveDelay}
	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"europe": "de"},
		probes:   map[string]probeEvidence{"de": successfulEvidence(80), "nl": successfulEvidence(reserveDelay)},
		underlay: underlayEvidence{Known: true, WANOK: true, DNSOK: true},
	}
	controller := &healthController{
		opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
		warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item},
	}
	if err := controller.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "de" || item.AvailabilityFailures["de"] != 0 || item.UnderlayFailure != "" {
		t.Fatalf("underlay recovery used stale failure: selected=%s failures=%d underlay=%s", item.Selected, item.AvailabilityFailures["de"], item.UnderlayFailure)
	}
	if hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("underlay recovery selected reserve before rechecking active: %#v", runtime.selections)
	}
	if !contains(runtime.probeCalls, "de") {
		t.Fatalf("active route was not rechecked after underlay recovery: %#v", runtime.probeCalls)
	}
}

func TestRecoveredUnderlayRequiresFreshFastLaneFailureBeforeSwitching(t *testing.T) {
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.CandidateSignature = "de\nnl"
	item.UnderlayFailure = "wan"
	item.UnderlayCheckedAt = time.Unix(995, 0).UTC().Format(time.RFC3339Nano)
	item.AvailabilityOK = map[string]bool{}
	item.QualityOK = map[string]bool{}
	item.MedianDelayMS = map[string]*int{}
	item.AvailabilityOK["nl"], item.QualityOK["nl"] = true, true
	item.Recoveries["nl"] = contract.Policy.RecoveryThreshold
	item.LastProbeAt["nl"] = 999
	reserveDelay := 90
	item.MedianDelayMS["nl"] = &reserveDelay
	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"europe": "de"},
		probes:   map[string]probeEvidence{"de": {Failure: probeFailureFatal}, "nl": successfulEvidence(reserveDelay)},
		underlay: underlayEvidence{Known: true, WANOK: true, DNSOK: true},
	}
	controller := &healthController{
		opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
		warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item},
		livenessAt: map[string]time.Time{},
	}
	changed, err := controller.checkActiveAvailability(time.Unix(1000, 0), "europe", contract, item, true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || item.Selected != "de" || item.AvailabilityFailures["de"] != 0 || item.UnderlayFailure != "" {
		t.Fatalf("first post-recovery failure changed route: selected=%s failures=%d underlay=%s", item.Selected, item.AvailabilityFailures["de"], item.UnderlayFailure)
	}
	if hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("first post-recovery failure selected reserve: %#v", runtime.selections)
	}
	if _, err := controller.checkActiveAvailability(time.Unix(1005, 0), "europe", contract, item, true); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "nl" || item.LastSwitchReason != "active-unavailable" {
		t.Fatalf("confirmed endpoint failure did not switch: selected=%s reason=%s", item.Selected, item.LastSwitchReason)
	}
}

func TestMassOutagePrefersConfirmedReserveAndRecoversWithoutCooldown(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{failureThreshold: 3, recoveryThreshold: 3, backup: 300}
	for _, mode := range []string{"priority", "best"} {
		t.Run(mode, func(t *testing.T) {
			item := newPolicyHealthState()
			item.AvailabilityFailures["active"] = settings.failureThreshold
			item.AvailabilityFailures["dead-a"] = settings.failureThreshold
			item.AvailabilityFailures["dead-b"] = settings.failureThreshold
			item.Recoveries["flapping"] = 1
			item.Recoveries["stable"] = settings.recoveryThreshold
			item.LastProbeAt["stable"] = float64(now.Add(-30 * time.Second).Unix())
			activeDelay, flappingDelay, stableDelay := 100, 50, 200
			candidates := []string{"active", "dead-a", "flapping", "dead-b", "stable"}
			quality := map[string]bool{"flapping": true, "stable": true}
			available := map[string]bool{"flapping": true, "stable": true}
			desired, reason := selectDesired(
				now, mode, "active", candidates,
				map[string]int{"active": 0, "dead-a": 0, "flapping": 0, "dead-b": 1, "stable": 2}, nil,
				map[string]*int{"active": &activeDelay, "flapping": &flappingDelay, "stable": &stableDelay}, nil,
				map[string]probeEvidence{"dead-a": failedEvidence(), "flapping": successfulEvidence(flappingDelay), "dead-b": failedEvidence()},
				quality, available, item, settings,
			)
			if desired != "stable" || reason != "active-unavailable" {
				t.Fatalf("mass outage selected %q (%s), want confirmed reserve", desired, reason)
			}

			item.AvailabilityFailures["stable"] = settings.failureThreshold
			quality["stable"], available["stable"] = false, false
			desired, reason = selectDesired(
				now, mode, "active", candidates,
				map[string]int{"active": 0, "dead-a": 0, "flapping": 0, "dead-b": 1, "stable": 2}, nil,
				map[string]*int{"active": &activeDelay, "flapping": &flappingDelay, "stable": &stableDelay}, nil,
				map[string]probeEvidence{"dead-a": failedEvidence(), "flapping": successfulEvidence(flappingDelay), "dead-b": failedEvidence(), "stable": failedEvidence()},
				quality, available, item, settings,
			)
			if desired != "flapping" || reason != "active-unavailable" {
				t.Fatalf("mass outage did not use the first current recovery: %q (%s)", desired, reason)
			}

			available["flapping"] = false
			desired, reason = selectDesired(
				now, mode, "active", candidates,
				map[string]int{"active": 0, "dead-a": 0, "flapping": 0, "dead-b": 1, "stable": 2}, nil,
				map[string]*int{"active": &activeDelay, "flapping": &flappingDelay, "stable": &stableDelay}, nil,
				map[string]probeEvidence{"dead-a": failedEvidence(), "flapping": failedEvidence(), "dead-b": failedEvidence(), "stable": failedEvidence()},
				map[string]bool{}, available, item, settings,
			)
			if desired != "block" || reason != "all-candidates-unavailable" {
				t.Fatalf("mass outage kept an unavailable path: %q (%s)", desired, reason)
			}
		})
	}
}

func TestPriorityStartupRestoresReserveAndServicePermissions(t *testing.T) {
	root := t.TempDir()
	config, poolPath := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	allowed, denied, block := serviceSelectorTag("europe", "allowed"), serviceSelectorTag("europe", "denied"), serviceBlockTag("europe")
	text := fmt.Sprintf(`{"routing":{"balancers":[{"tag":"europe","selector":["de","nl"]},{"tag":%q,"selector":[%q,"de","nl"]},{"tag":%q,"selector":[%q,"de","nl"]}]}}`, allowed, block, denied, block)
	if err := os.WriteFile(config, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = "priority"
	contract.Groups = []healthGroup{{Selector: "primary", Members: []string{"de"}}, {Selector: "reserve", Members: []string{"nl"}}}
	contract.Policy.CandidateServiceIDs = []string{"allowed", "denied"}
	contract.Policy.CandidateServiceAccess = map[string][]string{"primary": {"allowed", "denied"}, "reserve": {"allowed"}}
	pool.HealthPolicies["europe"] = contract
	if err := writeJSONAtomic(poolPath, pool); err != nil {
		t.Fatal(err)
	}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.Mode, item.RuntimeConfirmed = "nl", "nl", "priority", true
	item.CandidateSignature = "de\nnl"
	item.AvailabilityOK = map[string]bool{"de": false, "nl": true}
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: poolPath})
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]string{"europe": "nl", allowed: "nl", denied: block}
	if len(got) != len(wants) {
		t.Fatalf("missing startup selectors: %+v", got)
	}
	for _, choice := range got {
		if choice.Outbound != wants[choice.Tag] {
			t.Fatalf("wrong startup choice: %+v", choice)
		}
	}
	// A saved working reserve must use today's service access, not cached grants.
	rememberWorkingSelection(contract, item)
	item.RuntimeConfirmed, item.RuntimeSelected = false, ""
	contract.Policy.CandidateServiceAccess["reserve"] = []string{"denied"}
	pool.HealthPolicies["europe"] = contract
	if err := writeJSONAtomic(poolPath, pool); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	got, err = XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: poolPath})
	if err != nil {
		t.Fatal(err)
	}
	wants[allowed], wants[denied] = block, "nl"
	for _, choice := range got {
		if choice.Outbound != wants[choice.Tag] {
			t.Fatalf("stale service permission: %+v", choice)
		}
	}
	// Changing the explicit priority order must still take effect.
	item.CandidateSignature = "nl\nde"
	item.LastWorkingSelection.CandidateSignature = "nl\nde"
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	got, err = XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: poolPath})
	if err != nil || got[0].Outbound != "de" {
		t.Fatal("saved choice ignored an explicit priority reorder")
	}
	item.CandidateSignature = "de\nnl"
	item.LastWorkingSelection.CandidateSignature = "de\nnl"
	item.AvailabilityOK["nl"] = false
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	got, err = XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: poolPath})
	if err != nil || got[0].Outbound != "de" {
		t.Fatal("known failed saved leaf restored")
	}
}
