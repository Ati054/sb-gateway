package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeSelectorRuntime struct {
	pool              healthPool
	reset             bool
	probes            map[string]probeEvidence
	selections        [][2]string
	current           map[string]string
	probeCalls        []string
	availabilityCalls []string
	speedCalls        int
	throughputCalls   []string
	speeds            map[string]int64
	underlay          underlayEvidence
}

func (runtime *fakeSelectorRuntime) Reload() (healthPool, bool, error) {
	reset := runtime.reset
	runtime.reset = false
	return runtime.pool, reset, nil
}

func (runtime *fakeSelectorRuntime) Select(selector, member string) error {
	runtime.selections = append(runtime.selections, [2]string{selector, member})
	if runtime.current == nil {
		runtime.current = make(map[string]string)
	}
	runtime.current[selector] = member
	return nil
}

func (runtime *fakeSelectorRuntime) Current(selector string) (string, error) {
	return runtime.current[selector], nil
}

func (runtime *fakeSelectorRuntime) Probe(candidate string) probeEvidence {
	runtime.probeCalls = append(runtime.probeCalls, candidate)
	return runtime.probes[candidate]
}

func (runtime *fakeSelectorRuntime) ProbeAvailability(candidate string) probeEvidence {
	runtime.availabilityCalls = append(runtime.availabilityCalls, candidate)
	return runtime.probes[candidate]
}

func (runtime *fakeSelectorRuntime) ProbeAvailabilityParallel(candidates []string, onResult func(string, probeEvidence) bool) map[string]probeEvidence {
	measured := make(map[string]probeEvidence, len(candidates))
	for _, candidate := range candidates {
		evidence := runtime.ProbeAvailability(candidate)
		measured[candidate] = evidence
		if onResult != nil {
			onResult(candidate, evidence)
		}
	}
	return measured
}

func (runtime *fakeSelectorRuntime) UnderlayStatus() underlayEvidence {
	return runtime.underlay
}

func (runtime *fakeSelectorRuntime) Throughput(candidate string, _ int) (int64, error) {
	runtime.speedCalls++
	runtime.throughputCalls = append(runtime.throughputCalls, candidate)
	if speed := runtime.speeds[candidate]; speed > 0 {
		return speed, nil
	}
	return 0, os.ErrNotExist
}

func TestOutageFastRecoveryWithoutBackupDelayOrSpeedDownload(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%t", mode, restart), func(t *testing.T) {
				pool := healthFixture(true)
				contract := pool.HealthPolicies["europe"]
				contract.Mode = mode
				contract.Candidates = []string{"de", "nl", "fr"}
				contract.Policy.ActiveCheckSeconds = 60
				contract.Policy.BackupCheckSeconds = 300
				contract.Policy.FullScanSeconds = 1800
				pool.HealthPolicies["europe"] = contract
				item := newPolicyHealthState()
				item.Selected = "block"
				item.RuntimeConfirmed = true
				item.CandidateSignature = strings.Join(contract.Candidates, "\n")
				item.NextFullScanAt = 2800
				item.CooldownUntil = 9000
				for _, candidate := range contract.Candidates {
					item.LastProbeAt[candidate] = 1000
					item.AvailabilityFailures[candidate] = 20
					item.Samples[candidate] = []healthSample{{OK: false}, {OK: false}, {OK: false}, {OK: false}, {OK: false}}
				}
				root := t.TempDir()
				if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), healthState{"europe": item}); err != nil {
					t.Fatal(err)
				}
				runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "block"}, reset: restart,
					probes: map[string]probeEvidence{"de": failedEvidence(), "nl": successfulEvidence(400), "fr": failedEvidence()}}
				controller := &healthController{opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: runtime, warmStarted: map[string]bool{"europe": true}}
				if err := controller.Tick(time.Unix(1014, 0)); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls) != 0 || controller.nextInterval() != 15*time.Second {
					t.Fatalf("retry not bounded: calls=%v wait=%v", runtime.probeCalls, controller.nextInterval())
				}
				if err := controller.Tick(time.Unix(1015, 0)); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != "de,nl,fr" || runtime.speedCalls != 0 {
					t.Fatalf("recovery must select the first usable result while completing the background map: quality=%v availability=%v speed=%d", runtime.probeCalls, runtime.availabilityCalls, runtime.speedCalls)
				}
				var persisted healthState
				if err := readJSON(filepath.Join(root, "selector-health.json"), &persisted); err != nil {
					t.Fatal(err)
				}
				got := persisted["europe"]
				if got.Selected != "nl" || got.RuntimeSelected != "nl" || !got.RuntimeConfirmed || !got.AvailabilityOK["nl"] || got.LastSwitchReason != "fresh-path-available" {
					t.Fatalf("fresh recovery was not published: %+v", got)
				}
				if controller.nextInterval() != activeLivenessInterval {
					t.Fatal("normal cadence did not resume")
				}
				runtime.probeCalls = nil
				if err := controller.Tick(time.Unix(1030, 0)); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls) != 0 {
					t.Fatalf("healthy policy was probed on another policy's fast tick: %v", runtime.probeCalls)
				}
			})
		}
	}
}

func TestNewPolicyRunsBeforeRoutineChecksForExistingPolicies(t *testing.T) {
	base := healthFixture(false).HealthPolicies["europe"]
	oldContract := base
	oldContract.Candidates = []string{"old-node"}
	newContract := base
	newContract.Candidates = []string{"new-node"}
	pool := healthPool{HealthPolicies: map[string]healthPolicyContract{
		"a-existing": oldContract,
		"z-new":      newContract,
	}}
	old := newPolicyHealthState()
	ensureHealthMaps(old)
	old.Selected = "old-node"
	old.RuntimeSelected = "old-node"
	old.RuntimeConfirmed = true
	old.CandidateSignature = "old-node"
	old.Samples["old-node"] = []healthSample{{OK: true}}
	root := t.TempDir()
	if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), healthState{"a-existing": old}); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeSelectorRuntime{
		pool:    pool,
		current: map[string]string{"a-existing": "old-node", "z-new": "block"},
		probes: map[string]probeEvidence{
			"old-node": successfulEvidence(20),
			"new-node": successfulEvidence(30),
		},
	}
	controller := &healthController{
		opts:        Options{StateRoot: root, HealthInterval: time.Minute},
		runtime:     runtime,
		warmStarted: map[string]bool{"a-existing": true},
	}
	if err := controller.Tick(time.Unix(2000, 0)); err != nil {
		t.Fatal(err)
	}
	if len(runtime.availabilityCalls) == 0 || runtime.availabilityCalls[0] != "new-node" {
		t.Fatalf("new policy did not receive the first recovery probe: availability=%v quality=%v", runtime.availabilityCalls, runtime.probeCalls)
	}
	if got := controller.state["z-new"].Selected; got != "new-node" {
		t.Fatalf("new policy remained unavailable: selected=%q", got)
	}
}

func TestOutageProbeRotationCoversWholePoolWithBoundedBatch(t *testing.T) {
	item := newPolicyHealthState()
	candidates := []string{"a", "b", "c", "d", "e", "f", "g"}
	p := policySettings(healthPolicy{ProbeBatchSize: 2, MaxProbeCandidates: 1}, "priority")
	for _, candidate := range candidates {
		item.LastProbeAt[candidate] = 1000
	}
	var checked []string
	for tick := 1; tick <= 4; tick++ {
		now := time.Unix(1000+int64(tick*15), 0)
		batch := outageProbeTargets(now, candidates, item, p)
		if len(batch) != 2 {
			t.Fatalf("batch size: %v", batch)
		}
		checked = append(checked, batch...)
		for _, candidate := range batch {
			item.LastProbeAt[candidate] = float64(now.Unix())
		}
	}
	if strings.Join(checked, ",") != "a,b,c,d,e,f,g,a" {
		t.Fatalf("nodes outside shortlist were starved: %v", checked)
	}
	p.batch = 10
	if got := outageProbeTargets(time.Unix(2000, 0), candidates, item, p); len(got) != len(candidates) {
		t.Fatalf("outage must honor the configured batch without exceeding the pool: %v", got)
	}
}

func TestHealthControllerFailsOverOnlyAfterThreshold(t *testing.T) {
	root := t.TempDir()
	falseValue := false
	runtime := &fakeSelectorRuntime{
		pool:  healthFixture(falseValue),
		reset: true,
		probes: map[string]probeEvidence{
			"de": failedEvidence(),
			"nl": successfulEvidence(40),
		},
	}
	controller := &healthController{
		opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool),
	}
	for second := 0; second < 2; second++ {
		if err := controller.Tick(time.Unix(int64(second), 0)); err != nil {
			t.Fatal(err)
		}
	}
	if hasSelection(runtime.selections, "europe", "nl") {
		t.Fatal("selector changed before failure threshold")
	}
	if err := controller.Tick(time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if !hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("failover selection missing: %#v", runtime.selections)
	}
	var state healthState
	if err := readJSON(filepath.Join(root, "selector-health.json"), &state); err != nil {
		t.Fatal(err)
	}
	if state["europe"].Selected != "nl" || !state["europe"].AvailabilityOK["nl"] {
		t.Fatalf("unexpected persisted health: %#v", state["europe"])
	}
}

func TestHealthControllerBlocksOnlyWhenEveryCandidateConfirmedDown(t *testing.T) {
	root := t.TempDir()
	falseValue := false
	runtime := &fakeSelectorRuntime{
		pool:   healthFixture(falseValue),
		probes: map[string]probeEvidence{"de": failedEvidence(), "nl": failedEvidence()},
	}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool)}
	for second := 0; second < 3; second++ {
		if err := controller.Tick(time.Unix(int64(second), 0)); err != nil {
			t.Fatal(err)
		}
	}
	if !hasSelection(runtime.selections, "europe", "block") {
		t.Fatalf("fail-closed selection missing: %#v", runtime.selections)
	}
}

func TestBlockedPolicyRecoversOnFirstUsableFreshPath(t *testing.T) {
	root := t.TempDir()
	falseValue := false
	state := healthState{"europe": newPolicyHealthState()}
	state["europe"].Selected = "block"
	if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), state); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeSelectorRuntime{
		pool:   healthFixture(falseValue),
		probes: map[string]probeEvidence{"de": successfulEvidence(50), "nl": failedEvidence()},
	}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool)}
	if err := controller.Tick(time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	if !hasSelection(runtime.selections, "europe", "de") {
		t.Fatalf("fresh recovery missing: %#v", runtime.selections)
	}
}

func TestPriorityReorderPromotesKnownAvailableCandidateOnRuntimeReload(t *testing.T) {
	root := t.TempDir()
	falseValue := false
	state := healthState{"europe": newPolicyHealthState()}
	state["europe"].Selected = "nl"
	state["europe"].CandidateSignature = "nl\nde"
	state["europe"].AvailabilityOK = map[string]bool{"de": true, "nl": true}
	if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), state); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeSelectorRuntime{
		pool:   healthFixture(falseValue),
		reset:  true,
		probes: map[string]probeEvidence{"de": successfulEvidence(30), "nl": successfulEvidence(40)},
	}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool)}
	if err := controller.Tick(time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	if !hasSelection(runtime.selections, "europe", "de") {
		t.Fatalf("updated priority was not activated: %#v", runtime.selections)
	}
	var persisted healthState
	if err := readJSON(filepath.Join(root, "selector-health.json"), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted["europe"].Selected != "de" || persisted["europe"].LastSwitchReason != "priority-order-updated" {
		t.Fatalf("unexpected persisted selection: %#v", persisted["europe"])
	}
}

func TestPriorityReorderDoesNotPromoteUnknownCandidate(t *testing.T) {
	root := t.TempDir()
	falseValue := false
	state := healthState{"europe": newPolicyHealthState()}
	state["europe"].Selected = "nl"
	state["europe"].CandidateSignature = "nl\nde"
	state["europe"].AvailabilityOK = map[string]bool{"nl": true}
	if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), state); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeSelectorRuntime{
		pool:   healthFixture(falseValue),
		reset:  true,
		probes: map[string]probeEvidence{"de": successfulEvidence(30), "nl": successfulEvidence(40)},
	}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool)}
	if err := controller.Tick(time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	if hasSelection(runtime.selections, "europe", "de") {
		t.Fatalf("unknown higher-priority candidate was activated: %#v", runtime.selections)
	}
}

func TestHealthControllerReconcilesPersistedSelectionWithXray(t *testing.T) {
	root := t.TempDir()
	falseValue := false
	state := healthState{"europe": newPolicyHealthState()}
	state["europe"].Selected = "nl"
	if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), state); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeSelectorRuntime{
		pool: healthFixture(falseValue), current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{"de": successfulEvidence(30), "nl": successfulEvidence(40)},
	}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool)}
	if err := controller.Tick(time.Unix(10, 0)); err != nil {
		t.Fatal(err)
	}
	var persisted healthState
	if err := readJSON(filepath.Join(root, "selector-health.json"), &persisted); err != nil {
		t.Fatal(err)
	}
	item := persisted["europe"]
	if item.Selected != "de" || item.RuntimeSelected != "de" || !item.RuntimeConfirmed {
		t.Fatalf("persisted state did not follow Xray: %#v", item)
	}
}

func TestRemovedActiveCandidatePromotesKnownReserveImmediately(t *testing.T) {
	root := t.TempDir()
	falseValue := false
	pool := healthFixture(falseValue)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = "best"
	contract.Candidates = []string{"nl", "fr"}
	contract.Nodes["fr"] = healthNode{Label: "France", Country: "FR"}
	contract.Policy.SwitchCooldownSeconds = 600
	contract.Policy.SwitchImprovementMS = 50
	pool.HealthPolicies["europe"] = contract

	item := newPolicyHealthState()
	item.Selected = "de"
	item.RuntimeSelected = "de"
	item.RuntimeConfirmed = true
	item.CandidateSignature = "de\nfr\nnl"
	item.Shortlist = []string{"de", "fr", "nl"}
	item.AvailabilityOK = map[string]bool{"de": true, "fr": true, "nl": true}
	item.QualityOK = map[string]bool{"de": true, "fr": true, "nl": true}
	item.Recoveries = map[string]int{"de": 3, "fr": 3, "nl": 3}
	frDelay, nlDelay := 20, 40
	item.MedianDelayMS = map[string]*int{"fr": &frDelay, "nl": &nlDelay}
	item.Samples["fr"] = []healthSample{{OK: true, DelayMS: &frDelay}}
	item.Samples["nl"] = []healthSample{{OK: true, DelayMS: &nlDelay}}
	if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}

	runtime := &fakeSelectorRuntime{
		pool: pool, reset: true, current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{"fr": successfulEvidence(frDelay), "nl": successfulEvidence(nlDelay)},
	}
	controller := &healthController{opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: runtime, warmStarted: make(map[string]bool)}
	now := time.Unix(1_000, 0)
	if err := controller.Tick(now); err != nil {
		t.Fatal(err)
	}
	if len(runtime.selections) == 0 || runtime.selections[0] != [2]string{"europe", "fr"} {
		t.Fatalf("removed active did not promote the maintained reserve first: %#v", runtime.selections)
	}
	if hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("controller made an avoidable second jump: %#v", runtime.selections)
	}
	got := controller.state["europe"]
	if got.Selected != "fr" || got.RuntimeSelected != "fr" || !got.RuntimeConfirmed || got.LastSwitchReason != "active-removed" {
		t.Fatalf("replacement state was not confirmed: %#v", got)
	}
	if got.CooldownUntil <= float64(now.Unix()) {
		t.Fatalf("replacement was not protected from immediate re-ranking: %#v", got)
	}
}

func TestWarmRestartProtectsRestoredSelectionButNotFailedPath(t *testing.T) {
	for _, test := range []struct {
		name       string
		activeOK   bool
		want       string
		wantReason string
	}{
		{name: "planned improvement waits for cooldown", activeOK: true, want: "de"},
		{name: "confirmed outage fails over immediately", activeOK: false, want: "nl", wantReason: "active-unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = "best"
			contract.Policy.SwitchCooldownSeconds = 600
			contract.Policy.SwitchImprovementMS = 50
			pool.HealthPolicies["europe"] = contract

			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
			item.Mode = contract.Mode
			item.CandidateSignature = strings.Join(contract.Candidates, "\n")
			item.AvailabilityOK = map[string]bool{"de": true, "nl": true}
			item.QualityOK = map[string]bool{"de": true, "nl": true}
			item.Recoveries = map[string]int{"de": 3, "nl": 3}
			deDelay, nlDelay := 500, 100
			item.Samples["de"] = []healthSample{{OK: true, DelayMS: &deDelay}, {OK: true, DelayMS: &deDelay}, {OK: true, DelayMS: &deDelay}}
			item.Samples["nl"] = []healthSample{{OK: true, DelayMS: &nlDelay}, {OK: true, DelayMS: &nlDelay}, {OK: true, DelayMS: &nlDelay}}
			item.LastWorkingSelection = &workingSelection{Selected: "de", Mode: contract.Mode, CandidateSignature: item.CandidateSignature}
			probes := map[string]probeEvidence{"de": successfulEvidence(deDelay), "nl": successfulEvidence(nlDelay)}
			if !test.activeOK {
				item.AvailabilityFailures["de"] = contract.Policy.FailureThreshold - 1
				probes["de"] = failedEvidence()
			}
			if err := writeJSONAtomic(filepath.Join(root, "selector-health.json"), healthState{"europe": item}); err != nil {
				t.Fatal(err)
			}

			runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"}, probes: probes}
			controller := &healthController{opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: runtime, warmStarted: make(map[string]bool)}
			now := time.Unix(1_000, 0)
			if err := controller.Tick(now); err != nil {
				t.Fatal(err)
			}
			got := controller.state["europe"]
			if got.Selected != test.want || got.LastSwitchReason != test.wantReason {
				t.Fatalf("warm selection = %q (%q), want %q (%q)", got.Selected, got.LastSwitchReason, test.want, test.wantReason)
			}
			if test.activeOK {
				if hasSelection(runtime.selections, "europe", "nl") {
					t.Fatalf("restored path was immediately re-ranked: %#v", runtime.selections)
				}
				if got.CooldownUntil != float64(now.Add(10*time.Minute).Unix()) {
					t.Fatalf("startup cooldown = %.0f, want %d", got.CooldownUntil, now.Add(10*time.Minute).Unix())
				}
			} else if !hasSelection(runtime.selections, "europe", "nl") {
				t.Fatalf("startup cooldown delayed outage failover: %#v", runtime.selections)
			}
		})
	}
}

func healthFixture(speedCheck bool) healthPool {
	return healthPool{
		Version: 3,
		HealthPolicies: map[string]healthPolicyContract{
			"europe": {
				Mode:       "priority",
				Candidates: []string{"de", "nl"},
				Groups:     []healthGroup{{Selector: "country:DE", Members: []string{"de"}}, {Selector: "country:NL", Members: []string{"nl"}}},
				Nodes:      map[string]healthNode{"de": {Label: "Germany", Country: "DE"}, "nl": {Label: "Netherlands", Country: "NL"}},
				Policy: healthPolicy{
					FailureThreshold: 3, RecoveryThreshold: 3, QualityWindow: 5,
					MaxPacketLossPercent: 40, MaxLatencyMS: 2000,
					ActiveCheckSeconds: 1, BackupCheckSeconds: 1, FullScanSeconds: 1,
					MaxProbeCandidates: 5, ProbeBatchSize: 5, SpeedCheckEnabled: &speedCheck,
				},
			},
		},
	}
}

func successfulEvidence(delay int) probeEvidence {
	return probeEvidence{OK: true, DelayMS: &delay, Targets: map[string]*int{"gstatic-204": &delay}}
}

func failedEvidence() probeEvidence {
	return probeEvidence{Targets: map[string]*int{"gstatic-204": nil}}
}

func TestConfiguredMonitorIntervalsControlScheduling(t *testing.T) {
	policy := healthPolicy{
		ActiveCheckSeconds: 30, ActiveLivenessSeconds: 7,
		FailureRetrySeconds: 1, BlockRecoverySeconds: 11,
	}
	p := policySettings(policy, "best")
	if p.active != 30 || p.liveness != 7 || p.failureRetry != 1 || p.blockRecovery != 11 {
		t.Fatalf("monitor settings were not resolved: %+v", p)
	}
	item := newPolicyHealthState()
	item.Selected = "active"
	item.ProbeLimits = probeLimits{LivenessSeconds: 7, FailureRetrySeconds: 1, BlockRecoverySeconds: 11}
	controller := &healthController{
		opts:  Options{HealthInterval: time.Minute},
		state: healthState{"policy": item},
	}
	if got := controller.nextInterval(); got != 7*time.Second {
		t.Fatalf("healthy liveness interval = %v, want 7s", got)
	}
	item.AvailabilityFailures["active"] = 1
	if got := controller.nextInterval(); got != time.Second {
		t.Fatalf("failure retry interval = %v, want 1s", got)
	}
	item.Selected = "block"
	if got := controller.nextInterval(); got != 11*time.Second {
		t.Fatalf("block recovery interval = %v, want 11s", got)
	}
	contract := healthPolicyContract{Mode: "best", Policy: policy}
	if got := controller.regularInterval(contract); got != 30*time.Second {
		t.Fatalf("quality interval = %v, want 30s", got)
	}
}

func hasSelection(values [][2]string, selector, member string) bool {
	for _, value := range values {
		if value[0] == selector && value[1] == member {
			return true
		}
	}
	return false
}

func TestPolicySettingsHonorVisibleThirtySecondLatencyImprovementBoundary(t *testing.T) {
	settings := policySettings(healthPolicy{SwitchImprovementMS: 30000}, "best")
	if settings.improvement != 30000 {
		t.Fatalf("switch improvement was silently clamped to %d", settings.improvement)
	}
}

func TestBestModeRequiresStableRecoveryLatencyAndThroughputBeforePlannedSwitch(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{
		failureThreshold:  3,
		recoveryThreshold: 3,
		improvement:       50,
		speedEnabled:      true,
		speedImprovement:  25,
	}

	tests := []struct {
		name           string
		recoveries     int
		selectedDelay  int
		candidateDelay int
		selectedSpeed  int64
		candidateSpeed int64
		want           string
		wantReason     string
	}{
		{
			name:       "one recovery is not stable",
			recoveries: 1, selectedDelay: 140, candidateDelay: 70,
			selectedSpeed: 1_000, candidateSpeed: 1_500, want: "active",
		},
		{
			name:       "small latency variation does not switch",
			recoveries: 3, selectedDelay: 140, candidateDelay: 91,
			selectedSpeed: 1_000, candidateSpeed: 1_500, want: "active",
		},
		{
			name:       "material latency gain permits smaller speed gain",
			recoveries: 3, selectedDelay: 140, candidateDelay: 80,
			selectedSpeed: 1_000, candidateSpeed: 1_240, want: "reserve", wantReason: "meaningfully-faster",
		},
		{
			name:       "stable material gain switches",
			recoveries: 3, selectedDelay: 140, candidateDelay: 80,
			selectedSpeed: 1_000, candidateSpeed: 1_250, want: "reserve", wantReason: "meaningfully-faster",
		},
		{
			name:       "response tradeoff still requires recovery",
			recoveries: 1, selectedDelay: 560, candidateDelay: 346,
			selectedSpeed: 14_600, candidateSpeed: 10_100, want: "active",
		},
		{
			name:       "confirmed screenshot tradeoff switches",
			recoveries: 3, selectedDelay: 560, candidateDelay: 346,
			selectedSpeed: 14_600, candidateSpeed: 10_100, want: "reserve", wantReason: "meaningfully-faster",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := newPolicyHealthState()
			item.Recoveries["reserve"] = test.recoveries
			delays := map[string]*int{"active": &test.selectedDelay, "reserve": &test.candidateDelay}
			speeds := map[string]*int64{"active": &test.selectedSpeed, "reserve": &test.candidateSpeed}
			desired, reason := selectDesired(
				now, "best", "active", []string{"active", "reserve"},
				map[string]int{"active": 0, "reserve": 0}, nil, delays, speeds, nil,
				map[string]bool{"active": true, "reserve": true},
				map[string]bool{"active": true, "reserve": true}, item, settings,
			)
			if desired != test.want || reason != test.wantReason {
				t.Fatalf("selectDesired() = (%q, %q), want (%q, %q)", desired, reason, test.want, test.wantReason)
			}
		})
	}
}

func TestPlannedBestSwitchRequiresTwoFreshPairedConfirmations(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{active: 60, cooldown: 600}
	item := newPolicyHealthState()

	desired, reason := gatePlannedOptimization(
		now, "active", "reserve", "meaningfully-faster", "", nil, item, settings,
	)
	if desired != "active" || reason != "" || item.OptimizationBaseline != "active" ||
		item.OptimizationCandidate != "reserve" || item.OptimizationChecks != 0 || item.OptimizationNextAt != 1060 {
		t.Fatalf("planned comparison was not staged: desired=%q reason=%q item=%+v", desired, reason, item)
	}

	confirmed := true
	desired, reason = gatePlannedOptimization(
		now.Add(time.Minute), "active", "reserve", "meaningfully-faster", "reserve", &confirmed, item, settings,
	)
	if desired != "active" || reason != "" || item.OptimizationChecks != 1 || item.OptimizationNextAt != 1120 {
		t.Fatalf("first paired comparison switched early: desired=%q reason=%q item=%+v", desired, reason, item)
	}

	desired, reason = gatePlannedOptimization(
		now.Add(2*time.Minute), "active", "reserve", "meaningfully-faster", "reserve", &confirmed, item, settings,
	)
	if desired != "reserve" || reason != "meaningfully-faster" || item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
		t.Fatalf("second paired comparison did not switch: desired=%q reason=%q item=%+v", desired, reason, item)
	}
}

func TestFailedPlannedComparisonBacksOffButEmergencySwitchDoesNotWait(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{active: 60, cooldown: 600}
	item := newPolicyHealthState()
	_, _ = gatePlannedOptimization(now, "active", "reserve", "meaningfully-faster", "", nil, item, settings)
	confirmed := false
	desired, reason := gatePlannedOptimization(
		now.Add(time.Minute), "active", "reserve", "meaningfully-faster", "reserve", &confirmed, item, settings,
	)
	if desired != "active" || reason != "" || item.OptimizationCandidate != "" || item.OptimizationRetryAfter != 1660 {
		t.Fatalf("failed comparison did not back off: desired=%q reason=%q item=%+v", desired, reason, item)
	}
	desired, reason = gatePlannedOptimization(
		now.Add(2*time.Minute), "active", "reserve", "active-unavailable", "", nil, item, settings,
	)
	if desired != "reserve" || reason != "active-unavailable" || item.OptimizationRetryAfter != 0 {
		t.Fatalf("emergency switch waited for optimization state: desired=%q reason=%q item=%+v", desired, reason, item)
	}
}

func TestPlannedComparisonUsesFreshPairedLatencyAndSpeed(t *testing.T) {
	settings := effectivePolicySettings{improvement: 50, speedEnabled: true, speedImprovement: 25}
	activeDelay, reserveDelay := 600, 530
	measured := map[string]probeEvidence{
		"active":  successfulEvidence(activeDelay),
		"reserve": successfulEvidence(reserveDelay),
	}
	if freshOptimizationWin("active", "reserve", measured, map[string]int64{"active": 12_000, "reserve": 8_000}, settings) {
		t.Fatal("fresh comparison accepted a throughput loss larger than the latency gain")
	}
	if !freshOptimizationWin("active", "reserve", measured, map[string]int64{"active": 12_000, "reserve": 16_000}, settings) {
		t.Fatal("fresh comparison rejected a candidate that wins both paired measurements")
	}
	if freshOptimizationWin("active", "reserve", measured, map[string]int64{"active": 12_000}, settings) {
		t.Fatal("fresh comparison reused a missing or historical candidate speed")
	}
}

func TestControllerBoundsPlannedComparisonToActiveAndOneCandidate(t *testing.T) {
	root := t.TempDir()
	pool := healthFixture(true)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = "best"
	contract.Candidates = []string{"active", "reserve", "background"}
	contract.Groups = nil
	contract.Nodes = map[string]healthNode{
		"active": {Label: "Active"}, "reserve": {Label: "Reserve"}, "background": {Label: "Background"},
	}
	contract.Policy.ActiveCheckSeconds = 60
	contract.Policy.BackupCheckSeconds = 300
	contract.Policy.FullScanSeconds = 1800
	contract.Policy.ProbeBatchSize = 2
	contract.Policy.SwitchImprovementMS = 50
	contract.Policy.SpeedImprovementPercent = 25
	contract.Policy.SwitchCooldownSeconds = 600
	pool.HealthPolicies["europe"] = contract

	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.NextFullScanAt = 2_000
	item.AvailabilityOK = make(map[string]bool)
	item.QualityOK = make(map[string]bool)
	activeDelay, reserveDelay, backgroundDelay := 600, 500, 300
	for candidate, delay := range map[string]*int{
		"active": &activeDelay, "reserve": &reserveDelay, "background": &backgroundDelay,
	} {
		item.AvailabilityOK[candidate] = true
		item.QualityOK[candidate] = true
		item.Recoveries[candidate] = 3
		item.LastProbeAt[candidate] = 1_000
		item.LastSpeedProbeAt[candidate] = 1_000
		item.Samples[candidate] = []healthSample{{OK: true, DelayMS: delay}, {OK: true, DelayMS: delay}, {OK: true, DelayMS: delay}}
	}
	item.SpeedSamplesBPS["active"] = []int64{12_000}
	item.SpeedSamplesBPS["reserve"] = []int64{16_000}
	item.SpeedSamplesBPS["background"] = []int64{1_000}

	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"europe": "active"},
		probes: map[string]probeEvidence{
			"active": successfulEvidence(activeDelay), "reserve": successfulEvidence(reserveDelay),
			"background": successfulEvidence(backgroundDelay),
		},
		speeds: map[string]int64{"active": 12_000, "reserve": 16_000, "background": 50_000},
	}
	controller := &healthController{
		opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: runtime,
		state: healthState{"europe": item}, stateLoaded: true, warmStarted: map[string]bool{"europe": true},
	}

	for _, at := range []int64{1_000, 1_060, 1_120} {
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatalf("paired comparison did not select the confirmed candidate: %+v", item)
	}
	if strings.Join(runtime.throughputCalls, ",") != "active,reserve,active,reserve" {
		t.Fatalf("planned comparison escaped its bounded pair: %v", runtime.throughputCalls)
	}
	if hasSelection(runtime.selections, "europe", "background") {
		t.Fatalf("background node was selected without paired confirmation: %v", runtime.selections)
	}
}

func TestBestModeCooldownStopsFlappingButNeverDelaysFailureFailover(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{
		failureThreshold:  3,
		recoveryThreshold: 3,
		improvement:       50,
		speedEnabled:      true,
		speedImprovement:  25,
	}
	activeDelay, reserveDelay := 140, 80
	activeSpeed, reserveSpeed := int64(1_000), int64(1_500)
	delays := map[string]*int{"active": &activeDelay, "reserve": &reserveDelay}
	speeds := map[string]*int64{"active": &activeSpeed, "reserve": &reserveSpeed}
	quality := map[string]bool{"active": true, "reserve": true}
	available := map[string]bool{"active": true, "reserve": true}

	item := newPolicyHealthState()
	item.Recoveries["reserve"] = settings.recoveryThreshold
	item.CooldownUntil = float64(now.Add(10 * time.Minute).Unix())
	desired, reason := selectDesired(
		now, "best", "active", []string{"active", "reserve"},
		map[string]int{"active": 0, "reserve": 0}, nil, delays, speeds, nil,
		quality, available, item, settings,
	)
	if desired != "active" || reason != "" {
		t.Fatalf("cooldown allowed a planned switch: (%q, %q)", desired, reason)
	}

	item.Failures["active"] = settings.failureThreshold
	item.AvailabilityFailures["active"] = settings.failureThreshold
	measured := map[string]probeEvidence{"reserve": successfulEvidence(reserveDelay)}
	desired, reason = selectDesired(
		now, "best", "active", []string{"active", "reserve"},
		map[string]int{"active": 0, "reserve": 0}, nil, delays, speeds, measured,
		quality, available, item, settings,
	)
	if desired != "reserve" || reason != "active-unavailable" {
		t.Fatalf("cooldown delayed an outage failover: (%q, %q)", desired, reason)
	}
}

func TestEmergencyFailoverPinsRecoveredReserveButNotInitialPath(t *testing.T) {
	now := time.Unix(1_000, 0)
	if got := switchCooldownUntil(now, "fresh-path-available", 600); got != 0 {
		t.Fatalf("fresh-path-available cooldown = %.0f", got)
	}
	if got := switchCooldownUntil(now, "active-unavailable", 600); got != 1600 {
		t.Fatalf("active-unavailable cooldown = %.0f", got)
	}
	if got := switchCooldownUntil(now, "meaningfully-faster", 600); got != 1600 {
		t.Fatalf("planned switch cooldown = %.0f", got)
	}
}

func TestEmergencyFailoverPrefersConfirmedReserveOverFreshCandidate(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{failureThreshold: 3, recoveryThreshold: 3, backup: 300}
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			item := newPolicyHealthState()
			item.AvailabilityFailures["active"] = settings.failureThreshold
			item.Recoveries["first-fresh"] = 1
			item.Recoveries["confirmed-reserve"] = settings.recoveryThreshold
			item.LastProbeAt["confirmed-reserve"] = float64(now.Add(-time.Minute).Unix())
			activeDelay, freshDelay, reserveDelay := 900, 100, 500
			freshSpeed, reserveSpeed := int64(50_000), int64(10_000)
			desired, reason := selectDesired(
				now, mode, "active", []string{"active", "first-fresh", "confirmed-reserve"},
				map[string]int{"active": 0, "first-fresh": 0, "confirmed-reserve": 1}, nil,
				map[string]*int{"active": &activeDelay, "first-fresh": &freshDelay, "confirmed-reserve": &reserveDelay},
				map[string]*int64{"first-fresh": &freshSpeed, "confirmed-reserve": &reserveSpeed},
				map[string]probeEvidence{"first-fresh": successfulEvidence(freshDelay)},
				map[string]bool{"first-fresh": true, "confirmed-reserve": true},
				map[string]bool{"first-fresh": true, "confirmed-reserve": true}, item, settings,
			)
			if desired != "confirmed-reserve" || reason != "active-unavailable" {
				t.Fatalf("emergency selection = (%q, %q)", desired, reason)
			}
		})
	}
}

func TestBlockedPolicyRejectsFreshCandidateOutsideLatencyThreshold(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{failureThreshold: 3, recoveryThreshold: 3, backup: 300, maxLatency: 2_000}
	delay := 2_500
	item := newPolicyHealthState()
	desired, reason := selectDesired(
		now, "best", "block", []string{"unstable"}, nil, nil,
		map[string]*int{"unstable": &delay}, nil,
		map[string]probeEvidence{"unstable": successfulEvidence(delay)},
		map[string]bool{"unstable": false}, map[string]bool{"unstable": true}, item, settings,
	)
	if desired != "block" || reason != "" {
		t.Fatalf("degraded fresh candidate selected: (%q, %q)", desired, reason)
	}
}

func TestHealthPolicyJSONDefaultsDoNotDisableSwitchProtection(t *testing.T) {
	var policy healthPolicy
	if err := json.Unmarshal([]byte(`{}`), &policy); err != nil {
		t.Fatal(err)
	}
	p := policySettings(policy, "best")
	if p.cooldown != 600 || p.improvement != 50 || p.speedImprovement != 25 || p.maxLatency != 2000 || p.maxLoss != 40 {
		t.Fatalf("omitted thresholds lost defaults: %+v", p)
	}
	if err := json.Unmarshal([]byte(`{"switch_cooldown_seconds":0,"switch_cooldown":300,"switch_improvement_ms":0,"speed_improvement_percent":0,"max_latency_ms":0,"max_packet_loss_percent":0}`), &policy); err != nil {
		t.Fatal(err)
	}
	p = policySettings(policy, "best")
	if p.cooldown != 0 || p.improvement != 0 || p.speedImprovement != 0 || p.maxLatency != 0 || p.maxLoss != 0 {
		t.Fatalf("explicit zero thresholds ignored: %+v", p)
	}
}

func TestBestModeDoesNotBounceBetweenReachableDegradedPaths(t *testing.T) {
	item := newPolicyHealthState()
	item.Selected = "de"
	settings := policySettings(healthPolicy{SwitchCooldownSeconds: 600}, "best")
	delay := 2500
	candidates := []string{"de", "nl"}
	for tick := 0; tick < 100; tick++ {
		for _, candidate := range candidates {
			item.Failures[candidate]++
		}
		desired, reason := selectDesired(time.Unix(int64(tick*60), 0), "best", item.Selected,
			candidates, nil, nil, map[string]*int{"de": &delay, "nl": &delay}, nil,
			map[string]probeEvidence{"de": successfulEvidence(delay), "nl": successfulEvidence(delay)},
			map[string]bool{"de": false, "nl": false}, map[string]bool{"de": true, "nl": true}, item, settings)
		if desired != "de" || reason != "" {
			t.Fatalf("reachable degraded paths bounced at tick %d: %s (%s)", tick, desired, reason)
		}
	}
}

func TestDegradedPathSwitchRequiresStableReserveButBypassesCooldown(t *testing.T) {
	for _, test := range []struct {
		name       string
		mode       string
		recoveries int
		cooldown   float64
		lastReason string
		want       string
	}{
		{"unconfirmed reserve", "best", 1, 0, "", "de"},
		{"normal cooldown does not pin degraded active", "best", 3, 2000, "meaningfully-faster", "nl"},
		{"failover cooldown prevents ping-pong", "best", 3, 2000, "active-unavailable", "de"},
		{"priority recovery cooldown prevents ping-pong", "priority", 3, 2000, "higher-priority-recovered", "de"},
		{"stable reserve after cooldown", "best", 3, 0, "active-unavailable", "nl"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := newPolicyHealthState()
			item.Failures["de"] = 3
			item.Recoveries["nl"] = test.recoveries
			item.CooldownUntil = test.cooldown
			item.LastSwitchReason = test.lastReason
			settings := policySettings(healthPolicy{}, test.mode)
			delay := 50
			desired, _ := selectDesired(time.Unix(1000, 0), test.mode, "de", []string{"de", "nl"},
				nil, nil, map[string]*int{"nl": &delay}, nil, nil,
				map[string]bool{"nl": true}, map[string]bool{"de": true, "nl": true}, item, settings)
			if desired != test.want {
				t.Fatalf("selected %s, want %s", desired, test.want)
			}
		})
	}
}
