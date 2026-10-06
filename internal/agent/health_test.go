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

func TestOutageFastRecoveryWithoutBackupDelay(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%t", mode, restart), func(t *testing.T) {
				pool := healthFixture(true)
				contract := pool.HealthPolicies["europe"]
				contract.Mode = mode
				contract.Candidates = []string{"de", "nl", "fr"}
				contract.Policy.ActiveCheckSeconds = 60
				pool.HealthPolicies["europe"] = contract
				item := newPolicyHealthState()
				item.Selected = "block"
				item.RuntimeConfirmed = true
				item.CandidateSignature = strings.Join(contract.Candidates, "\n")
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
				if len(runtime.probeCalls) != 0 || strings.Join(runtime.availabilityCalls, ",") != "de,nl,fr" {
					t.Fatalf("recovery must select the first usable result while completing the background map: quality=%v availability=%v", runtime.probeCalls, runtime.availabilityCalls)
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
	p := policySettings(healthPolicy{ProbeBatchSize: 2}, "priority")
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
	// Independent confirmations retain the default two-second retry interval.
	for _, second := range []int64{0, 2} {
		if err := controller.Tick(time.Unix(second, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if hasSelection(runtime.selections, "europe", "nl") {
		t.Fatal("selector changed before failure threshold")
	}
	if err := controller.Tick(time.Unix(4, 0)); err != nil {
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
	for _, second := range []int64{0, 2, 4} {
		if err := controller.Tick(time.Unix(second, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if !hasSelection(runtime.selections, "europe", "block") {
		t.Fatalf("fail-closed selection missing: %#v", runtime.selections)
	}
}

func TestHealthControllerDoesNotOverwriteUnreadableHistory(t *testing.T) {
	for _, body := range []string{"{invalid", "null"} {
		t.Run(body, func(t *testing.T) {
			root := t.TempDir()
			path := statePath(root, "selector-health")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			runtime := &fakeSelectorRuntime{pool: healthFixture(false), probes: map[string]probeEvidence{
				"de": successfulEvidence(30), "nl": successfulEvidence(40),
			}}
			controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool)}
			if err := controller.Tick(time.Unix(10, 0)); err == nil {
				t.Fatal("unreadable history was accepted")
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != body || len(runtime.selections) != 0 {
				t.Fatalf("unreadable history was overwritten or route changed: %q, %v", got, runtime.selections)
			}
		})
	}
}

func TestHealthControllerPreservesHistoryAfterRestartWithUnchangedOutbounds(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 28, 2, 0, 0, 0, time.UTC)
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Nodes["de"] = healthNode{Label: "Germany", Country: "DE", Fingerprint: "stable-de"}
	contract.Nodes["nl"] = healthNode{Label: "Netherlands", Country: "NL", Fingerprint: "stable-nl"}
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.CandidateSignature = "de\nnl"
	item.CandidateNodes = contract.Nodes
	item.LastSwitchAt = "2026-09-27T20:00:00Z"
	item.HistoryDays["de"] = map[string]dayBucket{"2026-09-27": {Samples: 23, Successes: 23}}
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	for restart := range 2 {
		runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"}, probes: map[string]probeEvidence{
			"de": successfulEvidence(30), "nl": successfulEvidence(40),
		}}
		controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: make(map[string]bool)}
		if err := controller.Tick(now.Add(time.Duration(restart) * time.Minute)); err != nil {
			t.Fatal(err)
		}
		var saved healthState
		if err := readJSON(statePath(root, "selector-health"), &saved); err != nil {
			t.Fatal(err)
		}
		if saved["europe"].HistoryDays["de"]["2026-09-27"].Samples != 23 || saved["europe"].LastSwitchAt != item.LastSwitchAt {
			t.Fatalf("history or selection was reset on restart %d", restart)
		}
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
}

func TestWarmRestartProtectsRestoredSelectionButNotFailedPath(t *testing.T) {
	for _, test := range []struct {
		name       string
		activeOK   bool
		want       string
		wantReason string
	}{
		{name: "planned improvement needs two fresh wins", activeOK: true, want: "de"},
		{name: "confirmed outage fails over immediately", activeOK: false, want: "nl", wantReason: "active-unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = "best"
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
				item.AvailabilityFailures["de"] = healthFailureConfirmations - 1
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
				if got.OptimizationChecks != 1 {
					t.Fatalf("warm restart did not start a fresh confirmation: %+v", got.OptimizationLastResult)
				}
				if err := controller.Tick(now.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				if got.Selected != "nl" || got.LastSwitchReason != "meaningfully-faster" {
					t.Fatalf("warm restart delayed two fresh wins: selected=%s reason=%s", got.Selected, got.LastSwitchReason)
				}
			} else if !hasSelection(runtime.selections, "europe", "nl") {
				t.Fatalf("startup confirmation delayed outage failover: %#v", runtime.selections)
			}
		})
	}
}

func healthFixture(_ bool) healthPool {
	return healthPool{
		Version: 3,
		HealthPolicies: map[string]healthPolicyContract{
			"europe": {
				Mode:       "priority",
				Candidates: []string{"de", "nl"},
				Groups:     []healthGroup{{Selector: "country:DE", Members: []string{"de"}}, {Selector: "country:NL", Members: []string{"nl"}}},
				Nodes:      map[string]healthNode{"de": {Label: "Germany", Country: "DE"}, "nl": {Label: "Netherlands", Country: "NL"}},
				Policy: healthPolicy{
					ActiveCheckSeconds: 1, ProbeBatchSize: 5,
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
	}
	p := policySettings(policy, "best")
	if p.active != 30 || p.liveness != 7 || p.failureRetry != 2 || p.blockRecovery != 15 {
		t.Fatalf("monitor settings were not resolved: %+v", p)
	}
	item := newPolicyHealthState()
	item.Selected = "active"
	item.ProbeLimits = probeLimits{LivenessSeconds: 7, FailureRetrySeconds: 2, BlockRecoverySeconds: 15}
	controller := &healthController{
		opts:  Options{HealthInterval: time.Minute},
		state: healthState{"policy": item},
	}
	if got := controller.nextInterval(); got != 7*time.Second {
		t.Fatalf("healthy liveness interval = %v, want 7s", got)
	}
	item.AvailabilityFailures["active"] = 1
	if got := controller.nextInterval(); got != 2*time.Second {
		t.Fatalf("failure retry interval = %v, want 2s", got)
	}
	item.Selected = "block"
	if got := controller.nextInterval(); got != 15*time.Second {
		t.Fatalf("block recovery interval = %v, want 15s", got)
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

func TestBestModeRequiresStableRecoveryAndLatencyBeforePlannedSwitch(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{failureThreshold: 3, recoveryThreshold: 3, improvement: 50, active: 60, backup: 300}
	for _, sample := range []struct {
		name                        string
		recoveries, active, reserve int
		want                        string
	}{
		{"one recovery is not stable", 1, 140, 70, "active"},
		{"small latency variation does not switch", 3, 140, 91, "active"},
		{"hysteresis boundary does not nominate", 3, 140, 90, "active"},
		{"strict hysteresis improvement nominates", 3, 140, 89, "reserve"},
		{"stable material latency gain nominates", 3, 560, 346, "reserve"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			item := newPolicyHealthState()
			item.Recoveries["reserve"] = sample.recoveries
			item.LastProbeAt["reserve"] = float64(now.Add(-10 * time.Second).Unix())
			item.Samples["reserve"] = []healthSample{{At: item.LastProbeAt["reserve"], OK: true, DelayMS: &sample.reserve}}
			desired, reason := selectDesired(now, "best", "active", []string{"active", "reserve"}, nil, nil,
				map[string]*int{"active": &sample.active, "reserve": &sample.reserve},
				map[string]probeEvidence{"active": successfulEvidence(sample.active), "reserve": successfulEvidence(sample.reserve)},
				map[string]bool{"active": true, "reserve": true}, map[string]bool{"active": true, "reserve": true}, item, settings)
			if desired != sample.want || (desired != "active" && reason != "meaningfully-faster") {
				t.Fatalf("selected %q (%q), want %q", desired, reason, sample.want)
			}
		})
	}
}

func TestPlannedBestSwitchRequiresTwoFreshPairedConfirmations(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{active: 60}
	item := newPolicyHealthState()

	desired, reason := gatePlannedOptimization(
		now, "active", "reserve", "meaningfully-faster", nil, item, settings,
	)
	if desired != "active" || reason != "" || item.OptimizationChecks != 0 {
		t.Fatalf("unmeasured nomination moved traffic: desired=%q reason=%q item=%+v", desired, reason, item)
	}

	confirmed := &optimizationComparison{At: now.Add(time.Minute).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
	desired, reason = gatePlannedOptimization(
		now.Add(time.Minute), "active", "reserve", "meaningfully-faster", confirmed, item, settings,
	)
	if desired != "active" || reason != "" || item.OptimizationChecks != 1 {
		t.Fatalf("first paired comparison switched early: desired=%q reason=%q item=%+v", desired, reason, item)
	}

	confirmed = &optimizationComparison{At: now.Add(2 * time.Minute).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
	desired, reason = gatePlannedOptimization(
		now.Add(2*time.Minute), "active", "reserve", "meaningfully-faster", confirmed, item, settings,
	)
	if desired != "reserve" || reason != "meaningfully-faster" || item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
		t.Fatalf("second paired comparison did not switch: desired=%q reason=%q item=%+v", desired, reason, item)
	}
}

func TestFailedPlannedComparisonBacksOffButEmergencySwitchDoesNotWait(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{active: 60}
	item := newPolicyHealthState()
	_, _ = gatePlannedOptimization(now, "active", "reserve", "meaningfully-faster", nil, item, settings)
	confirmed := &optimizationComparison{Candidate: "reserve", Result: optimizationLoss}
	desired, reason := gatePlannedOptimization(
		now.Add(time.Minute), "active", "reserve", "meaningfully-faster", confirmed, item, settings,
	)
	if desired != "active" || reason != "" || item.OptimizationCandidate != "" {
		t.Fatalf("failed comparison retained state or a penalty: desired=%q reason=%q item=%+v", desired, reason, item)
	}
	desired, reason = gatePlannedOptimization(
		now.Add(90*time.Second), "active", "reserve", "active-unavailable", nil, item, settings,
	)
	if desired != "reserve" || reason != "active-unavailable" {
		t.Fatalf("emergency switch waited for optimization state: desired=%q reason=%q item=%+v", desired, reason, item)
	}
}

func TestControllerBoundsPlannedComparisonToActiveAndOneCandidate(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Candidates = append(contract.Candidates, "background")
	contract.Nodes["background"] = healthNode{Label: "Background"}
	runtime.pool.HealthPolicies["europe"] = contract
	runtime.probes["background"] = successfulEvidence(100)
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.AvailabilityOK["background"], item.QualityOK["background"] = true, true
	item.LastProbeAt["background"] = 1000
	for _, at := range []int64{1060, 1063, 1120} {
		if err := controller.Tick(time.Unix(at, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatalf("paired comparison did not select the confirmed candidate: %+v", item)
	}
	if strings.Join(runtime.probeCalls, ",") != "active,reserve,background,active,reserve" {
		t.Fatalf("ordinary rotation stopped for the pending comparison: %v", runtime.probeCalls)
	}
	if hasSelection(runtime.selections, "europe", "background") {
		t.Fatal("unconfirmed background node was selected")
	}
}

func stagedOptimizationController(t *testing.T) (*healthController, *policyHealthState, *fakeSelectorRuntime) {
	t.Helper()
	pool := healthFixture(true)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = "best"
	contract.Candidates = []string{"active", "reserve"}
	contract.Groups = nil
	contract.Nodes = map[string]healthNode{"active": {Label: "Active"}, "reserve": {Label: "Reserve"}}
	contract.Policy.ActiveCheckSeconds = 60
	contract.Policy.ProbeBatchSize = 2
	contract.Policy.SwitchImprovementMS = 50
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.OptimizationBaseline, item.OptimizationCandidate = "active", "reserve"
	item.AvailabilityOK = make(map[string]bool)
	item.QualityOK = make(map[string]bool)
	activeDelay, reserveDelay := 600, 500
	for candidate, delay := range map[string]*int{"active": &activeDelay, "reserve": &reserveDelay} {
		item.AvailabilityOK[candidate], item.QualityOK[candidate] = true, true
		item.Recoveries[candidate] = 3
		item.LastProbeAt[candidate] = 1_000
		item.Samples[candidate] = []healthSample{{OK: true, DelayMS: delay}, {OK: true, DelayMS: delay}, {OK: true, DelayMS: delay}}
	}
	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"europe": "active"},
		probes: map[string]probeEvidence{"active": successfulEvidence(activeDelay), "reserve": successfulEvidence(reserveDelay)},
	}
	controller := &healthController{
		opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
		state: healthState{"europe": item}, stateLoaded: true, warmStarted: map[string]bool{"europe": true},
	}
	return controller, item, runtime
}

func TestIncompletePairResetsEarlierConfirmation(t *testing.T) {
	item := newPolicyHealthState()
	item.OptimizationBaseline, item.OptimizationCandidate = "active", "reserve"
	settings := effectivePolicySettings{active: 60, backup: 300}
	win := &optimizationComparison{At: time.Unix(1000, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
	incomplete := &optimizationComparison{Candidate: "reserve", Result: optimizationInconclusive, Reason: "pair-incomplete"}
	_, _ = gatePlannedOptimization(time.Unix(1000, 0), "active", "reserve", "meaningfully-faster", win, item, settings)
	if item.OptimizationChecks != 1 {
		t.Fatal("first fresh pair was not counted")
	}
	_, _ = gatePlannedOptimization(time.Unix(1060, 0), "active", "reserve", "meaningfully-faster", incomplete, item, settings)
	if item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
		t.Fatal("incomplete pair retained its earlier confirmation")
	}
	_, _ = gatePlannedOptimization(time.Unix(1120, 0), "active", "reserve", "meaningfully-faster", nil, item, settings)
	win = &optimizationComparison{At: time.Unix(1180, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
	desired, _ := gatePlannedOptimization(time.Unix(1180, 0), "active", "reserve", "meaningfully-faster", win, item, settings)
	if desired != "active" || item.OptimizationChecks != 1 {
		t.Fatal("retry inherited a stale win")
	}
	win = &optimizationComparison{At: time.Unix(1240, 0).UTC().Format(time.RFC3339), Candidate: "reserve", Result: optimizationWin}
	desired, reason := gatePlannedOptimization(time.Unix(1240, 0), "active", "reserve", "meaningfully-faster", win, item, settings)
	if desired != "reserve" || reason != "meaningfully-faster" {
		t.Fatal("retry did not complete two new confirmations")
	}
}

func TestBestModeUnmeasuredNomineeDoesNotDelayFailureFailover(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{
		failureThreshold:  3,
		recoveryThreshold: 3,
		improvement:       50,
		active:            60,
		backup:            300,
	}
	activeDelay, reserveDelay := 140, 80
	delays := map[string]*int{"active": &activeDelay, "reserve": &reserveDelay}
	quality := map[string]bool{"active": true, "reserve": true}
	available := map[string]bool{"active": true, "reserve": true}

	item := newPolicyHealthState()
	item.Recoveries["reserve"] = settings.recoveryThreshold
	item.LastProbeAt["reserve"] = float64(now.Unix())
	item.Samples["reserve"] = []healthSample{{At: float64(now.Unix()), OK: true, DelayMS: &reserveDelay}}
	desired, reason := selectDesired(
		now, "best", "active", []string{"active", "reserve"},
		map[string]int{"active": 0, "reserve": 0}, nil, delays, nil,
		quality, available, item, settings,
	)
	if desired != "active" || reason != "" {
		t.Fatalf("unmeasured nomination allowed a planned switch: (%q, %q)", desired, reason)
	}

	item.Failures["active"] = settings.failureThreshold
	item.AvailabilityFailures["active"] = settings.failureThreshold
	measured := map[string]probeEvidence{"reserve": successfulEvidence(reserveDelay)}
	desired, reason = selectDesired(
		now, "best", "active", []string{"active", "reserve"},
		map[string]int{"active": 0, "reserve": 0}, nil, delays, measured,
		quality, available, item, settings,
	)
	if desired != "reserve" || reason != "active-unavailable" {
		t.Fatalf("ordinary nomination delayed an outage failover: (%q, %q)", desired, reason)
	}
}

func TestEmergencyFailoverClearsPendingComparison(t *testing.T) {
	for _, tc := range []struct{ selected, reason string }{
		{"block", "fresh-path-available"}, {"active", "active-unavailable"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			item := newPolicyHealthState()
			item.OptimizationBaseline, item.OptimizationCandidate, item.OptimizationChecks = "active", "other", 1
			desired, reason := gatePlannedOptimization(time.Unix(1000, 0), tc.selected, "reserve", tc.reason, nil, item,
				effectivePolicySettings{active: 60})
			if desired != "reserve" || reason != tc.reason || item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
				t.Fatalf("emergency waited for or retained planned comparison: desired=%s reason=%s checks=%d", desired, reason, item.OptimizationChecks)
			}
		})
	}
}

func TestEmergencyFailoverPrefersFreshlyConfirmedReserveOverFreshCandidate(t *testing.T) {
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
			desired, reason := selectDesired(
				now, mode, "active", []string{"active", "first-fresh", "confirmed-reserve"},
				map[string]int{"active": 0, "first-fresh": 0, "confirmed-reserve": 1}, nil,
				map[string]*int{"active": &activeDelay, "first-fresh": &freshDelay, "confirmed-reserve": &reserveDelay},
				map[string]probeEvidence{"first-fresh": successfulEvidence(freshDelay), "confirmed-reserve": successfulEvidence(reserveDelay)},
				map[string]bool{"first-fresh": true, "confirmed-reserve": true},
				map[string]bool{"first-fresh": true, "confirmed-reserve": true}, item, settings,
			)
			if desired != "confirmed-reserve" || reason != "active-unavailable" {
				t.Fatalf("emergency selection = (%q, %q)", desired, reason)
			}
		})
	}
}

func TestBlockedPolicyAcceptsSlowCurrentAvailability(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{failureThreshold: 3, recoveryThreshold: 3, backup: 300}
	for _, mode := range []string{"best", "priority"} {
		for _, tc := range []struct {
			name     string
			evidence probeEvidence
		}{
			{"slow-response", successfulEvidence(2500)},
			{"fallback-without-quality", probeEvidence{OK: true, QualityUnmeasured: true}},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				item := newPolicyHealthState()
				desired, reason := selectDesired(
					now, mode, "block", []string{"reserve"}, nil, nil,
					map[string]*int{"reserve": tc.evidence.DelayMS},
					map[string]probeEvidence{"reserve": tc.evidence},
					map[string]bool{"reserve": false}, map[string]bool{"reserve": true}, item, settings,
				)
				if desired != "reserve" || reason != "fresh-path-available" {
					t.Fatalf("current availability was rejected by a quality or latency ceiling: (%q, %q)", desired, reason)
				}
			})
		}
	}
}

func TestHealthPolicyJSONKeepsToleranceAndDropsRetiredControls(t *testing.T) {
	var policy healthPolicy
	if err := json.Unmarshal([]byte(`{}`), &policy); err != nil {
		t.Fatal(err)
	}
	p := policySettings(policy, "best")
	if p.improvement != 50 {
		t.Fatalf("omitted tolerance lost its default: %+v", p)
	}
	for _, legacy := range []int{0, 600} {
		if err := json.Unmarshal([]byte(fmt.Sprintf(`{"switch_cooldown_seconds":%d,"switch_cooldown":300,"switch_improvement_ms":0,"max_latency_ms":%d,"max_packet_loss_percent":0}`, legacy, legacy)), &policy); err != nil {
			t.Fatal(err)
		}
		p = policySettings(policy, "best")
		if p.improvement != 0 {
			t.Fatalf("explicit zero tolerance ignored: %+v", p)
		}
		body, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "switch_cooldown") || strings.Contains(string(body), "max_latency_ms") {
			t.Fatalf("retired controls survived serialization: %s", body)
		}
	}
}

func TestBestModeKeepsIncumbentForEqualSlowResponses(t *testing.T) {
	item := newPolicyHealthState()
	item.Selected = "de"
	settings := policySettings(healthPolicy{}, "best")
	delay := 2500
	candidates := []string{"de", "nl"}
	for tick := 0; tick < 100; tick++ {
		now := time.Unix(int64(1000+tick*60), 0)
		for _, candidate := range candidates {
			item.Recoveries[candidate] = healthRecoveryConfirmations
			item.LastProbeAt[candidate] = float64(now.Unix())
			item.Samples[candidate] = []healthSample{{At: float64(now.Unix()), OK: true, DelayMS: &delay}}
		}
		desired, reason := selectDesired(now, "best", item.Selected,
			candidates, nil, nil, map[string]*int{"de": &delay, "nl": &delay},
			map[string]probeEvidence{"de": successfulEvidence(delay), "nl": successfulEvidence(delay)},
			map[string]bool{"de": true, "nl": true}, map[string]bool{"de": true, "nl": true}, item, settings)
		if desired != "de" || reason != "" {
			t.Fatalf("equal slow responses displaced the incumbent at tick %d: %s (%s)", tick, desired, reason)
		}
	}
}

func TestPrimaryQualityFailureRequiresFreshQualifiedReserve(t *testing.T) {
	for _, test := range []struct {
		name       string
		mode       string
		recoveries int
		lastProbe  float64
		want       string
	}{
		{"unconfirmed reserve", "best", 1, 999, "de"},
		{"priority unconfirmed reserve", "priority", 1, 999, "de"},
		{"stale reserve cannot replace reachable active", "best", 3, 700, "de"},
		{"missing quality timestamp", "best", 3, 0, "de"},
		{"future quality timestamp", "best", 3, 1001, "de"},
		{"reserve with recent availability failure", "best", 3, 999, "de"},
		{"fresh qualified reserve", "best", 3, 999, "nl"},
		{"priority fresh qualified reserve", "priority", 3, 999, "nl"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := newPolicyHealthState()
			item.Failures["de"] = 3
			item.Recoveries["nl"] = test.recoveries
			item.LastProbeAt["nl"] = test.lastProbe
			if test.name == "reserve with recent availability failure" {
				item.AvailabilityFailures["nl"] = 1
			}
			settings := policySettings(healthPolicy{}, test.mode)
			delay := 50
			item.Samples["nl"] = []healthSample{{At: test.lastProbe, OK: true, DelayMS: &delay}}
			desired, _ := selectDesired(time.Unix(1000, 0), test.mode, "de", []string{"de", "nl"},
				nil, nil, map[string]*int{"nl": &delay}, nil,
				map[string]bool{"nl": true}, map[string]bool{"de": true, "nl": true}, item, settings)
			if desired != test.want {
				t.Fatalf("selected %s, want %s", desired, test.want)
			}
		})
	}
}

func TestRecoveredCurrentProbeClearsOverlappingQualityFailures(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		t.Run(mode, func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			contract.Policy.ActiveCheckSeconds = 60
			pool.HealthPolicies["europe"] = contract
			item := newPolicyHealthState()
			ensureHealthMaps(item)
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
			item.CandidateSignature = "de\nnl"
			item.Failures["de"] = 2
			fast, slow := 500, 2500
			item.Samples["de"] = []healthSample{{OK: true, DelayMS: &fast}, {OK: true, DelayMS: &fast},
				{OK: true, DelayMS: &slow}, {OK: true, DelayMS: &slow}, {OK: true, DelayMS: &slow}}
			item.Samples["nl"] = []healthSample{{OK: true, DelayMS: &fast}, {OK: true, DelayMS: &fast}, {OK: true, DelayMS: &fast}}
			item.AvailabilityOK = map[string]bool{}
			item.QualityOK = map[string]bool{}
			item.AvailabilityOK["nl"], item.QualityOK["nl"] = true, true
			item.Recoveries["nl"] = 3
			item.LastProbeAt["de"], item.LastProbeAt["nl"] = 940, 999
			runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"},
				probes: map[string]probeEvidence{"de": successfulEvidence(fast), "nl": successfulEvidence(fast)}}
			controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute},
				runtime: runtime, stateLoaded: true, warmStarted: map[string]bool{"europe": true}, state: healthState{"europe": item}}
			if err := controller.Tick(time.Unix(1000, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "de" || item.Failures["de"] != 0 || hasSelection(runtime.selections, "europe", "nl") {
				t.Fatalf("current healthy probe caused a false soft switch: selected=%s failures=%d selections=%v", item.Selected, item.Failures["de"], runtime.selections)
			}
		})
	}
}

func TestReachableSlowActiveUsesRelativeLatencyAndMode(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		t.Run(mode, func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			contract.Policy.ActiveCheckSeconds = 60
			pool.HealthPolicies["europe"] = contract
			item := newPolicyHealthState()
			ensureHealthMaps(item)
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
			item.CandidateSignature = "de\nnl"
			item.Failures["de"] = 2
			slow, fast := 2500, 500
			item.Samples["de"] = []healthSample{{OK: true, DelayMS: &slow}, {OK: true, DelayMS: &slow}}
			item.Samples["nl"] = []healthSample{{At: 999, OK: true, DelayMS: &fast}}
			item.AvailabilityOK = map[string]bool{"nl": true}
			item.QualityOK = map[string]bool{"nl": true}
			item.Recoveries["nl"] = 3
			item.LastProbeAt["de"], item.LastProbeAt["nl"] = 940, 999
			runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"},
				probes: map[string]probeEvidence{"de": successfulEvidence(slow), "nl": successfulEvidence(fast)}}
			controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute},
				runtime: runtime, stateLoaded: true, warmStarted: map[string]bool{"europe": true}, state: healthState{"europe": item}}
			for _, at := range []int64{1000, 1060, 1120} {
				if err := controller.Tick(time.Unix(at, 0)); err != nil {
					t.Fatal(err)
				}
				if !item.QualityOK["de"] || !item.AvailabilityOK["de"] || item.Failures["de"] != 0 {
					t.Fatalf("successful slow HEAD was classified as a failure at %d", at)
				}
				if at < 1120 && (item.Selected != "de" || hasSelection(runtime.selections, "europe", "nl")) {
					t.Fatal("slow response bypassed two fresh relative comparisons")
				}
			}
			if mode == "best" {
				if item.Selected != "nl" || item.LastSwitchReason != "meaningfully-faster" {
					t.Fatalf("two relative wins failed to switch: selected=%s reason=%s", item.Selected, item.LastSwitchReason)
				}
			} else if item.Selected != "de" || hasSelection(runtime.selections, "europe", "nl") {
				t.Fatalf("priority switched a reachable active solely for latency: %v", runtime.selections)
			}
		})
	}
}
