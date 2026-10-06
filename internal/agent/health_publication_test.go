package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type publicationRuntime struct {
	*fakeSelectorRuntime
	onProbe func()
}

func (runtime *publicationRuntime) Probe(candidate string) probeEvidence {
	runtime.onProbe()
	return runtime.fakeSelectorRuntime.Probe(candidate)
}

func TestConfirmedMembershipPublishedBeforeQualityProbes(t *testing.T) {
	root := t.TempDir()
	fake := &fakeSelectorRuntime{pool: healthFixture(true), current: map[string]string{"europe": "de"}, probes: map[string]probeEvidence{}}
	probed := false
	runtime := &publicationRuntime{fakeSelectorRuntime: fake, onProbe: func() {
		probed = true
		var state healthState
		if err := readJSON(statePath(root, "selector-health"), &state); err != nil {
			t.Fatal(err)
		}
		item := state["europe"]
		if item == nil || !item.RuntimeConfirmed || item.RuntimeSelected != "de" || item.RuntimeObservedAt == "" || len(item.CandidateLabels) == 0 || item.CandidateNodes["de"].Country != "DE" {
			t.Fatalf("confirmed selector not published before probe: %#v", item)
		}
		if len(item.DailyStats) != 0 {
			t.Fatal("fabricated historical measurements")
		}
	}}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: map[string]bool{}}
	if err := controller.Tick(time.Now()); err != nil {
		t.Fatal(err)
	}
	if !probed {
		t.Fatal("test did not reach a probe")
	}
}

type switchPublicationRuntime struct {
	*fakeSelectorRuntime
	onProbe  func(string)
	onSelect func(string, string)
}

func (runtime *switchPublicationRuntime) Probe(candidate string) probeEvidence {
	if runtime.onProbe != nil {
		runtime.onProbe(candidate)
	}
	return runtime.fakeSelectorRuntime.Probe(candidate)
}

func (runtime *switchPublicationRuntime) Select(selector, member string) error {
	if err := runtime.fakeSelectorRuntime.Select(selector, member); err != nil {
		return err
	}
	if runtime.onSelect != nil {
		runtime.onSelect(selector, member)
	}
	return nil
}

func TestFastLaneSwitchPublishedBeforeOtherPolicyProbe(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, now := switchPublicationFixture(t, mode)
			probed, switched := false, false
			assertPublished := func() {
				t.Helper()
				var state healthState
				if err := readJSON(statePath(controller.opts.StateRoot, "selector-health"), &state); err != nil {
					t.Fatal(err)
				}
				item := state["a-fast"]
				if item == nil || item.Selected != "nl" || item.RuntimeSelected != "nl" || !item.RuntimeConfirmed ||
					item.RuntimeObservedAt == "stale" || item.LastSwitchReason != "active-unavailable" {
					t.Fatalf("confirmed failover was not published: %+v", item)
				}
				if len(state) != 3 || state["b-slow"] == nil || state["c-current"] == nil ||
					state["b-slow"].Selected != "slow" || state["c-current"].Selected != "current" {
					t.Fatalf("checkpoint dropped an unprocessed current policy or kept a removed one: %+v", state)
				}
				if _, exists := state["removed"]; exists {
					t.Fatal("checkpoint restored a policy absent from the current health pool")
				}
			}
			controller.eventSink = func(event healthEvent) {
				if event.Event == "switch" && event.Policy == "a-fast" {
					switched = true
					assertPublished()
				}
			}
			runtime.onProbe = func(candidate string) {
				if candidate == "slow" {
					probed = true
					assertPublished()
				}
			}
			if err := controller.Tick(now); err != nil {
				t.Fatal(err)
			}
			if !probed || !switched || !hasSelection(runtime.selections, "a-fast", "nl") {
				t.Fatalf("fixture missed the fast-lane switch or subsequent slow policy: probe=%t switch=%t selections=%v", probed, switched, runtime.selections)
			}
			if len(controller.state) != 3 {
				t.Fatal("completed tick retained removed policy state")
			}
		})
	}
}

func TestFastLaneSwitchPublicationErrorDoesNotUndoConfirmedRoute(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, now := switchPublicationFixture(t, mode)
			path := statePath(controller.opts.StateRoot, "selector-health")
			blocker := filepath.Join(path, "blocked")
			blocked, unblocked, switched := false, false, false
			runtime.onSelect = func(selector, member string) {
				if selector != "a-fast" || member != "nl" {
					return
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(blocker, []byte("prevent atomic replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
				blocked = true
			}
			controller.eventSink = func(event healthEvent) {
				if event.Event == "switch" && event.Policy == "a-fast" {
					switched = true
				}
			}
			runtime.onProbe = func(candidate string) {
				if candidate != "slow" || unblocked {
					return
				}
				if err := os.Remove(blocker); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				unblocked = true
			}
			err := controller.Tick(now)
			if err == nil || !strings.Contains(err.Error(), "publish policy a-fast switch") {
				t.Fatalf("checkpoint failure was hidden by final publication: %v", err)
			}
			if !blocked || !unblocked || !switched {
				t.Fatalf("fixture missed publication failure/retry: blocked=%t unblocked=%t switched=%t", blocked, unblocked, switched)
			}
			var state healthState
			if err := readJSON(path, &state); err != nil {
				t.Fatal(err)
			}
			item := state["a-fast"]
			if item.Selected != "nl" || item.RuntimeSelected != "nl" || !item.RuntimeConfirmed || item.RuntimeError != "" || runtime.current["a-fast"] != "nl" {
				t.Fatalf("publication failure changed a confirmed runtime route: %+v", item)
			}
		})
	}
}

func switchPublicationFixture(t *testing.T, mode string) (*healthController, *switchPublicationRuntime, time.Time) {
	t.Helper()
	now := time.Unix(1000, 0)
	contract := healthFixture(false).HealthPolicies["europe"]
	contract.Mode = mode
	contract.Groups = nil
	contract.Policy.ActiveCheckSeconds = 60
	pool := healthPool{Version: 3, HealthPolicies: map[string]healthPolicyContract{"a-fast": contract}}
	for policy, node := range map[string]string{"b-slow": "slow", "c-current": "current"} {
		other := contract
		other.Candidates = []string{node}
		other.Nodes = map[string]healthNode{node: {Label: node}}
		pool.HealthPolicies[policy] = other
	}
	state := make(healthState)
	current := make(map[string]string)
	warm := make(map[string]bool)
	for policy, currentContract := range pool.HealthPolicies {
		selected := currentContract.Candidates[0]
		item := newPolicyHealthState()
		item.Mode = mode
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = selected, selected, true
		item.RuntimeObservedAt = "stale"
		item.CandidateSignature = strings.Join(currentContract.Candidates, "\n")
		item.CandidateNodes = currentContract.Nodes
		item.LastProbeAt[selected] = float64(now.Unix() - 60)
		item.Samples[selected] = []healthSample{{OK: true}}
		state[policy], current[policy], warm[policy] = item, selected, true
	}
	state["a-fast"].AvailabilityFailures["de"] = 2
	state["c-current"].LastProbeAt["current"] = float64(now.Unix())
	removed := newPolicyHealthState()
	removed.Selected = "removed-node"
	state["removed"] = removed
	root := t.TempDir()
	if err := writeJSONAtomic(statePath(root, "selector-health"), state); err != nil {
		t.Fatal(err)
	}
	runtime := &switchPublicationRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{
		pool: pool, current: current,
		probes: map[string]probeEvidence{"de": failedEvidence(), "nl": successfulEvidence(40), "slow": successfulEvidence(50), "current": successfulEvidence(50)},
	}}
	controller := &healthController{
		opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: runtime,
		state: state, stateLoaded: true, warmStarted: warm,
		regularNext: map[string]time.Time{"a-fast": now.Add(time.Minute), "c-current": now.Add(time.Minute)},
		livenessAt:  make(map[string]time.Time),
	}
	return controller, runtime, now
}
