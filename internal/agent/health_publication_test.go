package agent

import (
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
