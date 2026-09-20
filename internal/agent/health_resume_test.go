package agent

import (
	"testing"
	"time"
)

type crossPolicyRuntime struct {
	*fakeSelectorRuntime
	controller  *healthController
	now         time.Time
	interrupted error
}

func (r *crossPolicyRuntime) Probe(candidate string) probeEvidence {
	r.interrupted = r.controller.checkDuringProbe(r.now, r.pool)
	if r.interrupted != nil {
		return failedEvidence()
	}
	return r.fakeSelectorRuntime.Probe(candidate)
}

func (r *crossPolicyRuntime) takeProbeInterruption() error {
	err := r.interrupted
	r.interrupted = nil
	return err
}

func TestInterruptedSheetReconcilesBeforeRestartingEarlierSheet(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			pool.HealthPolicies["z-last"] = contract
			pool.HealthPolicies["europe"] = contract
			runtime := &crossPolicyRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{
				pool: pool, current: map[string]string{"europe": "de", "z-last": "nl"},
				probes: map[string]probeEvidence{"de": successfulEvidence(100), "nl": successfulEvidence(100)},
			}, now: time.Unix(1000, 0)}
			state := healthState{}
			for _, id := range []string{"europe", "z-last"} {
				item := newPolicyHealthState()
				item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
				state[id] = item
			}
			c := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime, state: state, stateLoaded: true, warmStarted: map[string]bool{}}
			runtime.controller = c
			if err := c.Tick(runtime.now); err != nil {
				t.Fatal(err)
			}
			if !c.yielded || c.priorityPolicy != "z-last" {
				t.Fatal("changed sheet was not queued first")
			}
			// A stale/mismatched persisted selection on the second sheet must not keep
			// cancelling the first sheet before reconciliation can ever run.
			if err := c.Tick(runtime.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if c.yielded {
				t.Fatal("cross-sheet cancellation loop")
			}
			for _, id := range []string{"europe", "z-last"} {
				if !c.warmStarted[id] || !state[id].RuntimeConfirmed {
					t.Fatalf("%s never completed", id)
				}
			}
			if state["z-last"].RuntimeSelected != "nl" {
				t.Fatal("did not reconcile current Xray member")
			}
		})
	}
}
