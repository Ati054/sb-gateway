package agent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type observedTransitionRuntime struct {
	*fakeSelectorRuntime
	beforeProbe func(string)
}

func (runtime *observedTransitionRuntime) ProbeAvailability(candidate string) probeEvidence {
	if runtime.beforeProbe != nil {
		runtime.beforeProbe(candidate)
	}
	return runtime.fakeSelectorRuntime.ProbeAvailability(candidate)
}

func (runtime *observedTransitionRuntime) ProbeAvailabilityParallel(candidates []string, accept func(string, probeEvidence) bool) map[string]probeEvidence {
	measured := make(map[string]probeEvidence)
	for _, candidate := range candidates {
		evidence := runtime.ProbeAvailability(candidate)
		measured[candidate] = evidence
		if accept(candidate, evidence) {
			break
		}
	}
	return measured
}

func transitionFixture(t *testing.T, batch int) (*healthController, *observedTransitionRuntime, *policyHealthState) {
	t.Helper()
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Candidates = []string{"nl", "fr"}
	contract.Groups = nil
	contract.Nodes["fr"] = healthNode{Label: "France"}
	contract.Policy.ProbeBatchSize = batch
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.Mode, item.CandidateSignature = contract.Mode, "de"
	item.AvailabilityOK = map[string]bool{"de": true}
	item.LastProbeAt["de"] = 999
	runtime := &observedTransitionRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{
		pool: pool, reset: true, current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{"de": successfulEvidence(40), "nl": failedEvidence(), "fr": successfulEvidence(50)},
	}}
	controller := &healthController{
		opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
		state: healthState{"europe": item}, stateLoaded: true, warmStarted: map[string]bool{"europe": true},
	}
	return controller, runtime, item
}

func TestRemovedActiveProbesReplacementBeforeChangingSelector(t *testing.T) {
	controller, runtime, item := transitionFixture(t, 2)
	runtime.beforeProbe = func(candidate string) {
		if current := runtime.current["europe"]; current != "de" {
			t.Fatalf("probe %s observed interrupted path %s", candidate, current)
		}
	}
	if err := controller.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if item.RuntimeSelected != "fr" || !item.RuntimeConfirmed || item.LastSwitchReason != "active-removed" {
		t.Fatalf("replacement was not confirmed: %+v", item)
	}
	if hasSelection(runtime.selections, "europe", "block") {
		t.Fatalf("transition passed through block: %v", runtime.selections)
	}
	if !controller.hotRuntimeReconciled() {
		t.Fatal("confirmed replacement did not acknowledge the contract")
	}
}

func TestRemovedActiveKeepsWorkingPathAcrossBoundedProbeBatches(t *testing.T) {
	controller, runtime, item := transitionFixture(t, 1)
	if err := controller.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if item.RuntimeSelected != "de" || !item.RuntimeConfirmed || len(runtime.selections) != 0 {
		t.Fatalf("failed first batch withdrew working route: %v %s", runtime.selections, item.RuntimeSelected)
	}
	if controller.hotRuntimeReconciled() || controller.nextInterval() != time.Second {
		t.Fatal("pending replacement was acknowledged or delayed")
	}
	if err := controller.Tick(time.Unix(1001, 0)); err != nil {
		t.Fatal(err)
	}
	if item.RuntimeSelected != "fr" || hasSelection(runtime.selections, "europe", "block") {
		t.Fatalf("later working candidate was not promoted directly: %v", runtime.selections)
	}
}

func TestRemovedActiveDoesNotTrustADeadCachedReserve(t *testing.T) {
	controller, runtime, item := transitionFixture(t, 2)
	item.AvailabilityOK["nl"] = true
	item.Recoveries["nl"] = 3
	item.Shortlist = []string{"nl"}
	if err := controller.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if item.RuntimeSelected != "fr" || hasSelection(runtime.selections, "europe", "nl") || hasSelection(runtime.selections, "europe", "block") {
		t.Fatalf("stale reserve was selected before a fresh successful probe: %v", runtime.selections)
	}
}

func TestRemovedActiveKeepsParallelWinnerInsteadOfCachedPriority(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, item := transitionFixture(t, 2)
			contract := runtime.pool.HealthPolicies["europe"]
			contract.Mode = mode
			runtime.pool.HealthPolicies["europe"] = contract
			item.AvailabilityOK["nl"] = true
			item.Recoveries["nl"] = 3
			item.LastProbeAt["nl"] = 999
			item.Samples["nl"] = []healthSample{{OK: true, DelayMS: successfulEvidence(20).DelayMS}}
			item.Shortlist = []string{"nl"}
			runtime.probes["nl"] = successfulEvidence(20)
			// The second lane finishes first. The cached preferred lane is still
			// pending when the first usable result ends the transition race.
			controller.runtime = &reverseParallelRuntime{runtime.fakeSelectorRuntime}
			if err := controller.Tick(time.Unix(1000, 0)); err != nil {
				t.Fatal(err)
			}
			if contains(runtime.availabilityCalls, "nl") {
				t.Fatalf("test did not leave the preferred availability lane pending: %v", runtime.availabilityCalls)
			}
			if item.RuntimeSelected != "fr" || item.LastSwitchReason != "active-removed" ||
				hasSelection(runtime.selections, "europe", "nl") || hasSelection(runtime.selections, "europe", "block") {
				t.Fatalf("fresh parallel winner was superseded in its transition tick: %v reason=%s", runtime.selections, item.LastSwitchReason)
			}
		})
	}
}

func TestFailedReplacementKeepsOldRouteUntilContractRollback(t *testing.T) {
	controller, runtime, item := transitionFixture(t, 2)
	runtime.probes["fr"] = failedEvidence()
	for _, second := range []int64{1000, 1003, 1030, 1090} {
		if err := controller.Tick(time.Unix(second, 0)); err != nil {
			t.Fatal(err)
		}
		if item.RuntimeSelected != "de" || !item.RuntimeConfirmed || controller.hotRuntimeReconciled() {
			t.Fatalf("failed candidate changed or acknowledged route at %d", second)
		}
	}
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Candidates = []string{"de"}
	runtime.pool.HealthPolicies["europe"] = contract
	runtime.reset = true
	if err := controller.Tick(time.Unix(1091, 0)); err != nil {
		t.Fatal(err)
	}
	if item.RuntimeSelected != "de" || len(controller.transitions) != 0 || !controller.hotRuntimeReconciled() || hasSelection(runtime.selections, "europe", "block") {
		t.Fatal("rollback did not restore the original contract without a gap")
	}
}

func TestRemovedActiveTransitionRetainsNormalOutageAndGraceBounds(t *testing.T) {
	for _, reason := range []string{"old-path-failed", "grace-expired"} {
		t.Run(reason, func(t *testing.T) {
			controller, runtime, item := transitionFixture(t, 2)
			runtime.probes["fr"] = failedEvidence()
			if err := controller.Tick(time.Unix(1000, 0)); err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1001, 0)
			if reason == "old-path-failed" {
				item.AvailabilityFailures["de"] = 3
			} else {
				now = time.Unix(1000, 0).Add(policyTransitionGrace)
			}
			if err := controller.Tick(now); err != nil {
				t.Fatal(err)
			}
			if !hasSelection(runtime.selections, "europe", "block") {
				t.Fatal("transition retained the old route after its safety bound")
			}
		})
	}
}

func TestTransitionLivenessDoesNotYieldJustBecauseOldLeafWasRemoved(t *testing.T) {
	controller, runtime, item := transitionFixture(t, 1)
	if err := controller.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := controller.checkDuringProbe(time.Unix(1005, 0), runtime.pool); errors.Is(err, errHealthYield) {
		t.Fatal("background preparation yielded solely on the old leaf membership")
	}
	if !item.RuntimeConfirmed || runtime.current["europe"] != "de" || strings.Join(runtime.availabilityCalls, ",") != "nl,de" {
		t.Fatalf("transition liveness changed route: %v", runtime.availabilityCalls)
	}
}
