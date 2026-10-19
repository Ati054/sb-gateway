package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

type failedStartupReadback struct{ *fakeSelectorRuntime }

func (runtime *failedStartupReadback) Current(id string) (string, error) {
	if id == "failed" {
		return "", errors.New("readback unavailable")
	}
	return runtime.fakeSelectorRuntime.Current(id)
}

type startupPublicationRuntime struct {
	*fakeSelectorRuntime
	beforeProbe func()
}

func (*startupPublicationRuntime) hotRuntimeGeneration() hotRuntimeGeneration {
	return hotRuntimeGeneration{XrayPID: 123}
}

func (runtime *startupPublicationRuntime) Probe(node string) probeEvidence {
	runtime.beforeProbe()
	return runtime.fakeSelectorRuntime.Probe(node)
}

func (runtime *startupPublicationRuntime) ProbeAvailability(node string) probeEvidence {
	runtime.beforeProbe()
	return runtime.fakeSelectorRuntime.ProbeAvailability(node)
}

func TestStartupPublishesEverySelectorBeforeAnyQualityProbe(t *testing.T) {
	root := t.TempDir()
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	pool.HealthPolicies = map[string]healthPolicyContract{"first": contract, "last": contract}
	state := make(healthState)
	for id := range pool.HealthPolicies {
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "nl", "nl", true
		item.Mode, item.CandidateSignature = contract.Mode, "de\nnl"
		item.RuntimeObservedAt = "2020-01-01T00:00:00Z"
		state[id] = item
	}
	if err := publishHealthState(statePath(root, "selector-health"), state); err != nil {
		t.Fatal(err)
	}
	started := time.Now().UTC()
	checks := 0
	runtime := &startupPublicationRuntime{fakeSelectorRuntime: &fakeSelectorRuntime{
		pool: pool, reset: true, current: map[string]string{"first": "nl", "last": "nl"},
		probes: map[string]probeEvidence{"de": successfulEvidence(500), "nl": successfulEvidence(400)},
	}}
	runtime.beforeProbe = func() {
		checks++
		var proof map[string]runtimeproof.SelectorObservation
		if err := readJSON(filepath.Join(root, runtimeproof.SelectorSnapshotName), &proof); err != nil {
			t.Fatal(err)
		}
		for id := range pool.HealthPolicies {
			value := proof[id]
			at, err := time.Parse(time.RFC3339Nano, value.Observed)
			if err != nil || at.Before(started) || !value.Confirmed || value.Selected != "nl" {
				t.Errorf("quality work delayed startup readback for %s: %+v", id, value)
			}
		}
	}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime,
		state: state, stateLoaded: true, warmStarted: make(map[string]bool)}
	if err := controller.Tick(time.Now()); err != nil {
		t.Fatal(err)
	}
	if checks == 0 {
		t.Fatal("quality probe fixture did not run")
	}
}

func TestStartupReadinessRejectsMissingUnapprovedAndFailedReadbacks(t *testing.T) {
	root := t.TempDir()
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	pool.HealthPolicies = make(map[string]healthPolicyContract)
	state := make(healthState)
	for _, id := range []string{"valid", "blocked", "missing", "removed", "failed"} {
		pool.HealthPolicies[id] = contract
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "nl", "nl", true
		state[id] = item
	}
	runtime := &failedStartupReadback{&fakeSelectorRuntime{pool: pool,
		current: map[string]string{"valid": "nl", "blocked": "block", "removed": "unknown"}}}
	controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, state: state}
	if err := controller.publishStartupReadbacks(pool, []string{"valid", "blocked", "missing", "removed", "failed"}); err != nil {
		t.Fatal(err)
	}
	var proof map[string]runtimeproof.SelectorObservation
	if err := readJSON(filepath.Join(root, runtimeproof.SelectorSnapshotName), &proof); err != nil {
		t.Fatal(err)
	}
	for id, item := range proof {
		if item.Confirmed != (id == "valid" || id == "blocked") {
			t.Fatalf("incorrect startup proof for %s: %+v", id, item)
		}
		if state[id].Selected != "nl" {
			t.Fatal("readback phase changed selection instead of observing it")
		}
	}
	if len(runtime.probeCalls)+len(runtime.availabilityCalls)+len(runtime.selections) != 0 {
		t.Fatal("startup proof must not probe or change routes")
	}
}

func TestStartupHelperPublishesOnlyCompleteLiveRPCProof(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "partial failure"}[failSecond], func(t *testing.T) {
			root := t.TempDir()
			config := filepath.Join(root, "xray.json")
			if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"one","selector":["nl"]},{"tag":"two","selector":["nl"]}]}}`), 0600); err != nil {
				t.Fatal(err)
			}
			var reads atomic.Int32
			client := controlRPCFixture(t, func(_ context.Context, method string, _ []byte) ([]byte, error) {
				if strings.HasSuffix(method, "/OverrideBalancerTarget") {
					return nil, nil
				}
				if strings.HasSuffix(method, "/GetBalancerInfo") {
					if reads.Add(1) == 2 && failSecond {
						return nil, errors.New("unconfirmed selector")
					}
					return controlWireField(1, controlWireField(5, controlWireField(2, []byte("nl")))), nil
				}
				return nil, errors.New("unexpected startup RPC")
			})
			started := time.Now().UTC()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := RestoreXraySelectors(ctx, config, Options{StateRoot: root, XrayAPIServer: client.conn.Target()})
			proofPath := filepath.Join(root, runtimeproof.SelectorSnapshotName)
			if failSecond {
				if _, statErr := os.Stat(proofPath); err == nil || !os.IsNotExist(statErr) {
					t.Fatalf("partial startup published a proof: %v, %v", err, statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var proof map[string]runtimeproof.SelectorObservation
			if err := readJSON(proofPath, &proof); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"one", "two"} {
				value := proof[id]
				at, err := time.Parse(time.RFC3339Nano, value.Observed)
				if err != nil || at.Before(started) || !value.Confirmed || value.Selected != "nl" {
					t.Fatalf("invalid live proof: %+v", value)
				}
			}
			if _, err := os.Stat(statePath(root, "selector-health")); !os.IsNotExist(err) {
				t.Fatal("startup helper rewrote health history")
			}
		})
	}
}
