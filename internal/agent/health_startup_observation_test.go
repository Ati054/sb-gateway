package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type unavailableStartupObservation struct{ *fakeSelectorRuntime }

func (*unavailableStartupObservation) Current(string) (string, error) {
	return "", errors.New("Xray selector state is unavailable")
}

func TestDurableStartupSelectionRespectsCurrentContract(t *testing.T) {
	for _, test := range []struct {
		name, mode, savedMode, signature, selected, members string
		available                                           bool
		failures                                            int
		want                                                string
	}{
		{"API unavailable", "best", "best", "de\nnl", "nl", "nl", true, 0, "nl"},
		{"priority reserve", "priority", "priority", "de\nnl", "nl", "nl", true, 0, "nl"},
		{"priority reordered", "priority", "priority", "nl\nde", "nl", "nl", true, 0, "de"},
		{"URLTest inventory changed", "best", "best", "nl\nde", "nl", "nl", true, 0, "nl"},
		{"mode changed", "priority", "best", "de\nnl", "nl", "nl", true, 0, "de"},
		{"removed", "best", "best", "de\nnl", "removed", "removed", true, 0, "de"},
		{"not rendered", "best", "best", "de\nnl", "nl", "nl-prefix", true, 0, "de"},
		{"failed leaf", "best", "best", "de\nnl", "nl", "nl", false, 0, "de"},
		{"failure threshold", "best", "best", "de\nnl", "nl", "nl", true, 3, "de"},
		{"single failure", "best", "best", "de\nnl", "nl", "nl", true, 1, "nl"},
		{"block", "best", "best", "de\nnl", "block", "block", true, 0, "de"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			config, poolPath := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
			if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["de","`+test.members+`"]}]}}`), 0600); err != nil {
				t.Fatal(err)
			}
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = test.mode
			pool.HealthPolicies["europe"] = contract
			if err := writeJSONAtomic(poolPath, pool); err != nil {
				t.Fatal(err)
			}
			item := newPolicyHealthState()
			item.LastWorkingSelection = &workingSelection{test.selected, test.savedMode, test.signature}
			item.AvailabilityOK = map[string]bool{test.selected: test.available}
			item.AvailabilityFailures[test.selected] = test.failures
			if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
				t.Fatal(err)
			}
			got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: poolPath})
			if err != nil || len(got) != 1 || got[0].Outbound != test.want {
				t.Fatalf("startup: %+v, %v", got, err)
			}
		})
	}
}

func TestWorkingSelectionRequiresBothReadbackAndAvailability(t *testing.T) {
	contract := healthFixture(false).HealthPolicies["europe"]
	item := newPolicyHealthState()
	item.Mode, item.CandidateSignature = contract.Mode, "de\nnl"
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "nl", "nl", true
	if rememberWorkingSelection(contract, item) {
		t.Fatal("unprobed leaf remembered")
	}
	item.AvailabilityOK = map[string]bool{"nl": true}
	if !rememberWorkingSelection(contract, item) {
		t.Fatal("working leaf not remembered")
	}
	if rememberWorkingSelection(contract, item) {
		t.Fatal("unchanged evidence must not trigger writes")
	}
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "", false
	item.AvailabilityOK["de"] = true
	if rememberWorkingSelection(contract, item) || item.LastWorkingSelection.Selected != "nl" {
		t.Fatal("unconfirmed selection replaced working evidence")
	}
}

// A control-API error must not erase durable evidence of a working leaf.
func TestStartupSelectionAfterPersistedObservationError(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, lane := range []string{"quality", "liveness"} {
			t.Run(mode+"/"+lane, func(t *testing.T) {
				root := t.TempDir()
				config, poolPath := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
				if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["de","nl"]}]}}`), 0600); err != nil {
					t.Fatal(err)
				}
				pool := healthFixture(false)
				contract := pool.HealthPolicies["europe"]
				contract.Mode = mode
				pool.HealthPolicies["europe"] = contract
				if err := writeJSONAtomic(poolPath, pool); err != nil {
					t.Fatal(err)
				}
				item := newPolicyHealthState()
				item.Selected, item.RuntimeSelected, item.RuntimeConfirmed, item.Mode = "nl", "nl", true, mode
				item.CandidateSignature = "de\nnl"
				item.AvailabilityOK = map[string]bool{"nl": true}
				state := healthState{"europe": item}
				opts := Options{StateRoot: root, HealthPoolFile: poolPath, HealthInterval: time.Minute}
				if err := writeJSONAtomic(statePath(root, "selector-health"), state); err != nil {
					t.Fatal(err)
				}
				before, err := XrayStartupSelections(config, opts)
				if err != nil || len(before) != 1 || before[0].Outbound != "nl" {
					t.Fatalf("confirmed leaf was not restored: %+v, %v", before, err)
				}
				now := time.Unix(1000, 0)
				next := now
				if lane == "liveness" {
					next = now.Add(time.Minute)
				}
				runtime := &unavailableStartupObservation{&fakeSelectorRuntime{pool: pool}}
				controller := &healthController{opts: opts, runtime: runtime, state: state, stateLoaded: true,
					warmStarted: map[string]bool{"europe": true}, regularNext: map[string]time.Time{"europe": next},
					livenessAt: map[string]time.Time{}}
				if err := controller.Tick(now); err == nil {
					t.Fatal("missing simulated API error")
				}
				var saved healthState
				if err := readJSON(statePath(root, "selector-health"), &saved); err != nil {
					t.Fatal(err)
				}
				if saved["europe"].RuntimeConfirmed || saved["europe"].Selected != "nl" || !saved["europe"].AvailabilityOK["nl"] {
					t.Fatal("expected observation-only failure, not a failed or removed leaf")
				}
				after, err := XrayStartupSelections(config, opts)
				if err != nil || len(after) != 1 || after[0].Outbound != "nl" {
					t.Fatalf("working leaf lost after API error: %+v, %v", after, err)
				}
				if len(runtime.selections) != 0 || len(runtime.probeCalls) != 0 || len(runtime.availabilityCalls) != 0 {
					t.Fatal("API error should occur before probes or selector writes")
				}
				t.Log("confirmed nl -> API observation error persisted -> startup restores nl")
			})
		}
	}
}
