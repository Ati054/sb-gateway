package agent

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func cloneSettingsPool(t *testing.T, pool healthPool) healthPool {
	t.Helper()
	body, err := json.Marshal(pool)
	if err != nil {
		t.Fatal(err)
	}
	var result healthPool
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHealthSettingsOnlyRequiresUnchangedForwardingContract(t *testing.T) {
	controller, runtime, _ := callbackOrderFixture(t, "best")
	_ = controller
	base := runtime.pool
	for _, test := range []struct {
		name    string
		allowed bool
		change  func(*healthPool)
	}{
		{"same", true, func(*healthPool) {}},
		{"scheduling", true, func(p *healthPool) {
			p.ProbeBudget = 1
			p.ProbeLanes = 1
			c := p.HealthPolicies["z-target"]
			c.Policy.ActiveCheckSeconds = 30
			c.Policy.ActiveLivenessSeconds = 5
			c.Policy.ProbeBatchSize = 1
			c.Policy.SwitchImprovementMS = 200
			p.HealthPolicies["z-target"] = c
		}},
		{"endpoint", false, func(p *healthPool) { p.Outbounds["target"] = json.RawMessage(`{"protocol":"blackhole"}`) }},
		{"mode", false, func(p *healthPool) {
			c := p.HealthPolicies["z-target"]
			c.Mode = "priority"
			p.HealthPolicies["z-target"] = c
		}},
		{"order", false, func(p *healthPool) {
			c := p.HealthPolicies["z-target"]
			c.Candidates[0], c.Candidates[1] = c.Candidates[1], c.Candidates[0]
		}},
		{"measurement", false, func(p *healthPool) {
			c := p.HealthPolicies["z-target"]
			c.Policy.LatencyMeasurement = "different"
			p.HealthPolicies["z-target"] = c
		}},
		{"permissions", false, func(p *healthPool) {
			c := p.HealthPolicies["z-target"]
			c.Policy.CandidateServiceAccess = map[string][]string{"target": {"service"}}
			p.HealthPolicies["z-target"] = c
		}},
		{"prefix", false, func(p *healthPool) { p.PolicyPrefixes = map[string]string{"z-target": "new"} }},
		{"new-policy", false, func(p *healthPool) { p.HealthPolicies["new"] = p.HealthPolicies["z-target"] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := cloneSettingsPool(t, base)
			target := cloneSettingsPool(t, base)
			before := cloneSettingsPool(t, previous)
			test.change(&target)
			if got := healthSettingsOnly(previous, target); got != test.allowed {
				t.Fatalf("settingsOnly=%t want %t", got, test.allowed)
			}
			if !reflect.DeepEqual(previous, before) {
				t.Fatal("comparison mutated previous contract")
			}
		})
	}
}

type settingsReloadRuntime struct {
	*fakeSelectorRuntime
	generation hotRuntimeGeneration
	readbacks  []string
	readError  bool
}

func (r *settingsReloadRuntime) hotRuntimeGeneration() hotRuntimeGeneration { return r.generation }
func (r *settingsReloadRuntime) Current(id string) (string, error) {
	r.readbacks = append(r.readbacks, id)
	if r.readError {
		return "", errors.New("unavailable")
	}
	return r.fakeSelectorRuntime.Current(id)
}

func TestObserveHealthSettingsRequiresEveryLiveReadback(t *testing.T) {
	for _, reason := range []string{"ready", "unloaded", "transition", "unconfirmed", "cold", "mismatch", "api-error", "outside-contract"} {
		t.Run(reason, func(t *testing.T) {
			controller, fake, _ := callbackOrderFixture(t, "best")
			r := &settingsReloadRuntime{fakeSelectorRuntime: fake}
			controller.runtime = r
			switch reason {
			case "unloaded":
				controller.stateLoaded = false
			case "transition":
				controller.transitions = map[string]*policyTransition{"z-target": {previous: "target-reserve"}}
			case "unconfirmed":
				controller.state["z-target"].RuntimeConfirmed = false
			case "cold":
				controller.warmStarted["z-target"] = false
			case "mismatch":
				fake.current["z-target"] = "target-reserve"
			case "api-error":
				r.readError = true
			case "outside-contract":
				fake.current["z-target"] = "removed"
				controller.state["z-target"].Selected = "removed"
				controller.state["z-target"].RuntimeSelected = "removed"
			}
			got := controller.observeUnchangedHotPolicies(fake.pool, []string{"a-healthy", "z-target"})
			if got != (reason == "ready") {
				t.Fatalf("accepted=%t for %s", got, reason)
			}
			for _, item := range controller.state {
				if (item.RuntimeObservedAt != "") != got {
					t.Fatal("partial/absent readback was stamped as observed")
				}
			}
			if got && len(r.readbacks) != 2 {
				t.Fatalf("missing live readbacks: %v", r.readbacks)
			}
			if len(fake.probeCalls)+len(fake.availabilityCalls)+len(fake.selections) != 0 {
				t.Fatal("settings observation probed or switched a node")
			}
		})
	}
}

func TestSettingsReloadRetainsWarmSelectionAndPendingFailure(t *testing.T) {
	controller, fake, _ := callbackOrderFixture(t, "best")
	controller.processedPool = cloneSettingsPool(t, fake.pool)
	controller.processedGeneration = hotRuntimeGeneration{XrayPID: 123}
	fake.reset = true
	r := &settingsReloadRuntime{fakeSelectorRuntime: fake, generation: hotRuntimeGeneration{XrayPID: 123}}
	controller.runtime = r
	c := fake.pool.HealthPolicies["z-target"]
	c.Policy.ActiveCheckSeconds = 30
	fake.pool.HealthPolicies["z-target"] = c
	item := controller.state["z-target"]
	item.AvailabilityFailures["target"] = 1
	item.FailureClass["target"] = string(probeFailureTimeout)
	// Keep the next independent failure proof outside this Tick: a settings
	// edit itself must not discard it or manufacture a selection.
	controller.livenessAt["z-target"] = time.Unix(1001, 0)
	if err := controller.Tick(time.Unix(1001, 0)); err != nil {
		t.Fatal(err)
	}
	if item.AvailabilityFailures["target"] != 1 {
		t.Fatalf("pending failure reset by scheduling edit: %d", item.AvailabilityFailures["target"])
	}
	if !controller.warmStarted["a-healthy"] || !controller.warmStarted["z-target"] || item.RuntimeObservedAt == "" || len(fake.selections) != 0 {
		t.Fatalf("same-core settings edit reselected or lost observation: warm=%v selections=%v", controller.warmStarted, fake.selections)
	}
}
