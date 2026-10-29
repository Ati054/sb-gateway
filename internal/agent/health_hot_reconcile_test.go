package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type orderedHotRuntime struct {
	*settingsReloadRuntime
	probeObserver func(string)
	currentError  string
}

func (r *orderedHotRuntime) Probe(node string) probeEvidence {
	if r.probeObserver != nil {
		r.probeObserver(node)
	}
	return r.fakeSelectorRuntime.Probe(node)
}

func (r *orderedHotRuntime) Current(id string) (string, error) {
	if id == r.currentError {
		return "", errors.New("readback unavailable")
	}
	return r.settingsReloadRuntime.Current(id)
}

func hotReconcileFixture(t *testing.T) (*healthController, *orderedHotRuntime) {
	t.Helper()
	c, fake, _ := callbackOrderFixture(t, "best")
	fake.pool.ProbeBudget, fake.pool.ProbeLanes = 10, 4
	for _, node := range []string{"healthy", "healthy-reserve", "target", "target-reserve"} {
		fake.pool.Outbounds[node] = json.RawMessage(`{"protocol":"freedom"}`)
		fake.probes[node] = successfulEvidence(100)
	}
	c.processedPool = cloneSettingsPool(t, fake.pool)
	c.processedGeneration = hotRuntimeGeneration{XrayPID: 123, PoolSHA256: "old", PoolMTimeUnixNano: 1}
	r := &orderedHotRuntime{settingsReloadRuntime: &settingsReloadRuntime{fakeSelectorRuntime: fake, generation: hotRuntimeGeneration{XrayPID: 123, PoolSHA256: "new", PoolMTimeUnixNano: 2}}}
	c.runtime = r
	for id := range c.regularNext {
		c.regularNext[id] = time.Unix(1000, 0)
	}
	return c, r
}

func TestHotPolicyScopeRetainsOnlyIdenticalInputs(t *testing.T) {
	_, r := hotReconcileFixture(t)
	base := r.pool
	for _, test := range []struct {
		name            string
		healthy, target bool
		change          func(*healthPool)
	}{
		{"other-mode", true, false, func(p *healthPool) {
			v := p.HealthPolicies["z-target"]
			v.Mode = "priority"
			p.HealthPolicies["z-target"] = v
		}},
		{"endpoint", false, true, func(p *healthPool) { p.Outbounds["healthy"] = json.RawMessage(`{"protocol":"blackhole"}`) }},
		{"measurement", false, true, func(p *healthPool) {
			v := p.HealthPolicies["a-healthy"]
			v.Policy.LatencyMeasurement = "other"
			p.HealthPolicies["a-healthy"] = v
		}},
		{"permissions", false, true, func(p *healthPool) {
			v := p.HealthPolicies["a-healthy"]
			v.Policy.CandidateServiceIDs = []string{"service"}
			p.HealthPolicies["a-healthy"] = v
		}},
		{"common-bindings", false, false, func(p *healthPool) { p.Policies = map[string][]string{"binding": {"changed"}} }},
		{"prefix", false, false, func(p *healthPool) { p.PolicyPrefixes = map[string]string{"a-healthy": "other"} }},
		{"version", false, false, func(p *healthPool) { p.Version++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := cloneSettingsPool(t, base)
			previous := cloneSettingsPool(t, base)
			test.change(&target)
			if sameHotPolicyContract(previous, target, "a-healthy") != test.healthy || sameHotPolicyContract(previous, target, "z-target") != test.target {
				t.Fatal("changed forwarding inputs were retained or unrelated policy was discarded")
			}
		})
	}
}

func TestHotModeApplyAcknowledgesBeforeUnrelatedQuality(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(map[bool]string{false: "new-generation", true: "retry-after-yield"}[retry], func(t *testing.T) {
			c, r := hotReconcileFixture(t)
			contract := r.pool.HealthPolicies["z-target"]
			contract.Mode = "priority"
			r.pool.HealthPolicies["z-target"] = contract
			r.reset = true
			if retry {
				r.reset = false
				c.processedPool = cloneSettingsPool(t, r.pool)
				c.processedGeneration = r.generation
				c.hotPendingGeneration = r.generation
				c.warmStarted["z-target"] = false
				c.yielded = true
			}
			acknowledged, unrelatedChecked := false, false
			c.hotPublisher = func(_ Options, ack hotRuntimeAcknowledgement) error {
				if ack.hotRuntimeGeneration != r.generation || len(ack.PolicySelections) != 2 {
					t.Fatal("wrong acknowledged generation/scope")
				}
				var persisted healthState
				if err := readJSON(statePath(c.opts.StateRoot, "selector-health"), &persisted); err != nil || persisted["z-target"].Mode != "priority" {
					t.Fatalf("marker preceded applied public mode: %v", err)
				}
				acknowledged = true
				return nil
			}
			r.probeObserver = func(node string) {
				if strings.HasPrefix(node, "healthy") {
					unrelatedChecked = true
					if !acknowledged {
						t.Fatal("Apply still waits for unrelated quality survey")
					}
				}
			}
			if err := c.Tick(time.Unix(1001, 0)); err != nil {
				t.Fatal(err)
			}
			if !acknowledged || !unrelatedChecked || c.hotPendingGeneration.XrayPID != 0 {
				t.Fatalf("ack=%t unrelated=%t pending=%+v", acknowledged, unrelatedChecked, c.hotPendingGeneration)
			}
			if len(r.probeCalls) == 0 || !strings.HasPrefix(r.probeCalls[0], "target") {
				t.Fatalf("changed policy did not run before unrelated work: %v", r.probeCalls)
			}
		})
	}
}

func TestHotPolicyReuseRequiresLiveReadback(t *testing.T) {
	c, r := hotReconcileFixture(t)
	contract := r.pool.HealthPolicies["z-target"]
	contract.Mode = "priority"
	r.pool.HealthPolicies["z-target"] = contract
	r.currentError = "a-healthy"
	r.reset = true
	c.hotPublisher = func(Options, hotRuntimeAcknowledgement) error {
		t.Fatal("failed live readback was acknowledged")
		return nil
	}
	if err := c.Tick(time.Unix(1001, 0)); err == nil {
		t.Fatal("missing live API readback did not fail")
	}
}

func TestCoreRestartDoesNotReuseHotPolicyReadbacks(t *testing.T) {
	c, r := hotReconcileFixture(t)
	contract := r.pool.HealthPolicies["z-target"]
	contract.Mode = "priority"
	r.pool.HealthPolicies["z-target"] = contract
	r.reset = true
	r.generation.XrayPID = 456
	first := ""
	acknowledged := false
	r.probeObserver = func(node string) {
		if first == "" {
			first = node
		}
	}
	c.hotPublisher = func(_ Options, ack hotRuntimeAcknowledgement) error {
		if !c.hotRuntimeReconciled() || ack.XrayPID != 456 {
			t.Fatal("new core acknowledged before full reconciliation")
		}
		var persisted healthState
		if err := readJSON(statePath(c.opts.StateRoot, "selector-health"), &persisted); err != nil || persisted["z-target"].Mode != "priority" {
			t.Fatalf("core acknowledgement preceded applied mode: %v", err)
		}
		acknowledged = true
		return nil
	}
	if err := c.Tick(time.Unix(1001, 0)); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "healthy") || c.hotPendingGeneration.XrayPID != 0 || !acknowledged {
		t.Fatalf("new core reused a same-process acknowledgement: first=%s pending=%+v", first, c.hotPendingGeneration)
	}
}
