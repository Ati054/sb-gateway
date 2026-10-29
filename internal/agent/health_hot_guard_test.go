package agent

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type guardInterruptedHotRuntime struct {
	*orderedHotRuntime
	blocked bool
}

func (r *guardInterruptedHotRuntime) Reload() (healthPool, bool, error) {
	if r.blocked {
		r.blocked = false
		return healthPool{}, false, errHealthPlannedApply
	}
	return r.orderedHotRuntime.Reload()
}

func TestPlannedGuardDoesNotEraseTheLastConsumedGeneration(t *testing.T) {
	c, r := hotReconcileFixture(t)
	previous := c.processedGeneration
	contract := r.pool.HealthPolicies["z-target"]
	contract.Mode = "priority"
	r.pool.HealthPolicies["z-target"] = contract
	r.reset = true
	c.runtime = &guardInterruptedHotRuntime{orderedHotRuntime: r, blocked: true}
	if err := c.Tick(time.Unix(1001, 0)); !errors.Is(err, errHealthPlannedApply) {
		t.Fatalf("planned interruption=%v", err)
	}
	if c.processedGeneration != previous {
		t.Fatal("planned interruption erased the consumed generation")
	}
	acknowledged := false
	c.hotPublisher = func(Options, hotRuntimeAcknowledgement) error { acknowledged = true; return nil }
	r.probeObserver = func(node string) {
		if strings.HasPrefix(node, "healthy") && !acknowledged {
			t.Fatal("planned guard forced an unrelated full survey before Apply acknowledgement")
		}
	}
	if err := c.Tick(time.Unix(1002, 0)); err != nil {
		t.Fatal(err)
	}
	if !acknowledged {
		t.Fatal("changed policy was not acknowledged")
	}
}
