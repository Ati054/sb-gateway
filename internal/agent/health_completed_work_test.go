package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

type completedBackgroundRuntime struct {
	*fakeSelectorRuntime
	done chan struct{}
}

func (runtime *completedBackgroundRuntime) backgroundJobComplete() bool {
	select {
	case <-runtime.done:
		return true
	default:
		return false
	}
}

func (runtime *completedBackgroundRuntime) ProbeAvailability(node string) probeEvidence {
	runtime.availabilityCalls = append(runtime.availabilityCalls, node)
	if !runtime.backgroundJobComplete() {
		close(runtime.done)
	}
	if evidence, ok := runtime.probes[node]; ok {
		return evidence
	}
	return successfulEvidence(100)
}

func completedSixPolicyFixture(t *testing.T) (*healthController, *fakeSelectorRuntime) {
	t.Helper()
	controller, base, _ := callbackOrderFixture(t, "best")
	contract := base.pool.HealthPolicies["a-healthy"]
	base.pool.HealthPolicies, controller.state = map[string]healthPolicyContract{}, healthState{}
	base.current = map[string]string{}
	for i := 0; i < 6; i++ {
		id, node := fmt.Sprintf("route-%d", i), fmt.Sprintf("node-%d", i)
		policy := contract
		policy.Candidates = []string{node}
		base.pool.HealthPolicies[id], base.current[id] = policy, node
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = node, node, true
		controller.state[id] = item
	}
	return controller, base
}

func TestCompletedQualityBatchStopsUnrelatedSixPolicyChecks(t *testing.T) {
	controller, base := completedSixPolicyFixture(t)
	runtime := &completedBackgroundRuntime{fakeSelectorRuntime: base, done: make(chan struct{})}
	controller.runtime = runtime
	if err := controller.checkDuringProbe(time.Unix(1010, 0), base.pool); err != nil {
		t.Fatal(err)
	}
	if len(base.availabilityCalls) != 1 {
		t.Fatalf("completed quality result waited for unrelated checks: calls=%v", base.availabilityCalls)
	}
}

func TestCompletedBackgroundStillConfirmsPendingFailure(t *testing.T) {
	controller, base, _ := callbackOrderFixture(t, "best")
	runtime := &completedBackgroundRuntime{fakeSelectorRuntime: base, done: make(chan struct{})}
	close(runtime.done)
	controller.runtime = runtime
	item := controller.state["z-target"]
	item.AvailabilityFailures["target"] = 1
	item.FailureClass["target"] = string(probeFailureTimeout)
	base.probes["target"] = probeEvidence{Failure: probeFailureTimeout}
	if err := controller.checkDuringProbe(time.Unix(1010, 0), base.pool); !errors.Is(err, errHealthYield) {
		t.Fatalf("pending failure did not preempt the completed result: %v", err)
	}
	if len(base.availabilityCalls) != 1 || base.availabilityCalls[0] != "target" ||
		item.AvailabilityFailures["target"] != healthFailureConfirmations || len(base.selections) != 0 {
		t.Fatalf("pending proof changed routing or was postponed: calls=%v failures=%d selections=%v", base.availabilityCalls, item.AvailabilityFailures["target"], base.selections)
	}
}

func TestCompletedParallelHTTPSBatchSkipsSixUnrelatedActiveChecks(t *testing.T) {
	oldTargets := healthTargets
	defer func() { healthTargets = oldTargets }()
	healthTargets = append(healthTargets[:0:0], oldTargets[0])
	healthTargets[0].url = "http://probe.invalid/generate_204"
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	pool := healthFixture(false)
	pool.Version, pool.BaseOutboundTags = 4, []string{"a", "b", "c"}
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	lanes := make([]*xraySelectorRuntime, 3)
	for i := range lanes {
		selector, selected := fmt.Sprintf("test-background-%d", i), ""
		lane := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: server.URL})
		lane.probeSelector = selector
		lane.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[1] == "bo" {
				selected = args[len(args)-1]
				return nil, nil
			}
			return selectorInfo(selected), nil
		}
		lanes[i] = lane
	}
	controller, base := completedSixPolicyFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime := &responsiveSelectorRuntime{selectorRuntime: base, backgrounds: lanes, ctx: ctx,
		enabled: true, parallelEnabled: true, generationPaths: []string{path}}
	runtime.generation = generationStamp(runtime.generationPaths)
	controller.runtime = runtime
	checks := 0
	runtime.check = func() error {
		checks++
		if checks != 1 {
			return errors.New("completed batch repeated the periodic callback")
		}
		close(release)
		for !runtime.backgroundJobComplete() && ctx.Err() == nil {
			time.Sleep(time.Millisecond)
		}
		return controller.checkDuringProbe(time.Unix(1010, 0), base.pool)
	}
	measured := runtime.ProbeQualityParallel([]string{"a", "b", "c"})
	if checks != 1 || len(base.availabilityCalls) != 0 || len(measured) != 3 || takeProbeInterruption(runtime) != nil {
		t.Fatalf("completed HTTPS batch was delayed or lost: callbacks=%d active=%v measured=%v", checks, base.availabilityCalls, measured)
	}
	for node, evidence := range measured {
		if !evidence.OK {
			t.Fatalf("completed HTTPS evidence lost for %s: %+v", node, evidence)
		}
	}
}

func TestCompletedBackgroundStillServicesForcedActiveProof(t *testing.T) {
	controller, base, _ := callbackOrderFixture(t, "best")
	runtime := &completedBackgroundRuntime{fakeSelectorRuntime: base, done: make(chan struct{})}
	close(runtime.done)
	controller.runtime = runtime
	controller.forceLiveness = map[string]bool{"z-target": true}
	if err := controller.checkDuringProbe(time.Unix(1010, 0), base.pool); err != nil {
		t.Fatal(err)
	}
	if len(base.availabilityCalls) != 1 || base.availabilityCalls[0] != "target" {
		t.Fatalf("completion bypassed a forced active proof: calls=%v", base.availabilityCalls)
	}
}

func TestFinishedProbeDoesNotRepeatPeriodicCallback(t *testing.T) {
	for attempt := 0; attempt < 32; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		release, returned := make(chan struct{}), make(chan struct{})
		checks := 0
		result := awaitProbeJob(ctx, time.Millisecond, func() error {
			checks++
			if checks > 1 {
				return fmt.Errorf("finished worker waited for another callback")
			}
			close(release)
			<-returned
			// Both the result and a periodic tick become ready while this check
			// finishes. Consuming the result must not start more network work.
			time.Sleep(5 * time.Millisecond)
			return nil
		}, func(context.Context) probeJobResult {
			<-release
			close(returned)
			return probeJobResult{evidence: successfulEvidence(100)}
		})
		cancel()
		if result.err != nil || !result.evidence.OK || checks != 1 {
			t.Fatalf("completed probe delayed on attempt %d: checks=%d error=%v", attempt, checks, result.err)
		}
	}
}
