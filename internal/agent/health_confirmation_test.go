package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type confirmationFixture struct {
	*fakeSelectorRuntime
	calls          []string
	onConfirmation func()
}

func (runtime *confirmationFixture) ProbeConfirmationAvailability(candidate string) probeEvidence {
	runtime.calls = append(runtime.calls, candidate)
	if runtime.onConfirmation != nil {
		runtime.onConfirmation()
	}
	return runtime.probes[candidate]
}

func TestActiveTimeoutUsesParallelConfirmationAndKeepsSelectionOnRecovery(t *testing.T) {
	controller, item, base := stagedOptimizationController(t)
	runtime := &confirmationFixture{fakeSelectorRuntime: base}
	controller.runtime = runtime
	controller.livenessAt = make(map[string]time.Time)
	contract := base.pool.HealthPolicies["europe"]
	now := time.Unix(2000, 0)
	base.probes["active"] = probeEvidence{Failure: probeFailureTimeout}
	if _, err := controller.checkActiveAvailability(now, "europe", contract, item, false); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "active" || item.AvailabilityFailures["active"] != 1 || len(runtime.calls) != 0 {
		t.Fatal("first timeout changed route or used confirmation fanout")
	}
	base.probes["active"] = successfulEvidence(4000)
	if _, err := controller.checkActiveAvailability(now.Add(10*time.Second), "europe", contract, item, false); err != nil {
		t.Fatal(err)
	}
	if len(runtime.calls) != 1 || len(base.availabilityCalls) != 1 || item.Selected != "active" || item.AvailabilityFailures["active"] != 0 {
		t.Fatal("timeout recovery did not use confirmation or changed route")
	}
	if _, err := controller.checkActiveAvailability(now.Add(time.Minute), "europe", contract, item, false); err != nil {
		t.Fatal(err)
	}
	if len(runtime.calls) != 1 || len(base.availabilityCalls) != 2 {
		t.Fatal("healthy path retained confirmation fanout")
	}
}

func TestConfirmationAvailabilityStartsAllOriginsAndJoinsWorkers(t *testing.T) {
	original, primary, fallback := healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout
	t.Cleanup(func() {
		healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout = original, primary, fallback
	})
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout, availabilityFallbackTimeout = 500*time.Millisecond, 500*time.Millisecond
	allStarted, joined := make(chan struct{}), make(chan struct{})
	var started, canceled atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if started.Add(1) == 3 {
			close(allStarted)
		}
		if r.URL.Path == "/cloudflare-trace" {
			select {
			case <-allStarted:
				w.WriteHeader(http.StatusOK)
			case <-r.Context().Done():
			}
			return
		}
		<-r.Context().Done()
		if canceled.Add(1) == 2 {
			close(joined)
		}
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeConfirmationAvailability("direct-wan")
	if !evidence.OK || !evidence.QualityUnmeasured || started.Load() != 3 || len(evidence.TargetFailures) != 0 {
		t.Fatalf("confirmation did not start all origins: %+v", evidence)
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("canceled workers still running")
	}
}

func TestConfirmationAvailabilityRejectsChangedGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generation")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	base := &confirmationFixture{fakeSelectorRuntime: &fakeSelectorRuntime{probes: map[string]probeEvidence{"a": successfulEvidence(1)}}}
	base.onConfirmation = func() {
		if err := os.WriteFile(path, []byte("after-longer"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runtime := &responsiveSelectorRuntime{selectorRuntime: base, ctx: context.Background(), generationPaths: []string{path}}
	runtime.generation = generationStamp(runtime.generationPaths)
	if evidence := runtime.ProbeConfirmationAvailability("a"); !evidence.LocalFailure || evidence.OK || !errors.Is(runtime.takeProbeInterruption(), errHealthYield) {
		t.Fatalf("replaced generation accepted: %+v", evidence)
	}
}

func TestActiveNonTimeoutDoesNotUseConfirmationFanout(t *testing.T) {
	controller, item, base := stagedOptimizationController(t)
	runtime := &confirmationFixture{fakeSelectorRuntime: base}
	controller.runtime = runtime
	controller.livenessAt = make(map[string]time.Time)
	item.AvailabilityFailures["active"] = 1
	item.FailureClass["active"] = string(probeFailureTransient)
	contract := base.pool.HealthPolicies["europe"]
	if _, err := controller.checkActiveAvailability(time.Unix(2000, 0), "europe", contract, item, false); err != nil {
		t.Fatal(err)
	}
	if len(runtime.calls) != 0 || len(base.availabilityCalls) != 1 {
		t.Fatal("non-timeout failure expanded confirmation fanout")
	}
}

func TestConfirmationAvailabilityCancellationDoesNotPenalizeNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := &confirmationFixture{fakeSelectorRuntime: &fakeSelectorRuntime{probes: map[string]probeEvidence{"a": successfulEvidence(1)}}}
	base.onConfirmation = cancel
	runtime := &responsiveSelectorRuntime{selectorRuntime: base, ctx: ctx}
	runtime.generation = generationStamp(runtime.generationPaths)
	if evidence := runtime.ProbeConfirmationAvailability("a"); !evidence.LocalFailure || evidence.OK || !errors.Is(runtime.takeProbeInterruption(), errHealthYield) {
		t.Fatalf("canceled confirmation penalized node: %+v", evidence)
	}
	if evidence := runtime.ProbeConfirmationAvailability("a"); !evidence.LocalFailure || len(base.calls) != 1 {
		t.Fatal("canceled context started another confirmation")
	}
}
