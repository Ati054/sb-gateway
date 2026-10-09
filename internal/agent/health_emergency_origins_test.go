package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmergencyAvailabilityStartsAllOriginsAndJoinsCanceledSiblings(t *testing.T) {
	original, primaryTimeout, fallbackTimeout := healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout
	t.Cleanup(func() {
		healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout = original, primaryTimeout, fallbackTimeout
	})
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout, availabilityFallbackTimeout = time.Second, 1500*time.Millisecond
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
	at := time.Now()
	evidence := runtime.ProbeEmergencyAvailability("direct-wan")
	if !evidence.OK || !evidence.QualityUnmeasured || evidence.DelayMS == nil ||
		evidence.Targets["cloudflare-trace"] == nil || len(evidence.TargetFailures) != 0 ||
		started.Load() != 3 || time.Since(at) >= availabilityProbeTimeout {
		t.Fatalf("emergency waited for primary or recorded canceled origins as failures: %+v", evidence)
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("emergency origin workers survived the successful probe")
	}
}

func TestEmergencyAvailabilityRetainsAllOriginDeadlinesAndFailureEvidence(t *testing.T) {
	original, primaryTimeout, fallbackTimeout := healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout
	t.Cleanup(func() {
		healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout = original, primaryTimeout, fallbackTimeout
	})
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout, availabilityFallbackTimeout = 30*time.Millisecond, 150*time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	at := time.Now()
	evidence := runtime.ProbeEmergencyAvailability("direct-wan")
	if evidence.OK || evidence.LocalFailure || evidence.Failure != probeFailureTimeout ||
		len(evidence.TargetFailures) != 3 || time.Since(at) < availabilityFallbackTimeout {
		t.Fatalf("emergency shortened fallback deadlines or used incomplete negative evidence: %+v", evidence)
	}
}

type emergencyModeFixture struct {
	*fakeSelectorRuntime
	emergencyCalls []string
}

func TestEmergencyAvailabilityRecoversOnNextProbeAfterLateRecovery(t *testing.T) {
	original, primaryTimeout, fallbackTimeout := healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout
	t.Cleanup(func() {
		healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout = original, primaryTimeout, fallbackTimeout
	})
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout, availabilityFallbackTimeout = 60*time.Millisecond, 150*time.Millisecond
	var recovered atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !recovered.Load() {
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/gstatic-204" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	if first := runtime.ProbeEmergencyAvailability("direct-wan"); first.OK || first.Failure != probeFailureTimeout {
		t.Fatalf("node recovered after the first batch's deadlines, not during it: %+v", first)
	}
	// Recovery happens only after the first batch has exhausted its deadlines.
	recovered.Store(true)
	if next := runtime.ProbeEmergencyAvailability("direct-wan"); !next.OK {
		t.Fatalf("late recovery did not pass the next independent probe: %+v", next)
	}
}

func (runtime *emergencyModeFixture) ProbeEmergencyAvailability(candidate string) probeEvidence {
	runtime.emergencyCalls = append(runtime.emergencyCalls, candidate)
	return runtime.probes[candidate]
}

func TestEmergencyOriginsAreNotUsedForOrdinaryAvailability(t *testing.T) {
	base := &emergencyModeFixture{fakeSelectorRuntime: &fakeSelectorRuntime{
		probes: map[string]probeEvidence{"a": successfulEvidence(100)},
	}}
	runtime := &responsiveSelectorRuntime{selectorRuntime: base, ctx: context.Background()}
	runtime.ProbeAvailabilityParallel([]string{"a"}, nil)
	if len(base.emergencyCalls) != 0 || len(base.availabilityCalls) != 1 {
		t.Fatal("routine availability expanded its origin fanout")
	}
	runtime.ProbeEmergencyAvailabilityParallel([]string{"a"}, nil)
	if len(base.emergencyCalls) != 1 || len(base.availabilityCalls) != 1 {
		t.Fatal("confirmed emergency did not use the urgent origin path")
	}
}
