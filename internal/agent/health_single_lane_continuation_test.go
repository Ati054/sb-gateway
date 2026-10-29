package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSingleQualityLaneContinuesPairDuringActiveCallback(t *testing.T) {
	oldTargets := healthTargets
	defer func() { healthTargets = oldTargets }()
	healthTargets = append(healthTargets[:0:0], oldTargets[0])
	healthTargets[0].url = "http://probe.invalid/generate_204"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, secondStarted := make(chan struct{}), make(chan struct{})
	var requests, active, peak atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for prior := peak.Load(); current > prior && !peak.CompareAndSwap(prior, current); prior = peak.Load() {
		}
		switch requests.Add(1) {
		case 1:
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		case 2:
			close(secondStarted)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	pool := healthFixture(false)
	pool.Version, pool.BaseOutboundTags = 4, []string{"a", "b"}
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	lane := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: server.URL})
	lane.probeSelector = "single-background"
	selected := ""
	lane.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "bo" {
			selected = args[len(args)-1]
			return nil, nil
		}
		return selectorInfo(selected), nil
	}
	runtime := &responsiveSelectorRuntime{background: lane, backgrounds: []*xraySelectorRuntime{lane}, ctx: ctx,
		enabled: true, parallelEnabled: true, generationPaths: []string{path}}
	runtime.generation = generationStamp(runtime.generationPaths)
	checks := 0
	runtime.check = func() error {
		checks++
		if checks != 1 {
			return fmt.Errorf("completed pair repeated an active callback")
		}
		close(release)
		// An already-running active check can take longer than a quality request.
		// Its callback must not own the worker's transition to the second target.
		select {
		case <-secondStarted:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("single-lane continuation waited behind the active callback: %w", ctx.Err())
		}
	}
	measured := runtime.ProbeQualityParallel([]string{"a", "b"})
	if checks != 1 || requests.Load() != 2 || peak.Load() != 1 || len(measured) != 2 {
		t.Fatalf("pair did not advance in one lane: checks=%d requests=%d peak=%d measured=%v", checks, requests.Load(), peak.Load(), measured)
	}
	for node, evidence := range measured {
		if !evidence.OK || evidence.ObservedAt.IsZero() {
			t.Fatalf("lost quality observation for %s: %+v", node, evidence)
		}
	}
	if err := takeProbeInterruption(runtime); err != nil {
		t.Fatalf("pair interrupted: %v", err)
	}
}
