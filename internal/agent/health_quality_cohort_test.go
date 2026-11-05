package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type concurrentCohortRuntime struct{ *observedQualityRuntime }

func (*concurrentCohortRuntime) qualityLaneCount() int { return 2 }

func TestParallelComparisonDoesNotMixCachedAndNewWaves(t *testing.T) {
	for _, scenario := range []string{"missing-peer", "different-waves", "same-wave"} {
		t.Run(scenario, func(t *testing.T) {
			runtime := &concurrentCohortRuntime{&observedQualityRuntime{&fakeSelectorRuntime{probes: map[string]probeEvidence{
				"a": successfulEvidence(1200), "b": successfulEvidence(300),
				"c": successfulEvidence(300), "d": successfulEvidence(300),
			}}}}
			c := &healthController{runtime: runtime}
			c.beginProbeBudget(healthPool{ProbeBudget: 8}, nil)
			contract := budgetContract("a", "b", "c", "d")
			contract.Mode = "best"
			c.sharedQualityBatch("first", contract, []string{"a", "b"})
			pair := []string{"a", "c"}
			if scenario == "different-waves" {
				c.sharedQualityBatch("first", contract, []string{"c", "d"})
			} else if scenario == "same-wave" {
				pair = []string{"a", "b"}
			}
			before := len(runtime.probeCalls)
			result := c.sharedQualityBatch("second", contract, pair)
			if len(runtime.probeCalls) != before {
				t.Fatalf("mixed comparison launched an unrelated new request: %v", runtime.probeCalls[before:])
			}
			for _, node := range pair {
				if scenario == "same-wave" {
					if !result[node].OK || result[node].Deferred {
						t.Fatalf("coherent cached wave was not shared: %+v", result)
					}
				} else if !result[node].Deferred {
					t.Fatalf("%s was accepted as a concurrent comparison: %+v", scenario, result)
				}
			}
		})
	}
}

func TestQualityWaveDoesNotLetFastLaneStealPreparingPeer(t *testing.T) {
	oldTargets := healthTargets
	defer func() { healthTargets = oldTargets }()
	healthTargets = append(healthTargets[:0:0], oldTargets[0])
	healthTargets[0].url = "http://probe.invalid/generate_204"
	peerPreparing, releasePeer, firstPrepared, stolen := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce, peerOnce, preparedOnce, stolenOnce sync.Once
	var earlyRequests atomic.Int32
	unblock := func() { releaseOnce.Do(func() { close(releasePeer) }) }
	defer unblock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-peerPreparing:
			select {
			case <-releasePeer:
			default:
				earlyRequests.Add(1)
			}
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	pool := healthFixture(false)
	pool.Version, pool.BaseOutboundTags = 4, []string{"a", "b"}
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lanes := make([]*xraySelectorRuntime, 2)
	for i := range lanes {
		index, selector, selected := i, fmt.Sprintf("cohort-%d", i), ""
		lane := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: server.URL})
		lane.probeSelector = selector
		lane.command = func(ctx context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
			if index == 1 {
				peerOnce.Do(func() { close(peerPreparing) })
				select {
				case <-releasePeer:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			if len(args) > 1 && args[1] == "bo" {
				selected = args[len(args)-1]
				if index == 0 && selected == "a" {
					preparedOnce.Do(func() { close(firstPrepared) })
				}
				if index == 0 && selected == "b" {
					stolenOnce.Do(func() { close(stolen) })
				}
				return nil, nil
			}
			return selectorInfo(selected), nil
		}
		lanes[i] = lane
	}
	runtime := &responsiveSelectorRuntime{selectorRuntime: &fakeSelectorRuntime{}, backgrounds: lanes,
		ctx: ctx, enabled: true, parallelEnabled: true, generationPaths: []string{path}}
	runtime.generation = generationStamp(runtime.generationPaths)
	done := make(chan map[string]probeEvidence, 1)
	go func() { done <- runtime.ProbeQualityParallel([]string{"a", "b"}) }()
	select {
	case <-firstPrepared:
	case <-ctx.Done():
		t.Fatal("first lane did not complete while its peer prepared")
	}
	wasStolen := false
	select {
	case <-stolen:
		wasStolen = true
	case <-time.After(200 * time.Millisecond):
	}
	unblock()
	select {
	case result := <-done:
		if wasStolen || earlyRequests.Load() != 0 || !result["a"].OK || !result["b"].OK ||
			result["a"].QualityWave == 0 || result["a"].QualityWave != result["b"].QualityWave ||
			result["a"].QualityStartedAt.IsZero() || result["b"].QualityStartedAt.IsZero() {
			t.Fatalf("quality batch did not start independent prepared lanes together: stolen=%v early=%d results=%+v", wasStolen, earlyRequests.Load(), result)
		}
	case <-ctx.Done():
		t.Fatal("quality workers were not joined")
	}
}

func TestDifferentQualityWavesCannotWinOptimization(t *testing.T) {
	for _, wave := range []uint64{0, 2} {
		active, candidate := successfulEvidence(1300), successfulEvidence(300)
		active.QualityWave, candidate.QualityWave = 1, wave
		comparison := regularOptimizationComparison(time.Now(), "a", "b", map[string]probeEvidence{"a": active, "b": candidate},
			&policyHealthState{}, true, true, effectivePolicySettings{mode: "best", active: 60, improvement: 200})
		if comparison != nil {
			t.Fatalf("different physical waves were treated as comparative evidence: %+v", comparison)
		}
	}
}

func TestQualityPreparationWaitYieldsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queues := probeLaneJobs([]string{"a", "b"}, 2, true, cancel)
	first, second := <-queues[0], <-queues[1]
	done := make(chan error, 1)
	go func() { done <- first.start.wait(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("preparation ignored cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("preparation retained a cancelled worker")
	}
	second.start.arrive()
}

func TestInterleavedQualityWavePreservesIndependentConfirmation(t *testing.T) {
	now := time.Now()
	p := effectivePolicySettings{mode: "best", active: 60, improvement: 200}
	item := newPolicyHealthState()
	for node, ms := range map[string]int{"a": 700, "b": 300} {
		value := ms
		item.Samples[node] = []healthSample{{At: float64(now.Add(-time.Second).UnixNano()) / 1e9, OK: true, DelayMS: &value}}
	}
	pair := func(at time.Time, wave uint64) map[string]probeEvidence {
		a, b := successfulEvidence(700), successfulEvidence(300)
		a.ObservedAt, b.ObservedAt = at, at
		a.QualityWave, b.QualityWave = wave, wave
		a.QualityStartedAt, b.QualityStartedAt = at.Add(-700*time.Millisecond), at.Add(-300*time.Millisecond)
		return map[string]probeEvidence{"a": a, "b": b}
	}
	firstAt := now.Add(-time.Second)
	first := regularOptimizationComparison(firstAt, "a", "b", pair(firstAt, 1), item, true, true, p)
	selected, _ := gatePlannedOptimization(firstAt, "a", "b", "meaningfully-faster", first, item, p)
	if selected != "a" || item.OptimizationChecks != 1 {
		t.Fatal("first independent confirmation was not retained")
	}
	for _, activeMS := range []int{700, 250} {
		other := pair(now, 2)
		delete(other, "b")
		active := other["a"]
		active.DelayMS = &activeMS
		other["a"] = active
		middle := regularOptimizationComparison(now, "a", "b", other, item, true, true, p)
		selected, _ = gatePlannedOptimization(now, "a", "b", "meaningfully-faster", middle, item, p)
		if selected != "a" || item.OptimizationChecks != 1 || item.OptimizationCandidate != "b" {
			t.Fatalf("checking another reserve erased a valid independent confirmation: %+v", middle)
		}
		expired := *item
		expiry := now.Add(3 * time.Minute)
		gatePlannedOptimization(expiry, "a", "b", "meaningfully-faster", nil, &expired, p)
		if expired.OptimizationChecks != 0 || expired.OptimizationCandidate != "" {
			t.Fatal("unpaired waves prevented pending proof expiry")
		}
	}
	earlyAt := now.Add(time.Second)
	early := regularOptimizationComparison(earlyAt, "a", "b", pair(earlyAt, 3), item, true, true, p)
	selected, _ = gatePlannedOptimization(earlyAt, "a", "b", "meaningfully-faster", early, item, p)
	if selected != "a" || item.OptimizationChecks != 1 {
		t.Fatal("a complete pair inside the quality interval earned another confirmation")
	}
	nextAt := firstAt.Add(time.Duration(p.active) * time.Second)
	next := regularOptimizationComparison(nextAt, "a", "b", pair(nextAt, 4), item, true, true, p)
	selected, reason := gatePlannedOptimization(nextAt, "a", "b", "meaningfully-faster", next, item, p)
	if selected != "b" || reason != "meaningfully-faster" {
		t.Fatal("second independent coherent pair did not complete the switch")
	}
}
