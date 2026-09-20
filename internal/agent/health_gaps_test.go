package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBestModeFiltersAllThresholdsBeforeRanking(t *testing.T) {
	current, tooClose, good := 500, 480, 400
	currentSpeed, topSpeed, goodSpeed := int64(100), int64(200), int64(150)
	got := meaningfullyBetter("active", []string{"fast-but-close", "eligible"},
		map[string]*int{"active": &current, "fast-but-close": &tooClose, "eligible": &good},
		map[string]*int64{"active": &currentSpeed, "fast-but-close": &topSpeed, "eligible": &goodSpeed},
		effectivePolicySettings{speedEnabled: true, speedImprovement: 25, improvement: 50})
	if got != "eligible" {
		t.Fatalf("valid second choice was ignored: %q", got)
	}
}

func TestFailedPrimaryRecoversWithoutWaitingForFullScan(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		for _, batch := range []int{1, 2} {
			stateRoot := t.TempDir()
			t.Cleanup(func() {
				for attempt := 0; attempt < 10; attempt++ {
					if err := os.RemoveAll(stateRoot); err == nil {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			})
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			contract.Policy.MaxActiveCandidates, contract.Policy.ProbeBatchSize = 1, batch
			contract.Policy.ActiveCheckSeconds, contract.Policy.BackupCheckSeconds, contract.Policy.FullScanSeconds = 60, 300, 1800
			pool.HealthPolicies["europe"] = contract
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "nl", "nl", true
			item.CandidateSignature, item.NextFullScanAt = "de\nnl", 2800
			item.Samples["de"] = []healthSample{{OK: false}, {OK: false}, {OK: false}}
			item.AvailabilityFailures["de"] = 3
			item.LastProbeAt["de"] = 1000
			runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "nl"}, probes: map[string]probeEvidence{"de": successfulEvidence(50), "nl": successfulEvidence(500)}}
			controller := &healthController{opts: Options{StateRoot: stateRoot, HealthInterval: time.Minute}, runtime: runtime, warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item}}
			for second := int64(1060); second <= 1600; second += 60 {
				runtime.probeCalls = nil
				if err := controller.Tick(time.Unix(second, 0)); err != nil {
					t.Fatal(err)
				}
				if len(runtime.probeCalls) > batch {
					t.Fatal("recovery exceeded batch budget")
				}
			}
			if item.Selected != "de" || item.NextFullScanAt != 2800 {
				t.Fatalf("%s recovery waited for full scan: selected=%s queue=%v", mode, item.Selected, item.ScanQueue)
			}
		}
	}
}

func TestProbeHTTPRejectsErrorsRedirectsAndWrongExpectedStatus(t *testing.T) {
	for _, status := range []int{200, 204, 302, 403, 429, 500, 503} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Header().Set("Location", "http://other.invalid/")
			w.WriteHeader(status)
		}))
		_, err := downloadThroughProxyContext(context.Background(), server.URL, "http://target.invalid/", time.Second, 1024, 204)
		server.Close()
		if (err == nil) != (status == 204) || calls != 1 {
			t.Fatalf("status=%d calls=%d err=%v", status, calls, err)
		}
	}
}

func TestHealthWaitServicesActiveChecksAndCancelsThenJoinsWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	checks := 0
	joined := make(chan struct{})
	result := awaitProbeJob(ctx, time.Millisecond, func() error {
		checks++
		if checks == 3 {
			return errHealthYield
		}
		return nil
	}, func(ctx context.Context) probeJobResult {
		defer close(joined)
		<-ctx.Done()
		return probeJobResult{err: ctx.Err()}
	})
	if !errors.Is(result.err, errHealthYield) || checks != 3 {
		t.Fatalf("slow worker blocked active checks: %+v / %d", result, checks)
	}
	select {
	case <-joined:
	default:
		t.Fatal("worker leaked after cancellation")
	}
}

func TestGenerationChangeDiscardsDelayedProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	stamp := generationStamp([]string{path})
	result := awaitProbeJob(context.Background(), time.Millisecond, func() error {
		if generationStamp([]string{path}) != stamp {
			return errHealthYield
		}
		return nil
	}, func(ctx context.Context) probeJobResult {
		if err := os.WriteFile(path, []byte("new-generation"), 0600); err != nil {
			return probeJobResult{err: err}
		}
		<-ctx.Done()
		return probeJobResult{evidence: successfulEvidence(1)}
	})
	if !errors.Is(result.err, errHealthYield) || result.evidence.OK {
		t.Fatal("stale generation result survived")
	}
}

func TestActiveFailureDuringBackgroundWorkYieldsWithoutRescoring(t *testing.T) {
	c, runtime, item := livenessFixture(t, "priority")
	runtime.probes["de"] = failedEvidence()
	err := c.checkDuringProbe(time.Unix(1010, 0), runtime.pool)
	if !errors.Is(err, errHealthYield) || item.AvailabilityFailures["de"] != 1 || !c.regularNext["europe"].IsZero() {
		t.Fatalf("active failure not prioritized: %v", err)
	}
	if strings.Join(runtime.probeCalls, ",") != "de" {
		t.Fatal("background callback recursively started a quality scan")
	}
}

func TestResponsiveRuntimeUsesIsolatedLaneAndDiscardsCancelledResult(t *testing.T) {
	oldTargets := healthTargets
	defer func() { healthTargets = oldTargets }()
	healthTargets = append(healthTargets[:0:0], oldTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-r.Context().Done()
		select {
		case <-stopped:
		default:
			close(stopped)
		}
	}))
	defer server.Close()
	pool := healthFixture(false)
	pool.Version = 3
	pool.BaseOutboundTags = []string{"de", "nl"}
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	background := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: server.URL})
	background.probeSelector = "outbound-health-background"
	selected := ""
	background.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if args[1] == "bo" {
			if args[len(args)-2] != "outbound-health-background" {
				return nil, errors.New("wrong lane")
			}
			selected = args[len(args)-1]
		}
		return selectorInfo(selected), nil
	}
	c, primary, item := livenessFixture(t, "priority")
	primary.probes["de"] = failedEvidence()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime := &responsiveSelectorRuntime{selectorRuntime: primary, background: background, ctx: ctx, enabled: true, generationPaths: []string{path}, check: func() error { return c.checkDuringProbe(time.Unix(1010, 0), primary.pool) }}
	runtime.generation = generationStamp(runtime.generationPaths)
	result := runtime.Probe("nl")
	if result.OK || !errors.Is(runtime.takeProbeInterruption(), errHealthYield) || item.AvailabilityFailures["de"] != 1 {
		t.Fatal("background failure was not cancelled by active-path check")
	}
	if len(primary.availabilityCalls) != 1 || selected != "nl" {
		t.Fatal("probe lanes were mixed")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("cancelled HTTP worker did not stop")
	}
}

func TestResponsiveRuntimeRejectsGenerationChangedBeforeJob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool")
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	runtime := &responsiveSelectorRuntime{ctx: context.Background(), generationPaths: []string{path}}
	runtime.generation = generationStamp(runtime.generationPaths)
	if err := os.WriteFile(path, []byte("after-apply"), 0600); err != nil {
		t.Fatal(err)
	}
	result := runtime.run(func() probeJobResult {
		t.Fatal("stale contract started a new worker")
		return probeJobResult{}
	})
	if !errors.Is(result.err, errHealthYield) || !errors.Is(runtime.takeProbeInterruption(), errHealthYield) {
		t.Fatal("generation change before dispatch not rejected")
	}
}

func TestResponsiveRuntimeRejectsPreReleaseV2Contract(t *testing.T) {
	pool := healthFixture(false)
	pool.Version = 2
	primary := &fakeSelectorRuntime{pool: pool, probes: map[string]probeEvidence{"de": successfulEvidence(20)}}
	runtime := &responsiveSelectorRuntime{selectorRuntime: primary}
	if _, _, err := runtime.Reload(); err == nil {
		t.Fatal("pre-release v2 health contract was accepted")
	}
}

func TestResponsiveRuntimeKeepsV3SingleBackgroundLane(t *testing.T) {
	pool := healthFixture(false)
	pool.Version = 3
	primary := &fakeSelectorRuntime{pool: pool}
	runtime := &responsiveSelectorRuntime{selectorRuntime: primary}
	if _, _, err := runtime.Reload(); err != nil {
		t.Fatal(err)
	}
	if !runtime.enabled || runtime.parallelEnabled {
		t.Fatalf("v3 compatibility flags: enabled=%t parallel=%t", runtime.enabled, runtime.parallelEnabled)
	}
}

func TestEmergencyAvailabilityUsesParallelLanesAndKeepsAllResults(t *testing.T) {
	oldTargets := healthTargets
	defer func() { healthTargets = oldTargets }()
	healthTargets = append(healthTargets[:0:0], oldTargets[0])
	healthTargets[0].url = "http://probe.invalid/generate_204"

	proxy := func(delay time.Duration) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(delay)
			w.WriteHeader(http.StatusNoContent)
		}))
	}
	fast := proxy(40 * time.Millisecond)
	slowA := proxy(300 * time.Millisecond)
	slowB := proxy(300 * time.Millisecond)
	defer fast.Close()
	defer slowA.Close()
	defer slowB.Close()

	pool := healthFixture(false)
	pool.Version = 4
	pool.BaseOutboundTags = []string{"a", "b", "c"}
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	selectors := []string{"outbound-health-background", "outbound-health-background-2", "outbound-health-background-3"}
	servers := []string{fast.URL, slowA.URL, slowB.URL}
	lanes := make([]*xraySelectorRuntime, 0, len(selectors))
	for index, selector := range selectors {
		lane := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: servers[index]})
		lane.probeSelector = selector
		selected := ""
		lane.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[1] == "bo" {
				selected = args[len(args)-1]
				return nil, nil
			}
			return selectorInfo(selected), nil
		}
		lanes = append(lanes, lane)
	}
	runtime := &responsiveSelectorRuntime{
		selectorRuntime: &fakeSelectorRuntime{}, backgrounds: lanes, ctx: context.Background(), enabled: true,
		parallelEnabled: true, generationPaths: []string{path}, check: func() error { return nil },
	}
	runtime.generation = generationStamp(runtime.generationPaths)
	started := time.Now()
	firstResult := time.Duration(0)
	measured := runtime.ProbeAvailabilityParallel([]string{"a", "b", "c"}, func(_ string, evidence probeEvidence) bool {
		if evidence.OK && firstResult == 0 {
			firstResult = time.Since(started)
		}
		return evidence.OK
	})
	elapsed := time.Since(started)
	if len(measured) != 3 || !measured["a"].OK || !measured["b"].OK || !measured["c"].OK {
		t.Fatalf("parallel map incomplete: %#v", measured)
	}
	if firstResult <= 0 || firstResult >= 180*time.Millisecond {
		t.Fatalf("first usable result was delayed: %v", firstResult)
	}
	if elapsed < 250*time.Millisecond || elapsed >= 550*time.Millisecond {
		t.Fatalf("parallel probes took %v; expected one slow-lane duration", elapsed)
	}
}

type interruptedTestRuntime struct {
	*fakeSelectorRuntime
	duringSpeed bool
	interrupted bool
}

func (runtime *interruptedTestRuntime) Probe(candidate string) probeEvidence {
	if !runtime.duringSpeed {
		runtime.interrupted = true
		return failedEvidence()
	}
	return runtime.fakeSelectorRuntime.Probe(candidate)
}

func (runtime *interruptedTestRuntime) Throughput(string, int) (int64, error) {
	runtime.interrupted = true
	return 0, context.Canceled
}

func (runtime *interruptedTestRuntime) takeProbeInterruption() error {
	if runtime.interrupted {
		runtime.interrupted = false
		return errHealthYield
	}
	return nil
}

func TestInterruptedBatchDoesNotCommitFailuresOrProbeTimestamps(t *testing.T) {
	for _, speed := range []bool{false, true} {
		pool := healthFixture(true)
		contract := pool.HealthPolicies["europe"]
		contract.Mode = "best"
		pool.HealthPolicies["europe"] = contract
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
		primary := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "de"}, probes: map[string]probeEvidence{"de": successfulEvidence(100), "nl": successfulEvidence(90)}}
		runtime := &interruptedTestRuntime{fakeSelectorRuntime: primary, duringSpeed: speed}
		controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime, warmStarted: map[string]bool{}, stateLoaded: true, state: healthState{"europe": item}}
		if err := controller.Tick(time.Unix(1000, 0)); err != nil {
			t.Fatal(err)
		}
		if !controller.yielded || controller.nextInterval() != 0 || item.Selected != "de" || !item.RuntimeConfirmed {
			t.Fatalf("interrupted batch did not yield cleanly (speed=%v)", speed)
		}
		if len(item.Samples["de"]) != 0 || item.AvailabilityFailures["de"] != 0 || item.LastProbeAt["de"] != 0 || item.LastSpeedProbeAt["de"] != 0 || !contains(item.ScanQueue, "de") {
			t.Fatalf("cancelled batch changed evidence or lost queue (speed=%v)", speed)
		}
	}
}

func TestCancelledProbeCleanupRetainsOwnershipForRetry(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{})
	runtime.probeRuntimeTag = "old-probe"
	runtime.loadedDynamic["old-probe"] = true
	runtime.command = func(context.Context, time.Duration, string, ...string) ([]byte, error) { return nil, context.Canceled }
	if runtime.removeOutbound("old-probe") == nil || runtime.probeRuntimeTag != "old-probe" || !runtime.loadedDynamic["old-probe"] {
		t.Fatal("cancelled cleanup forgot the dynamic outbound")
	}
	runtime.command = func(context.Context, time.Duration, string, ...string) ([]byte, error) { return nil, nil }
	if err := runtime.removeOutbound("old-probe"); err != nil || runtime.probeRuntimeTag != "" || runtime.loadedDynamic["old-probe"] {
		t.Fatal("cleanup retry failed")
	}
}
