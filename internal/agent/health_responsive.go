package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

var errHealthYield = errors.New("background probe yielded to active path or runtime change")

// The controller remains the sole owner of health state and routing choices.
// Slow quality and speed requests use one separate loopback selector. Emergency
// availability checks may use several isolated selectors concurrently; workers
// publish evidence through the controller callback and never own controller state.
type responsiveSelectorRuntime struct {
	selectorRuntime
	background      *xraySelectorRuntime
	backgrounds     []*xraySelectorRuntime
	ctx             context.Context
	check           func() error
	generationPaths []string
	enabled         bool
	parallelEnabled bool
	interrupted     error
	generation      string
	currentPool     healthPool
	signals         <-chan xrayFailureSignal
	acceptSignal    func(xrayFailureSignal) bool
}

func (runtime *responsiveSelectorRuntime) Reload() (healthPool, bool, error) {
	stamp := generationStamp(runtime.generationPaths)
	pool, reset, err := runtime.selectorRuntime.Reload()
	if err == nil && pool.Version < 3 {
		return pool, reset, errors.New("health pool contract predates the 1.6.15 release baseline")
	}
	runtime.enabled = pool.Version >= 3
	runtime.parallelEnabled = pool.Version >= 4
	if err == nil && generationStamp(runtime.generationPaths) != stamp {
		return pool, reset, errHealthYield
	}
	runtime.generation = stamp
	runtime.currentPool = pool
	return pool, reset, err
}

func (runtime *responsiveSelectorRuntime) takeProbeInterruption() error {
	err := runtime.interrupted
	runtime.interrupted = nil
	return err
}

func takeProbeInterruption(runtime selectorRuntime) error {
	if value, ok := runtime.(interface{ takeProbeInterruption() error }); ok {
		return value.takeProbeInterruption()
	}
	return nil
}

type probeJobResult struct {
	evidence probeEvidence
	speed    int64
	err      error
	abort    bool
}

func generationStamp(paths []string) string {
	parts := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			parts = append(parts, path+":missing")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", path, info.ModTime().UnixNano(), info.Size()))
	}
	return strings.Join(parts, "|")
}

// Wait for either the normal health cadence or an atomically published runtime
// contract. Route-list eligibility edits only replace the health pool; waking
// the existing agent avoids restarting Xray, the watchdog, or ruleset workers.
func waitForGenerationChange(ctx context.Context, timeout time.Duration, paths []string, pollInterval time.Duration) bool {
	return waitForHealthWake(ctx, timeout, paths, pollInterval, nil, nil)
}

func waitForHealthWake(ctx context.Context, timeout time.Duration, paths []string, pollInterval time.Duration, signals <-chan xrayFailureSignal, accept func(xrayFailureSignal) bool) bool {
	if timeout <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	stamp := generationStamp(paths)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-ticker.C:
			if generationStamp(paths) != stamp {
				return true
			}
		case signal, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			if accept != nil && accept(signal) {
				return true
			}
		}
	}
}

// Waiting is cancellable and services the active path instead of sleeping behind
// a 15-second download or a whole multi-node batch. Always join the worker before
// starting another job, including on Apply, shutdown and confirmed outage.
func awaitProbeJob(ctx context.Context, cadence time.Duration, check func() error, operation func(context.Context) probeJobResult) probeJobResult {
	return awaitProbeJobWithSignals(ctx, cadence, check, operation, nil, nil)
}

func awaitProbeJobWithSignals(ctx context.Context, cadence time.Duration, check func() error, operation func(context.Context) probeJobResult, signals <-chan xrayFailureSignal, accept func(xrayFailureSignal) bool) probeJobResult {
	jobContext, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan probeJobResult, 1)
	go func() { done <- operation(jobContext) }()
	timer := time.NewTicker(cadence)
	defer timer.Stop()
	for {
		select {
		case result := <-done:
			return result
		case <-ctx.Done():
			cancel()
			<-done
			return probeJobResult{err: ctx.Err()}
		case <-timer.C:
			if err := check(); err != nil {
				cancel()
				<-done
				return probeJobResult{err: err}
			}
		case signal, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			if accept != nil && accept(signal) {
				if err := check(); err != nil {
					cancel()
					<-done
					return probeJobResult{err: err}
				}
			}
		}
	}
}

func (runtime *responsiveSelectorRuntime) run(operation func() probeJobResult) probeJobResult {
	stamp := generationStamp(runtime.generationPaths)
	if stamp != runtime.generation {
		runtime.interrupted = errHealthYield
		return probeJobResult{err: errHealthYield}
	}
	check := func() error {
		if generationStamp(runtime.generationPaths) != stamp {
			return errHealthYield
		}
		return runtime.check()
	}
	result := awaitProbeJobWithSignals(runtime.ctx, time.Second, check, func(ctx context.Context) probeJobResult {
		runtime.background.probeContext = ctx
		if _, _, err := runtime.background.Reload(); err != nil {
			return probeJobResult{err: err, abort: true}
		}
		return operation()
	}, runtime.signals, runtime.acceptSignal)
	if generationStamp(runtime.generationPaths) != stamp || runtime.ctx.Err() != nil {
		result.err = errHealthYield
	}
	if errors.Is(result.err, errHealthYield) || errors.Is(result.err, context.Canceled) {
		runtime.interrupted = errHealthYield
	} else if result.abort {
		runtime.interrupted = result.err
	}
	return result
}

func (runtime *responsiveSelectorRuntime) Probe(candidate string) probeEvidence {
	if !runtime.enabled {
		return runtime.selectorRuntime.Probe(candidate)
	}
	result := runtime.run(func() probeJobResult { return probeJobResult{evidence: runtime.background.Probe(candidate)} })
	return result.evidence
}

func (runtime *responsiveSelectorRuntime) UnderlayStatus() underlayEvidence {
	if probe, ok := runtime.selectorRuntime.(underlayRuntime); ok {
		return probe.UnderlayStatus()
	}
	return underlayEvidence{}
}

func (runtime *responsiveSelectorRuntime) ProbeAvailabilityParallel(candidates []string, onResult func(string, probeEvidence) bool) map[string]probeEvidence {
	measured := make(map[string]probeEvidence, len(candidates))
	lanes := runtime.backgrounds
	if len(lanes) == 0 && runtime.background != nil {
		lanes = []*xraySelectorRuntime{runtime.background}
	}
	if !runtime.parallelEnabled || len(lanes) < 2 || len(candidates) < 2 {
		for _, candidate := range candidates {
			evidence := runtime.selectorRuntime.ProbeAvailability(candidate)
			measured[candidate] = evidence
			if onResult != nil && onResult(candidate, evidence) {
				break
			}
		}
		return measured
	}
	stamp := generationStamp(runtime.generationPaths)
	if stamp != runtime.generation {
		runtime.interrupted = errHealthYield
		return measured
	}
	type result struct {
		candidate string
		evidence  probeEvidence
	}
	ctx, cancel := context.WithCancel(runtime.ctx)
	defer cancel()
	jobs := make(chan string, len(candidates))
	results := make(chan result, len(candidates))
	for _, candidate := range candidates {
		jobs <- candidate
	}
	close(jobs)
	workerCount := minInt(len(lanes), len(candidates))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for _, lane := range lanes[:workerCount] {
		lane := lane
		go func() {
			defer workers.Done()
			lane.probeContext = ctx
			if _, _, err := lane.Reload(); err != nil {
				for candidate := range jobs {
					results <- result{candidate: candidate, evidence: probeEvidence{Failure: probeFailureTransient}}
				}
				return
			}
			for candidate := range jobs {
				if ctx.Err() != nil {
					return
				}
				evidence := lane.ProbeAvailability(candidate)
				select {
				case results <- result{candidate: candidate, evidence: evidence}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		workers.Wait()
		close(done)
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	remaining := len(candidates)
	for remaining > 0 {
		select {
		case value := <-results:
			remaining--
			measured[value.candidate] = value.evidence
			if onResult != nil && onResult(value.candidate, value.evidence) {
				cancel()
				<-done
				return measured
			}
		case <-ticker.C:
			if generationStamp(runtime.generationPaths) != stamp {
				cancel()
				<-done
				runtime.interrupted = errHealthYield
				return measured
			}
			if runtime.check != nil {
				if err := runtime.check(); err != nil {
					cancel()
					<-done
					runtime.interrupted = err
					return measured
				}
			}
		case <-ctx.Done():
			cancel()
			<-done
			runtime.interrupted = errHealthYield
			return measured
		}
	}
	<-done
	return measured
}

func (runtime *responsiveSelectorRuntime) Throughput(candidate string, size int) (int64, error) {
	if !runtime.enabled {
		return runtime.selectorRuntime.Throughput(candidate, size)
	}
	result := runtime.run(func() probeJobResult {
		speed, err := runtime.background.Throughput(candidate, size)
		return probeJobResult{speed: speed, err: err}
	})
	return result.speed, result.err
}

func (controller *healthController) checkDuringProbe(now time.Time, pool healthPool) error {
	ids := make([]string, 0, len(pool.HealthPolicies))
	for id := range pool.HealthPolicies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	dirty := false
	var result error
	for _, id := range ids {
		item := controller.state[id]
		if item == nil || item.Selected == "" || item.Selected == "block" {
			continue
		}
		contract := pool.HealthPolicies[id]
		if item.AvailabilityFailures[item.Selected] >= policySettings(contract.Policy, contract.Mode).failureThreshold {
			continue
		}
		changed, err := controller.checkActiveAvailability(now, id, contract, item, false)
		dirty = dirty || changed
		if err != nil || (changed && item.AvailabilityFailures[item.Selected] > 0) {
			controller.regularNext[id] = time.Time{}
			// Resume the sheet which interrupted the worker first. Otherwise an
			// earlier sheet can restart its job and be cancelled by this same
			// unresolved selector mismatch forever, especially after a restart.
			controller.priorityPolicy = id
			result = errHealthYield
			break
		}
	}
	if dirty {
		if err := writeJSONAtomic(statePath(controller.opts.StateRoot, "selector-health"), controller.state); err != nil {
			return errHealthYield
		}
	}
	return result
}
