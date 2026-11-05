package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"log"
	"os"
	"time"
)

const healthCheckpointInterval = 10 * time.Second

// Only routing, membership and failure changes bypass routine history batching.
// Timestamps, samples, display comparisons and success counters remain live in
// the controller; traffic readiness has its own immediate, small publication.
type healthCheckpointCritical struct {
	Selected, RuntimeSelected, RuntimeError, Mode string
	CandidateSignature, WarmMarker, Underlay      string
	Confirmed                                     bool
	Availability, Quality                         map[string]bool
	Failures                                      map[string]int
	FailureClass                                  map[string]string
	Nodes                                         map[string]healthNode
	Working                                       *workingSelection
}

func healthCheckpointFailures(values map[string]int) map[string]int {
	result := make(map[string]int)
	for node, count := range values {
		if count > 0 {
			result[node] = count
		}
	}
	// A missing count and an explicit zero both mean no failure. New successful
	// observations must not force a large checkpoint just by inserting zero.
	return result
}

func (controller *healthController) publishRoutineHealthState(path string, state healthState) error {
	critical := make(map[string]healthCheckpointCritical, len(state))
	for id, item := range state {
		if item == nil {
			continue
		}
		rememberDisplayComparisons(item)
		critical[id] = healthCheckpointCritical{
			Selected: item.Selected, RuntimeSelected: item.RuntimeSelected, RuntimeError: item.RuntimeError,
			Mode: item.Mode, CandidateSignature: item.CandidateSignature, WarmMarker: item.WarmPlanningMarker,
			Underlay: item.UnderlayFailure, Confirmed: item.RuntimeConfirmed,
			Availability: item.AvailabilityOK, Quality: item.QualityOK,
			Failures: healthCheckpointFailures(item.AvailabilityFailures), FailureClass: item.FailureClass,
			Nodes: item.CandidateNodes, Working: item.LastWorkingSelection,
		}
	}
	encoded, err := json.Marshal(critical)
	if err != nil {
		return err
	}
	now := time.Now()
	if controller.checkpointNow != nil {
		now = controller.checkpointNow()
	}
	fingerprint := sha256.Sum256(encoded)
	_, statErr := os.Stat(path)
	if controller.checkpointAt.IsZero() || now.Sub(controller.checkpointAt) >= healthCheckpointInterval ||
		fingerprint != controller.checkpointFingerprint || os.IsNotExist(statErr) {
		controller.checkpointPending = true
		if err := publishHealthState(path, state); err != nil {
			return err
		}
		controller.checkpointAt, controller.checkpointFingerprint = now, fingerprint
		controller.checkpointPending = false
		return nil
	}
	controller.checkpointPending = true
	return publishSelectorReadiness(path, state)
}

// Preserve callers' durable startup, Apply-reconciliation and selector-change
// snapshots. Use the same bookkeeping so the next routine tick cannot repeat
// that encoding merely because it did not observe the forced publication.
func (controller *healthController) publishImmediateHealthState(path string, state healthState) error {
	controller.checkpointAt = time.Time{}
	return controller.publishRoutineHealthState(path, state)
}

// A maintenance flush resumes the original health deadline. It must neither
// trigger an extra probe cycle nor postpone an already scheduled active check.
// All writes stay on the controller goroutine and use its latest state.
func (controller *healthController) waitWithHealthCheckpoint(ctx context.Context, delay time.Duration, paths []string, poll time.Duration, signals <-chan xrayFailureSignal, accept func(xrayFailureSignal) bool) bool {
	if !controller.checkpointPending {
		return waitForHealthWake(ctx, delay, paths, poll, signals, accept)
	}
	deadline, generation := time.Now().Add(delay), generationStamp(paths)
	for {
		flushAt := controller.checkpointAt.Add(healthCheckpointInterval)
		maintenance := controller.checkpointPending && flushAt.Before(deadline)
		remaining := max(time.Until(deadline), time.Duration(0))
		if maintenance {
			remaining = min(remaining, max(time.Until(flushAt), time.Duration(0)))
		}
		accepted := false
		if !waitForHealthWake(ctx, remaining, paths, poll, signals, func(signal xrayFailureSignal) bool {
			if accept != nil && accept(signal) {
				accepted = true
				return true
			}
			return false
		}) {
			return false
		}
		if accepted || generation != generationStamp(paths) || !maintenance || time.Now().Before(flushAt) {
			return true
		}
		if err := controller.publishRoutineHealthState(statePath(controller.opts.StateRoot, "selector-health"), controller.state); err != nil {
			log.Printf("agent: routine health checkpoint flush failed: %v", err)
			if generation != generationStamp(paths) {
				return true
			}
			// Retain the pending latest state, but do not turn an unwritable file
			// into an immediate retry loop. Signals and generation changes still wake.
			return waitForHealthWake(ctx, max(time.Until(deadline), time.Duration(0)), paths, poll, signals, accept)
		}
	}
}
