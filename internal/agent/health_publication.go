package agent

import (
	"path/filepath"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

func publishHealthState(path string, state healthState) error {
	for _, item := range state {
		if item != nil {
			rememberDisplayComparisons(item)
		}
	}
	if err := publishSelectorReadiness(path, state); err != nil {
		return err
	}
	if err := writeJSONAtomic(path, healthCheckpointProjection(state)); err != nil {
		return err
	}
	// Optional UI-cache failure must not become a readiness/routing failure.
	// Readers verify the history generation and fall back to the full file.
	_ = publishCompactHealthStatus(path, state)
	return nil
}

type warmPolicyCheckpoint struct {
	*policyHealthState
	WarmLatencyComparisons     map[string]latencyComparison `json:"warm_latency_comparisons,omitempty"`
	WarmLastLatencyComparisons map[string]latencyComparison `json:"warm_last_latency_comparisons,omitempty"`
	WarmOptimizationLastResult *optimizationComparison      `json:"warm_optimization_last_result,omitempty"`
}

// Cold-only publication returns the original graph without allocating or
// serializing individual policies. Experimental wire views copy only a policy
// header; cold history is encoded once by the ordinary outer JSON encoder.
func healthCheckpointProjection(state healthState) any {
	var projected map[string]any
	for id, item := range state {
		if item == nil || item.WarmPlanningMarker == "" {
			continue
		}
		if projected == nil {
			projected = make(map[string]any, len(state))
			for key, original := range state {
				projected[key] = original
			}
		}
		legacy := *item
		legacy.OptimizationBaseline, legacy.OptimizationCandidate, legacy.OptimizationChecks = "", "", 0
		legacy.OptimizationLastResult = nil
		legacy.LatencyComparisons, legacy.LastLatencyComparisons = nil, nil
		projected[id] = warmPolicyCheckpoint{&legacy, item.LatencyComparisons, item.LastLatencyComparisons, item.OptimizationLastResult}
	}
	if projected == nil {
		return state
	}
	return projected
}

// The panel retains the last qualified pair while the same route is active.
// Selection uses fresh probe evidence and never reads this display history.
func rememberDisplayComparisons(item *policyHealthState) {
	if !item.RuntimeConfirmed || item.RuntimeSelected == "" {
		return
	}
	for candidate, pair := range item.LastLatencyComparisons {
		if pair.Active != item.RuntimeSelected || candidate == item.RuntimeSelected || item.RuntimeSelected == "block" {
			delete(item.LastLatencyComparisons, candidate)
		}
	}
	for candidate, pair := range item.LatencyComparisons {
		if pair.Active != item.RuntimeSelected || candidate == item.RuntimeSelected || item.RuntimeSelected == "block" {
			continue
		}
		if item.LastLatencyComparisons == nil {
			item.LastLatencyComparisons = make(map[string]latencyComparison)
		}
		item.LastLatencyComparisons[candidate] = pair
	}
}

func publishSelectorReadiness(path string, state healthState) error {
	proof := make(map[string]runtimeproof.SelectorObservation, len(state))
	for id, item := range state {
		if item != nil {
			proof[id] = runtimeproof.SelectorObservation{
				Selected: item.RuntimeSelected, Observed: item.RuntimeObservedAt, Confirmed: item.RuntimeConfirmed,
			}
		}
	}
	// Withdrawals and confirmations must reach readiness before serializing the
	// much larger history. The history is not the source of live traffic proof.
	return writeJSONAtomic(filepath.Join(filepath.Dir(path), runtimeproof.SelectorSnapshotName), proof)
}
