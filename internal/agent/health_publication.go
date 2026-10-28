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
	return writeJSONAtomic(path, state)
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
