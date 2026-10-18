package agent

import (
	"path/filepath"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

func publishHealthState(path string, state healthState) error {
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
	if err := writeJSONAtomic(filepath.Join(filepath.Dir(path), runtimeproof.SelectorSnapshotName), proof); err != nil {
		return err
	}
	return writeJSONAtomic(path, state)
}
