package runtimeproof

const SelectorSnapshotName = "selector-runtime.json"
const SelectorSnapshotMaxBytes = 256 << 10

// SelectorObservation is live route evidence, independent of quality history.
type SelectorObservation struct {
	Selected  string `json:"runtime_selected"`
	Observed  string `json:"runtime_observed_at"`
	Confirmed bool   `json:"runtime_confirmed"`
}
