package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/sb-gateway/sb-gateway/internal/healthsnapshot"
)

// This optional projection omits retained samples and day reservoirs. It never
// supplies traffic readiness or changes the existing checkpoint cadence.
type compactHealthStatus struct {
	Selected    string                       `json:"runtime_selected"`
	Confirmed   bool                         `json:"runtime_confirmed"`
	Observed    string                       `json:"runtime_observed_at"`
	Error       string                       `json:"runtime_error,omitempty"`
	Labels      map[string]string            `json:"candidate_labels"`
	Nodes       map[string]healthNode        `json:"candidate_nodes"`
	Count       int                          `json:"candidate_count"`
	Available   map[string]bool              `json:"availability_ok"`
	Shortlist   []string                     `json:"shortlist"`
	Comparisons map[string]latencyComparison `json:"latency_comparisons,omitempty"`
	Last        map[string]latencyComparison `json:"last_latency_comparisons,omitempty"`
	WarmMarker  string                       `json:"warm_planning_marker,omitempty"`
	Warm        map[string]latencyComparison `json:"warm_latency_comparisons,omitempty"`
	WarmLast    map[string]latencyComparison `json:"warm_last_latency_comparisons,omitempty"`
}

func publishCompactHealthStatus(historyPath string, state healthState) error {
	info, err := os.Stat(historyPath)
	if err != nil {
		return err
	}
	stamp := healthsnapshot.Stamp(info)
	if stamp == "" {
		return nil
	}
	status := make(map[string]*compactHealthStatus, len(state))
	for id, item := range state {
		if item == nil {
			status[id] = nil
			continue
		}
		record := &compactHealthStatus{Selected: item.RuntimeSelected, Confirmed: item.RuntimeConfirmed, Observed: item.RuntimeObservedAt,
			Error: item.RuntimeError, Labels: item.CandidateLabels, Nodes: item.CandidateNodes, Count: item.CandidateCount,
			Available: item.AvailabilityOK, Shortlist: item.Shortlist}
		if item.WarmPlanningMarker != "" {
			record.WarmMarker, record.Warm, record.WarmLast = item.WarmPlanningMarker, item.LatencyComparisons, item.LastLatencyComparisons
		} else {
			record.Comparisons, record.Last = item.LatencyComparisons, item.LastLatencyComparisons
		}
		status[id] = record
	}
	body, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if len(body) > healthsnapshot.MaxBytes-512 {
		return nil
	}
	return writeCompactStatusCache(filepath.Join(filepath.Dir(historyPath), healthsnapshot.Filename), healthsnapshot.Envelope{Version: 1, HistoryStamp: stamp, Status: body})
}

// This cache can be rebuilt from the durable history. Atomic replacement is
// needed for concurrent polls, but another forced disk flush is unnecessary.
// Missing or torn cache data after a crash is rejected by the reader.
func writeCompactStatusCache(path string, envelope healthsnapshot.Envelope) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".selector-status.*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(envelope); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(file.Name(), path)
}
