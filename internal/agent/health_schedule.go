package agent

import "time"

// Continue a bounded sweep without waiting another full quality interval.
func (controller *healthController) remainingProbeInterval(now time.Time, contract healthPolicyContract, item *policyHealthState) time.Duration {
	p := policySettings(contract.Policy, contract.Mode)
	interval := controller.regularInterval(contract)
	for _, candidate := range contract.Candidates {
		remaining := time.Duration(p.active)*time.Second - now.Sub(time.Unix(int64(item.LastProbeAt[candidate]), 0))
		if item.LastProbeAt[candidate] == 0 || remaining <= 0 {
			return time.Duration(p.liveness) * time.Second
		}
		if remaining < interval {
			interval = remaining
		}
	}
	return interval
}

// An oldest-first rotation checks the entire selected inventory. The active
// node shares a batch whenever due, but a one-slot budget cannot starve others.
func regularProbeTargets(now time.Time, selected string, candidates, shortlist []string, item *policyHealthState, p effectivePolicySettings) []string {
	result := make([]string, 0, p.batch)
	due := func(candidate string) bool {
		last := item.LastProbeAt[candidate]
		return last == 0 || float64(now.Unix())-last >= float64(p.active)
	}
	activeTurn := p.batch > 1 || item.LastProbeAt[selected] == 0
	for _, candidate := range candidates {
		if candidate != selected && item.LastProbeAt[candidate] > item.LastProbeAt[selected] {
			activeTurn = true
		}
	}
	if activeTurn && contains(candidates, selected) && due(selected) {
		result = append(result, selected)
	}
	if candidate := item.OptimizationCandidate; item.OptimizationChecks > 0 &&
		len(result) < p.batch && candidate != selected && contains(candidates, candidate) && due(candidate) {
		result = append(result, candidate)
	}
	for len(result) < p.batch {
		oldest := ""
		for _, candidate := range candidates {
			if contains(result, candidate) || !due(candidate) {
				continue
			}
			if oldest == "" || item.LastProbeAt[candidate] < item.LastProbeAt[oldest] {
				oldest = candidate
			}
		}
		if oldest == "" {
			break
		}
		result = append(result, oldest)
	}
	item.ScanQueue = without(item.ScanQueue, result)
	return result
}
