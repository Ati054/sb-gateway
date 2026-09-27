package agent

// A stable subscription ID preserves user selection, but its connectivity
// evidence belongs to the concrete outbound. A new port, address, credential,
// or transport must not inherit the previous endpoint's healthy reserve state.
func invalidateChangedOutboundHealth(item *policyHealthState, candidates []string, nodes map[string]healthNode) []string {
	changed := make([]string, 0)
	for _, id := range candidates {
		current := nodes[id].Fingerprint
		if current == "" {
			continue
		}
		previous := item.CandidateNodes[id].Fingerprint
		if previous == current {
			continue
		}
		// An older state file has no fingerprint. Clear its evidence once on
		// upgrade rather than trusting an unverifiable historical endpoint.
		if previous == "" && item.LastProbeAt[id] == 0 && len(item.Samples[id]) == 0 {
			continue
		}
		changed = append(changed, id)
		delete(item.Failures, id)
		delete(item.AvailabilityFailures, id)
		delete(item.Recoveries, id)
		delete(item.Samples, id)
		delete(item.DailySamples, id)
		delete(item.HistoryDays, id)
		delete(item.LastProbeAt, id)
		delete(item.LastGoodAt, id)
		delete(item.SpeedSamplesBPS, id)
		delete(item.LastSpeedProbeAt, id)
		delete(item.LastSpeedSuccessAt, id)
		delete(item.LastSpeedProbeStatus, id)
		delete(item.OptimizationBackoff, id)
		delete(item.DailyStats, id)
		delete(item.PeriodStats, id)
		delete(item.DelayMS, id)
		delete(item.MedianDelayMS, id)
		delete(item.PacketLossPercent, id)
		delete(item.QualityOK, id)
		delete(item.AvailabilityOK, id)
		delete(item.FailureClass, id)
		delete(item.HTTPSProbeTargets, id)
		delete(item.SpeedMedianBPS, id)
		if item.LastWorkingSelection != nil && item.LastWorkingSelection.Selected == id {
			item.LastWorkingSelection = nil
		}
		if item.OptimizationCandidate == id || item.OptimizationBaseline == id {
			clearOptimizationCandidate(item)
		}
		if item.Selected == id {
			item.CooldownUntil = 0
		}
	}
	return changed
}

// A removed subscription node must not keep its samples and daily history in
// the long-lived controller or in selector-health.json. History for a node
// that returns later starts with the new membership, not a stale endpoint.
func pruneRemovedCandidateHealth(item *policyHealthState, candidates []string) {
	active := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		active[candidate] = true
	}
	pruneNodeMap(item.Failures, active)
	pruneNodeMap(item.AvailabilityFailures, active)
	pruneNodeMap(item.Recoveries, active)
	pruneNodeMap(item.Samples, active)
	pruneNodeMap(item.DailySamples, active)
	pruneNodeMap(item.HistoryDays, active)
	pruneNodeMap(item.LastProbeAt, active)
	pruneNodeMap(item.LastGoodAt, active)
	pruneNodeMap(item.SpeedSamplesBPS, active)
	pruneNodeMap(item.LastSpeedProbeAt, active)
	pruneNodeMap(item.LastSpeedSuccessAt, active)
	pruneNodeMap(item.LastSpeedProbeStatus, active)
	pruneNodeMap(item.OptimizationBackoff, active)
	pruneNodeMap(item.DailyStats, active)
	for _, period := range item.PeriodStats {
		pruneNodeMap(period, active)
	}
	pruneNodeMap(item.DelayMS, active)
	pruneNodeMap(item.MedianDelayMS, active)
	pruneNodeMap(item.PacketLossPercent, active)
	pruneNodeMap(item.QualityOK, active)
	pruneNodeMap(item.AvailabilityOK, active)
	pruneNodeMap(item.FailureClass, active)
	pruneNodeMap(item.CandidateLabels, active)
	pruneNodeMap(item.CandidateNodes, active)
	pruneNodeMap(item.CandidateGroups, active)
	pruneNodeMap(item.CandidateServiceStatus, active)
	pruneNodeMap(item.HTTPSProbeTargets, active)
	pruneNodeMap(item.SpeedMedianBPS, active)
	item.Shortlist = keepActiveCandidates(item.Shortlist, active)
	item.ProbedCandidates = keepActiveCandidates(item.ProbedCandidates, active)
	item.SpeedProbeTargets = keepActiveCandidates(item.SpeedProbeTargets, active)
	if item.LastWorkingSelection != nil && !active[item.LastWorkingSelection.Selected] {
		item.LastWorkingSelection = nil
	}
	if item.OptimizationLastResult != nil && !active[item.OptimizationLastResult.Candidate] {
		item.OptimizationLastResult = nil
	}
}

func keepActiveCandidates(candidates []string, active map[string]bool) []string {
	kept := candidates[:0]
	for _, candidate := range candidates {
		if active[candidate] {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func pruneNodeMap[T any](values map[string]T, active map[string]bool) {
	for candidate := range values {
		if !active[candidate] {
			delete(values, candidate)
		}
	}
}
