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
