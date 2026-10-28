package agent

import "time"

func (controller *healthController) qualitySurveyLanes() int {
	if runtime, ok := controller.runtime.(interface{ qualityLaneCount() int }); ok {
		return max(1, runtime.qualityLaneCount())
	}
	if controller.processedPool.ProbeLanes > 0 {
		return healthProbeLaneCount(controller.processedPool)
	}
	return 0 // Legacy/custom runtimes without a known physical lane count.
}

// Limit ordinary quality work to the waves that fit the comparison window.
// Emergency discovery keeps its own early-success and cancellation behavior.
func (controller *healthController) surveySettings(p effectivePolicySettings) effectivePolicySettings {
	if lanes := controller.qualitySurveyLanes(); lanes > 0 {
		waves := max(1, int(optimizationPairSkew/qualityProbeTimeout))
		p.batch = min(p.batch, lanes*waves)
	}
	return p
}

// A survey can span multiple batches while the active node is due only once.
// Refresh its baseline inside a later batch when a successful primary probe
// could otherwise finish outside the comparison window. This consumes an
// ordinary batch slot, not an extra lane or an immediate retry.
func (controller *healthController) withSurveyBaseline(now time.Time, selected string, targets []string, item *policyHealthState, p effectivePolicySettings) []string {
	if p.batch < 2 || len(targets) == 0 || selected == "block" || contains(targets, selected) ||
		!item.RuntimeConfirmed || item.RuntimeSelected != selected || item.UnderlayFailure != "" || item.AvailabilityFailures[selected] > 0 ||
		(item.OptimizationCandidate != "" && item.OptimizationBaseline == selected && freshComparisonAt(now, item.OptimizationLastResult, p)) {
		return targets
	}
	// A failed primary must keep its normal retry cadence. Availability success
	// alone supplies neither a new quality baseline nor an accelerated retry.
	baseline, at := latestQualityObservation(item, selected)
	waves := 1
	if lanes := controller.qualitySurveyLanes(); lanes > 0 {
		count := min(p.batch, len(targets)+1)
		waves = (count + lanes - 1) / lanes
	}
	maximumAge := max(time.Duration(0), optimizationPairSkew-time.Duration(waves)*qualityProbeTimeout).Seconds()
	observedNow := qualityObservationAt(now, probeEvidence{})
	if !baseline.OK || baseline.DelayMS == nil || *baseline.DelayMS <= 0 || baseline.ObservedAt <= 0 || at > observedNow || observedNow-at <= maximumAge {
		return targets
	}
	if budget := controller.probeBudget; budget != nil && budget.Limit > 0 && budget.Limit-len(budget.Used) < 2 {
		// One remaining shared slot must still advance reserve rotation.
		return targets
	}
	result := make([]string, 0, min(p.batch, len(targets)+1))
	result = append(result, selected)
	retained := min(len(targets), p.batch-1)
	result = append(result, targets[:retained]...)
	item.ScanQueue = uniqueCandidates(append(targets[retained:], item.ScanQueue...))
	return result
}

// Continue a bounded sweep without waiting another full quality interval.
func (controller *healthController) remainingProbeInterval(now time.Time, contract healthPolicyContract, item *policyHealthState) time.Duration {
	p := controller.surveySettings(policySettings(contract.Policy, contract.Mode))
	// The quality interval is not the delay between the two sides of one pair.
	// A completed inconclusive pair returns no targets and cools normally.
	if item.RuntimeConfirmed && item.UnderlayFailure == "" && item.AvailabilityFailures[item.Selected] == 0 &&
		len(optimizationPairProbeTargets(now, item.Selected, contract.Candidates, item, p)) > 0 {
		return 0
	}
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
	result := optimizationPairProbeTargets(now, selected, candidates, item, p)
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
	if len(result) < p.batch && activeTurn && contains(candidates, selected) && due(selected) && !contains(result, selected) {
		result = append(result, selected)
	}
	if candidate := item.OptimizationCandidate; item.OptimizationChecks > 0 &&
		len(result) < p.batch && candidate != selected && contains(candidates, candidate) && !contains(result, candidate) && due(candidate) {
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
