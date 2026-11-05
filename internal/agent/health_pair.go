package agent

import "time"

const (
	optimizationPairSkew = 10 * time.Second
	qualityProbeTimeout  = 5 * time.Second
)

func qualityObservationAt(now time.Time, evidence probeEvidence) float64 {
	return float64(probeObservationTime(now, evidence).UnixNano()) / float64(time.Second)
}

func probeObservationTime(now time.Time, evidence probeEvidence) time.Time {
	if !evidence.ObservedAt.IsZero() {
		return evidence.ObservedAt
	}
	return now
}

func latestQualityObservation(item *policyHealthState, node string) (healthSample, float64) {
	if item.planningSampleView {
		if value, exists := item.warmPlanningLatest[node]; exists {
			sample := healthSample{At: float64(value.ObservedAt.Unix()), ObservedAt: float64(value.ObservedAt.UnixNano()) / float64(time.Second), OK: !value.Failed, DelayMS: value.DelayMS}
			return sample, sample.ObservedAt
		}
	} else if sample, exists := item.LatestQuality[node]; exists {
		return sample, qualityHistoryAt(sample)
	}
	samples := item.Samples[node]
	if len(samples) == 0 {
		return healthSample{}, 0
	}
	sample := samples[len(samples)-1]
	if sample.ObservedAt > 0 {
		return sample, sample.ObservedAt
	}
	return sample, sample.At
}

// Complete a nominated comparison within the ordinary batch budget. A one-slot
// policy measures the two sides in adjacent ticks rather than using an old
// active observation or exceeding the configured concurrency.
func optimizationPairProbeTargets(now time.Time, selected string, candidates []string, item *policyHealthState, p effectivePolicySettings) []string {
	if candidate := degradedPairProbeTarget(now, selected, candidates, item); candidate != "" {
		return []string{candidate}
	}
	if target := warmScanPairTarget(now, selected, candidates, item); target != "" {
		return []string{target}
	}
	item = warmPlanningScheduleView(item)
	candidate, previous := item.OptimizationCandidate, pendingOptimizationPair(now, selected, candidates, item, p)
	if previous == nil {
		return nil
	}
	_, activeAt := latestQualityObservation(item, selected)
	_, candidateAt := latestQualityObservation(item, candidate)
	activeAdvanced := activeAt > previous.ActiveSampleAt
	candidateAdvanced := candidateAt > previous.CandidateSampleAt
	due := func(node string) bool {
		return item.LastProbeAt[node] == 0 || float64(now.Unix())-item.LastProbeAt[node] >= float64(p.active)
	}
	// Refreshing the active node for another reserve does not start a new
	// confirmation round for this candidate. A completed first proof retains
	// the ordinary candidate interval; an eligible split round can still finish.
	if item.OptimizationChecks > 0 && !due(candidate) && !optimizationCandidateIntervalElapsed(item, candidateAt, p) {
		return nil
	}
	var targets []string
	switch {
	case activeAdvanced && !candidateAdvanced:
		targets = []string{candidate}
	case candidateAdvanced && !activeAdvanced:
		targets = []string{selected}
	case due(selected) || due(candidate):
		targets = []string{selected, candidate}
	case item.OptimizationChecks == 0 && previous.Reason == "pair-incomplete":
		targets = []string{selected, candidate}
	default:
		return nil
	}
	return targets[:min(len(targets), p.batch)]
}

// LastProbeAt and due() use whole producer seconds. Use the same clock for
// confirmations so a faster next response cannot miss an otherwise due round.
func optimizationCandidateIntervalElapsed(item *policyHealthState, observedAt float64, p effectivePolicySettings) bool {
	previous := item.OptimizationLastResult
	if isPairedPlanningMeasurement(qualityMeasurement(item.WarmPlanningMarker)) && item.OptimizationChecks > 0 && previous != nil {
		// Another policy may supply a shared result before this policy's own
		// scheduler is due. Never use whole-second truncation to count it early.
		return observedAt > 0 && previous.CandidateSampleAt > 0 && observedAt >= previous.CandidateSampleAt+float64(p.active)
	}
	return item.OptimizationChecks == 0 || previous == nil ||
		observedAt > 0 && previous.CandidateSampleAt > 0 &&
			int64(observedAt)-int64(previous.CandidateSampleAt) >= int64(p.active)
}

func pendingOptimizationPair(now time.Time, selected string, candidates []string, item *policyHealthState, p effectivePolicySettings) *optimizationComparison {
	candidate, previous := item.OptimizationCandidate, item.OptimizationLastResult
	if p.mode != "best" || p.batch < 1 || candidate == "" || candidate == selected ||
		item.OptimizationBaseline != selected || !contains(candidates, candidate) || !freshComparisonAt(now, previous, p) {
		return nil
	}
	return previous
}

// Finish one already-started pair before unrelated routine work consumes the
// shared one-slot budget. Failure recovery still has higher priority.
func optimizationPairHalfPending(now time.Time, contract healthPolicyContract, item *policyHealthState) bool {
	if item == nil || !item.RuntimeConfirmed || item.UnderlayFailure != "" || item.AvailabilityFailures[item.Selected] > 0 {
		return false
	}
	if degradedPairProbeTarget(now, item.Selected, contract.Candidates, item) != "" {
		return true
	}
	if warmScanPairTarget(now, item.Selected, contract.Candidates, item) != "" {
		return true
	}
	item = warmPlanningScheduleView(item)
	previous := pendingOptimizationPair(now, item.Selected, contract.Candidates, item, policySettings(contract.Policy, contract.Mode))
	if previous == nil {
		return false
	}
	_, activeAt := latestQualityObservation(item, item.Selected)
	_, candidateAt := latestQualityObservation(item, item.OptimizationCandidate)
	return (activeAt > previous.ActiveSampleAt) != (candidateAt > previous.CandidateSampleAt) &&
		len(optimizationPairProbeTargets(now, item.Selected, contract.Candidates, item, policySettings(contract.Policy, contract.Mode))) > 0
}
