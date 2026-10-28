package agent

import "time"

const (
	optimizationPairSkew = 10 * time.Second
	qualityProbeTimeout  = 5 * time.Second
)

func qualityObservationAt(now time.Time, evidence probeEvidence) float64 {
	if !evidence.ObservedAt.IsZero() {
		return float64(evidence.ObservedAt.UnixNano()) / float64(time.Second)
	}
	return float64(now.UnixNano()) / float64(time.Second)
}

func latestQualityObservation(item *policyHealthState, node string) (healthSample, float64) {
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
	previous := pendingOptimizationPair(now, item.Selected, contract.Candidates, item, policySettings(contract.Policy, contract.Mode))
	if previous == nil {
		return false
	}
	_, activeAt := latestQualityObservation(item, item.Selected)
	_, candidateAt := latestQualityObservation(item, item.OptimizationCandidate)
	return (activeAt > previous.ActiveSampleAt) != (candidateAt > previous.CandidateSampleAt)
}
