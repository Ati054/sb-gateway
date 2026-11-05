package agent

import "time"

// One-slot surveys finish one physical pair before yielding to another policy.
// Arming a continuation is not an optimization nomination or a confirmation.
// It is session-local and never appears in the persistent checkpoint.
type warmScanContinuation struct {
	Baseline, Candidate, Next string
	ObservedAt                time.Time
	CompletedAt               time.Time
	Signature                 string
}

func warmScanPairTarget(now time.Time, selected string, candidates []string, item *policyHealthState) string {
	if item == nil {
		return ""
	}
	pair := item.warmScanPair
	if pair == nil {
		return ""
	}
	age := now.Sub(pair.ObservedAt)
	if !isPairedPlanningMeasurement(qualityMeasurement(item.WarmPlanningMarker)) || pair.Signature != item.WarmPlanningSignature ||
		pair.Baseline != selected || !contains(candidates, pair.Baseline) || !contains(candidates, pair.Candidate) ||
		!item.RuntimeConfirmed || item.UnderlayFailure != "" || item.AvailabilityFailures[selected] > 0 ||
		age < 0 || age > optimizationPairSkew {
		item.warmScanPair = nil
		return ""
	}
	if !pair.CompletedAt.IsZero() {
		return "" // A completed token cannot hold the next policy's slot.
	}
	return pair.Next
}

func continueWarmScanPair(now time.Time, selected string, candidates []string, measured map[string]probeEvidence, item *policyHealthState, p effectivePolicySettings) {
	if p.mode != "best" || p.batch != 1 || !isPairedPlanningMeasurement(qualityMeasurement(item.WarmPlanningMarker)) {
		item.warmScanPair = nil
		return
	}
	if pair := item.warmScanPair; pair != nil {
		if !pair.CompletedAt.IsZero() {
			item.warmScanPair = nil
		} else if evidence, completed := measured[pair.Next]; completed && !evidence.Deferred &&
			(evidence.planningQuality() != nil || !evidence.QualityUnmeasured && !evidence.QualityStartedAt.IsZero()) {
			if evidence.OK && validPlanningQuality(evidence.planningQuality(), qualityMeasurement(item.WarmPlanningMarker)) && warmScanPairTarget(now, selected, candidates, item) == pair.Next {
				// Preserve this exact completed pair through selection. Merely
				// retaining two unrelated recent samples cannot create the token.
				pair.CompletedAt = evidence.planningQuality().ObservedAt
			} else {
				item.warmScanPair = nil
			}
			return // One pair is enough; rotate policies before starting another.
		} else if warmScanPairTarget(now, selected, candidates, item) != "" {
			return
		}
	}
	if item.OptimizationCandidate != "" {
		return // An admitted optimization pair already has its own continuation.
	}
	for node, evidence := range measured {
		if !evidence.OK || !validPlanningQuality(evidence.planningQuality(), qualityMeasurement(item.WarmPlanningMarker)) || !contains(candidates, node) {
			continue
		}
		// Never re-arm from a result already outside the real observation window.
		age := now.Sub(evidence.planningQuality().ObservedAt)
		if age < 0 || age > optimizationPairSkew {
			continue
		}
		candidate, next := node, selected
		if node == selected {
			candidate = ""
			for _, reserve := range candidates {
				last := item.WarmPlanningLastProbeAt[reserve]
				if reserve != selected && (last == 0 || float64(now.Unix())-last >= float64(p.active)) &&
					(candidate == "" || last < item.WarmPlanningLastProbeAt[candidate]) {
					candidate = reserve
				}
			}
			next = candidate
		} else {
			view := warmPlanningView(item)
			pairs := currentLatencyComparisons(now, view, []string{selected, candidate}, p)
			if _, complete := pairs[candidate]; complete {
				continue // The fresh reserve already has a comparable active side.
			}
		}
		if candidate != "" && next != "" {
			item.warmScanPair = &warmScanContinuation{Baseline: selected, Candidate: candidate, Next: next,
				ObservedAt: evidence.planningQuality().ObservedAt, Signature: item.WarmPlanningSignature}
		}
		return
	}
}
