package agent

import "time"

// A cached half must still be the exact qualified planning observation. Keep
// its real phase and wave; a retained display value supplies no fresh proof.
func cachedWarmPairEvidence(now time.Time, node string, item *policyHealthState) (probeEvidence, bool) {
	warm, exists := item.warmPlanningLatest[node]
	if !exists || !validPlanningQuality(&warm, qualityMeasurement(item.WarmPlanningMarker)) {
		return probeEvidence{}, false
	}
	samples := item.Samples[node]
	if len(samples) == 0 || !goodPlanningSample(samples[len(samples)-1]) || samples[len(samples)-1].ObservedAt <= 0 {
		return probeEvidence{}, false
	}
	// This is the processed physical observation, not the last admitted median
	// sample. A rate-limited history may legitimately have an older time/value.
	if processed, known := item.warmPlanningCountedAt[node]; !known || !processed.Equal(warm.ObservedAt) {
		return probeEvidence{}, false
	}
	return probeEvidence{OK: true, DelayMS: warm.DelayMS, QualityStartedAt: warm.StartedAt,
		ObservedAt: warm.ObservedAt, QualityWave: warm.Wave}, true
}

// Serial halves retain their observation order. Parallel delivery can reverse
// completion order only for the same physically overlapping wave, with both
// observations already completed at the controller's current observation time.
func cachedWarmHalfCanJoin(now time.Time, cached, fresh probeEvidence) bool {
	if !fresh.OK || fresh.QualityUnmeasured || fresh.DelayMS == nil || *fresh.DelayMS <= 0 ||
		fresh.QualityStartedAt.IsZero() || !fresh.ObservedAt.After(fresh.QualityStartedAt) ||
		cached.ObservedAt.After(now) || fresh.ObservedAt.After(now) {
		return false
	}
	return !cached.ObservedAt.After(fresh.ObservedAt) || cached.QualityWave != 0 && cached.QualityWave == fresh.QualityWave && qualityIntervalsOverlap(cached, fresh)
}

// Only the continuation that actually joined these two observations can finish
// an initial survey without a nomination. It is runtime-only, bounded to the
// normal pair window and cannot keep a completed half pending in the scheduler.
func completedWarmScanPair(now time.Time, selected, candidate string, measured map[string]probeEvidence, item *policyHealthState) bool {
	pair := item.warmScanPair
	if pair == nil || pair.CompletedAt.IsZero() || !isPairedPlanningMeasurement(qualityMeasurement(item.WarmPlanningMarker)) ||
		pair.Signature != item.WarmPlanningSignature || pair.Baseline != selected || pair.Candidate != candidate ||
		item.Selected != selected || !item.RuntimeConfirmed || item.UnderlayFailure != "" || item.AvailabilityFailures[selected] > 0 {
		return false
	}
	firstNode := selected
	if pair.Next == selected {
		firstNode = candidate
	} else if pair.Next != candidate {
		return false
	}
	first, firstValid := cachedWarmPairEvidence(now, firstNode, item)
	second, secondFresh := measured[pair.Next]
	qualifiedSecond, secondValid := cachedWarmPairEvidence(now, pair.Next, item)
	if !firstValid || !secondFresh || !secondValid || !second.OK || second.QualityUnmeasured || second.DelayMS == nil ||
		!first.ObservedAt.Equal(pair.ObservedAt) || !second.ObservedAt.Equal(pair.CompletedAt) ||
		!second.ObservedAt.Equal(qualifiedSecond.ObservedAt) || !second.QualityStartedAt.Equal(qualifiedSecond.QualityStartedAt) ||
		second.QualityWave != qualifiedSecond.QualityWave || *second.DelayMS != *qualifiedSecond.DelayMS {
		return false
	}
	firstAge, secondAge := now.Sub(pair.ObservedAt), now.Sub(pair.CompletedAt)
	if firstAge < 0 || firstAge > optimizationPairSkew || secondAge < 0 || secondAge > optimizationPairSkew {
		return false
	}
	return second.QualityWave != 0 || second.ObservedAt.After(first.ObservedAt)
}
