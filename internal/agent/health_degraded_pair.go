package agent

import (
	"math"
	"time"
)

type degradedPairContinuation struct {
	Active, Candidate string
	ActiveAt          float64
}

func primaryOriginAvailable(evidence probeEvidence) bool {
	if !evidence.OK || len(healthTargets) == 0 {
		return false
	}
	label := healthTargets[0].label
	delay := evidence.Targets[label]
	_, failed := evidence.TargetFailures[label]
	return delay != nil && *delay > 0 && !failed
}

// A missing HEAD duration alone is not proof of primary-origin degradation.
// Legacy samples without this marker cannot authorize a soft switch.
func primaryDegradationPending(item *policyHealthState, active string) bool {
	sample, at := latestQualityObservation(item, active)
	return item.Failures[active] > 0 && sample.OK && sample.PrimaryQualityFailed && at > 0
}

func closeDegradedPair(now time.Time, item *policyHealthState, active, candidate string) bool {
	if !primaryDegradationPending(item, active) {
		return false
	}
	_, activeAt := latestQualityObservation(item, active)
	reserve, reserveAt := latestQualityObservation(item, candidate)
	at := qualityObservationAt(now, probeEvidence{})
	window := optimizationPairSkew.Seconds()
	return reserve.OK && !reserve.PrimaryQualityFailed && reserve.DelayMS != nil && *reserve.DelayMS > 0 &&
		activeAt <= at && reserveAt > 0 && reserveAt <= at &&
		at-activeAt <= window && at-reserveAt <= window && math.Abs(activeAt-reserveAt) <= window
}

// Complete at most one missing reserve observation in an ordinary shared slot.
// Do not accelerate another active failure or retain a stale half indefinitely.
func degradedPairProbeTarget(now time.Time, selected string, candidates []string, item *policyHealthState) string {
	pair := item.degradedPair
	if pair == nil {
		return ""
	}
	_, activeAt := latestQualityObservation(item, selected)
	at := qualityObservationAt(now, probeEvidence{})
	if pair.Active != selected || !contains(candidates, pair.Candidate) || activeAt != pair.ActiveAt ||
		!primaryDegradationPending(item, selected) || at < activeAt || at-activeAt > optimizationPairSkew.Seconds() ||
		item.AvailabilityFailures[selected] > 0 || item.UnderlayFailure != "" {
		return ""
	}
	return pair.Candidate
}

func planDegradedPair(now time.Time, selected string, candidates, shortlist []string, measured map[string]probeEvidence, item *policyHealthState, freshActive bool) {
	if pair := item.degradedPair; pair != nil {
		if _, attempted := measured[pair.Candidate]; attempted || degradedPairProbeTarget(now, selected, candidates, item) == "" {
			item.degradedPair = nil
		}
	}
	active, measuredActive := measured[selected]
	if !freshActive || !measuredActive || !active.OK || active.LocalFailure || !active.PrimaryQualityFailed || !primaryDegradationPending(item, selected) {
		return
	}
	for _, candidate := range candidates {
		if candidate != selected && closeDegradedPair(now, item, selected, candidate) {
			return
		}
	}
	for _, candidate := range uniqueCandidates(append(append([]string(nil), shortlist...), candidates...)) {
		if candidate == selected || !contains(candidates, candidate) {
			continue
		}
		if _, attempted := measured[candidate]; attempted {
			continue
		}
		item.degradedPair = &degradedPairContinuation{Active: selected, Candidate: candidate, ActiveAt: qualityObservationAt(now, active)}
		return
	}
}

func freshQualityEvidence(item *policyHealthState, node string, at float64) bool {
	if item.qualityCountedAt == nil {
		item.qualityCountedAt = make(map[string]float64)
	}
	_, previousAt := latestQualityObservation(item, node)
	countedAt, counted := item.qualityCountedAt[node]
	if at < 0 || counted && at <= countedAt || previousAt > 0 && at <= previousAt {
		return false
	}
	item.qualityCountedAt[node] = at
	return true
}
