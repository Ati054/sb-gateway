package agent

import "time"

// Four bounded lanes share the existing batch: ready reserves, active quality,
// recovery and full-pool exploration. The cursor survives ticks/restarts so a
// continuously due class cannot monopolize the remaining slots, even at batch=1.
// Active liveness and emergency recovery run independently of this scheduler.
func regularProbeTargets(now time.Time, selected string, candidates, shortlist []string, item *policyHealthState, p effectivePolicySettings) []string {
	const lanes = 4
	result := make([]string, 0, p.batch)
	item.ProbeLane = ((item.ProbeLane % lanes) + lanes) % lanes
	oldest := func(values []string, interval int) string {
		best := ""
		for _, candidate := range values {
			if !contains(candidates, candidate) || contains(result, candidate) || float64(now.Unix())-item.LastProbeAt[candidate] < float64(interval) {
				continue
			}
			if best == "" || item.LastProbeAt[candidate] < item.LastProbeAt[best] {
				best = candidate
			}
		}
		return best
	}
	reserves := without(shortlist, []string{selected})
	recovering := []string{}
	for _, candidate := range candidates {
		if candidate != selected && len(item.Samples[candidate]) > 0 && !contains(shortlist, candidate) &&
			(!item.AvailabilityOK[candidate] || !item.QualityOK[candidate] || item.AvailabilityFailures[candidate] > 0 || item.Recoveries[candidate] < p.recoveryThreshold) {
			recovering = append(recovering, candidate)
		}
	}
	// At batch>=2, an overdue ready reserve always gets a slot immediately;
	// at least one slot remains for the fair rotation of all other work.
	if p.batch > 1 {
		if candidate := oldest(reserves, p.backup); candidate != "" {
			result = append(result, candidate)
		}
	}
	misses := 0
	for len(result) < p.batch && misses < lanes {
		lane := item.ProbeLane
		item.ProbeLane = (lane + 1) % lanes
		candidate := ""
		switch lane {
		case 0:
			candidate = oldest(reserves, p.backup)
		case 1:
			interval := p.active
			if item.AvailabilityFailures[selected] > 0 {
				interval = minInt(interval, int(failureRetryInterval/time.Second))
			}
			candidate = oldest([]string{selected}, interval)
		case 2:
			candidate = oldest(recovering, minInt(p.backup, 60))
		case 3:
			for _, queued := range item.ScanQueue {
				if contains(candidates, queued) && !contains(result, queued) {
					candidate = queued
					break
				}
			}
		}
		if candidate == "" {
			misses++
			continue
		}
		result = append(result, candidate)
		misses = 0
	}
	// Every full probe satisfies that member's pending exploration too. Aborted
	// batches are requeued by tickPolicy without committing probe timestamps.
	item.ScanQueue = without(item.ScanQueue, result)
	return result
}
