package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

const optimizationConfirmations = 2

type effectivePolicySettings struct {
	failureThreshold  int
	recoveryThreshold int
	qualityWindow     int
	maxLoss           float64
	maxLatency        int
	cooldown          int
	improvement       int
	speedEnabled      bool
	speedImprovement  int
	speedInterval     int
	speedBytes        int
	speedCandidates   int
	active            int
	backup            int
	fullScan          int
	shortlist         int
	batch             int
	liveness          int
	failureRetry      int
	blockRecovery     int
}

func policySettings(policy healthPolicy, mode string) effectivePolicySettings {
	speedEnabled := mode == "best" && (policy.SpeedCheckEnabled == nil || *policy.SpeedCheckEnabled)
	return effectivePolicySettings{
		failureThreshold:  defaultInt(policy.FailureThreshold, 3, 1, 20),
		recoveryThreshold: defaultInt(policy.RecoveryThreshold, 3, 1, 20),
		qualityWindow:     defaultInt(policy.QualityWindow, 5, 1, 60),
		maxLoss:           defaultFloat(policy.MaxPacketLossPercent, 40, 0, 100),
		maxLatency:        defaultIntAllowZero(policy.MaxLatencyMS, 2000, 0, 60000),
		cooldown:          defaultIntAllowZero(policy.SwitchCooldownSeconds, 600, 0, 86400),
		improvement:       defaultIntAllowZero(policy.SwitchImprovementMS, 50, 0, 30000),
		speedEnabled:      speedEnabled,
		speedImprovement:  defaultIntAllowZero(policy.SpeedImprovementPercent, 25, 0, 1000),
		speedInterval:     defaultInt(policy.SpeedCheckIntervalSeconds, 10800, 300, 86400),
		speedBytes:        defaultInt(policy.SpeedProbeBytes, defaultSpeedBytes, 256*1024, 10*1024*1024),
		speedCandidates:   defaultInt(policy.SpeedCandidateCount, 2, 1, 5),
		active:            defaultInt(policy.ActiveCheckSeconds, 60, 1, 3600),
		backup:            maxInt(defaultInt(policy.BackupCheckSeconds, 300, 1, 86400), defaultInt(policy.ActiveCheckSeconds, 60, 1, 3600)),
		fullScan:          maxInt(defaultInt(policy.FullScanSeconds, 1800, 1, 86400), defaultInt(policy.BackupCheckSeconds, 300, 1, 86400)),
		shortlist:         defaultInt(policy.MaxActiveCandidates, defaultInt(policy.MaxProbeCandidates, 5, 1, 10), 1, 10),
		batch:             defaultInt(policy.ProbeBatchSize, 5, 1, 10),
		liveness:          defaultInt(policy.ActiveLivenessSeconds, int(activeLivenessInterval/time.Second), 2, 30),
		failureRetry:      defaultInt(policy.FailureRetrySeconds, int(failureRetryInterval/time.Second), 1, 10),
		blockRecovery:     defaultInt(policy.BlockRecoverySeconds, int(outageRetryInterval/time.Second), 5, 60),
	}
}

// The working pool is recomputed from evidence, never from inventory position.
// Keep the current usable path pinned: pool maintenance must not cause a switch.
func workingShortlist(selected string, candidates []string, mode string, groups map[string]int, item *policyHealthState, p effectivePolicySettings) []string {
	eligible := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if item.AvailabilityOK[candidate] && item.QualityOK[candidate] && item.AvailabilityFailures[candidate] == 0 && item.Recoveries[candidate] >= p.recoveryThreshold {
			eligible = append(eligible, candidate)
		}
	}
	rankSpeeds := item.SpeedMedianBPS
	if !p.speedEnabled {
		rankSpeeds = nil
	}
	ranked := rankCandidates(eligible, mode, groups, item.DailyStats, item.MedianDelayMS, rankSpeeds)
	result := make([]string, 0, p.shortlist)
	if contains(candidates, selected) && item.AvailabilityOK[selected] {
		result = append(result, selected)
	}
	for _, candidate := range ranked {
		if len(result) == p.shortlist {
			break
		}
		if candidate != selected {
			result = append(result, candidate)
		}
	}
	return result
}

// Prefer an already measured reserve when an Apply removes the active member.
// Best mode preserves the maintained shortlist order; priority mode follows the
// newly published queue. Unknown or previously failed candidates are not used as
// an optimistic replacement.
func knownHealthyReplacement(candidates []string, mode string, groups map[string]int, item *policyHealthState, p effectivePolicySettings) string {
	known := func(candidate string) bool {
		return contains(candidates, candidate) && item.AvailabilityOK[candidate] &&
			item.AvailabilityFailures[candidate] < p.failureThreshold && item.Recoveries[candidate] > 0
	}
	if mode == "best" {
		for _, candidate := range item.Shortlist {
			if known(candidate) {
				return candidate
			}
		}
	}
	available := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if known(candidate) {
			available = append(available, candidate)
		}
	}
	rankSpeeds := item.SpeedMedianBPS
	if !p.speedEnabled {
		rankSpeeds = nil
	}
	available = rankCandidates(available, mode, groups, item.DailyStats, item.MedianDelayMS, rankSpeeds)
	if len(available) > 0 {
		return available[0]
	}
	return ""
}

// Rotate bounded speed downloads across reachable candidates, not just the
// current latency leaders. A policy-wide floor prevents a large subscription
// from downloading a new batch on every controller tick.
func speedProbeCandidates(now time.Time, selected string, candidates []string, measured map[string]probeEvidence, item *policyHealthState, p effectivePolicySettings) []string {
	latest := float64(0)
	for _, at := range item.LastSpeedProbeAt {
		if at > latest {
			latest = at
		}
	}
	if latest > 0 && float64(now.Unix())-latest < 300 {
		return nil
	}
	eligible := []string{}
	for _, candidate := range candidates {
		available := item.AvailabilityOK[candidate] && item.AvailabilityFailures[candidate] == 0
		if evidence, ok := measured[candidate]; ok {
			available = evidence.OK
		}
		last := item.LastSpeedProbeAt[candidate]
		if available && (last == 0 || float64(now.Unix())-last >= float64(p.speedInterval)) {
			eligible = append(eligible, candidate)
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i] == selected || eligible[j] == selected {
			return eligible[i] == selected
		}
		return item.LastSpeedProbeAt[eligible[i]] < item.LastSpeedProbeAt[eligible[j]]
	})
	return eligible[:minInt(len(eligible), 1+p.speedCandidates)]
}

func ensureHealthMaps(item *policyHealthState) {
	if item.Failures == nil {
		item.Failures = make(map[string]int)
	}
	if item.AvailabilityFailures == nil {
		item.AvailabilityFailures = make(map[string]int)
	}
	if item.Recoveries == nil {
		item.Recoveries = make(map[string]int)
	}
	if item.Samples == nil {
		item.Samples = make(map[string][]healthSample)
	}
	if item.DailySamples == nil {
		item.DailySamples = make(map[string][]healthSample)
	}
	if item.HistoryDays == nil {
		item.HistoryDays = make(map[string]map[string]dayBucket)
	}
	if item.LastProbeAt == nil {
		item.LastProbeAt = make(map[string]float64)
	}
	if item.LastGoodAt == nil {
		item.LastGoodAt = make(map[string]float64)
	}
	if item.SpeedSamplesBPS == nil {
		item.SpeedSamplesBPS = make(map[string][]int64)
	}
	if item.LastSpeedProbeAt == nil {
		item.LastSpeedProbeAt = make(map[string]float64)
	}
	if item.FailureClass == nil {
		item.FailureClass = make(map[string]string)
	}
}

func candidateGroups(groups []healthGroup, candidates []string, mode string) (map[string]int, map[string]string, map[string]string) {
	indices := make(map[string]int)
	selectors := make(map[string]string)
	labels := make(map[string]string)
	for index, group := range groups {
		selector := group.Selector
		if selector == "" {
			selector = "priority-" + strconvItoa(index+1)
		}
		labels[strconvItoa(index)] = selector
		for _, member := range group.Members {
			if contains(candidates, member) {
				if _, exists := indices[member]; !exists {
					indices[member] = index
				}
				if _, exists := selectors[member]; !exists {
					selectors[member] = selector
				}
			}
		}
	}
	for index, candidate := range candidates {
		if _, exists := indices[candidate]; !exists {
			if mode == "priority" {
				indices[candidate] = index
			} else {
				indices[candidate] = 0
			}
		}
	}
	return indices, selectors, labels
}

func selectDesired(now time.Time, mode, selected string, candidates []string, groups map[string]int, daily map[string]healthStats, medians map[string]*int, speeds map[string]*int64, measured map[string]probeEvidence, quality, available map[string]bool, item *policyHealthState, p effectivePolicySettings) (string, string) {
	rankSpeeds := speeds
	if !p.speedEnabled {
		rankSpeeds = nil
	}
	rank := func(values []string) []string {
		return rankCandidates(values, mode, groups, daily, medians, rankSpeeds)
	}
	// A current success may restore service when no maintained reserve exists,
	// but an excessively slow response is not a usable recovery. Rolling quality
	// remains mandatory for the confirmed-reserve tier below.
	fresh := func(candidate string) bool {
		evidence, ok := measured[candidate]
		return ok && evidence.OK && (p.maxLatency <= 0 || (evidence.DelayMS != nil && *evidence.DelayMS <= p.maxLatency))
	}
	known := func(candidate string, confirmations int) bool {
		return available[candidate] && item.Recoveries[candidate] >= confirmations && medians[candidate] != nil
	}
	confirmedReserve := func(candidate string) bool {
		lastProbe := item.LastProbeAt[candidate]
		return candidate != selected && quality[candidate] && known(candidate, p.recoveryThreshold) &&
			item.AvailabilityFailures[candidate] == 0 && lastProbe > 0 &&
			float64(now.Unix())-lastProbe <= float64(p.backup)
	}
	selectedFailed := selected == "block" || !contains(candidates, selected) || item.AvailabilityFailures[selected] >= p.failureThreshold
	desired, reason := selected, ""
	if selected == "block" {
		values := []string{}
		for _, candidate := range candidates {
			if fresh(candidate) {
				values = append(values, candidate)
			}
		}
		values = rank(values)
		if len(values) > 0 {
			desired, reason = values[0], "fresh-path-available"
		}
	} else if selectedFailed {
		confirmedValues, freshValues, qualifiedValues := []string{}, []string{}, []string{}
		for _, candidate := range candidates {
			if candidate == selected {
				continue
			}
			if confirmedReserve(candidate) {
				confirmedValues = append(confirmedValues, candidate)
			}
			if fresh(candidate) {
				freshValues = append(freshValues, candidate)
			}
			if quality[candidate] && item.AvailabilityFailures[candidate] == 0 && known(candidate, p.recoveryThreshold) {
				qualifiedValues = append(qualifiedValues, candidate)
			}
		}
		// Prefer the already maintained, recently checked working reserve. A
		// current success is only a fallback when no recent confirmed reserve is
		// available. This keeps mass-outage recovery immediate without letting a
		// one-off response displace a maintained working reserve.
		alternatives := rank(confirmedValues)
		if len(alternatives) == 0 {
			alternatives = rank(freshValues)
		}
		if len(alternatives) == 0 {
			alternatives = rank(qualifiedValues)
		}
		if len(alternatives) > 0 {
			desired, reason = alternatives[0], "active-unavailable"
		} else {
			// The active path is already confirmed unavailable. Do not keep
			// sending new connections to it merely because another candidate is
			// still unconfirmed; fail closed until a qualified reserve appears.
			desired, reason = "block", "all-candidates-unavailable"
		}
	} else {
		stable := []string{}
		for _, candidate := range candidates {
			if candidate != selected && quality[candidate] && known(candidate, p.recoveryThreshold) {
				stable = append(stable, candidate)
			}
		}
		if item.Failures[selected] >= p.failureThreshold && len(stable) > 0 {
			// A slow but reachable path is not an outage. Only leave it for a
			// confirmed healthy reserve, and honour cooldown. Otherwise two
			// slow paths can alternate on every tick forever.
			desired, reason = rank(stable)[0], "active-degraded"
		} else if mode == "priority" {
			higher := []string{}
			for _, candidate := range stable {
				if groups[candidate] < groups[selected] || (groups[candidate] == groups[selected] && candidateIndex(candidates, candidate) < candidateIndex(candidates, selected)) {
					higher = append(higher, candidate)
				}
			}
			higher = rank(higher)
			if len(higher) > 0 {
				desired, reason = higher[0], "higher-priority-recovered"
			}
		} else if better := meaningfullyBetter(selected, stable, medians, speeds, p); better != "" {
			desired, reason = better, "meaningfully-faster"
		}
		// Cooldown prevents elective re-ranking of a healthy path. A normally
		// degraded path may still move to a confirmed reserve, but a reserve just
		// selected after active-unavailable is held through the cooldown so noisy
		// quality samples cannot create ping-pong. A real availability failure is
		// handled by the outage branch above and is never delayed here.
		// A priority path that has just recovered needs the same anti-flap
		// protection as a newly chosen failover reserve. Otherwise three noisy
		// quality samples can immediately undo the recovery while the path is
		// still reachable, producing France -> reserve -> France -> reserve.
		degradedMayBypass := reason == "active-degraded" &&
			item.LastSwitchReason != "active-unavailable" && item.LastSwitchReason != "higher-priority-recovered"
		if desired != selected && !degradedMayBypass && float64(now.Unix()) < item.CooldownUntil {
			desired, reason = selected, ""
		}
	}
	return desired, reason
}

func meaningfullyBetter(selected string, candidates []string, delays map[string]*int, speeds map[string]*int64, p effectivePolicySettings) string {
	current := delays[selected]
	if current == nil || *current <= 0 {
		return ""
	}
	measured := []string{}
	for _, candidate := range candidates {
		if delays[candidate] != nil && *current-*delays[candidate] >= p.improvement {
			measured = append(measured, candidate)
		}
	}
	if p.speedEnabled {
		currentSpeed := speeds[selected]
		if currentSpeed == nil || *currentSpeed <= 0 {
			return ""
		}
		filtered := []string{}
		for _, candidate := range measured {
			if speeds[candidate] != nil && *speeds[candidate]*100 >= *currentSpeed*int64(100+p.speedImprovement) {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) == 0 {
			// No candidate materially improves both metrics. Prefer responsiveness
			// only when its relative gain outweighs the throughput cost. Keep a
			// hard floor of 65% of current throughput and require measured speed.
			for _, candidate := range measured {
				speed := speeds[candidate]
				if speed == nil || *speed <= 0 {
					continue
				}
				loss := 1 - float64(*speed)/float64(*currentSpeed)
				gain := 1 - float64(*delays[candidate])/float64(*current)
				if loss <= 0.35 && gain > 0 && gain > loss {
					filtered = append(filtered, candidate)
				}
			}
			sort.SliceStable(filtered, func(i, j int) bool {
				if *delays[filtered[i]] != *delays[filtered[j]] {
					return *delays[filtered[i]] < *delays[filtered[j]]
				}
				return *speeds[filtered[i]] > *speeds[filtered[j]]
			})
			if len(filtered) == 0 {
				return ""
			}
			return filtered[0]
		}
		sort.SliceStable(filtered, func(i, j int) bool {
			if *speeds[filtered[i]] != *speeds[filtered[j]] {
				return *speeds[filtered[i]] > *speeds[filtered[j]]
			}
			return *delays[filtered[i]] < *delays[filtered[j]]
		})
		measured = filtered
	} else {
		sort.SliceStable(measured, func(i, j int) bool { return *delays[measured[i]] < *delays[measured[j]] })
	}
	if len(measured) == 0 || *current-*delays[measured[0]] < p.improvement {
		return ""
	}
	return measured[0]
}

// A planned best-mode switch is intentionally slower than outage recovery.
// The rolling history may nominate a candidate, but only two fresh, paired
// comparisons may move traffic. This prevents a stale speed sample or one
// transient latency window from becoming a ten-minute sticky selection.
func gatePlannedOptimization(now time.Time, selected, desired, reason, probedCandidate string, confirmed *bool, item *policyHealthState, p effectivePolicySettings) (string, string) {
	if desired != selected && reason != "meaningfully-faster" {
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
		return desired, reason
	}

	if item.OptimizationCandidate != "" {
		if probedCandidate != item.OptimizationCandidate || confirmed == nil {
			return selected, ""
		}
		if !*confirmed {
			clearOptimizationCandidate(item)
			item.OptimizationRetryAfter = float64(now.Unix() + int64(p.cooldown))
			return selected, ""
		}
		item.OptimizationChecks++
		if item.OptimizationChecks < optimizationConfirmations {
			item.OptimizationNextAt = float64(now.Unix() + int64(p.active))
			return selected, ""
		}
		candidate := item.OptimizationCandidate
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
		return candidate, "meaningfully-faster"
	}

	if desired == selected || reason != "meaningfully-faster" || float64(now.Unix()) < item.OptimizationRetryAfter {
		return selected, ""
	}
	item.OptimizationBaseline = selected
	item.OptimizationCandidate = desired
	item.OptimizationChecks = 0
	item.OptimizationNextAt = float64(now.Unix() + int64(p.active))
	item.OptimizationRetryAfter = 0
	return selected, ""
}

func freshOptimizationWin(selected, candidate string, measured map[string]probeEvidence, measuredSpeed map[string]int64, p effectivePolicySettings) bool {
	activeEvidence, activeOK := measured[selected]
	candidateEvidence, candidateOK := measured[candidate]
	if !activeOK || !candidateOK || !activeEvidence.OK || !candidateEvidence.OK || activeEvidence.DelayMS == nil || candidateEvidence.DelayMS == nil {
		return false
	}
	delays := map[string]*int{selected: activeEvidence.DelayMS, candidate: candidateEvidence.DelayMS}
	var speeds map[string]*int64
	if p.speedEnabled {
		activeSpeed, activeSpeedOK := measuredSpeed[selected]
		candidateSpeed, candidateSpeedOK := measuredSpeed[candidate]
		if !activeSpeedOK || !candidateSpeedOK || activeSpeed <= 0 || candidateSpeed <= 0 {
			return false
		}
		speeds = map[string]*int64{selected: &activeSpeed, candidate: &candidateSpeed}
	}
	return meaningfullyBetter(selected, []string{candidate}, delays, speeds, p) == candidate
}

func clearOptimizationCandidate(item *policyHealthState) {
	item.OptimizationBaseline = ""
	item.OptimizationCandidate = ""
	item.OptimizationChecks = 0
	item.OptimizationNextAt = 0
	clearOptimizationActiveSample(item)
}

func clearOptimizationActiveSample(item *policyHealthState) {
	item.OptimizationActiveAt = 0
	item.OptimizationActiveMS = nil
	item.OptimizationActiveBPS = nil
}

func rankCandidates(values []string, mode string, groups map[string]int, daily map[string]healthStats, medians map[string]*int, speeds map[string]*int64) []string {
	result := append([]string(nil), values...)
	positions := make(map[string]int)
	for index, value := range values {
		positions[value] = index
	}
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if mode == "priority" {
			if groups[left] != groups[right] {
				return groups[left] < groups[right]
			}
			return positions[left] < positions[right]
		}
		leftSpeed, rightSpeed := candidateSpeed(left, speeds), candidateSpeed(right, speeds)
		leftDelay, rightDelay := candidateDelay(left, daily, medians), candidateDelay(right, daily, medians)
		leftMeasured := leftSpeed > 0 && leftDelay > 0
		rightMeasured := rightSpeed > 0 && rightDelay > 0
		if leftMeasured != rightMeasured {
			return leftMeasured
		}
		if leftMeasured && rightMeasured {
			// Rank healthy URLTest reserves by responsive throughput. Availability
			// and quality already gate this candidate set; they must not make a
			// materially slower path the normal reserve. Cross multiplication keeps
			// the comparison deterministic without floating-point rounding.
			leftScore := leftSpeed * int64(rightDelay)
			rightScore := rightSpeed * int64(leftDelay)
			if leftScore != rightScore {
				return leftScore > rightScore
			}
		}
		if leftSpeed != rightSpeed {
			return leftSpeed > rightSpeed
		}
		if (leftDelay > 0) != (rightDelay > 0) {
			return leftDelay > 0
		}
		if leftDelay > 0 && leftDelay != rightDelay {
			return leftDelay < rightDelay
		}
		leftLoss, rightLoss := 101.0, 101.0
		if daily != nil && daily[left].LossPercent != nil {
			leftLoss = *daily[left].LossPercent
		}
		if daily != nil && daily[right].LossPercent != nil {
			rightLoss = *daily[right].LossPercent
		}
		if leftLoss != rightLoss {
			return leftLoss < rightLoss
		}
		return positions[left] < positions[right]
	})
	return result
}

func candidateSpeed(candidate string, speeds map[string]*int64) int64 {
	if speeds != nil && speeds[candidate] != nil && *speeds[candidate] > 0 {
		return *speeds[candidate]
	}
	return 0
}

func candidateDelay(candidate string, daily map[string]healthStats, medians map[string]*int) int {
	if medians != nil && medians[candidate] != nil && *medians[candidate] > 0 {
		return *medians[candidate]
	}
	if daily != nil && daily[candidate].P95MS != nil && *daily[candidate].P95MS > 0 {
		return *daily[candidate].P95MS
	}
	return 0
}

func updateHistories(item *policyHealthState, candidates []string, measured map[string]probeEvidence, now time.Time) {
	cutoff := float64(now.Add(-24 * time.Hour).Unix())
	oldestDay := now.UTC().AddDate(0, 0, -(historyRetentionDays - 1)).Format("2006-01-02")
	for _, candidate := range candidates {
		history := []healthSample{}
		for _, sample := range item.DailySamples[candidate] {
			if sample.At >= cutoff {
				history = append(history, sample)
			}
		}
		if evidence, ok := measured[candidate]; ok {
			history = append(history, healthSample{At: float64(now.Unix()), OK: evidence.OK, DelayMS: evidence.DelayMS})
		}
		if len(history) > 1440 {
			history = history[len(history)-1440:]
		}
		item.DailySamples[candidate] = history
		days := item.HistoryDays[candidate]
		if days == nil {
			days = make(map[string]dayBucket)
			for _, sample := range history {
				appendHistoryDay(days, sample)
			}
		} else if _, ok := measured[candidate]; ok {
			appendHistoryDay(days, history[len(history)-1])
		}
		for _, key := range sortedKeys(days) {
			if key < oldestDay {
				delete(days, key)
			}
		}
		item.HistoryDays[candidate] = days
	}
}

func appendHistoryDay(days map[string]dayBucket, sample healthSample) {
	day := time.Unix(int64(sample.At), 0).UTC().Format("2006-01-02")
	bucket := days[day]
	bucket.Samples++
	if sample.OK && sample.DelayMS != nil {
		bucket.Successes++
		if len(bucket.LatencySamples) < historyReservoir {
			bucket.LatencySamples = append(bucket.LatencySamples, *sample.DelayMS)
		} else {
			slot := (bucket.Successes*1103515245 + 12345) % bucket.Successes
			if slot < historyReservoir {
				bucket.LatencySamples[slot] = *sample.DelayMS
			}
		}
	} else {
		bucket.Failures++
	}
	days[day] = bucket
}

func summarizeSamples(samples []healthSample) healthStats {
	delays := []int{}
	failures := 0
	for _, sample := range samples {
		if sample.OK && sample.DelayMS != nil {
			delays = append(delays, *sample.DelayMS)
		} else {
			failures++
		}
	}
	return buildStats(len(samples), len(delays), failures, delays, 0)
}

func summarizeDays(days map[string]dayBucket, count int, now time.Time) healthStats {
	if count <= 0 {
		return healthStats{}
	}
	oldestDay := now.UTC().AddDate(0, 0, -(count - 1)).Format("2006-01-02")
	newestDay := now.UTC().Format("2006-01-02")
	keys := []string{}
	for _, key := range sortedKeys(days) {
		if key >= oldestDay && key <= newestDay {
			keys = append(keys, key)
		}
	}
	samples, successes, failures := 0, 0, 0
	delays := []int{}
	for _, key := range keys {
		bucket := days[key]
		samples += bucket.Samples
		successes += bucket.Successes
		failures += bucket.Failures
		delays = append(delays, bucket.LatencySamples...)
	}
	stats := buildStats(samples, successes, failures, delays, len(keys))
	stats.LatencySampleCount = len(delays)
	stats.PercentilesApproximate = successes > len(delays)
	return stats
}

func buildStats(samples, successes, failures int, delays []int, days int) healthStats {
	stats := healthStats{Samples: samples, Successes: successes, Failures: failures, Days: days}
	if samples > 0 {
		loss := roundOne(float64(failures) * 100 / float64(samples))
		availability := roundOne(float64(successes) * 100 / float64(samples))
		stats.LossPercent, stats.AvailabilityPercent = &loss, &availability
	}
	if len(delays) > 0 {
		median := medianInt(delays)
		p95 := percentile(delays, .95)
		stats.MedianMS, stats.P95MS = &median, &p95
	}
	return stats
}

func sampleMedians(samples map[string][]healthSample, candidates []string) map[string]*int {
	result := make(map[string]*int)
	for _, candidate := range candidates {
		delays := []int{}
		for _, sample := range samples[candidate] {
			if sample.OK && sample.DelayMS != nil {
				delays = append(delays, *sample.DelayMS)
			}
		}
		if len(delays) > 0 {
			value := medianInt(delays)
			result[candidate] = &value
		}
	}
	return result
}

func medianInt(values []int) int {
	copyValues := append([]int(nil), values...)
	sort.Ints(copyValues)
	n := len(copyValues)
	if n%2 == 1 {
		return copyValues[n/2]
	}
	return (copyValues[n/2-1] + copyValues[n/2]) / 2
}
func medianInt64(values []int64) int64 {
	copyValues := append([]int64(nil), values...)
	sort.Slice(copyValues, func(i, j int) bool { return copyValues[i] < copyValues[j] })
	n := len(copyValues)
	if n%2 == 1 {
		return copyValues[n/2]
	}
	return (copyValues[n/2-1] + copyValues[n/2]) / 2
}
func percentile(values []int, q float64) int {
	copyValues := append([]int(nil), values...)
	sort.Ints(copyValues)
	position := int(float64(len(copyValues)-1)*q + .999999)
	if position >= len(copyValues) {
		position = len(copyValues) - 1
	}
	return copyValues[position]
}
func positiveSpeeds(values []int64) []int64 {
	result := []int64{}
	for _, value := range values {
		if value > 0 {
			result = append(result, value)
		}
	}
	return result
}
func uniqueCandidates(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if value != "" && value != "block" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
func without(values, removed []string) []string {
	result := []string{}
	for _, value := range values {
		if !contains(removed, value) {
			result = append(result, value)
		}
	}
	return result
}
func candidateIndex(values []string, value string) int {
	for index, candidate := range values {
		if candidate == value {
			return index
		}
	}
	return len(values)
}
func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func roundOne(value float64) float64 { return math.Round(value*10) / 10 }
func defaultInt(value, fallback, min, max int) int {
	if value < min || value > max {
		return fallback
	}
	return value
}
func defaultIntAllowZero(value, fallback, min, max int) int {
	if value < min || value > max {
		return fallback
	}
	return value
}
func defaultFloat(value, fallback, min, max float64) float64 {
	if value < min || value > max {
		return fallback
	}
	return value
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func strconvItoa(value int) string { return fmt.Sprint(value) }
func serviceSelectorTag(policyID, serviceID string) string {
	sum := sha256Bytes(policyID + "\x00" + serviceID)
	return "svc-" + sum[:20]
}
func serviceBlockTag(policyID string) string {
	sum := sha256Bytes(policyID)
	return "svc-block-" + sum[:16]
}
func sha256Bytes(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
