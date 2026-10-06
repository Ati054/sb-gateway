package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	optimizationConfirmations   = 2
	healthFailureConfirmations  = 3
	healthRecoveryConfirmations = 3
)

type optimizationComparison struct {
	At               string `json:"at"`
	Candidate        string `json:"candidate"`
	Result           string `json:"result"`
	Reason           string `json:"reason"`
	ActiveDelayMS    *int   `json:"active_delay_ms,omitempty"`
	CandidateDelayMS *int   `json:"candidate_delay_ms,omitempty"`
}

type latencyComparison struct {
	Active           string  `json:"active"`
	ActiveDelayMS    int     `json:"active_delay_ms"`
	CandidateDelayMS int     `json:"candidate_delay_ms"`
	ActiveAt         float64 `json:"active_at"`
	CandidateAt      float64 `json:"candidate_at"`
	ExpiresAt        float64 `json:"expires_at"`
}

// Publish only qualified, fresh ordinary quality evidence used by soft selection.
// This diagnostic does not probe nodes or change their ranking.
func currentLatencyComparisons(now time.Time, item *policyHealthState, candidates []string, p effectivePolicySettings) map[string]latencyComparison {
	active := item.RuntimeSelected
	if !item.RuntimeConfirmed || active == "" || active == "block" || active != item.Selected || !contains(candidates, active) {
		return nil
	}
	window := float64(minInt(p.backup, maxInt(p.active*2, 120)))
	qualified := func(candidate string, reserve bool) bool {
		age, good := qualitySampleAge(now, item, candidate)
		return good && age <= window && item.QualityOK[candidate] && item.AvailabilityOK[candidate] &&
			item.AvailabilityFailures[candidate] == 0 && (!reserve || item.Recoveries[candidate] >= p.recoveryThreshold)
	}
	if !qualified(active, false) {
		return nil
	}
	baseline := item.Samples[active][len(item.Samples[active])-1]
	result := make(map[string]latencyComparison)
	for _, candidate := range candidates {
		if candidate == active || !qualified(candidate, true) {
			continue
		}
		sample := item.Samples[candidate][len(item.Samples[candidate])-1]
		result[candidate] = latencyComparison{
			Active: active, ActiveDelayMS: *baseline.DelayMS, CandidateDelayMS: *sample.DelayMS,
			ActiveAt: baseline.At, CandidateAt: sample.At, ExpiresAt: min(baseline.At, sample.At) + window,
		}
	}
	return result
}

const (
	optimizationWin          = "win"
	optimizationLoss         = "loss"
	optimizationInconclusive = "inconclusive"
)

type effectivePolicySettings struct {
	mode              string
	failureThreshold  int
	recoveryThreshold int
	improvement       int
	active            int
	backup            int
	shortlist         int
	batch             int
	liveness          int
	failureRetry      int
	blockRecovery     int
}

func policySettings(policy healthPolicy, mode string) effectivePolicySettings {
	return effectivePolicySettings{
		mode:              mode,
		failureThreshold:  healthFailureConfirmations,
		recoveryThreshold: healthRecoveryConfirmations,
		improvement:       defaultIntAllowZero(policy.SwitchImprovementMS, 50, 0, 30000),
		active:            defaultInt(policy.ActiveCheckSeconds, 60, 1, 3600),
		backup:            maxInt(defaultInt(policy.ActiveCheckSeconds, 60, 1, 3600)*2, 120),
		shortlist:         defaultInt(policy.ProbeBatchSize, 10, 1, 64),
		batch:             defaultInt(policy.ProbeBatchSize, 10, 1, 64),
		liveness:          defaultInt(policy.ActiveLivenessSeconds, int(activeLivenessInterval/time.Second), 2, 30),
		failureRetry:      minInt(int(failureRetryInterval/time.Second), defaultInt(policy.ActiveLivenessSeconds, int(activeLivenessInterval/time.Second), 2, 30)),
		blockRecovery:     int(outageRetryInterval / time.Second),
	}
}

// The working pool is recomputed from evidence, never from inventory position.
// Keep the current usable path pinned: pool maintenance must not cause a switch.
func workingShortlist(now time.Time, selected string, candidates []string, mode string, groups map[string]int, item *policyHealthState, p effectivePolicySettings) []string {
	eligible := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if item.AvailabilityOK[candidate] && item.QualityOK[candidate] && item.AvailabilityFailures[candidate] == 0 && item.Recoveries[candidate] >= p.recoveryThreshold {
			eligible = append(eligible, candidate)
		}
	}
	ranked := rankCandidates(eligible, mode, groups, item.DailyStats, item.MedianDelayMS)
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
	available = rankCandidates(available, mode, groups, item.DailyStats, item.MedianDelayMS)
	if len(available) > 0 {
		return available[0]
	}
	return ""
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

func selectDesired(now time.Time, mode, selected string, candidates []string, groups map[string]int, daily map[string]healthStats, medians map[string]*int, measured map[string]probeEvidence, quality, available map[string]bool, item *policyHealthState, p effectivePolicySettings) (string, string) {
	rank := func(values []string) []string {
		return rankCandidates(values, mode, groups, daily, medians)
	}
	// Current availability can restore service even without primary quality.
	// Qualified primary quality still ranks the confirmed-reserve tier below.
	fresh := func(candidate string) bool {
		evidence, ok := measured[candidate]
		return ok && evidence.OK
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
		confirmedValues, freshValues := []string{}, []string{}
		for _, candidate := range candidates {
			if candidate == selected || !fresh(candidate) {
				continue
			}
			if confirmedReserve(candidate) {
				confirmedValues = append(confirmedValues, candidate)
			} else {
				freshValues = append(freshValues, candidate)
			}
		}
		// Historical confirmation ranks current successes, but never replaces
		// a fresh probe during a confirmed outage.
		alternatives := rank(confirmedValues)
		if len(alternatives) == 0 {
			alternatives = rank(freshValues)
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
			// A reachable active path must not be replaced using a reserve's
			// old quality snapshot. Availability failover has its own fast path.
			age, recentQuality := qualitySampleAge(now, item, candidate)
			freshForSoftSwitch := recentQuality && age <= float64(minInt(p.backup, maxInt(p.active*2, 120)))
			if candidate != selected && quality[candidate] && known(candidate, p.recoveryThreshold) &&
				item.AvailabilityFailures[candidate] == 0 && freshForSoftSwitch {
				stable = append(stable, candidate)
			}
		}
		priorityReturn := ""
		if mode == "priority" {
			higher := []string{}
			for _, candidate := range stable {
				if groups[candidate] < groups[selected] || (groups[candidate] == groups[selected] && candidateIndex(candidates, candidate) < candidateIndex(candidates, selected)) {
					higher = append(higher, candidate)
				}
			}
			if higher = rank(higher); len(higher) > 0 {
				priorityReturn = higher[0]
			}
		}
		if item.Failures[selected] >= p.failureThreshold && len(stable) > 0 {
			// Primary quality failure is not necessarily an availability outage.
			// Only leave it for a freshly qualified reserve.
			desired, reason = rank(stable)[0], "active-degraded"
		} else if priorityReturn != "" {
			desired, reason = priorityReturn, "higher-priority-recovered"
		} else if mode != "priority" {
			measuredStable := []string{}
			for _, candidate := range stable {
				evidence, measuredNow := measured[candidate]
				pending := candidate == item.OptimizationCandidate && item.OptimizationChecks > 0
				if pending || measuredNow && evidence.OK && evidence.DelayMS != nil && !evidence.QualityUnmeasured {
					measuredStable = append(measuredStable, candidate)
				}
			}
			if better := meaningfullyBetter(selected, measuredStable, medians, p); better != "" {
				desired, reason = better, "meaningfully-faster"
			}
		}
	}
	return desired, reason
}

func meaningfullyBetter(selected string, candidates []string, delays map[string]*int, p effectivePolicySettings) string {
	current := delays[selected]
	if current == nil || *current <= 0 {
		return ""
	}
	latencyQualified := []string{}
	for _, candidate := range candidates {
		if delay := delays[candidate]; delay != nil && *delay > 0 && *current-*delay > p.improvement {
			latencyQualified = append(latencyQualified, candidate)
		}
	}
	sort.SliceStable(latencyQualified, func(i, j int) bool { return *delays[latencyQualified[i]] < *delays[latencyQualified[j]] })
	if len(latencyQualified) == 0 {
		return ""
	}
	return latencyQualified[0]
}

func qualitySampleAge(now time.Time, item *policyHealthState, candidate string) (float64, bool) {
	samples := item.Samples[candidate]
	if len(samples) == 0 {
		return 0, false
	}
	sample := samples[len(samples)-1]
	age := float64(now.Unix()) - sample.At
	return age, sample.At > 0 && age >= 0 && sample.OK && sample.DelayMS != nil && *sample.DelayMS > 0
}

func isPlannedOptimization(reason string) bool {
	return reason == "meaningfully-faster"
}

func gatePlannedOptimization(now time.Time, selected, desired, reason string, comparison *optimizationComparison, item *policyHealthState, p effectivePolicySettings) (string, string) {
	if desired != selected && !isPlannedOptimization(reason) {
		clearOptimizationCandidate(item)
		return desired, reason
	}
	if item.OptimizationBaseline != "" && item.OptimizationBaseline != selected {
		clearOptimizationCandidate(item)
		return selected, ""
	}
	if comparison == nil {
		if item.OptimizationChecks > 0 && !freshComparisonAt(now, item.OptimizationLastResult, p) {
			clearOptimizationCandidate(item)
		}
		return selected, ""
	}
	if comparison.Result != optimizationWin || comparison.Candidate != desired {
		clearOptimizationCandidate(item)
		item.OptimizationLastResult = comparison
		return selected, ""
	}
	previous := item.OptimizationLastResult
	if item.OptimizationCandidate != desired || previous == nil ||
		!freshComparisonAt(now, previous, p) {
		item.OptimizationBaseline, item.OptimizationCandidate = selected, desired
		item.OptimizationChecks = 0
	}
	// Reused evidence in a cycle cannot count as another independent win.
	if previous != nil && previous.At == comparison.At {
		return selected, ""
	}
	item.OptimizationLastResult = comparison
	item.OptimizationChecks++
	if item.OptimizationChecks < optimizationConfirmations {
		return selected, ""
	}
	clearOptimizationCandidate(item)
	return desired, "meaningfully-faster"
}

func freshComparisonAt(now time.Time, comparison *optimizationComparison, p effectivePolicySettings) bool {
	if comparison == nil {
		return false
	}
	at, err := time.Parse(time.RFC3339, comparison.At)
	age := now.Sub(at)
	return err == nil && age >= 0 && age <= time.Duration(maxInt(p.active*2, 120))*time.Second
}

// A candidate needs a new ordinary probe. At a one-slot limit the active
// measurement may come from the preceding cycle, with the same freshness bound.
func regularOptimizationComparison(now time.Time, selected, candidate string, measured map[string]probeEvidence, item *policyHealthState, quality, available bool, p effectivePolicySettings) *optimizationComparison {
	if _, fresh := measured[candidate]; !fresh {
		return nil
	}
	pair := map[string]probeEvidence{candidate: measured[candidate]}
	if active, ok := measured[selected]; ok {
		pair[selected] = active
	} else {
		samples := item.Samples[selected]
		if len(samples) > 0 {
			last := samples[len(samples)-1]
			age := float64(now.Unix()) - last.At
			if last.At > 0 && age >= 0 && age <= float64(maxInt(p.active*2, 120)) {
				pair[selected] = probeEvidence{OK: last.OK, DelayMS: last.DelayMS}
			}
		}
	}
	return compareOptimization(now, selected, candidate, pair, quality, available, p)
}

func freshOptimizationWin(selected, candidate string, measured map[string]probeEvidence, p effectivePolicySettings) bool {
	activeEvidence, activeOK := measured[selected]
	candidateEvidence, candidateOK := measured[candidate]
	if !activeOK || !candidateOK || !activeEvidence.OK || !candidateEvidence.OK || activeEvidence.DelayMS == nil || candidateEvidence.DelayMS == nil {
		return false
	}
	delays := map[string]*int{selected: activeEvidence.DelayMS, candidate: candidateEvidence.DelayMS}
	return meaningfullyBetter(selected, []string{candidate}, delays, p) == candidate
}

func compareOptimization(now time.Time, selected, candidate string, measured map[string]probeEvidence, candidateQuality, candidateAvailable bool, p effectivePolicySettings) *optimizationComparison {
	comparison := &optimizationComparison{At: now.UTC().Format(time.RFC3339), Candidate: candidate}
	active, activeMeasured := measured[selected]
	reserve, candidateMeasured := measured[candidate]
	comparison.ActiveDelayMS = active.DelayMS
	comparison.CandidateDelayMS = reserve.DelayMS
	switch {
	case !activeMeasured || !candidateMeasured:
		comparison.Result, comparison.Reason = optimizationInconclusive, "pair-incomplete"
	case !active.OK || active.DelayMS == nil:
		comparison.Result, comparison.Reason = optimizationLoss, "active-https-failed"
	case !reserve.OK || reserve.DelayMS == nil || !candidateQuality || !candidateAvailable:
		comparison.Result, comparison.Reason = optimizationLoss, "candidate-quality"
	case freshOptimizationWin(selected, candidate, measured, p):
		comparison.Result, comparison.Reason = optimizationWin, "better"
	default:
		comparison.Result, comparison.Reason = optimizationLoss, "not-better"
	}
	return comparison
}

func clearOptimizationCandidate(item *policyHealthState) {
	item.OptimizationBaseline = ""
	item.OptimizationCandidate = ""
	item.OptimizationChecks = 0
}

func rankCandidates(values []string, mode string, groups map[string]int, _ map[string]healthStats, medians map[string]*int) []string {
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
		leftDelay, rightDelay := candidateDelay(left, medians), candidateDelay(right, medians)
		if (leftDelay > 0) != (rightDelay > 0) {
			return leftDelay > 0
		}
		if leftDelay > 0 && leftDelay != rightDelay {
			return leftDelay < rightDelay
		}
		return positions[left] < positions[right]
	})
	return result
}

func candidateDelay(candidate string, medians map[string]*int) int {
	if medians != nil && medians[candidate] != nil && *medians[candidate] > 0 {
		return *medians[candidate]
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
	if sample.OK {
		bucket.Successes++
		if sample.DelayMS == nil {
			days[day] = bucket
			return
		}
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
		if sample.OK {
			if sample.DelayMS != nil {
				delays = append(delays, *sample.DelayMS)
			}
		} else {
			failures++
		}
	}
	return buildStats(len(samples), len(samples)-failures, failures, delays, 0)
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
func percentile(values []int, q float64) int {
	copyValues := append([]int(nil), values...)
	sort.Ints(copyValues)
	position := int(float64(len(copyValues)-1)*q + .999999)
	if position >= len(copyValues) {
		position = len(copyValues) - 1
	}
	return copyValues[position]
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
