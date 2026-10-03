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
	optimizationConfirmations         = 2
	maxSpeedSwitchLatencyRegressionMS = 50
)

type optimizationComparison struct {
	At                string `json:"at"`
	Candidate         string `json:"candidate"`
	Result            string `json:"result"`
	Reason            string `json:"reason"`
	ActiveDelayMS     *int   `json:"active_delay_ms,omitempty"`
	CandidateDelayMS  *int   `json:"candidate_delay_ms,omitempty"`
	ActiveSpeedBPS    *int64 `json:"active_speed_bps,omitempty"`
	CandidateSpeedBPS *int64 `json:"candidate_speed_bps,omitempty"`
}

const (
	optimizationWin          = "win"
	optimizationLoss         = "loss"
	optimizationInconclusive = "inconclusive"
)

type effectivePolicySettings struct {
	mode                    string
	speedDegradationPercent int
	failureThreshold        int
	recoveryThreshold       int
	qualityWindow           int
	maxLoss                 float64
	maxLatency              int
	cooldown                int
	improvement             int
	speedEnabled            bool
	speedImprovement        int
	speedInterval           int
	speedBytes              int
	speedCandidates         int
	active                  int
	backup                  int
	fullScan                int
	shortlist               int
	batch                   int
	liveness                int
	failureRetry            int
	blockRecovery           int
}

func policySettings(policy healthPolicy, mode string) effectivePolicySettings {
	drop := 0
	if mode == "best" {
		drop = 50
	}
	if policy.SpeedDegradationPercent != nil {
		drop = defaultIntAllowZero(*policy.SpeedDegradationPercent, drop, 0, 99)
	}
	speedEnabled := (mode == "best" || drop > 0) && (policy.SpeedCheckEnabled == nil || *policy.SpeedCheckEnabled)
	return effectivePolicySettings{
		mode: mode, speedDegradationPercent: drop,
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

// Routine speed follows existing quality intervals. Keep recovery/reference
// lifetimes separate: faster sampling must not weaken the anti-flap guards.
func speedRoutineInterval(candidate, selected string, item *policyHealthState, p effectivePolicySettings) int {
	if candidate == selected {
		return minInt(900, maxInt(180, 3*p.active))
	}
	if _, recovering := item.SpeedProbation[candidate]; recovering {
		return minInt(900, maxInt(300, 3*p.backup))
	}
	if contains(item.Shortlist, candidate) {
		return minInt(p.speedInterval, maxInt(300, 3*p.backup))
	}
	return p.speedInterval
}

// Explore outside the working pool slowly; a per-policy batch floor bounds
// cold-start downloads, without delaying a due active probe behind a reserve.
func speedProbeCandidates(now time.Time, selected string, candidates []string, measured map[string]probeEvidence, item *policyHealthState, p effectivePolicySettings) []string {
	latest := float64(0)
	for _, at := range item.LastSpeedProbeAt {
		if at > latest {
			latest = at
		}
	}
	if latest > 0 && float64(now.Unix())-latest < 60 && (selected == "" || float64(now.Unix())-item.LastSpeedProbeAt[selected] < float64(speedRoutineInterval(selected, selected, item, p))) {
		return nil
	}
	eligible := []string{}
	for _, candidate := range candidates {
		available := item.AvailabilityOK[candidate] && item.AvailabilityFailures[candidate] == 0
		if evidence, ok := measured[candidate]; ok {
			available = evidence.OK
		}
		last := item.LastSpeedProbeAt[candidate]
		interval := speedRoutineInterval(candidate, selected, item, p)
		if available && (last == 0 || float64(now.Unix())-last >= float64(interval)) {
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
	if item.SpeedHistory == nil {
		item.SpeedHistory = make(map[string][]speedSample)
	}
	if item.SpeedProbation == nil {
		item.SpeedProbation = make(map[string]speedProbation)
	}
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
	if item.LastSpeedSuccessAt == nil {
		item.LastSpeedSuccessAt = make(map[string]float64)
	}
	if item.LastSpeedProbeStatus == nil {
		item.LastSpeedProbeStatus = make(map[string]string)
	}
	if item.OptimizationBackoff == nil {
		item.OptimizationBackoff = make(map[string]float64)
	}
	if item.OutagePenalty == nil {
		item.OutagePenalty = make(map[string]outagePenalty)
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
		stable, speedStable := []string{}, []string{}
		for _, candidate := range candidates {
			// A reachable active path must not be replaced using a reserve's
			// old quality snapshot. Availability failover has its own fast path.
			lastProbe := item.LastProbeAt[candidate]
			age := float64(now.Unix()) - lastProbe
			freshForSoftSwitch := lastProbe > 0 && age >= 0 && age <= float64(minInt(p.backup, maxInt(p.active*2, 120)))
			if candidate != selected && quality[candidate] && known(candidate, p.recoveryThreshold) &&
				item.AvailabilityFailures[candidate] == 0 && lastProbe > 0 && age >= 0 && age <= float64(maxInt(p.backup, 1800)) &&
				!outagePenaltyActive(now, item, candidate) && !speedProbationActive(now, item, candidate, p) {
				speedStable = append(speedStable, candidate)
			}
			if candidate != selected && quality[candidate] && known(candidate, p.recoveryThreshold) &&
				item.AvailabilityFailures[candidate] == 0 && freshForSoftSwitch && !outagePenaltyActive(now, item, candidate) && !speedProbationActive(now, item, candidate, p) {
				stable = append(stable, candidate)
			}
		}
		priorityReturn := ""
		if mode == "priority" && float64(now.Unix()) >= item.CooldownUntil {
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
			// A slow but reachable path is not an outage. Only leave it for a
			// confirmed healthy reserve, and honour cooldown. Otherwise two
			// slow paths can alternate on every tick forever.
			desired, reason = rank(stable)[0], "active-degraded"
		} else if priorityReturn != "" {
			desired, reason = priorityReturn, "higher-priority-recovered"
		} else if next := speedDegradationCandidate(now, selected, rank(speedStable), item, p); next != "" {
			desired, reason = next, "speed-degraded"
		} else if p.speedEnabled && p.speedDegradationPercent > 0 && item.SpeedDegradation != nil {
			// The bounded investigation owns this decision, not the old median.
		} else if mode != "priority" {
			if better := meaningfullyBetter(selected, withoutOptimizationBackoff(now, stable, item), medians, speeds, p); better != "" {
				desired, reason = better, "meaningfully-faster"
			}
		}
		// All soft switches respect cooldown. Confirmed availability failure
		// is handled above and is never delayed by this guard.
		if desired != selected && reason != "speed-degraded" && float64(now.Unix()) < item.CooldownUntil {
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
	latencyQualified := []string{}
	if p.speedEnabled {
		currentSpeed := speeds[selected]
		if currentSpeed == nil || *currentSpeed <= 0 {
			return ""
		}
		speedQualified := []string{}
		for _, candidate := range candidates {
			delay, speed := delays[candidate], speeds[candidate]
			if delay == nil || *delay <= 0 || speed == nil || *speed <= 0 {
				continue
			}
			// A faster path need not also beat the HTTPS latency threshold.
			// Bound its latency regression and require a strict improvement in
			// responsive throughput so the same evidence cannot justify a switch
			// straight back in the other direction.
			if *speed > *currentSpeed &&
				*speed*100 >= *currentSpeed*int64(100+p.speedImprovement) &&
				*delay <= *current+maxSpeedSwitchLatencyRegressionMS &&
				*speed*int64(*current) > *currentSpeed*int64(*delay) {
				speedQualified = append(speedQualified, candidate)
			}
			if *current-*delay >= p.improvement &&
				*speed*100 >= *currentSpeed*65 &&
				*speed*int64(*current) > *currentSpeed*int64(*delay) {
				latencyQualified = append(latencyQualified, candidate)
			}
		}
		if len(speedQualified) > 0 {
			sort.SliceStable(speedQualified, func(i, j int) bool {
				if *speeds[speedQualified[i]] != *speeds[speedQualified[j]] {
					return *speeds[speedQualified[i]] > *speeds[speedQualified[j]]
				}
				return *delays[speedQualified[i]] < *delays[speedQualified[j]]
			})
			return speedQualified[0]
		}
		// Without a speed winner, a responsive path may trade away at most
		// 35% throughput, provided its latency gain outweighs that loss.
		sort.SliceStable(latencyQualified, func(i, j int) bool {
			if *delays[latencyQualified[i]] != *delays[latencyQualified[j]] {
				return *delays[latencyQualified[i]] < *delays[latencyQualified[j]]
			}
			return *speeds[latencyQualified[i]] > *speeds[latencyQualified[j]]
		})
	} else {
		for _, candidate := range candidates {
			if delays[candidate] != nil && *current-*delays[candidate] >= p.improvement {
				latencyQualified = append(latencyQualified, candidate)
			}
		}
		sort.SliceStable(latencyQualified, func(i, j int) bool { return *delays[latencyQualified[i]] < *delays[latencyQualified[j]] })
	}
	if len(latencyQualified) == 0 {
		return ""
	}
	return latencyQualified[0]
}

// A planned best-mode switch is intentionally slower than outage recovery.
// The rolling history may nominate a candidate, but only two fresh, paired
// comparisons may move traffic. This prevents a stale speed sample or one
// transient latency window from becoming a ten-minute sticky selection.
func reconsiderPlannedOptimization(selected, desired, reason string, comparison *optimizationComparison, item *policyHealthState, medians map[string]*int, speeds map[string]*int64, p effectivePolicySettings) {
	pending := item.OptimizationCandidate
	if pending == "" || desired == selected || desired == pending || reason != "meaningfully-faster" ||
		comparison == nil || comparison.Candidate != pending || comparison.Result != optimizationWin ||
		item.OptimizationChecks+1 < optimizationConfirmations {
		return
	}
	// selectDesired has already applied recovery, freshness, penalty and cooldown
	// gates. Avoid an intermediate hop only for a material lead over the freshly
	// confirmed candidate; the new nominee must still earn its own two wins.
	delays := map[string]*int{pending: comparison.CandidateDelayMS, desired: medians[desired]}
	throughput := map[string]*int64{pending: comparison.CandidateSpeedBPS, desired: speeds[desired]}
	if meaningfullyBetter(pending, []string{desired}, delays, throughput, p) != desired {
		return
	}
	item.OptimizationLastResult = comparison
	clearOptimizationCandidate(item)
	item.OptimizationRetryAfter = 0
}

func gatePlannedOptimization(now time.Time, selected, desired, reason string, comparison *optimizationComparison, item *policyHealthState, p effectivePolicySettings) (string, string) {
	ensureHealthMaps(item)
	blocked := func(node string) bool {
		return outagePenaltyActive(now, item, node) || speedProbationActive(now, item, node, p)
	}
	if item.OptimizationCandidate != "" && blocked(item.OptimizationCandidate) {
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
	}
	emergency := reason == "active-unavailable" || reason == "fresh-path-available"
	if desired != selected && blocked(desired) && !emergency {
		return selected, ""
	}
	if desired != selected && !isPlannedOptimization(reason) {
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
		return desired, reason
	}

	if item.OptimizationCandidate != "" {
		if comparison == nil || comparison.Candidate != item.OptimizationCandidate {
			return selected, ""
		}
		item.OptimizationLastResult = comparison
		if item.OptimizationSpeedDegraded && (comparison.Reason == "active-speed-missing" || comparison.Reason == "active-https-failed") {
			if item.SpeedDegradation != nil {
				item.SpeedDegradation.RetryAfter = float64(now.Unix() + speedActiveInterval)
			}
			clearOptimizationCandidate(item)
			item.OptimizationBudgetAfter = float64(now.Unix() + 300)
			item.OptimizationRetryAfter = 0
			return selected, ""
		}
		if item.OptimizationSpeedDegraded && item.SpeedDegradation != nil {
			item.SpeedDegradation.Pairs++
			if handleSpeedSurveyComparison(now, comparison, item, p) {
				return selected, ""
			}
		}
		if comparison.Reason == "active-speed-recovered" || comparison.Reason == "active-https-failed" {
			clearOptimizationCandidate(item)
			item.OptimizationBudgetAfter = float64(now.Unix() + 300)
			item.OptimizationRetryAfter = 0
			return selected, ""
		}
		if comparison.Result == optimizationInconclusive {
			item.OptimizationChecks = 0
			item.OptimizationIncomplete++
			if item.OptimizationIncomplete < 2 {
				item.OptimizationNextAt = float64(now.Unix() + int64(maxInt(p.active, 120)))
				return selected, ""
			}
			if comparison.Reason == "active-speed-missing" {
				// Another reserve cannot establish a baseline either.
				clearOptimizationCandidate(item)
				item.OptimizationRetryAfter = float64(now.Unix() + int64(maxInt(p.backup, 300)))
				item.OptimizationBudgetAfter = float64(now.Unix() + 300)
			} else {
				failOptimizationCandidate(now, item.OptimizationCandidate, item, p)
			}
			return selected, ""
		}
		if comparison.Result != optimizationWin {
			failOptimizationCandidate(now, item.OptimizationCandidate, item, p)
			return selected, ""
		}
		item.OptimizationIncomplete = 0
		item.OptimizationChecks++
		if item.OptimizationChecks < optimizationConfirmations {
			item.OptimizationNextAt = float64(now.Unix() + int64(p.active))
			return selected, ""
		}
		candidate, winnerReason := item.OptimizationCandidate, "meaningfully-faster"
		if item.OptimizationSpeedDegraded {
			winnerReason = "speed-degraded"
		}
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
		return candidate, winnerReason
	}

	if desired == selected || !isPlannedOptimization(reason) || float64(now.Unix()) < item.OptimizationRetryAfter {
		return selected, ""
	}
	if reason == "speed-degraded" && !speedDegradationReady(now, selected, item, p) {
		return selected, ""
	}
	item.OptimizationBaseline = selected
	item.OptimizationCandidate = desired
	item.OptimizationSpeedDegraded = reason == "speed-degraded"
	item.OptimizationChecks = 0
	item.OptimizationIncomplete = 0
	item.OptimizationNextAt = float64(now.Unix() + int64(p.active))
	if item.OptimizationNextAt < item.OptimizationBudgetAfter {
		item.OptimizationNextAt = item.OptimizationBudgetAfter
	}
	item.OptimizationRetryAfter = 0
	return selected, ""
}

func withoutOptimizationBackoff(now time.Time, candidates []string, item *policyHealthState) []string {
	values := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if until := item.OptimizationBackoff[candidate]; until > float64(now.Unix()) {
			continue
		}
		values = append(values, candidate)
	}
	return values
}

func freshOptimizationWin(selected, candidate string, measured map[string]probeEvidence, measuredSpeed map[string]int64, p effectivePolicySettings) bool {
	activeEvidence, activeOK := measured[selected]
	candidateEvidence, candidateOK := measured[candidate]
	if !activeOK || !candidateOK || !activeEvidence.OK || !candidateEvidence.OK || activeEvidence.DelayMS == nil || candidateEvidence.DelayMS == nil {
		return false
	}
	if p.maxLatency > 0 && *candidateEvidence.DelayMS > p.maxLatency {
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

func compareOptimization(now time.Time, selected, candidate string, measured map[string]probeEvidence, measuredSpeed map[string]int64, candidateQuality, candidateAvailable bool, p effectivePolicySettings) *optimizationComparison {
	comparison := &optimizationComparison{At: now.UTC().Format(time.RFC3339), Candidate: candidate}
	active := measured[selected]
	reserve := measured[candidate]
	comparison.ActiveDelayMS = active.DelayMS
	comparison.CandidateDelayMS = reserve.DelayMS
	if speed, ok := measuredSpeed[selected]; ok {
		comparison.ActiveSpeedBPS = &speed
	}
	if speed, ok := measuredSpeed[candidate]; ok {
		comparison.CandidateSpeedBPS = &speed
	}
	switch {
	case !active.OK || active.DelayMS == nil:
		comparison.Result, comparison.Reason = optimizationLoss, "active-https-failed"
	case !reserve.OK || reserve.DelayMS == nil || !candidateQuality || !candidateAvailable:
		comparison.Result, comparison.Reason = optimizationLoss, "candidate-quality"
	case p.speedEnabled && comparison.ActiveSpeedBPS == nil:
		comparison.Result, comparison.Reason = optimizationInconclusive, "active-speed-missing"
	case p.speedEnabled && comparison.CandidateSpeedBPS == nil:
		comparison.Result, comparison.Reason = optimizationInconclusive, "candidate-speed-missing"
	case freshOptimizationWin(selected, candidate, measured, measuredSpeed, p):
		comparison.Result, comparison.Reason = optimizationWin, "better"
	default:
		comparison.Result, comparison.Reason = optimizationLoss, "not-better"
	}
	return comparison
}

func clearOptimizationCandidate(item *policyHealthState) {
	item.OptimizationSpeedDegraded = false
	item.OptimizationBaseline = ""
	item.OptimizationCandidate = ""
	item.OptimizationChecks = 0
	item.OptimizationIncomplete = 0
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
