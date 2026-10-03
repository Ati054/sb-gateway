package agent

import (
	"sort"
	"time"
)

const (
	speedHistoryAge      = 6 * 60 * 60
	speedActiveInterval  = 15 * 60
	speedRecoverySpacing = 5 * 60
	speedEpisodeLifetime = 30 * 60
)

type speedSample struct {
	At  float64 `json:"at"`
	BPS int64   `json:"bps"`
}

type speedSelectionReference struct {
	Node string  `json:"node"`
	At   float64 `json:"at"`
	BPS  int64   `json:"bps"`
}

type speedDegradation struct {
	Node            string                             `json:"node"`
	Since           float64                            `json:"since"`
	CycleAt         float64                            `json:"cycle_at"`
	RetryAfter      float64                            `json:"retry_after,omitempty"`
	BaselineBPS     int64                              `json:"baseline_bps"`
	RecoveryPercent int                                `json:"recovery_percent"`
	Pairs           int                                `json:"pairs"`
	Tried           []string                           `json:"tried,omitempty"`
	Recoveries      int                                `json:"recoveries,omitempty"`
	LastRecoveryAt  float64                            `json:"last_recovery_at,omitempty"`
	SurveyTargets   []string                           `json:"survey_targets,omitempty"`
	Survey          map[string]*optimizationComparison `json:"survey,omitempty"`
	SurveyComplete  bool                               `json:"survey_complete,omitempty"`
	Finalists       []string                           `json:"finalists,omitempty"`
}

type speedProbation struct {
	LastAt          float64 `json:"last_at"`
	Until           float64 `json:"until"`
	BaselineBPS     int64   `json:"baseline_bps"`
	RecoveryPercent int     `json:"recovery_percent"`
	Count           int     `json:"count"`
	Recoveries      int     `json:"recoveries,omitempty"`
	LastRecoveryAt  float64 `json:"last_recovery_at,omitempty"`
}

func freshSpeedSamples(now time.Time, samples []speedSample) []speedSample {
	values := make([]speedSample, 0, len(samples))
	at := float64(now.Unix())
	for _, sample := range samples {
		if sample.BPS > 0 && sample.At > 0 && sample.At <= at && at-sample.At <= speedHistoryAge {
			values = append(values, sample)
		}
	}
	if len(values) > 12 {
		values = values[len(values)-12:]
	}
	return values
}

func speedValues(samples []speedSample) []int64 {
	values := make([]int64, 0, len(samples))
	for _, sample := range samples {
		values = append(values, sample.BPS)
	}
	if len(values) > 5 {
		values = values[len(values)-5:]
	}
	return values
}

func recentSpeedBaseline(samples []speedSample) int64 {
	// Confirmation bursts must not manufacture an independent baseline.
	values := []int64{}
	last := float64(0)
	for i := len(samples) - 1; i >= 0; i-- {
		if last == 0 || last-samples[i].At >= speedRecoverySpacing {
			values = append(values, samples[i].BPS)
			last = samples[i].At
			if len(values) == 5 {
				break
			}
		}
	}
	if len(values) < 3 {
		return 0
	}
	return medianInt64(values)
}

func countSpeedRecovery(at float64, speed, baseline int64, recoveryPercent int, count *int, last *float64) {
	if at < *last || at-*last > speedActiveInterval*2 {
		*count, *last = 0, 0
	}
	if speed <= 0 || baseline <= 0 || speed*100 < baseline*int64(maxInt(recoveryPercent, 80)) {
		*count, *last = 0, 0
		return
	}
	if *last == 0 || at-*last >= speedRecoverySpacing {
		*count = minInt(*count+1, 3)
		*last = at
	}
}

func updateSpeedHistory(now time.Time, selected string, candidates, targets []string, measured map[string]int64, status map[string]string, item *policyHealthState, p effectivePolicySettings) map[string]*int64 {
	ensureHealthMaps(item)
	if !p.speedEnabled || p.speedDegradationPercent == 0 || (item.SpeedDegradation != nil && item.SpeedDegradation.Node != selected) {
		item.SpeedDegradation = nil
	}
	medians := make(map[string]*int64, len(candidates))
	at := float64(now.Unix())
	for _, node := range candidates {
		samples, present := item.SpeedHistory[node]
		if !present {
			// Legacy state dates only its last success, not all five old points.
			old := positiveSpeeds(item.SpeedSamplesBPS[node])
			if len(old) > 0 && item.LastSpeedSuccessAt[node] > 0 {
				samples = []speedSample{{At: item.LastSpeedSuccessAt[node], BPS: old[len(old)-1]}}
			}
		}
		samples = freshSpeedSamples(now, samples)
		baseline := recentSpeedBaseline(samples)
		if reference := item.SpeedSelectionReference; baseline == 0 && node == selected && reference != nil && reference.Node == selected &&
			at >= reference.At && at-reference.At <= speedActiveInterval*3 {
			baseline = reference.BPS
		}
		speed, success := measured[node]
		if contains(targets, node) {
			item.LastSpeedProbeAt[node], item.LastSpeedProbeStatus[node] = at, status[node]
			if success && speed > 0 {
				item.LastSpeedSuccessAt[node] = at
				if len(samples) == 0 || samples[len(samples)-1].At < at {
					samples = append(samples, speedSample{At: at, BPS: speed})
				}
			}
			if penalty, ok := item.SpeedProbation[node]; ok {
				countSpeedRecovery(at, speed, penalty.BaselineBPS, penalty.RecoveryPercent, &penalty.Recoveries, &penalty.LastRecoveryAt)
				item.SpeedProbation[node] = penalty
			}
			if p.speedEnabled && p.speedDegradationPercent > 0 && node == selected {
				if item.SpeedDegradation == nil && success && speed > 0 && baseline > 0 && speed*100 <= baseline*int64(100-p.speedDegradationPercent) {
					item.SpeedDegradation = &speedDegradation{Node: node, Since: at, CycleAt: at, BaselineBPS: baseline, RecoveryPercent: speedRecoveryPercent(p)}
				}
				if episode := item.SpeedDegradation; episode != nil {
					countSpeedRecovery(at, speed, episode.BaselineBPS, episode.RecoveryPercent, &episode.Recoveries, &episode.LastRecoveryAt)
					if episode.Recoveries >= 3 {
						item.SpeedDegradation = nil
					}
				}
			}
		}
		samples = freshSpeedSamples(now, samples)
		item.SpeedHistory[node] = samples
		values := speedValues(samples)
		item.SpeedSamplesBPS[node] = values
		if len(values) > 0 {
			median := medianInt64(values)
			medians[node] = &median
		}
	}
	return medians
}

func speedRecoveryPercent(p effectivePolicySettings) int {
	return maxInt(80, 100-p.speedDegradationPercent/2)
}

func speedProbationActive(now time.Time, item *policyHealthState, node string, p effectivePolicySettings) bool {
	if !p.speedEnabled || p.speedDegradationPercent == 0 {
		return false
	}
	penalty, ok := item.SpeedProbation[node]
	at := float64(now.Unix())
	return ok && (at < penalty.Until || penalty.Recoveries < 3 || penalty.LastRecoveryAt > at || at-penalty.LastRecoveryAt > speedActiveInterval*2)
}

func recordSpeedDegradationExit(now time.Time, item *policyHealthState, node string) {
	episode := item.SpeedDegradation
	if episode == nil || episode.Node != node {
		return
	}
	penalty := item.SpeedProbation[node]
	at := float64(now.Unix())
	if at < penalty.LastAt || at-penalty.LastAt >= 24*60*60 {
		penalty.Count = 0
	}
	penalty.Count = minInt(penalty.Count+1, 2)
	duration := 30 * 60
	if penalty.Count > 1 {
		duration = 2 * 60 * 60
	}
	penalty.LastAt, penalty.Until, penalty.BaselineBPS = at, at+float64(duration), episode.BaselineBPS
	penalty.RecoveryPercent = episode.RecoveryPercent
	penalty.Recoveries, penalty.LastRecoveryAt = 0, 0
	item.SpeedProbation[node] = penalty
	item.SpeedDegradation = nil
}

func speedSurveyLimit(p effectivePolicySettings) int {
	return maxInt(1, minInt(p.speedCandidates, maxInt(p.shortlist-1, 1)))
}
func speedCyclePairLimit(p effectivePolicySettings) int { return speedSurveyLimit(p) + 4 }

func refreshSpeedEpisode(now time.Time, selected string, item *policyHealthState, p effectivePolicySettings) {
	if reference := item.SpeedSelectionReference; reference != nil && (reference.Node != selected || float64(now.Unix()) < reference.At || float64(now.Unix())-reference.At > speedActiveInterval*3) {
		item.SpeedSelectionReference = nil
	}
	episode := item.SpeedDegradation
	if episode == nil {
		if item.OptimizationSpeedDegraded {
			clearOptimizationCandidate(item)
		}
		return
	}
	at := float64(now.Unix())
	if !p.speedEnabled || p.speedDegradationPercent == 0 || episode.Node != selected || at < episode.Since {
		item.SpeedDegradation = nil
		if item.OptimizationSpeedDegraded {
			clearOptimizationCandidate(item)
		}
		return
	}
	if episode.CycleAt == 0 {
		episode.CycleAt = episode.Since
	}
	if episode.RetryAfter > 0 {
		if at >= episode.RetryAfter {
			episode.CycleAt, episode.RetryAfter, episode.Pairs = at, 0, 0
			episode.Tried, episode.SurveyTargets, episode.Finalists = nil, nil, nil
			episode.Survey, episode.SurveyComplete = nil, false
		}
		return
	}
	if episode.Pairs >= speedCyclePairLimit(p) || at-episode.CycleAt >= speedEpisodeLifetime {
		episode.RetryAfter = at + speedActiveInterval
		if item.OptimizationSpeedDegraded {
			clearOptimizationCandidate(item)
		}
	}
}

func speedDegradationReady(now time.Time, selected string, item *policyHealthState, p effectivePolicySettings) bool {
	episode := item.SpeedDegradation
	at := float64(now.Unix())
	if !p.speedEnabled || p.speedDegradationPercent == 0 || episode == nil || episode.Node != selected || episode.RetryAfter > 0 || episode.Pairs >= speedCyclePairLimit(p) || at < episode.CycleAt || at-episode.CycleAt > speedEpisodeLifetime {
		return false
	}
	samples := freshSpeedSamples(now, item.SpeedHistory[selected])
	return len(samples) > 0 && samples[len(samples)-1].At >= episode.CycleAt && at-samples[len(samples)-1].At <= speedActiveInterval*2 && samples[len(samples)-1].BPS*100 < episode.BaselineBPS*int64(maxInt(episode.RecoveryPercent, 80))
}

func degradedSpeedBetter(activeDelay, candidateDelay int, activeSpeed, candidateSpeed int64, p effectivePolicySettings) bool {
	gain := maxInt(p.speedImprovement, 0)
	if p.mode == "priority" {
		gain = 0
	}
	return activeDelay > 0 && candidateDelay > 0 && activeSpeed > 0 && candidateSpeed-activeSpeed >= 1_000_000 && candidateSpeed*100 >= activeSpeed*int64(100+gain) && (p.maxLatency <= 0 || candidateDelay <= p.maxLatency) && candidateDelay <= maxInt(activeDelay+100, activeDelay*125/100) && candidateSpeed*int64(activeDelay) > activeSpeed*int64(candidateDelay)
}

func speedDegradationCandidate(now time.Time, selected string, ranked []string, item *policyHealthState, p effectivePolicySettings) string {
	if !speedDegradationReady(now, selected, item, p) {
		return ""
	}
	episode := item.SpeedDegradation
	eligible := withoutOptimizationBackoff(now, ranked, item)
	usable := func(node string) bool {
		return contains(eligible, node) && !contains(episode.Tried, node) && !speedProbationActive(now, item, node, p)
	}
	if p.mode == "priority" {
		for _, node := range eligible {
			if usable(node) {
				return node
			}
		}
		return ""
	}
	if len(episode.SurveyTargets) == 0 {
		for _, node := range eligible {
			if usable(node) {
				episode.SurveyTargets = append(episode.SurveyTargets, node)
				if len(episode.SurveyTargets) >= speedSurveyLimit(p) {
					break
				}
			}
		}
		episode.Survey = make(map[string]*optimizationComparison)
	}
	if !episode.SurveyComplete {
		for _, node := range episode.SurveyTargets {
			if _, checked := episode.Survey[node]; checked {
				continue
			}
			if usable(node) {
				return node
			}
			episode.Survey[node] = nil
		}
		if len(episode.SurveyTargets) == 0 {
			return ""
		}
		episode.SurveyComplete = true
		for _, node := range episode.SurveyTargets {
			result := episode.Survey[node]
			if result != nil && result.Result == optimizationWin && usable(node) {
				episode.Finalists = append(episode.Finalists, node)
			}
		}
		sort.SliceStable(episode.Finalists, func(i, j int) bool {
			a, b := episode.Survey[episode.Finalists[i]], episode.Survey[episode.Finalists[j]]
			if *a.CandidateSpeedBPS != *b.CandidateSpeedBPS {
				return *a.CandidateSpeedBPS > *b.CandidateSpeedBPS
			}
			return *a.CandidateDelayMS < *b.CandidateDelayMS
		})
		if len(episode.Finalists) > 2 {
			episode.Finalists = episode.Finalists[:2]
		}
	}
	for _, node := range episode.Finalists {
		if usable(node) {
			return node
		}
	}
	episode.RetryAfter = float64(now.Unix() + speedActiveInterval)
	return ""
}

func isPlannedOptimization(reason string) bool {
	return reason == "meaningfully-faster" || reason == "speed-degraded"
}

func comparePlannedOptimization(now time.Time, selected, candidate string, measured map[string]probeEvidence, speeds map[string]int64, quality, available bool, item *policyHealthState, p effectivePolicySettings) *optimizationComparison {
	comparison := compareOptimization(now, selected, candidate, measured, speeds, quality, available, p)
	if !item.OptimizationSpeedDegraded || (comparison.Reason != "better" && comparison.Reason != "not-better") {
		return comparison
	}
	episode := item.SpeedDegradation
	if episode == nil || episode.Node != selected || speeds[selected]*100 >= episode.BaselineBPS*int64(maxInt(episode.RecoveryPercent, 80)) {
		comparison.Result, comparison.Reason = optimizationLoss, "active-speed-recovered"
	} else if degradedSpeedBetter(*comparison.ActiveDelayMS, *comparison.CandidateDelayMS, speeds[selected], speeds[candidate], p) {
		comparison.Result, comparison.Reason = optimizationWin, "better"
	} else {
		comparison.Result, comparison.Reason = optimizationLoss, "not-better"
	}
	return comparison
}

func failOptimizationCandidate(now time.Time, candidate string, item *policyHealthState, p effectivePolicySettings) {
	if item.OptimizationSpeedDegraded && item.SpeedDegradation != nil {
		item.SpeedDegradation.Tried = uniqueCandidates(append(item.SpeedDegradation.Tried, candidate))
	}
	item.OptimizationBackoff[candidate] = float64(now.Unix() + int64(maxInt(p.cooldown, 300)))
	item.OptimizationBudgetAfter = float64(now.Unix() + 300)
	clearOptimizationCandidate(item)
	item.OptimizationRetryAfter = 0
}

func handleSpeedSurveyComparison(now time.Time, comparison *optimizationComparison, item *policyHealthState, p effectivePolicySettings) bool {
	episode := item.SpeedDegradation
	if episode == nil || p.mode == "priority" || episode.SurveyComplete {
		return false
	}
	if comparison.Reason == "active-speed-missing" || comparison.Reason == "active-https-failed" || comparison.Reason == "active-speed-recovered" {
		episode.RetryAfter = float64(now.Unix() + speedActiveInterval)
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
		return true
	}
	if episode.Survey == nil {
		episode.Survey = make(map[string]*optimizationComparison)
	}
	copy := *comparison
	episode.Survey[comparison.Candidate] = &copy
	if comparison.Result != optimizationWin {
		failOptimizationCandidate(now, comparison.Candidate, item, p)
	} else {
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
	}
	return true
}

func invalidateSpeedSurveyNode(item *policyHealthState, node string) {
	if item.SpeedSelectionReference != nil && item.SpeedSelectionReference.Node == node {
		item.SpeedSelectionReference = nil
	}
	episode := item.SpeedDegradation
	if episode == nil {
		return
	}
	if episode.Node == node {
		item.SpeedDegradation = nil
		return
	}
	delete(episode.Survey, node)
	episode.SurveyTargets = without(episode.SurveyTargets, []string{node})
	episode.Finalists = without(episode.Finalists, []string{node})
	episode.Tried = without(episode.Tried, []string{node})
}
