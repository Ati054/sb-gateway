package agent

import "time"

type historyChange struct{ daily, period bool }

type historyStatistics struct {
	day                string
	daily, week, month map[string]healthStats
}

func refreshHistoryStatistics(item *policyHealthState, candidates []string, measured map[string]probeEvidence, now time.Time) (map[string]healthStats, map[string]healthStats, map[string]healthStats) {
	changes := updateHistories(item, candidates, measured, now)
	previous := item.historyStatsCache
	day := now.UTC().Format("2006-01-02")
	dayChanged := previous == nil || previous.day != day
	next := &historyStatistics{day: day, daily: make(map[string]healthStats, len(candidates)), week: make(map[string]healthStats, len(candidates)), month: make(map[string]healthStats, len(candidates))}
	for _, candidate := range candidates {
		change := changes[candidate]
		var daily, week, month healthStats
		var haveDaily, haveWeek, haveMonth bool
		if previous != nil {
			daily, haveDaily = previous.daily[candidate]
			week, haveWeek = previous.week[candidate]
			month, haveMonth = previous.month[candidate]
		}
		if !haveDaily || change.daily {
			daily = summarizeSamples(item.DailySamples[candidate])
		}
		if !haveWeek || change.period || dayChanged {
			week = summarizeDays(item.HistoryDays[candidate], 7, now)
		}
		if !haveMonth || change.period || dayChanged {
			month = summarizeDays(item.HistoryDays[candidate], historyRetentionDays, now)
		}
		next.daily[candidate], next.week[candidate], next.month[candidate] = daily, week, month
	}
	// Keep the cache separate from published statistics: selector decisions must
	// observe the same previous public state until their existing commit point.
	item.historyStatsCache = next
	return next.daily, next.week, next.month
}
