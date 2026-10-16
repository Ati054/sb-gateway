package agent

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func historyStatsFixture(now time.Time) *policyHealthState {
	item := newPolicyHealthState()
	for _, node := range []string{"a", "b"} {
		delay := 100
		item.DailySamples[node] = []healthSample{{At: float64(now.Add(-time.Hour).Unix()), OK: true, DelayMS: &delay}}
	}
	return item
}

func requireHistoryStatistics(t *testing.T, item *policyHealthState, candidates []string, now time.Time, daily, week, month map[string]healthStats) {
	t.Helper()
	if len(daily) != len(candidates) || len(week) != len(candidates) || len(month) != len(candidates) {
		t.Fatal("removed candidates retained in statistics")
	}
	for _, node := range candidates {
		for _, pair := range []struct{ got, want healthStats }{{daily[node], summarizeSamples(item.DailySamples[node])}, {week[node], summarizeDays(item.HistoryDays[node], 7, now)}, {month[node], summarizeDays(item.HistoryDays[node], historyRetentionDays, now)}} {
			if !reflect.DeepEqual(pair.got, pair.want) {
				t.Fatalf("cached history differs for %s: got=%#v want=%#v", node, pair.got, pair.want)
			}
		}
	}
}

func TestHistoryStatisticsReusesUnchangedNodesWithoutEarlyPublication(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	item := historyStatsFixture(now)
	candidates := []string{"a", "b"}
	daily, week, month := refreshHistoryStatistics(item, candidates, nil, now)
	requireHistoryStatistics(t, item, candidates, now, daily, week, month)
	if len(item.DailyStats) != 0 || len(item.PeriodStats) != 0 {
		t.Fatal("statistics published before selector commit")
	}
	again, wAgain, mAgain := refreshHistoryStatistics(item, candidates, nil, now.Add(time.Minute))
	if again["a"].MedianMS != daily["a"].MedianMS || wAgain["b"].MedianMS != week["b"].MedianMS || mAgain["a"].MedianMS != month["a"].MedianMS {
		t.Fatal("unchanged histories recomputed")
	}
	delay := 300
	updated, wUpdated, mUpdated := refreshHistoryStatistics(item, candidates, map[string]probeEvidence{"a": {OK: true, DelayMS: &delay}}, now.Add(2*time.Minute))
	requireHistoryStatistics(t, item, candidates, now.Add(2*time.Minute), updated, wUpdated, mUpdated)
	if updated["a"].MedianMS == again["a"].MedianMS || wUpdated["a"].MedianMS == wAgain["a"].MedianMS || mUpdated["a"].MedianMS == mAgain["a"].MedianMS {
		t.Fatal("new evidence reused stale aggregates")
	}
	if updated["b"].MedianMS != again["b"].MedianMS || wUpdated["b"].MedianMS != wAgain["b"].MedianMS || mUpdated["b"].MedianMS != mAgain["b"].MedianMS {
		t.Fatal("unmeasured node was re-sorted")
	}
	// A failed selector transaction can leave public statistics uncommitted.
	item.DailyStats = daily
	item.PeriodStats = map[string]map[string]healthStats{"7d": week, "30d": month}
	retried, wRetried, mRetried := refreshHistoryStatistics(item, candidates, nil, now.Add(3*time.Minute))
	requireHistoryStatistics(t, item, candidates, now.Add(3*time.Minute), retried, wRetried, mRetried)
	if retried["a"].MedianMS != updated["a"].MedianMS {
		t.Fatal("retry trusted uncommitted public aggregates")
	}
}

func TestHistoryStatisticsRecalculatesExpiryRolloverResetAndReload(t *testing.T) {
	now := time.Date(2026, 1, 15, 23, 58, 0, 0, time.UTC)
	item := historyStatsFixture(now)
	candidates := []string{"a", "b"}
	delay := 900
	item.DailySamples["a"] = append(item.DailySamples["a"], healthSample{At: float64(now.Add(-24*time.Hour + 30*time.Second).Unix()), OK: true, DelayMS: &delay})
	daily, week, month := refreshHistoryStatistics(item, candidates, nil, now)
	expired := now.Add(time.Minute)
	d2, w2, m2 := refreshHistoryStatistics(item, candidates, nil, expired)
	requireHistoryStatistics(t, item, candidates, expired, d2, w2, m2)
	if d2["a"].MedianMS == daily["a"].MedianMS || w2["a"].MedianMS != week["a"].MedianMS || m2["a"].MedianMS != month["a"].MedianMS {
		t.Fatal("daily expiration did not invalidate only its own aggregate")
	}
	nextDay := now.Add(3 * time.Minute)
	item.HistoryDays["a"][nextDay.Format("2006-01-02")] = dayBucket{Samples: 1, Successes: 1, LatencySamples: []int{999}}
	d3, w3, m3 := refreshHistoryStatistics(item, candidates, nil, nextDay)
	requireHistoryStatistics(t, item, candidates, nextDay, d3, w3, m3)
	if w3["a"].MedianMS == w2["a"].MedianMS || m3["b"].MedianMS == m2["b"].MedianMS {
		t.Fatal("UTC rollover retained previous period cache")
	}
	delete(item.DailySamples, "a")
	delete(item.HistoryDays, "a")
	d4, w4, m4 := refreshHistoryStatistics(item, candidates, nil, nextDay)
	requireHistoryStatistics(t, item, candidates, nextDay, d4, w4, m4)
	if d4["a"].Samples != 0 || w4["a"].Samples != 0 {
		t.Fatal("fingerprint reset retained old aggregate")
	}
	d5, w5, m5 := refreshHistoryStatistics(item, []string{"b"}, nil, nextDay)
	requireHistoryStatistics(t, item, []string{"b"}, nextDay, d5, w5, m5)
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded policyHealthState
	if err := json.Unmarshal(body, &reloaded); err != nil {
		t.Fatal(err)
	}
	if reloaded.historyStatsCache != nil {
		t.Fatal("process-local aggregates persisted")
	}
	d6, w6, m6 := refreshHistoryStatistics(&reloaded, []string{"b"}, nil, nextDay.Add(time.Minute))
	requireHistoryStatistics(t, &reloaded, []string{"b"}, nextDay.Add(time.Minute), d6, w6, m6)
}

var benchmarkHistoryStatisticsResult [3]map[string]healthStats

func BenchmarkHistoryStatistics(b *testing.B) {
	now := time.Date(2026, 1, 30, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"full-sort", "incremental"} {
		b.Run(mode, func(b *testing.B) {
			item := newPolicyHealthState()
			candidates := make([]string, 32)
			for n := range candidates {
				node := fmt.Sprintf("node-%d", n)
				candidates[n] = node
				for s := 0; s < 1440; s++ {
					delay := 100 + (s*79+n*13)%900
					item.DailySamples[node] = append(item.DailySamples[node], healthSample{At: float64(now.Add(-time.Duration(1439-s) * time.Second).Unix()), OK: true, DelayMS: &delay})
				}
				days := make(map[string]dayBucket)
				for d := 0; d < 30; d++ {
					bucket := dayBucket{Samples: 1440, Successes: 1440}
					for s := 0; s < historyReservoir; s++ {
						bucket.LatencySamples = append(bucket.LatencySamples, 100+(s*83+d*11+n)%900)
					}
					days[now.AddDate(0, 0, -d).Format("2006-01-02")] = bucket
				}
				item.HistoryDays[node] = days
			}
			refreshHistoryStatistics(item, candidates, nil, now)
			delay := 350
			measured := map[string]probeEvidence{candidates[0]: {OK: true, DelayMS: &delay}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if mode == "incremental" {
					daily, week, month := refreshHistoryStatistics(item, candidates, measured, now)
					benchmarkHistoryStatisticsResult = [3]map[string]healthStats{daily, week, month}
				} else {
					updateHistories(item, candidates, measured, now)
					daily, week, month := make(map[string]healthStats), make(map[string]healthStats), make(map[string]healthStats)
					for _, node := range candidates {
						daily[node] = summarizeSamples(item.DailySamples[node])
						week[node] = summarizeDays(item.HistoryDays[node], 7, now)
						month[node] = summarizeDays(item.HistoryDays[node], historyRetentionDays, now)
					}
					benchmarkHistoryStatisticsResult = [3]map[string]healthStats{daily, week, month}
				}
			}
		})
	}
}
