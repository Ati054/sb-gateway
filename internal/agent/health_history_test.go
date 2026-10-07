// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestHistorySummariesPreserveValuesAndStoredOrder(t *testing.T) {
	now := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	for _, values := range [][]int{nil, {500}, {900, 100}, {400, 100, 900}, {900, 400, 100, 600}} {
		samples := []healthSample{{OK: false}, {OK: true}}
		for i := range values {
			samples = append(samples, healthSample{OK: true, DelayMS: &values[i]})
		}
		days := map[string]dayBucket{
			"2026-10-07": {Samples: len(samples), Successes: len(samples) - 1, Failures: 1, LatencySamples: append([]int(nil), values...)},
			"2026-09-01": {Samples: 100, Failures: 100, LatencySamples: []int{9999}},
			"2026-10-08": {Samples: 100, Failures: 100, LatencySamples: []int{9999}},
		}
		original := append([]int(nil), values...)
		daily := summarizeSamples(samples)
		period := summarizeDays(days, 7, now)
		for _, got := range []healthStats{daily, period} {
			if got.Samples != len(samples) || got.Successes != len(samples)-1 || got.Failures != 1 {
				t.Fatalf("counts changed: %+v", got)
			}
			if len(values) == 0 {
				if got.MedianMS != nil || got.P95MS != nil {
					t.Fatal("unmeasured successes acquired a latency")
				}
			} else if got.MedianMS == nil || *got.MedianMS != medianInt(values) || got.P95MS == nil || *got.P95MS != percentile(values, .95) {
				t.Fatalf("quantiles changed: %+v", got)
			}
		}
		if period.Days != 1 || period.LatencySampleCount != len(values) || !period.PercentilesApproximate {
			t.Fatalf("period metadata changed: %+v", period)
		}
		if !reflect.DeepEqual(original, values) || !reflect.DeepEqual(original, days["2026-10-07"].LatencySamples) {
			t.Fatal("summary reordered stored history")
		}
	}
}

func BenchmarkHistorySummaryBuffers(b *testing.B) {
	now := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	days := make(map[string]dayBucket)
	for i := 0; i < 30; i++ {
		values := make([]int, historyReservoir)
		for j := range values {
			values[j] = (i*37+j*101)%1000 + 1
		}
		days[now.AddDate(0, 0, -i).Format("2006-01-02")] = dayBucket{Samples: 1440, Successes: 1440, LatencySamples: values}
	}
	for _, legacy := range []bool{true, false} {
		b.Run(fmt.Sprintf("legacy=%t", legacy), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !legacy {
					summarizeDays(days, 30, now)
					continue
				}
				keys := sortedKeys(days)
				var delays []int
				for _, key := range keys {
					delays = append(delays, days[key].LatencySamples...)
				}
				medianInt(delays)
				percentile(delays, .95)
			}
		})
	}
}

func TestUpdateHistoriesReusesBufferAndClearsExpiredPointers(t *testing.T) {
	now := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	item := newPolicyHealthState()
	delay := 100
	old := []healthSample{
		{At: float64(now.Add(-25 * time.Hour).Unix()), OK: true, DelayMS: &delay},
		{At: float64(now.Add(-time.Hour).Unix()), OK: true, DelayMS: &delay},
		{At: float64(now.Unix()), OK: false},
	}
	item.DailySamples["node"] = old
	item.HistoryDays["node"] = map[string]dayBucket{}
	updateHistories(item, []string{"node"}, nil, now)
	history := item.DailySamples["node"]
	if len(history) != 2 || &history[0] != &old[0] || history[0].At != float64(now.Add(-time.Hour).Unix()) {
		t.Fatalf("history was not compacted in place: %+v", history)
	}
	if old[2].DelayMS != nil || old[2].At != 0 {
		t.Fatal("expired tail retained a sample")
	}
	updateHistories(item, []string{"node"}, nil, now)
	if &item.DailySamples["node"][0] != &old[0] || len(item.DailySamples["node"]) != 2 {
		t.Fatal("unmeasured history allocated another buffer")
	}
}

func TestUpdateHistoriesRetainsLatest1440AndCountsOnlyNewMeasurement(t *testing.T) {
	now := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	item := newPolicyHealthState()
	history := make([]healthSample, 1440, 1441)
	for i := range history {
		history[i] = healthSample{At: float64(now.Add(-time.Duration(1440-i) * time.Second).Unix()), OK: true}
	}
	item.DailySamples["node"] = history
	day := now.Format("2006-01-02")
	item.HistoryDays["node"] = map[string]dayBucket{day: {Samples: 1440, Successes: 1440}}
	updateHistories(item, []string{"node"}, map[string]probeEvidence{"node": {OK: false}}, now)
	got := item.DailySamples["node"]
	if len(got) != 1440 || &got[0] != &history[0] || got[0].At != float64(now.Add(-1439*time.Second).Unix()) || got[1439].OK {
		t.Fatal("latest daily samples were not retained in the original buffer")
	}
	if !reflect.DeepEqual(history[:cap(history)][1440], healthSample{}) {
		t.Fatal("truncated tail retained a sample")
	}
	bucket := item.HistoryDays["node"][day]
	if bucket.Samples != 1441 || bucket.Failures != 1 || bucket.Successes != 1440 {
		t.Fatalf("new measurement counted incorrectly: %+v", bucket)
	}
	updateHistories(item, []string{"node"}, nil, now)
	if !reflect.DeepEqual(bucket, item.HistoryDays["node"][day]) {
		t.Fatal("unmeasured node added a daily measurement")
	}
}

func BenchmarkUpdateHistoriesUnmeasured(b *testing.B) {
	now := time.Date(2026, time.October, 7, 12, 0, 0, 0, time.UTC)
	item := newPolicyHealthState()
	item.DailySamples["node"] = make([]healthSample, 1440)
	for i := range item.DailySamples["node"] {
		item.DailySamples["node"][i] = healthSample{At: float64(now.Unix()), OK: true}
	}
	item.HistoryDays["node"] = map[string]dayBucket{now.Format("2006-01-02"): {Samples: 1440, Successes: 1440}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateHistories(item, []string{"node"}, nil, now)
	}
}

func TestSummarizeDaysUsesCalendarWindowWithoutCountingOfflineGaps(t *testing.T) {
	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	days := map[string]dayBucket{
		"2026-09-01": {Samples: 1, Successes: 1, LatencySamples: []int{100}},
		"2026-09-07": {Samples: 1, Failures: 1},
		"2026-09-13": {Samples: 1, Successes: 1, LatencySamples: []int{200}},
	}

	stats := summarizeDays(days, 7, now)
	if stats.Samples != 2 || stats.Successes != 1 || stats.Failures != 1 {
		t.Fatalf("unexpected seven-day samples: %+v", stats)
	}
	if stats.AvailabilityPercent == nil || *stats.AvailabilityPercent != 50 {
		t.Fatalf("unexpected availability: %+v", stats.AvailabilityPercent)
	}
	if stats.Days != 2 {
		t.Fatalf("offline calendar gaps must not become samples, got days=%d", stats.Days)
	}
}

func TestUpdateHistoriesPrunesDaysOutsideCalendarRetention(t *testing.T) {
	now := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	item := newPolicyHealthState()
	item.HistoryDays["node"] = map[string]dayBucket{
		"2026-08-14": {Samples: 1, Successes: 1},
		"2026-08-15": {Samples: 1, Successes: 1},
	}

	updateHistories(item, []string{"node"}, nil, now)
	if _, ok := item.HistoryDays["node"]["2026-08-14"]; ok {
		t.Fatal("expired day was retained")
	}
	if _, ok := item.HistoryDays["node"]["2026-08-15"]; !ok {
		t.Fatal("oldest day inside the 30-day calendar window was removed")
	}
}
