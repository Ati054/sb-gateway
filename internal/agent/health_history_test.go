// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"
	"time"
)

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
