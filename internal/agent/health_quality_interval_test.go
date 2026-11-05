package agent

import (
	"testing"
	"time"
)

func TestOneQualityWaveRequiresOverlappingMeasurements(t *testing.T) {
	start := time.Now()
	for _, scenario := range []struct {
		name            string
		candidateOffset time.Duration
		wantWin         bool
	}{
		{"overlapping", 100 * time.Millisecond, true},
		{"peer-started-after-completion", 2 * time.Second, false},
		{"touching-intervals", 1300 * time.Millisecond, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			active, candidate := successfulEvidence(1300), successfulEvidence(300)
			active.QualityWave, candidate.QualityWave = 9, 9
			active.QualityStartedAt, active.ObservedAt = start, start.Add(1300*time.Millisecond)
			candidate.QualityStartedAt = start.Add(scenario.candidateOffset)
			candidate.ObservedAt = candidate.QualityStartedAt.Add(300 * time.Millisecond)
			now := active.ObservedAt
			if candidate.ObservedAt.After(now) {
				now = candidate.ObservedAt
			}
			item := newPolicyHealthState()
			item.Samples["a"] = []healthSample{{At: float64(now.Unix()), ObservedAt: float64(now.UnixNano()) / float64(time.Second), OK: true, DelayMS: active.DelayMS}}
			item.Samples["b"] = []healthSample{{At: float64(now.Unix()), ObservedAt: float64(now.UnixNano()) / float64(time.Second), OK: true, DelayMS: candidate.DelayMS}}
			comparison := regularOptimizationComparison(now, "a", "b", map[string]probeEvidence{"a": active, "b": candidate},
				item, true, true, effectivePolicySettings{mode: "best", active: 60, improvement: 200})
			if scenario.wantWin {
				if comparison == nil || comparison.Result != optimizationWin {
					t.Fatalf("overlapping wave lost valid result: %+v", comparison)
				}
			} else if comparison != nil {
				t.Fatalf("worker delayed after barrier created comparative evidence: %+v", comparison)
			}
		})
	}
}
