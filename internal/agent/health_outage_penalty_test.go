package agent

import (
	"testing"
	"time"
)

func TestConfirmedOutagePenaltyCountsEpisodesAndExpires(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	item := newPolicyHealthState()
	item.Recoveries["node"] = 3
	for index, want := range []time.Duration{time.Hour, 4 * time.Hour, 12 * time.Hour} {
		at := now.Add(time.Duration(index) * time.Hour)
		if !recordConfirmedOutage(at, item, "node") {
			t.Fatalf("outage %d was not recorded", index+1)
		}
		penalty := item.OutagePenalty["node"]
		if penalty.Count != index+1 || penalty.Until != float64(at.Add(want).Unix()) || !penalty.Open {
			t.Fatalf("outage %d penalty = %+v", index+1, penalty)
		}
		if item.Recoveries["node"] != 0 {
			t.Fatal("failed node retained soft-switch recovery evidence")
		}
		if recordConfirmedOutage(at.Add(time.Minute), item, "node") {
			t.Fatal("one continuous outage counted twice")
		}
		finishOutageEpisode(item, "node")
	}
	if !recordConfirmedOutage(now.Add(26*time.Hour), item, "node") || item.OutagePenalty["node"].Count != 1 {
		t.Fatalf("quiet period did not reset escalation: %+v", item.OutagePenalty["node"])
	}
	if outagePenaltyActive(now.Add(27*time.Hour), item, "node") {
		t.Fatal("expired hold-down remained active")
	}
}

func TestOutagePenaltyBlocksSoftSwitchButNotEmergency(t *testing.T) {
	now := time.Unix(1_000, 0)
	settings := effectivePolicySettings{active: 60, backup: 300, failureThreshold: 2, recoveryThreshold: 2, improvement: 20}
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	item.Recoveries["reserve"] = 2
	item.LastProbeAt["reserve"] = float64(now.Add(-10 * time.Second).Unix())
	item.OutagePenalty["reserve"] = outagePenalty{LastAt: float64(now.Unix()), Count: 2, Until: float64(now.Add(4 * time.Hour).Unix())}
	activeDelay, reserveDelay := 200, 50
	delays := map[string]*int{"active": &activeDelay, "reserve": &reserveDelay}
	quality := map[string]bool{"active": true, "reserve": true}
	available := map[string]bool{"active": true, "reserve": true}
	for _, mode := range []string{"priority", "best"} {
		desired, reason := selectDesired(now, mode, "active", []string{"reserve", "active"},
			map[string]int{"reserve": 0, "active": 1}, nil, delays, nil, nil, quality, available, item, settings)
		if desired != "active" || reason != "" {
			t.Fatalf("%s mode returned to penalized node: %q %q", mode, desired, reason)
		}
	}
	item.AvailabilityFailures["active"] = settings.failureThreshold
	desired, reason := selectDesired(now, "priority", "active", []string{"reserve", "active"},
		map[string]int{"reserve": 0, "active": 1}, nil, delays, nil,
		map[string]probeEvidence{"reserve": successfulEvidence(reserveDelay)}, quality, available, item, settings)
	if desired != "reserve" || reason != "active-unavailable" {
		t.Fatalf("emergency could not use freshly successful reserve: %q %q", desired, reason)
	}
}

func TestOutagePenaltyCancelsPendingOptimization(t *testing.T) {
	now := time.Unix(1_000, 0)
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	settings := effectivePolicySettings{active: 60, cooldown: 600}
	_, _ = gatePlannedOptimization(now, "active", "reserve", "meaningfully-faster", nil, item, settings)
	item.OutagePenalty["reserve"] = outagePenalty{LastAt: float64(now.Unix()), Count: 1, Until: float64(now.Add(time.Hour).Unix())}
	desired, reason := gatePlannedOptimization(now.Add(time.Minute), "active", "reserve", "meaningfully-faster",
		&optimizationComparison{Candidate: "reserve", Result: optimizationWin}, item, settings)
	if desired != "active" || reason != "" || item.OptimizationCandidate != "" {
		t.Fatalf("held node retained pending optimization: %q %q %+v", desired, reason, item)
	}
	desired, reason = gatePlannedOptimization(now.Add(time.Minute), "active", "reserve", "active-unavailable", nil, item, settings)
	if desired != "reserve" || reason != "active-unavailable" {
		t.Fatalf("hold-down blocked emergency: %q %q", desired, reason)
	}
}
