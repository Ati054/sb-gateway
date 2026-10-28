package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDisplayComparisonSurvivesMissingFreshPairAndRestart(t *testing.T) {
	pair := latencyComparison{Active: "active", ActiveDelayMS: 600, CandidateDelayMS: 350, ActiveAt: 990, CandidateAt: 995, ExpiresAt: 1110}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
	item.LatencyComparisons = map[string]latencyComparison{"reserve": pair}
	rememberDisplayComparisons(item)
	item.LatencyComparisons = nil // failure, expiry or a different routine batch
	rememberDisplayComparisons(item)
	if item.LastLatencyComparisons["reserve"] != pair {
		t.Fatal("routine polling erased the last qualified pair")
	}
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var restored policyHealthState
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.LastLatencyComparisons["reserve"] != pair || restored.LatencyComparisons != nil {
		t.Fatal("restart must retain display history without restoring fresh evidence")
	}
	comparison := regularOptimizationComparison(time.Unix(2000, 0), "active", "reserve", nil, &restored, true, true, policySettings(healthPolicy{}, "best"))
	if comparison != nil && comparison.Result == optimizationWin {
		t.Fatal("display history counted as a planned-switch win")
	}
	restored.RuntimeSelected, restored.Selected = "reserve", "reserve"
	rememberDisplayComparisons(&restored)
	if len(restored.LastLatencyComparisons) != 0 {
		t.Fatal("active switch retained another baseline")
	}
}

func TestDisplayComparisonInvalidatesChangedEndpointsAndMembership(t *testing.T) {
	for _, changed := range []string{"active", "reserve"} {
		item := newPolicyHealthState()
		item.LastLatencyComparisons = map[string]latencyComparison{"reserve": {Active: "active"}, "other": {Active: "active"}}
		item.CandidateNodes = map[string]healthNode{changed: {Fingerprint: "old"}}
		invalidateChangedOutboundHealth(item, []string{changed}, map[string]healthNode{changed: {Fingerprint: "new"}})
		if _, ok := item.LastLatencyComparisons["reserve"]; ok {
			t.Fatal("changed pair survived")
		}
		if len(item.LastLatencyComparisons) != map[string]int{"active": 0, "reserve": 1}[changed] {
			t.Fatal("unrelated pair was incorrectly removed or retained")
		}
	}
	item := newPolicyHealthState()
	item.LastLatencyComparisons = map[string]latencyComparison{"reserve": {Active: "active"}}
	pruneRemovedCandidateHealth(item, []string{"active"})
	if len(item.LastLatencyComparisons) != 0 {
		t.Fatal("removed candidate retained display history")
	}
}

func TestDisplayComparisonWithdrawnWhenFastReadbackFindsAnotherActive(t *testing.T) {
	pool := healthFixture(false)
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.LastLatencyComparisons = map[string]latencyComparison{"nl": {Active: "de"}}
	runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "nl"}}
	controller := &healthController{runtime: runtime, livenessAt: map[string]time.Time{}}
	_, _ = controller.checkActiveAvailability(time.Unix(1000, 0), "europe", pool.HealthPolicies["europe"], item, false)
	if len(item.LastLatencyComparisons) != 0 {
		t.Fatal("fast readback retained the previous baseline")
	}
}
