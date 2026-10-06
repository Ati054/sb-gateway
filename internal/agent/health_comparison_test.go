package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCurrentLatencyComparisonsUseQualifiedFreshQuality(t *testing.T) {
	now := time.Unix(1000, 0)
	p := policySettings(healthPolicy{}, "best")
	delay := func(value int) *int { return &value }
	fixture := func() *policyHealthState {
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
		item.Samples = map[string][]healthSample{
			"active":  {{At: 995, OK: true, DelayMS: delay(600)}},
			"reserve": {{At: 990, OK: true, DelayMS: delay(350)}},
		}
		item.QualityOK = map[string]bool{"active": true, "reserve": true}
		item.AvailabilityOK = map[string]bool{"active": true, "reserve": true}
		item.Recoveries["reserve"] = p.recoveryThreshold
		return item
	}
	item := fixture()
	got := currentLatencyComparisons(now, item, []string{"active", "reserve"}, p)
	pair, ok := got["reserve"]
	if !ok || len(got) != 1 || pair.Active != "active" || pair.ActiveDelayMS != 600 ||
		pair.CandidateDelayMS != 350 || pair.ActiveAt != 995 || pair.CandidateAt != 990 || pair.ExpiresAt != 1110 {
		t.Fatalf("comparison=%+v", got)
	}
	for name, alter := range map[string]func(*policyHealthState){
		"unconfirmed":    func(s *policyHealthState) { s.RuntimeConfirmed = false },
		"changed-active": func(s *policyHealthState) { s.RuntimeSelected = "reserve" },
		"unqualified":    func(s *policyHealthState) { s.Recoveries["reserve"] = 2 },
		"failed-active":  func(s *policyHealthState) { s.AvailabilityFailures["active"] = 1 },
		"failed-reserve": func(s *policyHealthState) { s.AvailabilityFailures["reserve"] = 1 },
		"stale-active":   func(s *policyHealthState) { s.Samples["active"][0].At = 879 },
		"stale-reserve":  func(s *policyHealthState) { s.Samples["reserve"][0].At = 879 },
		"future":         func(s *policyHealthState) { s.Samples["reserve"][0].At = 1001 },
		"fallback":       func(s *policyHealthState) { s.Samples["reserve"][0].DelayMS = nil },
		"bad-quality":    func(s *policyHealthState) { s.QualityOK["reserve"] = false },
	} {
		t.Run(name, func(t *testing.T) {
			s := fixture()
			alter(s)
			if got := currentLatencyComparisons(now, s, []string{"active", "reserve"}, p); len(got) != 0 {
				t.Fatalf("invalid comparison=%+v", got)
			}
		})
	}
	item.LatencyComparisons = got
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var restored policyHealthState
	if err := json.Unmarshal(body, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.LatencyComparisons != nil {
		t.Fatal("saved diagnostic survived restart")
	}
}

func TestFastFailureWithdrawsLatencyComparisonWithNewObservation(t *testing.T) {
	pool := healthFixture(false)
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.RuntimeObservedAt = "2026-01-01T00:00:00Z"
	item.LatencyComparisons = map[string]latencyComparison{"nl": {Active: "de"}}
	runtime := &fakeSelectorRuntime{
		pool: pool, current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{"de": {Failure: probeFailureTimeout}},
	}
	controller := &healthController{runtime: runtime, livenessAt: map[string]time.Time{}}
	changed, err := controller.checkActiveAvailability(time.Unix(1000, 0), "europe", pool.HealthPolicies["europe"], item, false)
	if err != nil || !changed || item.LatencyComparisons != nil || item.RuntimeObservedAt == "2026-01-01T00:00:00Z" {
		t.Fatalf("comparison withdrawal not published: changed=%t comparison=%v observed=%s err=%v", changed, item.LatencyComparisons, item.RuntimeObservedAt, err)
	}
}
