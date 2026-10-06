package agent

import (
	"reflect"
	"testing"
	"time"
)

func TestWorkingPoolReplacesDeadReserveAndRanksLatency(t *testing.T) {
	item := newPolicyHealthState()
	item.AvailabilityOK = map[string]bool{"active": true, "dead": false, "fast": true, "stable": true, "lossy": true}
	item.QualityOK = map[string]bool{"active": true, "fast": true, "stable": true, "lossy": true}
	zero, loss := 0.0, 30.0
	item.DailyStats = map[string]healthStats{"active": {LossPercent: &zero}, "fast": {LossPercent: &zero}, "stable": {LossPercent: &zero}, "lossy": {LossPercent: &loss}}
	fastDelay, stableDelay, lossyDelay := 100, 120, 2000
	item.MedianDelayMS = map[string]*int{"fast": &fastDelay, "stable": &stableDelay, "lossy": &lossyDelay}
	got := workingShortlist(time.Unix(1000, 0), "active", []string{"active", "dead", "lossy", "stable", "fast", "unknown"}, "best", nil, item, effectivePolicySettings{shortlist: 3})
	if !reflect.DeepEqual(got, []string{"active", "fast", "stable"}) {
		t.Fatalf("working pool must pin active, exclude dead/unknown and prefer lower latency: %v", got)
	}
	item.AvailabilityFailures["fast"] = 1
	got = workingShortlist(time.Unix(1000, 0), "active", []string{"active", "fast", "stable", "lossy"}, "best", nil, item, effectivePolicySettings{shortlist: 3})
	if contains(got, "fast") {
		t.Fatalf("failed reserve retained while alternatives exist: %v", got)
	}
	settings := policySettings(healthPolicy{}, "best")
	if settings.shortlist != 10 {
		t.Fatalf("legacy pool limit changed the common budget: %d", settings.shortlist)
	}
}

func TestBestModeRanksLowerLatencyBeforeHistoricalAvailability(t *testing.T) {
	fastLoss, stableLoss := 7.4, 5.1
	fastDelay, stableDelay := 567, 621
	values := rankCandidates(
		[]string{"stable-slow", "fast"}, "best", nil,
		map[string]healthStats{"fast": {LossPercent: &fastLoss}, "stable-slow": {LossPercent: &stableLoss}},
		map[string]*int{"fast": &fastDelay, "stable-slow": &stableDelay},
	)
	if !reflect.DeepEqual(values, []string{"fast", "stable-slow"}) {
		t.Fatalf("historical availability displaced the lower-latency healthy path: %v", values)
	}
}

func TestBackgroundScanFindsBetterNodeBeyondInitialThreeWithoutFlapping(t *testing.T) {
	for _, batch := range []int{1, 2} {
		pool := healthFixture(false)
		contract := pool.HealthPolicies["europe"]
		contract.Mode = "best"
		contract.Candidates = []string{"active", "dead", "slow", "better", "last"}
		contract.Policy.ProbeBatchSize = batch
		contract.Policy.ActiveCheckSeconds = 60
		contract.Policy.SwitchImprovementMS = 50
		pool.HealthPolicies["europe"] = contract
		runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "active"}, probes: map[string]probeEvidence{
			"active": successfulEvidence(500), "dead": failedEvidence(), "slow": successfulEvidence(800), "better": successfulEvidence(100), "last": successfulEvidence(400),
		}}
		controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime, warmStarted: map[string]bool{}}
		for tick := 0; tick < 200; tick++ {
			before := len(runtime.probeCalls)
			if err := controller.Tick(time.Unix(1000+int64(tick*3), 0)); err != nil {
				t.Fatal(err)
			}
			if len(runtime.probeCalls)-before > batch {
				t.Fatalf("scan exceeded batch=%d: %v", batch, runtime.probeCalls[before:])
			}
			item := controller.state["europe"]
			if item.Selected == "better" && item.Recoveries["better"] < 3 {
				t.Fatal("planned switch without recovery confirmations")
			}
			if len(item.Shortlist) > 3 || contains(item.Shortlist, "dead") {
				t.Fatalf("invalid working pool: %v", item.Shortlist)
			}
			if tick == 0 {
				if _, known := item.AvailabilityOK["last"]; known {
					t.Fatal("unprobed candidate published as unavailable")
				}
			}
		}
		for _, candidate := range contract.Candidates {
			if !contains(runtime.probeCalls, candidate) {
				t.Fatalf("batch=%d starved selected node %s", batch, candidate)
			}
		}
		if controller.state["europe"].Selected != "better" || len(runtime.selections) != 2 {
			t.Fatalf("batch=%d expected startup selection and one stable improvement, got %v; comparison=%+v samples=%+v probes=%v", batch,
				runtime.selections, controller.state["europe"].OptimizationLastResult,
				controller.state["europe"].Samples, runtime.probeCalls[maxInt(0, len(runtime.probeCalls)-20):])
		}
	}
}

func TestLatencyRankingDoesNotUseHistoricalPercentilesOrLossTies(t *testing.T) {
	delay, historical := 100, 1
	lowLoss, highLoss := 0.0, 40.0
	daily := map[string]healthStats{
		"historical-only": {P95MS: &historical, MedianMS: &historical, LossPercent: &lowLoss},
		"first":           {LossPercent: &highLoss}, "second": {LossPercent: &lowLoss},
	}
	got := rankCandidates([]string{"historical-only", "first", "second"}, "best", nil, daily,
		map[string]*int{"first": &delay, "second": &delay})
	if !reflect.DeepEqual(got, []string{"first", "second", "historical-only"}) {
		t.Fatalf("historical aggregates changed latency order: %v", got)
	}
}

func TestLatencyPolicyKeepsPoolSeparateFromProbeBatch(t *testing.T) {
	defaults := policySettings(healthPolicy{}, "best")
	if defaults.shortlist != 10 || defaults.batch != 10 {
		t.Fatalf("pool and global batch defaults were conflated: %+v", defaults)
	}
	for _, sample := range []struct{ requested, expected int }{{1, 1}, {10, 10}, {64, 64}, {65, 10}, {0, 10}} {
		p := policySettings(healthPolicy{ProbeBatchSize: sample.requested}, "best")
		if p.batch != sample.expected || p.shortlist != sample.expected {
			t.Fatalf("requested batch %d: batch=%d shortlist=%d", sample.requested, p.batch, p.shortlist)
		}
	}
}
