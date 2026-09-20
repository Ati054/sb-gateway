package agent

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWorkingPoolReplacesDeadReserveAndRanksResponsiveThroughput(t *testing.T) {
	item := newPolicyHealthState()
	item.AvailabilityOK = map[string]bool{"active": true, "dead": false, "fast": true, "stable": true, "lossy": true}
	item.QualityOK = map[string]bool{"active": true, "fast": true, "stable": true, "lossy": true}
	zero, loss := 0.0, 30.0
	item.DailyStats = map[string]healthStats{"active": {LossPercent: &zero}, "fast": {LossPercent: &zero}, "stable": {LossPercent: &zero}, "lossy": {LossPercent: &loss}}
	fast, stable, lossy := int64(100), int64(90), int64(1000)
	item.SpeedMedianBPS = map[string]*int64{"fast": &fast, "stable": &stable, "lossy": &lossy}
	fastDelay, stableDelay, lossyDelay := 100, 120, 2000
	item.MedianDelayMS = map[string]*int{"fast": &fastDelay, "stable": &stableDelay, "lossy": &lossyDelay}
	got := workingShortlist("active", []string{"active", "dead", "lossy", "stable", "fast", "unknown"}, "best", nil, item, effectivePolicySettings{shortlist: 3})
	if !reflect.DeepEqual(got, []string{"active", "fast", "stable"}) {
		t.Fatalf("working pool must pin active, exclude dead/unknown and prefer responsive throughput: %v", got)
	}
	item.AvailabilityFailures["fast"] = 1
	got = workingShortlist("active", []string{"active", "fast", "stable", "lossy"}, "best", nil, item, effectivePolicySettings{shortlist: 3})
	if contains(got, "fast") {
		t.Fatalf("failed reserve retained while alternatives exist: %v", got)
	}
	settings := policySettings(healthPolicy{MaxActiveCandidates: 3, MaxProbeCandidates: 8}, "best")
	if settings.shortlist != 3 {
		t.Fatalf("visible pool limit ignored: %d", settings.shortlist)
	}
}

func TestBestModeRanksFastHealthyReserveBeforeStableSlowEmergency(t *testing.T) {
	fastLoss, stableLoss := 7.4, 5.1
	fastDelay, stableDelay := 567, 621
	fastSpeed, stableSpeed := int64(13_780_000), int64(10_810_000)
	values := rankCandidates(
		[]string{"stable-slow", "fast"},
		"best",
		nil,
		map[string]healthStats{
			"fast":        {LossPercent: &fastLoss},
			"stable-slow": {LossPercent: &stableLoss},
		},
		map[string]*int{"fast": &fastDelay, "stable-slow": &stableDelay},
		map[string]*int64{"fast": &fastSpeed, "stable-slow": &stableSpeed},
	)
	if !reflect.DeepEqual(values, []string{"fast", "stable-slow"}) {
		t.Fatalf("slow high-availability reserve displaced faster healthy path: %v", values)
	}
}

func TestBackgroundScanFindsBetterNodeBeyondInitialThreeWithoutFlapping(t *testing.T) {
	for _, batch := range []int{1, 2} {
		pool := healthFixture(false)
		contract := pool.HealthPolicies["europe"]
		contract.Mode = "best"
		contract.Candidates = []string{"active", "dead", "slow", "better", "last"}
		contract.Policy.MaxActiveCandidates = 3
		contract.Policy.ProbeBatchSize = batch
		contract.Policy.ActiveCheckSeconds = 60
		contract.Policy.BackupCheckSeconds = 300
		contract.Policy.FullScanSeconds = 1800
		contract.Policy.SwitchImprovementMS = 50
		contract.Policy.SwitchCooldownSeconds = 600
		pool.HealthPolicies["europe"] = contract
		runtime := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "active"}, probes: map[string]probeEvidence{
			"active": successfulEvidence(500), "dead": failedEvidence(), "slow": successfulEvidence(800), "better": successfulEvidence(100), "last": successfulEvidence(400),
		}}
		controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime, warmStarted: map[string]bool{}}
		for tick := 0; tick < 30; tick++ {
			before := len(runtime.probeCalls)
			if err := controller.Tick(time.Unix(1000+int64(tick*60), 0)); err != nil {
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
			t.Fatalf("expected startup selection and one stable improvement, got %v", runtime.selections)
		}
	}
}

func TestSpeedExplorationRotatesBeyondShortlistAndPersistsBudget(t *testing.T) {
	item := newPolicyHealthState()
	nodes := []string{"a", "b", "c", "d", "e", "f", "dead"}
	item.AvailabilityOK = map[string]bool{"a": true, "b": true, "c": true, "d": true, "e": true, "f": true}
	p := policySettings(healthPolicy{}, "best")
	first := speedProbeCandidates(time.Unix(1000, 0), "a", nodes, nil, item, p)
	if strings.Join(first, ",") != "a,b,c" {
		t.Fatal(first)
	}
	for _, candidate := range first {
		item.LastSpeedProbeAt[candidate] = 1000
	}
	if got := speedProbeCandidates(time.Unix(1299, 0), "a", nodes, nil, item, p); len(got) != 0 {
		t.Fatalf("policy-wide download budget ignored: %v", got)
	}
	if got := speedProbeCandidates(time.Unix(1300, 0), "a", nodes, nil, item, p); strings.Join(got, ",") != "d,e,f" {
		t.Fatalf("later candidates not explored: %v", got)
	}
}
