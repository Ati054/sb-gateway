package agent

import (
	"testing"
	"time"
)

func speedTestPolicy() effectivePolicySettings {
	return effectivePolicySettings{mode: "best", speedEnabled: true, speedDegradationPercent: 50, speedImprovement: 25, speedInterval: 10800, speedCandidates: 2, shortlist: 3, batch: 2, active: 60, backup: 300, cooldown: 600, maxLatency: 2000, recoveryThreshold: 3, failureThreshold: 3}
}

func speedTestEpisode(t *testing.T, p effectivePolicySettings) (*policyHealthState, time.Time) {
	t.Helper()
	now := time.Unix(50_000, 0)
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	for i := 5; i > 0; i-- {
		item.SpeedHistory["active"] = append(item.SpeedHistory["active"], speedSample{At: float64(now.Unix() - int64(i*900)), BPS: 18_000_000})
	}
	updateSpeedHistory(now, "active", []string{"active", "a", "b"}, []string{"active"}, map[string]int64{"active": 6_000_000}, map[string]string{"active": "ok"}, item, p)
	if item.SpeedDegradation == nil {
		t.Fatal("fresh baseline did not admit an investigation")
	}
	return item, now
}

func TestSpeedPolicyDefaultsAndExplicitDisable(t *testing.T) {
	zero, thirty := 0, 30
	best := policySettings(healthPolicy{}, "best")
	priority := policySettings(healthPolicy{}, "priority")
	if best.speedDegradationPercent != 50 || !best.speedEnabled || priority.speedDegradationPercent != 0 || priority.speedEnabled {
		t.Fatal("mode defaults changed")
	}
	best = policySettings(healthPolicy{SpeedDegradationPercent: &zero}, "best")
	priority = policySettings(healthPolicy{SpeedDegradationPercent: &thirty}, "priority")
	if best.speedDegradationPercent != 0 || !best.speedEnabled || priority.speedDegradationPercent != 30 || !priority.speedEnabled {
		t.Fatal("explicit threshold lost its semantics")
	}
}

func TestSpeedLegacySamplesDoNotAcquireInventedTimestamps(t *testing.T) {
	now := time.Unix(50_000, 0)
	item := newPolicyHealthState()
	item.SpeedSamplesBPS["active"] = []int64{18_000_000, 19_000_000, 20_000_000, 21_000_000, 22_000_000}
	item.LastSpeedSuccessAt["active"] = float64(now.Unix() - 60)
	updateSpeedHistory(now, "active", []string{"active"}, []string{"active"}, map[string]int64{"active": 6_000_000}, map[string]string{"active": "ok"}, item, speedTestPolicy())
	if item.SpeedDegradation != nil || len(item.SpeedHistory["active"]) != 2 || item.SpeedHistory["active"][0].BPS != 22_000_000 {
		t.Fatal("legacy window fabricated a baseline")
	}
	updateSpeedHistory(now.Add(7*time.Hour), "active", []string{"active"}, nil, nil, nil, item, speedTestPolicy())
	if len(item.SpeedSamplesBPS["active"]) != 0 {
		t.Fatal("expired speeds still influence nomination")
	}
}

func TestConfiguredSmallSpeedDropHasRecoveryHysteresis(t *testing.T) {
	for _, drop := range []int{1, 10, 30, 50, 99} {
		p := speedTestPolicy()
		p.speedDegradationPercent = drop
		item := newPolicyHealthState()
		ensureHealthMaps(item)
		now := time.Unix(50_000, 0)
		for i := 3; i > 0; i-- {
			item.SpeedHistory["active"] = append(item.SpeedHistory["active"], speedSample{At: float64(now.Unix() - int64(i*900)), BPS: 20_000_000})
		}
		updateSpeedHistory(now, "active", []string{"active"}, []string{"active"}, map[string]int64{"active": 20_000_000 * int64(100-drop) / 100}, map[string]string{"active": "ok"}, item, p)
		if !speedDegradationReady(now, "active", item, p) {
			t.Fatalf("drop=%d treated as recovered", drop)
		}
	}
}

func TestDegradedTradeoffIsBounded(t *testing.T) {
	p := speedTestPolicy()
	if !degradedSpeedBetter(434, 490, 6_159_738, 18_305_771, p) {
		t.Fatal("reported speed exit rejected")
	}
	if degradedSpeedBetter(434, 900, 6_000_000, 30_000_000, p) || degradedSpeedBetter(434, 450, 6_000_000, 6_900_000, p) {
		t.Fatal("latency or absolute gain ignored")
	}
	a, b := 434, 490
	as, bs := int64(6_159_738), int64(18_305_771)
	if meaningfullyBetter("active", []string{"b"}, map[string]*int{"active": &a, "b": &b}, map[string]*int64{"active": &as, "b": &bs}, p) != "" {
		t.Fatal("ordinary latency guard changed")
	}
	p.speedImprovement = 10
	if !degradedSpeedBetter(434, 440, 10_000_000, 11_000_000, p) {
		t.Fatal("explicit relative gain ignored")
	}
}

func TestSpeedSurveyChoosesBestWithoutIntermediateSwitch(t *testing.T) {
	for _, unstable := range []bool{false, true} {
		p := speedTestPolicy()
		item, now := speedTestEpisode(t, p)
		calls := []string{}
		switched := ""
		for i := 0; i < speedCyclePairLimit(p); i++ {
			nominee := speedDegradationCandidate(now, "active", []string{"a", "b"}, item, p)
			if nominee == "" {
				t.Fatalf("lost nominee: %+v", item.SpeedDegradation)
			}
			gatePlannedOptimization(now, "active", nominee, "speed-degraded", nil, item, p)
			node := item.OptimizationCandidate
			at := now.Add(time.Minute)
			if float64(at.Unix()) < item.OptimizationNextAt {
				at = time.Unix(int64(item.OptimizationNextAt), 0)
			}
			speed := int64(12_000_000)
			if node == "b" {
				speed = 18_000_000
				if unstable && item.SpeedDegradation.SurveyComplete {
					speed = 5_000_000
				}
			}
			calls = append(calls, node)
			cmp := comparePlannedOptimization(at, "active", node, map[string]probeEvidence{"active": successfulEvidence(434), node: successfulEvidence(490)}, map[string]int64{"active": 6_000_000, node: speed}, true, true, item, p)
			desired, reason := gatePlannedOptimization(at, "active", nominee, "speed-degraded", cmp, item, p)
			now = at
			if desired != "active" {
				if reason != "speed-degraded" {
					t.Fatal(reason)
				}
				switched = desired
				break
			}
		}
		want := "b"
		if unstable {
			want = "a"
		}
		if switched != want || len(calls) < 4 || calls[0] != "a" || calls[1] != "b" {
			t.Fatalf("unstable=%v selected=%s calls=%v", unstable, switched, calls)
		}
	}
}

func TestPrioritySpeedExitPreservesQueueOrder(t *testing.T) {
	p := speedTestPolicy()
	p.mode = "priority"
	item, now := speedTestEpisode(t, p)
	nominee := speedDegradationCandidate(now, "active", []string{"a", "b"}, item, p)
	if nominee != "a" {
		t.Fatal("priority became throughput ranking")
	}
	gatePlannedOptimization(now, "active", nominee, "speed-degraded", nil, item, p)
	for i := 1; i <= 2; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		cmp := comparePlannedOptimization(at, "active", "a", map[string]probeEvidence{"active": successfulEvidence(434), "a": successfulEvidence(490)}, map[string]int64{"active": 6_000_000, "a": 12_000_000}, true, true, item, p)
		desired, _ := gatePlannedOptimization(at, "active", "a", "speed-degraded", cmp, item, p)
		if (i == 1 && desired != "active") || (i == 2 && desired != "a") {
			t.Fatalf("pair=%d selected=%s", i, desired)
		}
	}
}

func TestPrioritySpeedDropIgnoresURLTestGainThreshold(t *testing.T) {
	p := speedTestPolicy()
	p.mode, p.speedImprovement = "priority", 99
	item, now := speedTestEpisode(t, p)
	gatePlannedOptimization(now, "active", "a", "speed-degraded", nil, item, p)
	for i := 1; i <= 2; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		cmp := comparePlannedOptimization(at, "active", "a", map[string]probeEvidence{"active": successfulEvidence(434), "a": successfulEvidence(434)}, map[string]int64{"active": 6_000_000, "a": 7_000_000}, true, true, item, p)
		desired, reason := gatePlannedOptimization(at, "active", "a", "speed-degraded", cmp, item, p)
		if cmp.Result != optimizationWin || (i == 1 && desired != "active") || (i == 2 && (desired != "a" || reason != "speed-degraded")) {
			t.Fatalf("hidden URLTest threshold affected priority pair %d: %s %s %+v", i, desired, reason, cmp)
		}
	}
	p.mode = "best"
	if degradedSpeedBetter(434, 434, 6_000_000, 7_000_000, p) {
		t.Fatal("URLTest gain threshold was also bypassed")
	}
}

func TestPriorityDoesNotSwitchForSpeedGainAlone(t *testing.T) {
	p := speedTestPolicy()
	p.mode = "priority"
	item := newPolicyHealthState()
	now := time.Unix(50_000, 0)
	item.Recoveries["a"], item.LastProbeAt["a"] = 3, float64(now.Unix())
	delay, speed, faster := 434, int64(6_000_000), int64(100_000_000)
	desired, reason := selectDesired(now, "priority", "active", []string{"active", "a"}, nil, nil,
		map[string]*int{"active": &delay, "a": &delay}, map[string]*int64{"active": &speed, "a": &faster}, nil,
		map[string]bool{"active": true, "a": true}, map[string]bool{"active": true, "a": true}, item, p)
	if desired != "active" || reason != "" || item.SpeedDegradation != nil {
		t.Fatalf("priority chased a faster reserve without its own degradation: %s %s", desired, reason)
	}
}

func TestPriorityRecoveryIsNotBlockedByBackupSpeedEpisode(t *testing.T) {
	for _, blocked := range []string{"", "cooldown", "probation", "stale", "unconfirmed"} {
		t.Run(blocked, func(t *testing.T) {
			p := speedTestPolicy()
			p.mode = "priority"
			item, now := speedTestEpisode(t, p)
			item.Recoveries["a"], item.LastProbeAt["a"] = 3, float64(now.Unix())
			item.Recoveries["b"], item.LastProbeAt["b"] = 3, float64(now.Unix())
			item.SpeedProbation["a"] = speedProbation{Until: float64(now.Unix() - 1), Recoveries: 3, LastRecoveryAt: float64(now.Unix())}
			if blocked == "" {
				item.OptimizationCandidate, item.OptimizationBaseline = "b", "active"
				item.OptimizationSpeedDegraded, item.OptimizationChecks = true, 1
			}
			switch blocked {
			case "cooldown":
				item.CooldownUntil = float64(now.Unix() + 600)
			case "probation":
				item.SpeedProbation["a"] = speedProbation{Until: float64(now.Unix() + 600)}
			case "stale":
				item.LastProbeAt["a"] = float64(now.Unix() - 1000)
			case "unconfirmed":
				item.Recoveries["a"] = 1
			}
			delay, activeSpeed, primarySpeed, reserveSpeed := 434, int64(6_000_000), int64(5_000_000), int64(12_000_000)
			desired, reason := selectDesired(now, "priority", "active", []string{"a", "active", "b"}, nil, nil,
				map[string]*int{"active": &delay, "a": &delay, "b": &delay}, map[string]*int64{"active": &activeSpeed, "a": &primarySpeed, "b": &reserveSpeed}, nil,
				map[string]bool{"active": true, "a": true, "b": true}, map[string]bool{"active": true, "a": true, "b": true}, item, p)
			if blocked == "" {
				if desired != "a" || reason != "higher-priority-recovered" {
					t.Fatalf("qualified primary was held by speed investigation: %s %s", desired, reason)
				}
				winning := &optimizationComparison{Candidate: "b", Result: optimizationWin}
				desired, reason = gatePlannedOptimization(now, "active", desired, reason, winning, item, p)
				if desired != "a" || reason != "higher-priority-recovered" || item.OptimizationCandidate != "" || item.OptimizationChecks != 0 {
					t.Fatalf("second pending speed win overrode priority return: %s %s", desired, reason)
				}
			} else {
				if reason == "higher-priority-recovered" {
					t.Fatalf("normal priority return bypassed %s", blocked)
				}
				desired, _ = gatePlannedOptimization(now, "active", desired, reason, nil, item, p)
				if desired != "active" {
					t.Fatalf("unconfirmed speed nomination bypassed %s", blocked)
				}
			}
		})
	}
}

func TestSpeedProbationRequiresTimeAndSpacedFreshRecovery(t *testing.T) {
	p := speedTestPolicy()
	item, now := speedTestEpisode(t, p)
	recordSpeedDegradationExit(now, item, "active")
	probe := func(seconds int64) {
		updateSpeedHistory(now.Add(time.Duration(seconds)*time.Second), "other", []string{"active"}, []string{"active"}, map[string]int64{"active": 18_000_000}, map[string]string{"active": "ok"}, item, p)
	}
	probe(60)
	probe(61)
	probe(62)
	if item.SpeedProbation["active"].Recoveries != 1 {
		t.Fatal("burst cleared probation")
	}
	probe(360)
	probe(660)
	if !speedProbationActive(now.Add(29*time.Minute), item, "active", p) || speedProbationActive(now.Add(30*time.Minute), item, "active", p) {
		t.Fatal("duration or recovery ignored")
	}
	probe(10_000)
	if item.SpeedProbation["active"].Recoveries != 1 {
		t.Fatal("old recovery series survived a long gap")
	}
	item.SpeedDegradation = &speedDegradation{Node: "active", Since: float64(now.Unix() + 10_000), BaselineBPS: 18_000_000, RecoveryPercent: 80}
	recordSpeedDegradationExit(now.Add(10_000*time.Second), item, "active")
	penalty := item.SpeedProbation["active"]
	if penalty.Count != 2 || penalty.Until-penalty.LastAt != 7200 {
		t.Fatal("repeat drop not penalized")
	}
}

func TestExhaustedSpeedCycleRequiresFreshActiveBeforeRetry(t *testing.T) {
	p := speedTestPolicy()
	item, now := speedTestEpisode(t, p)
	item.SpeedDegradation.Pairs = speedCyclePairLimit(p)
	item.SpeedDegradation.Tried = []string{"a"}
	refreshSpeedEpisode(now, "active", item, p)
	retry := now.Add(15 * time.Minute)
	if speedDegradationReady(retry.Add(-time.Second), "active", item, p) {
		t.Fatal("exhausted cycle restarted")
	}
	refreshSpeedEpisode(retry, "active", item, p)
	if item.SpeedDegradation.BaselineBPS != 18_000_000 || len(item.SpeedDegradation.Tried) != 0 || speedDegradationReady(retry, "active", item, p) {
		t.Fatal("retry reused old evidence or lost baseline")
	}
	updateSpeedHistory(retry, "active", []string{"active"}, []string{"active"}, map[string]int64{"active": 6_000_000}, map[string]string{"active": "ok"}, item, p)
	if !speedDegradationReady(retry, "active", item, p) {
		t.Fatal("fresh slow evidence did not reopen investigation")
	}
}

func TestMissingActiveSpeedDoesNotAccuseReserve(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, finalist := range []bool{false, true} {
			p := speedTestPolicy()
			p.mode = mode
			item, now := speedTestEpisode(t, p)
			item.SpeedDegradation.SurveyComplete = finalist
			gatePlannedOptimization(now, "active", "a", "speed-degraded", nil, item, p)
			gatePlannedOptimization(now.Add(time.Minute), "active", "a", "speed-degraded", &optimizationComparison{Candidate: "a", Result: optimizationInconclusive, Reason: "active-speed-missing"}, item, p)
			if item.OptimizationBackoff["a"] != 0 || len(item.SpeedProbation) != 0 || item.UnderlayFailure != "" || item.SpeedDegradation.RetryAfter <= float64(now.Unix()) {
				t.Fatal("missing active speed invented reserve/WAN failure")
			}
		}
	}
}

func TestNewlyPromotedSpeedWinnerCanDetectFirstCollapse(t *testing.T) {
	p := speedTestPolicy()
	now := time.Unix(50_000, 0)
	item := newPolicyHealthState()
	item.SpeedSelectionReference = &speedSelectionReference{Node: "new", At: float64(now.Unix()), BPS: 18_000_000}
	updateSpeedHistory(now.Add(15*time.Minute), "new", []string{"new"}, []string{"new"}, map[string]int64{"new": 6_000_000}, map[string]string{"new": "ok"}, item, p)
	if item.SpeedDegradation == nil || len(item.SpeedHistory["new"]) != 1 {
		t.Fatal("first collapse missed or history invented")
	}
}

func TestSpeedDegradationBypassesSoftCooldownButDoesNotSwitchOnNomination(t *testing.T) {
	p := speedTestPolicy()
	item, now := speedTestEpisode(t, p)
	item.CooldownUntil = float64(now.Unix() + 600)
	item.Recoveries["a"] = 3
	item.LastProbeAt["a"] = float64(now.Unix() - 30)
	a, b := 434, 490
	as, bs := int64(18_000_000), int64(12_000_000)
	desired, reason := selectDesired(now, "best", "active", []string{"active", "a"}, nil, nil, map[string]*int{"active": &a, "a": &b}, map[string]*int64{"active": &as, "a": &bs}, nil, map[string]bool{"active": true, "a": true}, map[string]bool{"active": true, "a": true}, item, p)
	if desired != "a" || reason != "speed-degraded" {
		t.Fatalf("old cooldown/median vetoed investigation: %s %s", desired, reason)
	}
	desired, _ = gatePlannedOptimization(now, "active", desired, reason, nil, item, p)
	if desired != "active" || item.OptimizationChecks != 0 {
		t.Fatal("nomination moved traffic")
	}
}

func TestAvailabilityEmergencyMayUseSpeedProbationNode(t *testing.T) {
	p := speedTestPolicy()
	item, now := speedTestEpisode(t, p)
	item.SpeedProbation["a"] = speedProbation{Until: float64(now.Unix() + 7200), BaselineBPS: 18_000_000}
	item.AvailabilityFailures["active"] = 3
	item.Recoveries["a"] = 3
	item.LastProbeAt["a"] = float64(now.Unix())
	delay := 490
	desired, reason := selectDesired(now, "best", "active", []string{"active", "a"}, nil, nil, map[string]*int{"a": &delay}, nil, map[string]probeEvidence{"a": successfulEvidence(delay)}, map[string]bool{"a": true}, map[string]bool{"a": true}, item, p)
	desired, reason = gatePlannedOptimization(now, "active", desired, reason, nil, item, p)
	if desired != "a" || reason != "active-unavailable" {
		t.Fatalf("probation blocked emergency: %s %s", desired, reason)
	}
}

func TestComparisonLoserDoesNotBlockOtherReserve(t *testing.T) {
	p := speedTestPolicy()
	now := time.Unix(50_000, 0)
	item := newPolicyHealthState()
	item.OptimizationCandidate = "a"
	gatePlannedOptimization(now, "active", "a", "meaningfully-faster", &optimizationComparison{Candidate: "a", Result: optimizationLoss, Reason: "not-better"}, item, p)
	if item.OptimizationRetryAfter != 0 || item.OptimizationBackoff["a"] <= float64(now.Unix()) {
		t.Fatal("loss set global cooldown")
	}
	gatePlannedOptimization(now.Add(time.Second), "active", "b", "meaningfully-faster", nil, item, p)
	if item.OptimizationCandidate != "b" || item.OptimizationNextAt < float64(now.Unix()+300) {
		t.Fatal("other reserve cannot queue or budget vanished")
	}
}
