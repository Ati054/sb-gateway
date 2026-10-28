package agent

import (
	"testing"
	"time"
)

func TestRecentLatencyWindowIsBoundedAndExpires(t *testing.T) {
	p := effectivePolicySettings{active: 60, backup: 120}
	value := 300
	samples := []healthSample{{At: 0, OK: true, DelayMS: &value}, {At: 700, OK: true, DelayMS: &value}, {At: 760, OK: true, DelayMS: &value}, {At: 820, OK: true, DelayMS: &value}, {At: 880, OK: true, DelayMS: &value}, {At: 940, OK: true, DelayMS: &value}, {At: 1001, OK: true, DelayMS: &value}}
	kept := recentQualitySamples(time.Unix(1000, 0), samples, p)
	if len(kept) != 3 || kept[0].At != 820 || kept[2].At != 940 {
		t.Fatalf("incorrect bounded recent window: %+v", kept)
	}
	if len(recentQualitySamples(time.Unix(2000, 0), kept, p)) != 0 {
		t.Fatal("old latency pinned ranking after a long pause")
	}
}

func TestLatencyWindowRejectsSpikeWithoutPinningSlowerActive(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	contract := runtime.pool.HealthPolicies["europe"]
	contract.Policy.SwitchImprovementMS = 200
	runtime.pool.HealthPolicies["europe"] = contract
	baseline := 400
	for _, node := range []string{"active", "reserve"} {
		item.Samples[node] = []healthSample{{At: 880, OK: true, DelayMS: &baseline}, {At: 940, OK: true, DelayMS: &baseline}, {At: 1000, OK: true, DelayMS: &baseline}}
	}
	for i, active := range []int{400, 1200, 1200, 400, 400, 900, 900, 900, 900} {
		runtime.probes["active"], runtime.probes["reserve"] = successfulEvidence(active), successfulEvidence(400)
		if err := controller.Tick(time.Unix(1060+int64(i)*60, 0)); err != nil {
			t.Fatal(err)
		}
		if i < 7 && item.Selected != "active" {
			t.Fatalf("isolated spike or incomplete stable confirmation switched at sample %d", i)
		}
	}
	if item.Selected != "reserve" || item.LastSwitchReason != "meaningfully-faster" {
		t.Fatal("stable advantage above 200 ms did not replace the slower active")
	}
}

func TestAvailabilityFailureDoesNotWaitForLatencyMedian(t *testing.T) {
	controller, item, runtime := stagedOptimizationController(t)
	delay := 100
	item.Samples["active"] = []healthSample{{At: 880, OK: true, DelayMS: &delay}, {At: 940, OK: true, DelayMS: &delay}, {At: 1000, OK: true, DelayMS: &delay}}
	runtime.probes["active"] = probeEvidence{Failure: probeFailureFatal}
	if err := controller.Tick(time.Unix(1060, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "reserve" {
		t.Fatal("healthy latency history masked a current confirmed network failure")
	}
}

func TestCurrentLatencyComparisonUsesSameShortMedianAsRanking(t *testing.T) {
	item := newPolicyHealthState()
	item.QualityOK, item.AvailabilityOK = map[string]bool{}, map[string]bool{}
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
	for node, delays := range map[string][]int{"active": {600, 600, 1200}, "reserve": {350, 350, 450}} {
		for index, value := range delays {
			item.Samples[node] = append(item.Samples[node], healthSample{At: float64(880 + index*60), ObservedAt: float64(880 + index*60), OK: true, DelayMS: &value})
		}
		item.QualityOK[node], item.AvailabilityOK[node], item.Recoveries[node] = true, true, 3
	}
	pair := currentLatencyComparisons(time.Unix(1000, 0), item, []string{"active", "reserve"}, policySettings(healthPolicy{}, "best"))["reserve"]
	if pair.ActiveDelayMS != 600 || pair.CandidateDelayMS != 350 || pair.ActiveAt != 1000 || pair.CandidateAt != 1000 {
		t.Fatalf("panel and ranking use different windows: %+v", pair)
	}
}
