package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestURLTestEmergencyPlanUsesFreshQualityAndKeepsSweepSlot(t *testing.T) {
	now := time.Unix(1000, 0)
	item := newPolicyHealthState()
	item.MedianDelayMS = make(map[string]*int)
	item.AvailabilityOK, item.QualityOK = make(map[string]bool), make(map[string]bool)
	item.DailyStats = make(map[string]healthStats)
	candidates := []string{"active", "slow", "fast", "middle", "stale", "closed", "failed", "future", "unknown"}
	for index, candidate := range candidates {
		delay := 1000 - index*100
		item.MedianDelayMS[candidate] = &delay
		item.Samples[candidate] = []healthSample{{At: 999, OK: true, DelayMS: &delay}}
		item.AvailabilityOK[candidate], item.QualityOK[candidate] = true, true
		item.Recoveries[candidate], item.LastProbeAt[candidate] = 3, 999
	}
	fast, aggregate := 100, 1
	item.Samples["fast"][0].DelayMS = &fast
	item.MedianDelayMS["fast"] = &fast
	item.Samples["stale"][0].At = 700
	item.LastProbeAt["stale"] = 999 // a recent availability probe is not quality
	item.Samples["future"][0].At = 1001
	item.AvailabilityFailures["failed"] = 1
	item.Samples["failed"][0].OK = false
	item.PreflightClosed = map[string]bool{"closed": true}
	delete(item.Samples, "unknown")
	// Daily aggregates must not override current quality evidence.
	item.DailyStats["slow"] = healthStats{MedianMS: &aggregate}
	p := policySettings(healthPolicy{ProbeBatchSize: 3}, "best")
	targets, preferred := emergencyProbePlan(now, "active", []string{"unknown", "slow", "middle"}, candidates, nil, item, p)
	if !reflect.DeepEqual(targets, []string{"fast", "middle", "unknown"}) || !reflect.DeepEqual(preferred, []string{"fast", "middle"}) {
		t.Fatalf("plan=%v ranking=%v", targets, preferred)
	}
	p.batch = 1
	targets, preferred = emergencyProbePlan(now, "active", []string{"unknown"}, candidates, nil, item, p)
	if !reflect.DeepEqual(targets, []string{"fast"}) || !reflect.DeepEqual(preferred, []string{"fast"}) {
		t.Fatalf("single-slot plan=%v ranking=%v", targets, preferred)
	}
	p.mode, p.batch = "priority", 3
	targets, preferred = emergencyProbePlan(now, "active", []string{"unknown", "slow", "middle"}, []string{"slow", "fast"}, map[string]int{"slow": 0, "fast": 1}, item, p)
	if len(preferred) != 0 || targets[0] != "slow" {
		t.Fatalf("URLTest ranking changed priority mode: %v / %v", targets, preferred)
	}
}

func TestURLTestEmergencyRankingUsesLatestPrimaryWithoutPlannedRecoveryGate(t *testing.T) {
	for _, recoveries := range []int{0, 1, 2, 3} {
		t.Run(fmt.Sprintf("recoveries=%d", recoveries), func(t *testing.T) {
			item := newPolicyHealthState()
			item.AvailabilityOK = map[string]bool{"fast": true, "slow": true}
			item.QualityOK = map[string]bool{"fast": true, "slow": true}
			oldFast, latestFast, oldSlow, latestSlow := 900, 400, 300, 640
			item.MedianDelayMS = map[string]*int{"fast": &oldFast, "slow": &oldSlow}
			item.Samples["fast"] = []healthSample{{At: 970, OK: true, DelayMS: &oldFast}, {At: 999, ObservedAt: 999.5, OK: true, DelayMS: &latestFast}}
			item.Samples["slow"] = []healthSample{{At: 970, OK: true, DelayMS: &oldSlow}, {At: 999, ObservedAt: 999.5, OK: true, DelayMS: &latestSlow}}
			item.Recoveries["fast"], item.Recoveries["slow"] = recoveries, 3
			p := policySettings(healthPolicy{ProbeBatchSize: 2}, "best")
			targets, preferred := emergencyProbePlan(time.Unix(1000, 0), "active", []string{"slow", "unknown"}, []string{"active", "slow", "fast", "unknown"}, nil, item, p)
			if !reflect.DeepEqual(targets, []string{"fast", "slow"}) || !reflect.DeepEqual(preferred, []string{"fast", "slow"}) {
				t.Fatalf("latest primary evidence lost to old median/recovery gate: targets=%v preferred=%v", targets, preferred)
			}
			if item.Recoveries["fast"] != recoveries || *item.MedianDelayMS["fast"] != oldFast {
				t.Fatal("emergency ranking changed planned recovery or historical aggregates")
			}
		})
	}
}

func TestURLTestEmergencyRankingRejectsInvalidLatestQuality(t *testing.T) {
	delay := 100
	for _, tc := range []struct {
		name     string
		sample   healthSample
		failures int
	}{
		{name: "stale", sample: healthSample{At: 999, ObservedAt: 879, OK: true, DelayMS: &delay}},
		{name: "future", sample: healthSample{At: 999, ObservedAt: 1001, OK: true, DelayMS: &delay}},
		{name: "failed", sample: healthSample{At: 999, OK: false, DelayMS: &delay}},
		{name: "fallback-only", sample: healthSample{At: 999, OK: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := newPolicyHealthState()
			item.AvailabilityOK, item.QualityOK = map[string]bool{"node": true}, map[string]bool{"node": true}
			item.MedianDelayMS = map[string]*int{"node": &delay}
			item.Samples["node"] = []healthSample{tc.sample}
			item.Recoveries["node"], item.AvailabilityFailures["node"] = 3, tc.failures
			if got := knownFreshReserves(time.Unix(1000, 0), "active", []string{"node"}, "best", nil, item, policySettings(healthPolicy{}, "best")); len(got) != 0 {
				t.Fatalf("invalid primary entered emergency ranking: %v", got)
			}
		})
	}
}

func TestURLTestEmergencyLatestReserveMustPassCurrentProbe(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprintf("preferred-status=%d", status), func(t *testing.T) {
			runtime, _, nodes := rankedEmergencyFixture(t, []emergencyProbeResponse{{20 * time.Millisecond, 204}, {150 * time.Millisecond, status}})
			item := newPolicyHealthState()
			item.AvailabilityOK, item.QualityOK = map[string]bool{}, map[string]bool{}
			item.MedianDelayMS = map[string]*int{}
			for i, node := range nodes {
				latest, old := 640-i*240, 300+i*600
				item.Samples[node] = []healthSample{{At: 999, ObservedAt: 999.5, OK: true, DelayMS: &latest}}
				item.MedianDelayMS[node] = &old
				item.AvailabilityOK[node], item.QualityOK[node], item.Recoveries[node] = true, true, 1
			}
			p := policySettings(healthPolicy{ProbeBatchSize: 2}, "best")
			targets, preferred := emergencyProbePlan(time.Unix(1000, 0), "active", nodes, nodes, nil, item, p)
			controller := &healthController{runtime: runtime, state: healthState{"route": item}}
			measured, selected, err := controller.probeEmergencyCandidates("route", targets, preferred)
			want := nodes[1]
			if status != http.StatusNoContent {
				want = nodes[0]
			}
			if err != nil || selected != want || !measured[selected].OK {
				t.Fatalf("cached speed bypassed current proof: selected=%s want=%s err=%v", selected, want, err)
			}
			if item.LastEmergencySelection == nil || len(item.LastEmergencySelection.Preferred) != 2 || item.LastEmergencySelection.Preferred[0] != nodes[1] {
				t.Fatal("switch lost its emergency ranking evidence")
			}
		})
	}
}

func TestEmergencySelectionEvidenceIsTransientAndSanitized(t *testing.T) {
	item := newPolicyHealthState()
	delay := 400
	item.Samples["fast"] = []healthSample{{At: 999, OK: true, DelayMS: &delay}}
	preferred := []string{"fast"}
	item.LastEmergencySelection = emergencySelectionEvidence(item, []string{"fast", "slow", "pending"}, preferred,
		map[string]probeEvidence{"fast": {Failure: probeFailureTimeout, TargetFailures: map[string]probeFailureClass{"private-origin.example/secret": probeFailureTimeout}}, "slow": successfulEvidence(640)}, "slow")
	preferred[0], delay = "changed", 999
	selection := item.LastEmergencySelection
	if selection.Reason != "ranked-reserves-pending-or-unavailable" || selection.Preferred[0] != "fast" || *selection.Probes[0].PrimaryDelayMS != 400 || selection.Probes[2].Result != "not-completed" {
		t.Fatalf("inaccurate or aliased switch evidence: %+v", selection)
	}
	data, err := json.Marshal(healthEvent{ReserveSelection: selection})
	if err != nil || strings.Contains(string(data), "private-origin") || strings.Contains(string(data), "secret") || !strings.Contains(string(data), "reserve_selection") {
		t.Fatalf("invalid switch diagnostic: %s err=%v", data, err)
	}
	data, err = json.Marshal(item)
	if err != nil || strings.Contains(string(data), "ranked-reserves-pending-or-unavailable") {
		t.Fatal("transient switch diagnostic leaked into persisted health history")
	}
}

func TestKnownEmergencyReserveUsesQualitySampleTimestamp(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, at := range []float64{0, 879, 880, 999, 1001} {
			t.Run(fmt.Sprintf("%s/at=%g", mode, at), func(t *testing.T) {
				delay := 100
				item := newPolicyHealthState()
				item.AvailabilityOK, item.QualityOK = map[string]bool{"reserve": true}, map[string]bool{"reserve": true}
				item.MedianDelayMS = map[string]*int{"reserve": &delay}
				item.Recoveries["reserve"], item.LastProbeAt["reserve"] = 3, 1000
				item.Samples["reserve"] = []healthSample{{At: at, OK: true, DelayMS: &delay}}
				got := knownFreshReserve(time.Unix(1000, 0), "active", []string{"reserve"}, mode, nil, item, policySettings(healthPolicy{}, mode))
				want := ""
				if at == 880 || at == 999 {
					want = "reserve"
				}
				if got != want {
					t.Fatalf("quality at=%g, availability at=1000: reserve=%q want=%q", at, got, want)
				}
			})
		}
	}
}

func TestEmergencyChoicePrefersCurrentSuccessNotCompletionOrder(t *testing.T) {
	choice := emergencyChoice{preferred: []string{"fast", "middle"}, firstSuccess: "slow"}
	measured := map[string]probeEvidence{"slow": successfulEvidence(600)}
	if candidate, _ := choice.ready(measured); candidate != "" {
		t.Fatal("selected unranked response before the preferred probes")
	}
	measured["middle"] = successfulEvidence(300)
	if candidate, _ := choice.ready(measured); candidate != "" {
		t.Fatal("selected middle while the best reserve was still pending")
	}
	measured["fast"] = failedEvidence()
	if candidate, _ := choice.ready(measured); candidate != "middle" {
		t.Fatal("did not immediately use the next ranked confirmed reserve")
	}
	delete(measured, "fast")
	choice.expired = true
	if candidate, _ := choice.ready(measured); candidate != "middle" {
		t.Fatal("deadline did not use the best completed success")
	}
	measured["middle"] = failedEvidence()
	if candidate, _ := choice.ready(measured); candidate != "slow" {
		t.Fatal("deadline did not release an unranked working fallback")
	}
}

type emergencyProbeResponse struct {
	delay  time.Duration
	status int
}

func rankedEmergencyFixture(t *testing.T, responses []emergencyProbeResponse) (*responsiveSelectorRuntime, string, []string) {
	t.Helper()
	oldTargets := healthTargets
	healthTargets = append(healthTargets[:0:0], oldTargets[0])
	healthTargets[0].url = "http://probe.invalid/generate_204"
	t.Cleanup(func() { healthTargets = oldTargets })
	pool := healthFixture(false)
	pool.Version = 4
	candidates := []string{}
	byCandidate := make(map[string]emergencyProbeResponse)
	for index := range responses {
		candidate := fmt.Sprintf("reserve-%d", index)
		candidates = append(candidates, candidate)
		byCandidate[candidate] = responses[index]
	}
	pool.BaseOutboundTags = candidates
	path := filepath.Join(t.TempDir(), "pool.json")
	if err := writeJSONAtomic(path, pool); err != nil {
		t.Fatal(err)
	}
	lanes := []*xraySelectorRuntime{}
	for range responses {
		var selected atomic.Value
		selected.Store("")
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			response, known := byCandidate[selected.Load().(string)]
			if !known {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			select {
			case <-request.Context().Done():
				return
			case <-time.After(response.delay):
				w.WriteHeader(response.status)
			}
		}))
		t.Cleanup(proxy.Close)
		lane := newXraySelectorRuntime(Options{HealthPoolFile: path, ProbeURL: proxy.URL})
		lane.probeSelector = "outbound-health-background"
		lane.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
			if len(args) > 1 && args[1] == "bo" {
				selected.Store(args[len(args)-1])
				return nil, nil
			}
			return selectorInfo(selected.Load().(string)), nil
		}
		lanes = append(lanes, lane)
	}
	runtime := &responsiveSelectorRuntime{
		selectorRuntime: &fakeSelectorRuntime{}, backgrounds: lanes, ctx: context.Background(),
		enabled: true, parallelEnabled: true, generationPaths: []string{path},
	}
	runtime.generation = generationStamp(runtime.generationPaths)
	return runtime, path, candidates
}

func TestRankedEmergencyParallelSelection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		responses []emergencyProbeResponse
		preferred []string
		want      string
		minWait   time.Duration
		maxWait   time.Duration
	}{
		{"better reserve finishes second", []emergencyProbeResponse{{20 * time.Millisecond, 204}, {150 * time.Millisecond, 204}}, []string{"reserve-1", "reserve-0"}, "reserve-1", 100 * time.Millisecond, 800 * time.Millisecond},
		{"failed best releases fallback", []emergencyProbeResponse{{20 * time.Millisecond, 204}, {100 * time.Millisecond, 503}}, []string{"reserve-1"}, "reserve-0", 50 * time.Millisecond, 800 * time.Millisecond},
		{"hung best has bounded wait", []emergencyProbeResponse{{20 * time.Millisecond, 204}, {5 * time.Second, 204}}, []string{"reserve-1"}, "reserve-0", emergencyPreferenceWait, 2 * time.Second},
		{"best succeeds without waiting for sibling", []emergencyProbeResponse{{20 * time.Millisecond, 204}, {5 * time.Second, 204}}, []string{"reserve-0", "reserve-1"}, "reserve-0", 0, 800 * time.Millisecond},
		{"unknown ranking keeps immediate recovery", []emergencyProbeResponse{{20 * time.Millisecond, 204}, {5 * time.Second, 204}}, nil, "reserve-0", 0, 800 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, _, candidates := rankedEmergencyFixture(t, tc.responses)
			controller := &healthController{runtime: runtime}
			started := time.Now()
			measured, selected, err := controller.probeEmergencyCandidates("route", candidates, tc.preferred)
			elapsed := time.Since(started)
			primary := runtime.selectorRuntime.(*fakeSelectorRuntime)
			if err != nil || selected != tc.want || !measured[selected].OK || len(primary.selections) != 1 || elapsed < tc.minWait || elapsed > tc.maxWait {
				t.Fatalf("selected=%q switches=%v elapsed=%s err=%v", selected, primary.selections, elapsed, err)
			}
		})
	}
}

func TestRankedEmergencyDeadlineRejectsApplyAndShutdown(t *testing.T) {
	for _, change := range []string{"generation", "cancellation"} {
		t.Run(change, func(t *testing.T) {
			runtime, path, candidates := rankedEmergencyFixture(t, []emergencyProbeResponse{{20 * time.Millisecond, 204}, {5 * time.Second, 204}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runtime.ctx = ctx
			changed := make(chan error, 1)
			timer := time.AfterFunc(200*time.Millisecond, func() {
				if change == "generation" {
					changed <- os.WriteFile(path, []byte("new-generation"), 0600)
				} else {
					cancel()
					changed <- nil
				}
			})
			defer timer.Stop()
			controller := &healthController{runtime: runtime}
			_, selected, err := controller.probeEmergencyCandidates("route", candidates, []string{"reserve-1"})
			if changeErr := <-changed; changeErr != nil {
				t.Fatal(changeErr)
			}
			if selected != "" || len(runtime.selectorRuntime.(*fakeSelectorRuntime).selections) != 0 || !errors.Is(err, errHealthYield) {
				t.Fatalf("buffered success crossed Apply/shutdown: selected=%q err=%v", selected, err)
			}
		})
	}
}

func TestEmergencyPolicyUsesRankingInBothOutageBranches(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, confirmed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/confirmed=%t", mode, confirmed), func(t *testing.T) {
				runtime, _, reserves := rankedEmergencyFixture(t, []emergencyProbeResponse{{20 * time.Millisecond, 204}, {150 * time.Millisecond, 204}})
				runtime.enabled = false // quality evidence comes from the primary fixture
				pool := healthFixture(false)
				contract := pool.HealthPolicies["europe"]
				contract.Mode = mode
				contract.Policy.ActiveCheckSeconds, contract.Policy.ProbeBatchSize = 60, 3
				contract.Candidates = append([]string{"active"}, reserves...)
				contract.Groups = []healthGroup{{Members: []string{"active"}}, {Members: []string{reserves[0]}}, {Members: []string{reserves[1]}}}
				contract.Nodes = nil
				primary := runtime.selectorRuntime.(*fakeSelectorRuntime)
				primary.current = map[string]string{"europe": "active"}
				primary.probes = map[string]probeEvidence{"active": {Failure: probeFailureTLS}}
				item := newPolicyHealthState()
				item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
				item.CandidateSignature = strings.Join(contract.Candidates, "\n")
				item.LastProbeAt["active"] = 940
				if confirmed {
					item.AvailabilityFailures["active"] = healthFailureConfirmations
				} else {
					item.AvailabilityFailures["active"] = healthFailureConfirmations - 1
				}
				item.MedianDelayMS = make(map[string]*int)
				item.AvailabilityOK, item.QualityOK = make(map[string]bool), make(map[string]bool)
				for index, reserve := range reserves {
					delay := 600 - index*500
					primary.probes[reserve] = successfulEvidence(delay)
					item.MedianDelayMS[reserve] = &delay
					item.Samples[reserve] = []healthSample{{At: 999, OK: true, DelayMS: &delay}}
					item.AvailabilityOK[reserve], item.QualityOK[reserve] = true, true
					item.Recoveries[reserve], item.LastProbeAt[reserve] = 3, 999
				}
				controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime,
					warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item}}
				if err := controller.tickPolicy(time.Unix(1000, 0), "europe", contract, item); err != nil {
					t.Fatal(err)
				}
				want := reserves[0]
				if mode == "best" {
					want = reserves[1]
				}
				if item.Selected != want || item.LastSwitchReason != "active-unavailable" || len(primary.selections) != 1 {
					t.Fatalf("selected=%q want=%q switches=%v reason=%s", item.Selected, want, primary.selections, item.LastSwitchReason)
				}
			})
		}
	}
}

func TestRankedEmergencyMassFailureUsesTenthLane(t *testing.T) {
	responses := make([]emergencyProbeResponse, 10)
	preferred := []string{}
	for index := range responses {
		responses[index] = emergencyProbeResponse{5 * time.Second, 204}
		preferred = append(preferred, fmt.Sprintf("reserve-%d", index))
	}
	responses[9] = emergencyProbeResponse{20 * time.Millisecond, 204}
	runtime, _, candidates := rankedEmergencyFixture(t, responses)
	controller := &healthController{runtime: runtime}
	started := time.Now()
	_, selected, err := controller.probeEmergencyCandidates("route", candidates, preferred)
	if err != nil || selected != "reserve-9" || time.Since(started) > 2*time.Second {
		t.Fatalf("mass failure stalled behind the first nine lanes: selected=%q err=%v", selected, err)
	}
}
