package agent

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestChangedOutboundLosesOldHealthWithoutLosingStableID(t *testing.T) {
	item := newPolicyHealthState()
	item.Selected = "node"
	item.CandidateNodes = map[string]healthNode{"node": {Label: "Old name", Fingerprint: "old"}}
	item.LastProbeAt["node"] = 1000
	item.LastGoodAt["node"] = 1000
	item.AvailabilityOK = map[string]bool{"node": true}
	item.QualityOK = map[string]bool{"node": true}
	item.Recoveries["node"] = 3
	item.Samples["node"] = []healthSample{{OK: true}}
	item.LastWorkingSelection = &workingSelection{Selected: "node"}
	current := map[string]healthNode{"node": {Label: "New name", Fingerprint: "old"}}
	if got := invalidateChangedOutboundHealth(item, []string{"node"}, current); len(got) != 0 {
		t.Fatalf("label rename invalidated endpoint: %v", got)
	}
	current["node"] = healthNode{Label: "New name", Fingerprint: "new"}
	if got := invalidateChangedOutboundHealth(item, []string{"node"}, current); !reflect.DeepEqual(got, []string{"node"}) {
		t.Fatalf("changed endpoint not detected: %v", got)
	}
	if item.Selected != "node" || item.LastProbeAt["node"] != 0 || item.LastGoodAt["node"] != 0 || item.AvailabilityOK["node"] || item.QualityOK["node"] || item.Recoveries["node"] != 0 || len(item.Samples["node"]) != 0 || item.LastWorkingSelection != nil {
		t.Fatalf("stale health survived endpoint change: %+v", item)
	}
	if reserve := knownFreshReserve(time.Unix(1001, 0), "block", []string{"node"}, "priority", nil, item, effectivePolicySettings{backup: 300, recoveryThreshold: 3, failureThreshold: 3}); reserve != "" {
		t.Fatalf("stale reserve reused: %q", reserve)
	}
}

func TestRemovedCandidatesDoNotAccumulateAcrossCatalogGenerations(t *testing.T) {
	item := newPolicyHealthState()
	item.AvailabilityOK = make(map[string]bool)
	item.QualityOK = make(map[string]bool)
	item.CandidateNodes = make(map[string]healthNode)
	item.CandidateServiceStatus = make(map[string]serviceHealthStatus)
	item.PeriodStats = map[string]map[string]healthStats{"24h": {}}
	for generation := range 100 {
		id := fmt.Sprintf("node-%03d", generation)
		item.Selected, item.CandidateSignature = id, id
		item.Failures[id] = 1
		item.AvailabilityFailures[id] = 1
		item.Recoveries[id] = 1
		item.Samples[id] = []healthSample{{OK: true}}
		item.DailySamples[id] = []healthSample{{OK: true}}
		item.HistoryDays[id] = map[string]dayBucket{"2026-09-27": {Samples: 1}}
		item.LastProbeAt[id] = 1
		item.LastGoodAt[id] = 1
		item.SpeedSamplesBPS[id] = []int64{1}
		item.LastSpeedProbeAt[id] = 1
		item.LastSpeedSuccessAt[id] = 1
		item.LastSpeedProbeStatus[id] = "ok"
		item.OptimizationBackoff[id] = 1
		item.FailureClass[id] = "timeout"
		item.AvailabilityOK[id] = true
		item.QualityOK[id] = true
		item.CandidateNodes[id] = healthNode{Label: id}
		item.CandidateServiceStatus[id] = serviceHealthStatus{}
		item.PeriodStats["24h"][id] = healthStats{Samples: 1}
		item.Shortlist = append(item.Shortlist, id)
		item.ProbedCandidates = append(item.ProbedCandidates, id)
		item.SpeedProbeTargets = append(item.SpeedProbeTargets, id)
		item.LastWorkingSelection = &workingSelection{Selected: id}
		pruneRemovedCandidateHealth(item, []string{id})
		if len(item.Samples) != 1 || len(item.DailySamples) != 1 || len(item.HistoryDays) != 1 || len(item.SpeedSamplesBPS) != 1 || len(item.CandidateNodes) != 1 || len(item.PeriodStats["24h"]) != 1 || len(item.Shortlist) != 1 || len(item.ProbedCandidates) != 1 || len(item.SpeedProbeTargets) != 1 {
			t.Fatalf("generation %d retained removed node evidence", generation)
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		if generation > 0 && strings.Contains(string(encoded), fmt.Sprintf("node-%03d", generation-1)) {
			t.Fatalf("generation %d still persisted the previous node", generation)
		}
	}
}

func TestPolicyTickPrunesRemovedCandidateBeforePublishingState(t *testing.T) {
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Candidates = []string{"fr"}
	contract.Nodes = map[string]healthNode{"fr": {Label: "France"}}
	contract.Groups = nil
	item := newPolicyHealthState()
	item.Selected = "de"
	item.RuntimeSelected = "de"
	item.RuntimeConfirmed = true
	item.CandidateSignature = "de\nnl"
	item.CandidateNodes = map[string]healthNode{"de": {Label: "Germany"}, "nl": {Label: "Netherlands"}}
	item.Samples["de"] = []healthSample{{OK: true}}
	item.DailySamples["de"] = []healthSample{{OK: true}}
	item.HistoryDays["de"] = map[string]dayBucket{"2026-09-27": {Samples: 1}}
	item.SpeedSamplesBPS["de"] = []int64{123}
	item.LastSpeedSuccessAt["de"] = 999
	item.AvailabilityOK = map[string]bool{"de": true}
	root := t.TempDir()
	runtime := &fakeSelectorRuntime{
		current: map[string]string{"europe": "de"},
		probes:  map[string]probeEvidence{"fr": successfulEvidence(40)},
	}
	controller := &healthController{
		opts:        Options{StateRoot: root, HealthInterval: time.Minute},
		runtime:     runtime,
		state:       healthState{"europe": item},
		warmStarted: map[string]bool{"europe": true},
	}
	if err := controller.tickPolicy(time.Unix(1000, 0), "europe", contract, item); err != nil {
		t.Fatal(err)
	}
	var persisted healthState
	if err := readJSON(filepath.Join(root, "selector-health.json"), &persisted); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(persisted["europe"])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"de"`) || strings.Contains(string(encoded), `"nl"`) {
		t.Fatalf("removed candidates remained in state: %s", encoded)
	}
}
