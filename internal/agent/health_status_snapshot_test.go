package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/healthsnapshot"
)

func TestCompactHealthSnapshotOmitsHistoryAndKeepsDelta(t *testing.T) {
	for _, warm := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold", true: "warm"}[warm], func(t *testing.T) {
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "active", "active", true
			pair := latencyComparison{Active: "active", ActiveDelayMS: 100, CandidateDelayMS: 80, ActiveAt: 995, CandidateAt: 996, ExpiresAt: 1115}
			item.LastLatencyComparisons = map[string]latencyComparison{"reserve": pair}
			if warm {
				item.WarmPlanningMarker = string(qualityMeasurementWarm)
			}
			item.DailySamples["active"] = make([]healthSample, 10000)
			path := statePath(t.TempDir(), "selector-health")
			if err := publishHealthState(path, healthState{"route": item, "absent": nil}); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(filepath.Join(filepath.Dir(path), healthsnapshot.Filename))
			if err != nil {
				t.Fatal(err)
			}
			if len(body) > 4096 {
				t.Fatal("history entered compact snapshot")
			}
			for _, field := range []string{"daily_samples", "history_days", "daily_stats", "warm_planning_samples"} {
				if strings.Contains(string(body), field) {
					t.Fatal("unexpected history field", field)
				}
			}
			var envelope healthsnapshot.Envelope
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if envelope.Version != 1 || envelope.HistoryStamp != healthsnapshot.Stamp(info) {
				t.Fatal("wrong source generation")
			}
			var status map[string]compactHealthStatus
			if err := json.Unmarshal(envelope.Status, &status); err != nil {
				t.Fatal(err)
			}
			record := status["route"]
			if !record.Confirmed || record.Selected != "active" {
				t.Fatal("lost runtime facts")
			}
			if warm {
				if record.WarmLast["reserve"] != pair || len(record.Last) != 0 {
					t.Fatal("mixed warm/cold Delta")
				}
			} else if record.Last["reserve"] != pair || record.WarmMarker != "" {
				t.Fatal("lost cold Delta")
			}
		})
	}
}

func TestOptionalCompactSnapshotFailureDoesNotFailHistoryOrReadiness(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	if err := os.Mkdir(filepath.Join(root, healthsnapshot.Filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, healthsnapshot.Filename, "occupied"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishHealthState(path, healthState{"route": {RuntimeSelected: "active", RuntimeConfirmed: true}}); err != nil {
		t.Fatal(err)
	}
	var stored healthState
	if err := readJSON(path, &stored); err != nil || !stored["route"].RuntimeConfirmed {
		t.Fatal("optional cache affected committed history", err)
	}
}
