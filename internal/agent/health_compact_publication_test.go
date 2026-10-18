package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

func TestHealthPublicationSeparatesRuntimeProofFromHistory(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	item := &policyHealthState{RuntimeSelected: "node-a", RuntimeObservedAt: "2026-01-01T12:00:00Z", RuntimeConfirmed: true,
		CandidateLabels: map[string]string{"node-a": strings.Repeat("history", 100000)}}
	state := healthState{"route": item, "absent": nil}
	if err := publishHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(root, runtimeproof.SelectorSnapshotName)
	body, err := os.ReadFile(proofPath)
	if err != nil || len(body) > 300 || strings.Contains(string(body), "history") {
		t.Fatalf("runtime proof retained quality history: bytes=%d err=%v", len(body), err)
	}
	var proof map[string]runtimeproof.SelectorObservation
	if err := readJSON(proofPath, &proof); err != nil || len(proof) != 1 || !proof["route"].Confirmed || proof["route"].Selected != "node-a" {
		t.Fatalf("wrong runtime proof: %#v, %v", proof, err)
	}
	var history healthState
	if err := readJSON(path, &history); err != nil || history["route"].CandidateLabels["node-a"] != item.CandidateLabels["node-a"] {
		t.Fatalf("history publication changed: %v", err)
	}
	item.RuntimeConfirmed = false
	item.RuntimeSelected = ""
	if err := publishHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(proofPath, &proof); err != nil || proof["route"].Confirmed || proof["route"].Selected != "" {
		t.Fatalf("withdrawal retained stale confirmation: %#v, %v", proof, err)
	}
	if err := publishHealthState(path, healthState{}); err != nil {
		t.Fatal(err)
	}
	proof = nil
	if err := readJSON(proofPath, &proof); err != nil || len(proof) != 0 {
		t.Fatalf("removed policy retained readiness: %#v, %v", proof, err)
	}
}

func TestHealthPublicationDoesNotReplaceHistoryWhenProofCannotBeWritten(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, runtimeproof.SelectorSnapshotName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, runtimeproof.SelectorSnapshotName, "keep"), []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishHealthState(path, healthState{"route": {RuntimeConfirmed: false}}); err == nil {
		t.Fatal("failed proof publication was ignored")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "previous" {
		t.Fatalf("history changed despite failed proof publication: %q, %v", body, err)
	}
}

func TestHealthProofWithdrawalSurvivesHistoryWriteFailure(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishHealthState(path, healthState{"route": {RuntimeSelected: "node-a", RuntimeConfirmed: false}}); err == nil {
		t.Fatal("history write unexpectedly succeeded")
	}
	var proof map[string]runtimeproof.SelectorObservation
	if err := readJSON(filepath.Join(root, runtimeproof.SelectorSnapshotName), &proof); err != nil || len(proof) != 1 || proof["route"].Confirmed {
		t.Fatalf("history error prevented readiness withdrawal: %#v, %v", proof, err)
	}
}
