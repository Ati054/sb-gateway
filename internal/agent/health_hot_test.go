package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHotRuntimeAcknowledgementRequiresReconciledSelectors(t *testing.T) {
	for _, reason := range []string{"ready", "block", "outside-contract", "unconfirmed", "old-signature", "yield", "transition"} {
		t.Run(reason, func(t *testing.T) {
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "nl", "nl", true
			item.Mode, item.CandidateSignature = "best", "nl"
			controller := &healthController{
				state: healthState{"route": item}, warmStarted: map[string]bool{"route": true},
				processedPool: healthPool{HealthPolicies: map[string]healthPolicyContract{"route": {Mode: "best", Candidates: []string{"nl"}}}},
			}
			switch reason {
			case "block":
				item.Selected, item.RuntimeSelected = "block", "block"
			case "outside-contract":
				item.Selected, item.RuntimeSelected = "de", "de"
			case "unconfirmed":
				item.RuntimeConfirmed = false
			case "old-signature":
				item.CandidateSignature = "de\nnl"
			case "yield":
				controller.yielded = true
			case "transition":
				controller.transitions = map[string]*policyTransition{"route": {previous: "de"}}
			}
			// A reconciled block is reported, not hidden: the activation waiter
			// decides whether this policy is required to be available.
			if got := controller.hotRuntimeReconciled(); got != (reason == "ready" || reason == "block") {
				t.Fatalf("reconciled=%t for %s", got, reason)
			}
		})
	}
}

func TestHotRuntimeAcknowledgementCannotNameGenerationPublishedAfterTick(t *testing.T) {
	root := t.TempDir()
	opts := Options{
		HealthPoolFile: filepath.Join(root, "pool.json"), XrayReadyFile: filepath.Join(root, "ready"),
		HotRuntimeReadyFile: filepath.Join(root, "hot-ready.json"),
	}
	proc := filepath.Join(root, "proc")
	if err := os.MkdirAll(filepath.Join(proc, "345"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		opts.HealthPoolFile: "processed-pool", opts.XrayReadyFile: "345\n",
		filepath.Join(proc, "345", "comm"): "xray\n", filepath.Join(proc, "345", "stat"): "345 (xray) S 1 0 0",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256([]byte("processed-pool"))
	info, err := os.Stat(opts.HealthPoolFile)
	if err != nil {
		t.Fatal(err)
	}
	processed := hotRuntimeAcknowledgement{
		hotRuntimeGeneration{hex.EncodeToString(digest[:]), info.ModTime().UnixNano(), 345},
		map[string]string{"route": "nl", "remote": "block"},
	}
	if err := publishHotRuntimeReadyAt(opts, processed, proc); err != nil {
		t.Fatal(err)
	}
	var marker hotRuntimeAcknowledgement
	if err := readJSON(opts.HotRuntimeReadyFile, &marker); err != nil || marker.hotRuntimeGeneration != processed.hotRuntimeGeneration ||
		marker.PolicySelections["route"] != "nl" || marker.PolicySelections["remote"] != "block" {
		t.Fatalf("processed generation was not published: %+v %v", marker, err)
	}
	if err := os.Remove(opts.HotRuntimeReadyFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opts.HealthPoolFile, []byte("newer-pool"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishHotRuntimeReadyAt(opts, processed, proc); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(opts.HotRuntimeReadyFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unprocessed generation was acknowledged: %v", err)
	}
}
