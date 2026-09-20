package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcessPIDSkipsExitedCoreAfterRuntimeRestart(t *testing.T) {
	root := t.TempDir()
	process := func(id, name, stat string) {
		t.Helper()
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if stat != "" {
			if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	process("100", "xray", "100 (xray) Z 1 100 100")
	process("101", "xray", "101 (xray) X 1 101 101")
	process("102", "xray", "") // process disappeared between reads
	process("103", "xray", "malformed")
	process("104", "other", "104 (other) S 1 104 104")
	if pid := processPIDAt(root, "xray"); pid != 0 {
		t.Fatalf("dead core accepted: %d", pid)
	}
	process("345", "xray", "345 (xray) S 1 345 345")
	if pid := processPIDAt(root, "xray"); pid != 345 {
		t.Fatalf("wrong live core: %d", pid)
	}
	if err := os.Remove(filepath.Join(root, "345", "stat")); err != nil {
		t.Fatal(err)
	}
	if pid := processPIDAt(root, "xray"); pid != 0 {
		t.Fatal("stale process returned")
	}
}

func TestReadyProcessPIDUsesPinnedCoreInsteadOfTransientXrayClient(t *testing.T) {
	root := t.TempDir()
	process := func(id, name, state string) {
		t.Helper()
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(id+" ("+name+") "+state+" 1 1 1"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	process("100", "xray", "S") // short-lived `xray api` client
	process("345", "xray", "S") // long-lived core
	ready := filepath.Join(t.TempDir(), "xray-ready")
	if err := os.WriteFile(ready, []byte("345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pid := readyProcessPIDAt(root, ready, "xray"); pid != 345 {
		t.Fatalf("pinned core PID = %d, want 345", pid)
	}
	if err := os.WriteFile(filepath.Join(root, "345", "stat"), []byte("345 (xray) Z 1 1 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pid := readyProcessPIDAt(root, ready, "xray"); pid != 0 {
		t.Fatalf("stale ready marker accepted PID %d", pid)
	}
}
