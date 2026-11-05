package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var errAtomicJSONFixture = errors.New("synthetic encoding failure")

type failingAtomicJSONFixture struct{}

func (failingAtomicJSONFixture) MarshalJSON() ([]byte, error) {
	return nil, errAtomicJSONFixture
}

func TestAtomicJSONCheckpointWireCompatibility(t *testing.T) {
	cold, warm := benchmarkMatureCheckpointStates(1)
	for _, fixture := range []struct {
		name  string
		value any
	}{
		{"null", nil},
		{"text", map[string]any{"html": "<>&", "unicode": "тест\u2028", "invalid": string([]byte{0xff})}},
		{"raw", map[string]any{"raw": json.RawMessage(`{"b":2,"a":1}`), "array": []any{false, 12.25, nil}}},
		{"mature-cold", healthCheckpointProjection(cold)},
		{"mature-warm", healthCheckpointProjection(warm)},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			if err := os.WriteFile(path, []byte("old checkpoint\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			legacy, err := json.Marshal(fixture.value)
			if err != nil {
				t.Fatal(err)
			}
			legacy = append(legacy, '\n')
			if err := writeJSONAtomic(path, fixture.value); err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, legacy) {
				t.Fatal("atomic checkpoint changed its existing wire format")
			}
			if runtime.GOOS != "windows" {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0o600 {
					t.Fatalf("checkpoint permissions: %v", info.Mode())
				}
			}
			assertNoAtomicJSONTemporary(t, path)
		})
	}
}

func TestAtomicJSONEncodingFailurePreservesCommittedCheckpoint(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		value any
	}{
		{"unsupported-number", math.NaN()},
		{"unsupported-type", make(chan int)},
		{"marshaler-error", failingAtomicJSONFixture{}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checkpoint.json")
			committed := []byte("{\"committed\":true}\n")
			if err := os.WriteFile(path, committed, 0o600); err != nil {
				t.Fatal(err)
			}
			err := writeJSONAtomic(path, fixture.value)
			if err == nil {
				t.Fatal("invalid checkpoint was accepted")
			}
			if fixture.name == "marshaler-error" && !errors.Is(err, errAtomicJSONFixture) {
				t.Fatalf("lost encoding error: %v", err)
			}
			actual, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(actual, committed) {
				t.Fatal("failed encode replaced the committed checkpoint")
			}
			assertNoAtomicJSONTemporary(t, path)
		})
	}
}

func TestAtomicJSONRenameFailureRemovesTemporary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "keep"), []byte("existing directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(path, map[string]bool{"new": true}); err == nil {
		t.Fatal("directory was replaced by checkpoint")
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		t.Fatalf("existing destination changed: %v", err)
	}
	assertNoAtomicJSONTemporary(t, path)
}

func assertNoAtomicJSONTemporary(t *testing.T, path string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("abandoned temporary checkpoints: %v", paths)
	}
}
