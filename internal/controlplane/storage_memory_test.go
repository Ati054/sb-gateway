package controlplane

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLargeStateIsUncachedAndCallerOwned(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "large.json")
	for _, size := range []int{1, stateDocumentCacheMaxBytes + 1, 1} {
		value := map[string]any{"padding": strings.Repeat("x", size), "nested": map[string]any{"ok": true}}
		if err := repository.writeJSON(path, value); err != nil {
			t.Fatal(err)
		}
		_, cached := repository.cache[path]
		if cached != (size == 1) {
			t.Fatalf("unexpected write cache state for size %d: %v", size, cached)
		}
		value["nested"].(map[string]any)["ok"] = false
		first, err := repository.readJSON(path)
		if err != nil {
			t.Fatal(err)
		}
		if first["nested"].(map[string]any)["ok"] != true {
			t.Fatal("writer mutation escaped")
		}
		first["nested"].(map[string]any)["ok"] = false
		second, err := repository.readJSON(path)
		if err != nil {
			t.Fatal(err)
		}
		if second["nested"].(map[string]any)["ok"] != true {
			t.Fatal("reader mutation escaped")
		}
		_, cached = repository.cache[path]
		if cached != (size == 1) {
			t.Fatalf("unexpected read cache state for size %d: %v", size, cached)
		}
	}
}

func TestLargeExternalReplacementEvictsCachedState(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "large.json")
	if err := repository.writeJSON(path, map[string]any{"value": "small"}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"value":"` + strings.Repeat("x", stateDocumentCacheMaxBytes) + `"}`)
	if err := writeAtomic(path, body, 0600, false); err != nil {
		t.Fatal(err)
	}
	got, err := repository.readJSON(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["value"].(string)) != stateDocumentCacheMaxBytes {
		t.Fatal("stale cache returned")
	}
	if _, exists := repository.cache[path]; exists {
		t.Fatal("large replacement retained cached object")
	}
}

func TestFileMatchesBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if fileMatchesBytes(path, nil) {
		t.Fatal("missing file matched")
	}
	for _, size := range []int{0, 1, 32767, 32768, 32769, 1 << 20} {
		body := bytes.Repeat([]byte("x"), size)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if !fileMatchesBytes(path, body) {
			t.Fatalf("identical %d bytes did not match", size)
		}
		if fileMatchesBytes(path, append(bytes.Clone(body), 'x')) {
			t.Fatal("different length matched")
		}
		if size > 0 {
			body[size-1] = 'y'
			if fileMatchesBytes(path, body) {
				t.Fatal("different tail matched")
			}
			if err := writeAtomic(path, body, 0600, true); err != nil {
				t.Fatal(err)
			}
			if !fileMatchesBytes(path, body) {
				t.Fatal("changed atomic write was skipped")
			}
		}
	}
	if fileMatchesBytes(filepath.Dir(path), nil) {
		t.Fatal("directory matched")
	}
}

func BenchmarkFileMatchesBytesLarge(b *testing.B) {
	path := filepath.Join(b.TempDir(), "state")
	body := bytes.Repeat([]byte("x"), 8<<20)
	if err := os.WriteFile(path, body, 0600); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for b.Loop() {
		if !fileMatchesBytes(path, body) {
			b.Fatal("identical file did not match")
		}
	}
}

var benchmarkStateDocument map[string]any

func BenchmarkLargeStateReadOwnership(b *testing.B) {
	repository, err := newStateRepository(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(repository.root, "history.json")
	body := []byte(`{"samples":[` + strings.Repeat(`{"node":"sample","delay":310},`, 19999) + `{"node":"sample","delay":310}]}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { benchmarkStateDocument = nil })
	b.Run("decoded-plus-clone", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			value, err := readJSONObject(path)
			if err != nil {
				b.Fatal(err)
			}
			benchmarkStateDocument = cloneJSONObject(value)
		}
	})
	b.Run("uncached-owned", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			benchmarkStateDocument, err = repository.readJSON(path)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
