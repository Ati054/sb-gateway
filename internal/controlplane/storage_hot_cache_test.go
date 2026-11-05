package controlplane

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHotDocumentWorkingSetFitsExistingByteBudget(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 8)
	for i := range paths {
		paths[i] = filepath.Join(repository.root, fmt.Sprintf("hot-%d.json", i))
		if err := repository.writeJSON(paths[i], map[string]any{"value": i, "padding": strings.Repeat("x", 32<<10)}); err != nil {
			t.Fatal(err)
		}
	}
	for repeat := 0; repeat < 4; repeat++ {
		for _, path := range paths {
			if _, err := repository.readJSON(path); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, path := range paths {
		if _, ok := repository.cache[path]; !ok {
			t.Fatal("small hot working set was evicted")
		}
	}
}

func TestDocumentCacheRefreshesRecencyAndBoundsTotalBytes(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < stateDocumentCacheLimit; i++ {
		if err := repository.saveAuxiliary(fmt.Sprintf("item-%d", i), map[string]any{"value": i}); err != nil {
			t.Fatal(err)
		}
	}
	first := filepath.Join(repository.root, "item-0.json")
	if _, err := repository.readJSON(first); err != nil {
		t.Fatal(err)
	}
	if err := repository.saveAuxiliary("newest", map[string]any{"value": true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := repository.cache[first]; !ok {
		t.Fatal("recently read entry was evicted")
	}
	if _, ok := repository.cache[filepath.Join(repository.root, "item-1.json")]; ok {
		t.Fatal("oldest entry retained over hot entry")
	}
	for i := 0; i < stateDocumentCacheLimit; i++ {
		if err := repository.saveAuxiliary(fmt.Sprintf("large-%d", i), map[string]any{"padding": strings.Repeat("x", 128<<10)}); err != nil {
			t.Fatal(err)
		}
	}
	var used int64
	for _, cached := range repository.cache {
		used += cached.size
	}
	if len(repository.cache) > stateDocumentCacheLimit || used > stateDocumentCacheByteLimit {
		t.Fatal("cache exceeded existing encoded-input ceiling")
	}
}

func TestOversizedDocumentDoesNotEvictOtherHotEntries(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := repository.saveAuxiliary(fmt.Sprintf("hot-%d", i), map[string]any{"value": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.saveAuxiliary("oversized", map[string]any{"padding": strings.Repeat("x", stateDocumentCacheByteLimit)}); err != nil {
		t.Fatal(err)
	}
	if len(repository.cache) != 8 {
		t.Fatal("non-admitted document evicted hot entries")
	}
	if _, err := repository.auxiliary("oversized"); err != nil {
		t.Fatal(err)
	}
	if len(repository.cache) != 8 {
		t.Fatal("uncached read evicted hot entries")
	}
}

func BenchmarkStateRepositoryHotWorkingSet(b *testing.B) {
	repository, err := newStateRepository(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	paths := make([]string, 8)
	for i := range paths {
		paths[i] = filepath.Join(repository.root, fmt.Sprintf("hot-%d.json", i))
		rows := make([]any, 80)
		for j := range rows {
			rows[j] = map[string]any{"id": fmt.Sprintf("row-%d", j), "enabled": true, "label": strings.Repeat("sample", 40)}
		}
		body, err := json.Marshal(map[string]any{"revision": i, "rows": rows})
		if err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(paths[i], body, 0600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		for _, path := range paths {
			if _, err := repository.readJSON(path); err != nil {
				b.Fatal(err)
			}
		}
	}
}
