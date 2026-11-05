package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func largeSubscriptionMetadataFixture(t testing.TB) (*stateRepository, string) {
	t.Helper()
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([]any, 1600)
	for i := range nodes {
		nodes[i] = map[string]any{"id": fmt.Sprintf("node-%d", i), "label": strings.Repeat("NODE-DETAIL-", 25)}
	}
	if err := repository.saveAuxiliary("subscription-nodes", map[string]any{"sub": map[string]any{
		"provider":     map[string]any{"name": "old", "counter": json.Number("9007199254740999")},
		"refreshed_at": "2026-01-01T12:00:00Z", "nodes": nodes,
	}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "subscription-nodes.json")
	info, err := os.Stat(path)
	if err != nil || info.Size() <= stateDocumentCacheMaxBytes {
		t.Fatal("fixture must bypass generic cache", err)
	}
	return repository, path
}

func TestSubscriptionMetadataCacheIsSmallDetachedAndGenerationBound(t *testing.T) {
	repository, path := largeSubscriptionMetadataFixture(t)
	first, err := repository.subscriptionMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if nestedValue(first, "sub", "provider", "counter") != json.Number("9007199254740999") || nestedValue(first, "sub", "refreshed_at") != "2026-01-01T12:00:00Z" {
		t.Fatal("metadata changed")
	}
	body, err := canonicalJSON(repository.subscriptionMetadataCache.value)
	if err != nil || len(body) > subscriptionMetadataCacheMaxBytes || bytes.Contains(body, []byte("NODE-DETAIL-")) {
		t.Fatal("node graph retained", err)
	}
	objectAt(objectAt(first, "sub"), "provider")["name"] = "caller-mutation"
	next, err := repository.subscriptionMetadata()
	if err != nil || nestedValue(next, "sub", "provider", "name") != "old" {
		t.Fatal("caller changed cached metadata", err)
	}
	info, _ := os.Stat(path)
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := bytes.ReplaceAll(stored, []byte(`"name":"old"`), []byte(`"name":"new"`))
	if bytes.Equal(stored, replacement) || len(stored) != len(replacement) {
		t.Fatal("replacement must preserve source size")
	}
	if err := writeAtomic(path, replacement, 0600, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	next, err = repository.subscriptionMetadata()
	if err != nil || nestedValue(next, "sub", "provider", "name") != "new" {
		t.Fatal("stale atomic generation reused", err)
	}
	if err := os.WriteFile(path, []byte(`broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.subscriptionMetadata(); err == nil {
		t.Fatal("corrupt source served cached metadata")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	next, err = repository.subscriptionMetadata()
	if err != nil || len(next) != 0 || repository.subscriptionMetadataCache.source != nil {
		t.Fatal("deleted source revived cache", err)
	}
}

func TestSubscriptionMetadataProjectionPreservesLooseRecordTypesAndBoundsAdmission(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"missing": nil, "scalar": true, "array": []any{1}, "loose": map[string]any{"provider": []any{"x"}, "refreshed_at": 42}}
	if err := repository.saveAuxiliary("subscription-nodes", state); err != nil {
		t.Fatal(err)
	}
	got, err := repository.subscriptionMetadata()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"missing", "scalar", "array"} {
		if got[id] != nil {
			t.Fatal("non-object record changed")
		}
	}
	if nestedValue(got, "loose", "refreshed_at") != json.Number("42") {
		t.Fatal("numeric metadata changed")
	}
	if err := repository.saveAuxiliary("subscription-nodes", map[string]any{"large": map[string]any{"provider": map[string]any{"padding": strings.Repeat("x", subscriptionMetadataCacheMaxBytes+1)}}}); err != nil {
		t.Fatal(err)
	}
	got, err = repository.subscriptionMetadata()
	if err != nil || len(got) != 1 || repository.subscriptionMetadataCache.source != nil {
		t.Fatal("oversized projection was retained or lost", err)
	}
}

func BenchmarkSubscriptionMetadataCache(b *testing.B) {
	repository, _ := largeSubscriptionMetadataFixture(b)
	for _, mode := range []string{"full-node-file", "metadata-cache"} {
		b.Run(mode, func(b *testing.B) {
			if mode == "metadata-cache" {
				if _, err := repository.subscriptionMetadata(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				var err error
				if mode == "full-node-file" {
					_, err = repository.auxiliary("subscription-nodes")
				} else {
					_, err = repository.subscriptionMetadata()
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSubscriptionMetadataConcurrentReadersSeeCoherentSnapshots(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "subscription-nodes.json")
	write := func(version string) error {
		body, err := canonicalJSON(map[string]any{"sub": map[string]any{"provider": map[string]any{"name": version}, "refreshed_at": version, "nodes": []any{map[string]any{"id": "unused"}}}})
		if err != nil {
			return err
		}
		return writeAtomic(path, body, 0600, false)
	}
	if err := write("initial"); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 6; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := 0; n < 80; n++ {
				value, err := repository.subscriptionMetadata()
				if err != nil {
					t.Error(err)
					return
				}
				if nestedValue(value, "sub", "provider", "name") != nestedValue(value, "sub", "refreshed_at") {
					t.Error("mixed source generations")
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if err := write(fmt.Sprintf("version-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
}
