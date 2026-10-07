package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectorReadinessProjectsOnlyCurrentEvidence(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	body := `{"route":{"runtime_selected":"node-a","runtime_observed_at":"2026-10-07T10:00:00Z","runtime_confirmed":true,"history_days":{"node-a":{"samples":[` + strings.Repeat(`100,`, 10000) + `100]}}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := repository.selectorReadiness()
	if err != nil {
		t.Fatal(err)
	}
	item := objectAt(first, "route")
	if len(item) != 3 || item["runtime_selected"] != "node-a" || item["runtime_confirmed"] != true {
		t.Fatalf("unexpected readiness projection: %#v", item)
	}
	item["runtime_selected"] = "mutated"
	second, err := repository.selectorReadiness()
	if err != nil || text(objectAt(second, "route")["runtime_selected"]) != "node-a" {
		t.Fatalf("caller mutated readiness cache: %#v, %v", second, err)
	}
	if len(repository.cache) != 0 {
		t.Fatal("readiness populated the full history cache")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(body, "node-a", "node-b", 1)
	if err := writeAtomic(path, []byte(updated), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	third, err := repository.selectorReadiness()
	if err != nil || text(objectAt(third, "route")["runtime_selected"]) != "node-b" {
		t.Fatalf("same-size replacement was not observed: %#v, %v", third, err)
	}
}

func TestSelectorReadinessRejectsCorruptStateInsteadOfUsingCache(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	if err := repository.saveAuxiliary("selector-health", map[string]any{"route": map[string]any{"runtime_selected": "node-a", "runtime_confirmed": true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.selectorReadiness(); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"route":`, `{} {}`, `{"route":{"runtime_confirmed":"true"}}`} {
		if err := writeAtomic(path, []byte(body), 0o600, false); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.selectorReadiness(); err == nil {
			t.Fatalf("corrupt selector state was accepted: %s", body)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	values, err := repository.selectorReadiness()
	if err != nil || len(values) != 0 {
		t.Fatalf("deleted state used stale readiness: %#v, %v", values, err)
	}
}
