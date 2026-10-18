package controlplane

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
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

func TestSelectorReadinessUsesCompactProofWithoutReadingHistory(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// A directory cannot be decoded as history. Live proof must not open it.
	if err := os.Mkdir(filepath.Join(repository.root, "selector-health.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, runtimeproof.SelectorSnapshotName)
	first := `{"route":{"runtime_selected":"node-a","runtime_observed_at":"2026-01-01T12:00:00Z","runtime_confirmed":true}}`
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := repository.selectorReadiness()
	if err != nil || objectAt(values, "route")["runtime_confirmed"] != true {
		t.Fatalf("compact proof not used: %#v, %v", values, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte(strings.Replace(first, "node-a", "node-b", 1)), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	values, err = repository.selectorReadiness()
	if err != nil || objectAt(values, "route")["runtime_selected"] != "node-b" {
		t.Fatalf("atomic compact replacement was missed: %#v, %v", values, err)
	}
}

func TestCompactSelectorProofStillRequiresFreshConfirmation(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	active := map[string]any{
		"policies":      []any{map[string]any{"id": "route", "enabled": true}},
		"local_clients": []any{map[string]any{"id": "client", "policy_id": "route"}},
	}
	notBefore := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		observed           string
		confirmed, pending bool
	}{
		{"2026-01-01T11:59:59Z", true, true},
		{"2026-01-01T12:00:01Z", true, false},
		{"2026-01-01T12:00:02Z", false, true},
	} {
		proof := map[string]selectorReadiness{"route": {Selected: "node-a", Observed: test.observed, Confirmed: test.confirmed}}
		if err := repository.saveAuxiliary("selector-runtime", map[string]any{"route": proof["route"]}); err != nil {
			t.Fatal(err)
		}
		values, err := repository.selectorReadiness()
		if err != nil {
			t.Fatal(err)
		}
		_, pending := trafficReadyPolicies(active, values, notBefore)
		if (len(pending) != 0) != test.pending {
			t.Fatalf("freshness or withdrawal bypassed: %#v, pending=%v", test, pending)
		}
	}
}

func BenchmarkSelectorReadinessChangedState(b *testing.B) {
	for _, compact := range []bool{false, true} {
		name := "history"
		if compact {
			name = "compact"
		}
		b.Run(name, func(b *testing.B) {
			repository, err := newStateRepository(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			history := filepath.Join(repository.root, "selector-health.json")
			body := `{"route":{"runtime_selected":"node-a","runtime_confirmed":true,"history_padding":"` + strings.Repeat("x", 8<<20) + `"}}`
			if err := os.WriteFile(history, []byte(body), 0o600); err != nil {
				b.Fatal(err)
			}
			path := history
			if compact {
				path = filepath.Join(repository.root, runtimeproof.SelectorSnapshotName)
				if err := os.WriteFile(path, []byte(`{"route":{"runtime_selected":"node-a","runtime_confirmed":true}}`), 0o600); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stamp := time.Unix(1, int64(i+1))
				if err := os.Chtimes(path, stamp, stamp); err != nil {
					b.Fatal(err)
				}
				if _, err := repository.selectorReadiness(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSelectorReadinessDoesNotFallBackFromMissingOrInvalidCompactProof(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	legacy := map[string]any{"route": map[string]any{"runtime_selected": "old-node", "runtime_confirmed": true}}
	if err := repository.saveAuxiliary("selector-health", legacy); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, runtimeproof.SelectorSnapshotName)
	for _, body := range []string{`{"route":`, `{} {}`, `{"route":{"runtime_confirmed":"true"}}`, strings.Repeat(" ", runtimeproof.SelectorSnapshotMaxBytes+1)} {
		if err := writeAtomic(path, []byte(body), 0o600, false); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.selectorReadiness(); err == nil {
			t.Fatal("invalid compact proof was accepted")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	values, err := repository.selectorReadiness()
	if err != nil || len(values) != 0 {
		t.Fatalf("deleted compact proof fell back to stale history: %#v, %v", values, err)
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

func TestSelectorReadinessConcurrentCompactPublication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("production uses Unix atomic replacement; Windows development publication is not atomic")
	}
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initial := `{"route":{"runtime_selected":"node-a","runtime_confirmed":true}}`
	if err := os.WriteFile(filepath.Join(repository.root, "selector-health.json"), []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, runtimeproof.SelectorSnapshotName)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 50; i++ {
			body := initial
			if i%2 != 0 {
				body = strings.Replace(body, "node-a", "node-b", 1)
			}
			if err := writeAtomic(path, []byte(body), 0o600, false); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for {
		values, err := repository.selectorReadiness()
		if err != nil {
			t.Fatal(err)
		}
		if item, exists := values["route"]; exists {
			selected := text(item.(map[string]any)["runtime_selected"])
			if selected != "node-a" && selected != "node-b" {
				t.Fatalf("partial runtime proof: %#v", values)
			}
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		default:
		}
	}
}
