package controlplane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/healthsnapshot"
)

func writeCompactSelectorFixture(t testing.TB, root string, body []byte) {
	t.Helper()
	info, err := os.Stat(filepath.Join(root, "selector-health.json"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(healthsnapshot.Envelope{Version: 1, HistoryStamp: healthsnapshot.Stamp(info), Status: body})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, healthsnapshot.Filename), envelope, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCompactSelectorCompanionMatchesLegacyProjectionAndRejectsStaleGeneration(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	projection := `{"route":{"runtime_selected":"node-a","runtime_confirmed":true,"candidate_count":2,"warm_planning_marker":"gstatic-warm-head-v1","warm_last_latency_comparisons":{"reserve":{"active":"node-a","active_delay_ms":100,"candidate_delay_ms":80}}}}`
	if err := os.WriteFile(path, []byte(projection), 0600); err != nil {
		t.Fatal(err)
	}
	legacy, err := repository.selectorStatus()
	if err != nil {
		t.Fatal(err)
	}
	writeCompactSelectorFixture(t, repository.root, []byte(projection))
	info, _ := os.Stat(path)
	if repository.compactHealthStatus(info) == nil {
		t.Fatal("matching compact snapshot not used")
	}
	repository.selectors = cachedSelectorStatus{}
	compact, err := repository.selectorStatus()
	if err != nil || !reflect.DeepEqual(compact, legacy) {
		t.Fatal("projection changed", err)
	}
	if err := writeAtomic(path, []byte(strings.ReplaceAll(projection, "node-a", "node-b")), 0600, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	newInfo, _ := os.Stat(path)
	if repository.compactHealthStatus(newInfo) != nil {
		t.Fatal("same-size replacement reused old compact state")
	}
	next, err := repository.selectorStatus()
	if err != nil || text(objectAt(next, "route")["runtime_selected"]) != "node-b" {
		t.Fatal("stale baseline revived", err)
	}
}

func TestCompactSelectorInvalidCompanionFallsBackToCurrentHistory(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	if err := os.WriteFile(path, []byte(`{"route":{"runtime_selected":"current","runtime_confirmed":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	stamp := strconv.Quote(healthsnapshot.Stamp(info))
	for _, body := range []string{`broken`, `{"version":2,"history_stamp":` + stamp + `,"status":{}}`, `{"version":1,"history_stamp":"old","status":{}}`, `{"version":1,"history_stamp":` + stamp + `,"status":{"route":[]}}`, `{"version":1,"history_stamp":` + stamp + `,"status":null}`, `{"version":1,"history_stamp":` + stamp + `,"status":{}} {}`} {
		if err := os.WriteFile(filepath.Join(repository.root, healthsnapshot.Filename), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		repository.selectors = cachedSelectorStatus{}
		got, err := repository.selectorStatus()
		if err != nil || text(objectAt(got, "route")["runtime_selected"]) != "current" {
			t.Fatal("invalid optional cache changed current state", err)
		}
	}
}

func BenchmarkSelectorStatusCompanion(b *testing.B) {
	repository, err := newStateRepository(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	projection := `{"route":{"runtime_selected":"active","runtime_confirmed":true,"candidate_count":24}}`
	history := strings.TrimSuffix(projection, "}}") + `,"history_days":[` + strings.Repeat("300,", 400000) + `300]}}`
	if err := os.WriteFile(filepath.Join(repository.root, "selector-health.json"), []byte(history), 0600); err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"history-miss", "companion-miss"} {
		b.Run(mode, func(b *testing.B) {
			if mode == "companion-miss" {
				writeCompactSelectorFixture(b, repository.root, []byte(projection))
			} else {
				_ = os.Remove(filepath.Join(repository.root, healthsnapshot.Filename))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				repository.selectors = cachedSelectorStatus{}
				if _, err := repository.selectorStatus(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
