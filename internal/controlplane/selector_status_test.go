package controlplane

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompactSelectorStatusRequiresAuthAndOmitsHistory(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	if err := server.repository.saveAuxiliary("selector-health", map[string]any{"europe": map[string]any{
		"runtime_selected": "canada", "runtime_confirmed": true, "runtime_observed_at": "2026-09-07T10:00:00Z",
		"shortlist":        []string{"canada", "finland"},
		"candidate_labels": map[string]any{"canada": "Canada"}, "daily_stats": map[string]any{"canada": map[string]any{"samples": 100}}, "history_days": map[string]any{"private": "large"},
	}}); err != nil {
		t.Fatal(err)
	}
	unauthorized := performRequest(t, server, http.MethodGet, apiPrefix+"/status?view=selectors", nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatal("selector status accepted without auth")
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/status?view=selectors", nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	item := decodeResponse(t, response)["selector_health"].(map[string]any)["europe"].(map[string]any)
	if item["runtime_selected"] != "canada" || item["runtime_confirmed"] != true || item["runtime_error"] != "" {
		t.Fatalf("missing current facts: %#v", item)
	}
	if _, ok := item["history_days"]; ok {
		t.Fatal("full history leaked into fast polling")
	}
	if _, ok := item["daily_stats"]; ok {
		t.Fatal("statistics leaked into fast polling")
	}
	if len(item["shortlist"].([]any)) != 2 {
		t.Fatal("working pool missing from fast polling")
	}
	if value, exists := item["latency_comparisons"]; !exists || value != nil {
		t.Fatal("absent comparisons must explicitly clear the UI merge")
	}
	pairs := map[string]any{"finland": map[string]any{"active": "canada", "active_delay_ms": 600, "candidate_delay_ms": 350}}
	if err := server.repository.saveAuxiliary("selector-health", map[string]any{
		"europe": map[string]any{"runtime_selected": "canada", "runtime_confirmed": true, "latency_comparisons": pairs},
	}); err != nil {
		t.Fatal(err)
	}
	response = performRequest(t, server, http.MethodGet, apiPrefix+"/status?view=selectors", nil, nil, cookie)
	item = decodeResponse(t, response)["selector_health"].(map[string]any)["europe"].(map[string]any)
	pair := item["latency_comparisons"].(map[string]any)["finland"].(map[string]any)
	if pair["active"] != "canada" || pair["candidate_delay_ms"] != float64(350) {
		t.Fatalf("missing compact comparison=%v", item)
	}
}

func TestSelectorStatusCacheExcludesHistoryAndObservesAtomicReplacement(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	body := `{"route":{"runtime_selected":"node-a","candidate_count":10,"history_days":{"samples":[` + strings.Repeat(`100,`, 10000) + `100]}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := repository.selectorStatus()
	if err != nil {
		t.Fatal(err)
	}
	item := objectAt(first, "route")
	if len(item) != 4 || text(item["runtime_selected"]) != "node-a" {
		t.Fatalf("unexpected projection: %#v", item)
	}
	if len(repository.cache) != 0 || len(objectAt(repository.selectors.value, "route")) != 4 {
		t.Fatal("full history entered the polling cache")
	}
	item["runtime_selected"] = "changed"
	second, err := repository.selectorStatus()
	if err != nil || text(objectAt(second, "route")["runtime_selected"]) != "node-a" {
		t.Fatal("caller mutated the compact cache")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte(strings.Replace(body, "node-a", "node-b", 1)), 0o600, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	third, err := repository.selectorStatus()
	if err != nil || text(objectAt(third, "route")["runtime_selected"]) != "node-b" {
		t.Fatal("same-size atomic replacement used stale status")
	}
	for _, invalid := range []string{`{"route":`, `{} {}`} {
		if err := writeAtomic(path, []byte(invalid), 0o600, false); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.selectorStatus(); err == nil {
			t.Fatal("corrupt status was accepted")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	missing, err := repository.selectorStatus()
	if err != nil || len(missing) != 0 {
		t.Fatal("deleted status reused a stale cache")
	}
}
