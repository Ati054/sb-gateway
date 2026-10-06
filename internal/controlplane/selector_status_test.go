package controlplane

import (
	"net/http"
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
