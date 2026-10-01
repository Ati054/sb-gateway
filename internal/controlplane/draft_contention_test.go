package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDraftMutationsRejectBusyConfigurationWithoutLateWrite(t *testing.T) {
	for _, test := range []struct {
		name, method, endpoint string
		body                   map[string]any
	}{
		{"put", http.MethodPut, "/drafts/current", currentConfigFixture(t)},
		{"patch", http.MethodPatch, "/drafts/current", map[string]any{"section": "system", "value": map[string]any{"name": "Busy write"}}},
		{"reset", http.MethodPost, "/drafts/reset", map[string]any{}},
		{"create", http.MethodPost, "/policies", map[string]any{"item": map[string]any{"id": "busy-policy", "display_name": "Busy policy"}}},
		{"update", http.MethodPut, "/policies/busy-policy", map[string]any{"display_name": "Busy policy"}},
		{"delete", http.MethodDelete, "/policies/busy-policy", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t)
			cookie, csrf := bootstrapSession(t, server)
			before, err := server.getDraft()
			if err != nil {
				t.Fatal(err)
			}
			beforeRevision, err := revisionFor(before)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.repository.saveDraft(before); err != nil {
				t.Fatal(err)
			}
			server.configMu.Lock()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- performRequest(t, server, test.method, apiPrefix+test.endpoint, test.body, map[string]string{csrfHeader: csrf}, cookie)
			}()
			var response *httptest.ResponseRecorder
			select {
			case response = <-done:
				server.configMu.Unlock()
			case <-time.After(time.Second):
				server.configMu.Unlock()
				<-done
				t.Fatal("Draft mutation queued behind a busy configuration")
			}
			if response.Code != http.StatusConflict || decodeResponse(t, response)["error"].(map[string]any)["code"] != "state_mutation_in_progress" {
				t.Fatalf("Busy draft mutation returned %d %s", response.Code, response.Body.String())
			}
			after, err := server.getDraft()
			if err != nil {
				t.Fatal(err)
			}
			afterRevision, err := revisionFor(after)
			if err != nil || afterRevision != beforeRevision {
				t.Fatalf("Busy mutation changed draft: %v", err)
			}
		})
	}
}
