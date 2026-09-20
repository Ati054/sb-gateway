package controlplane

import (
	"net/http"
	"strings"
	"testing"
)

func TestSubscriptionMetadataIsAuthenticatedCompactAndUsesLastStoredProvider(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"a": map[string]any{
		"provider": map[string]any{"expires_at": "2026-12-26T16:06:00Z"}, "refreshed_at": "2026-09-07T10:00:00Z",
		"nodes": []any{map[string]any{"label": "DO-NOT-RETURN-NODES", "secret_ref": "secret/path"}},
	}}); err != nil {
		t.Fatal(err)
	}
	path := apiPrefix + "/status?view=subscriptions"
	if response := performRequest(t, server, http.MethodGet, path, nil, nil); response.Code != http.StatusUnauthorized {
		t.Fatal("metadata accepted without auth")
	}
	response := performRequest(t, server, http.MethodGet, path, nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	item := decodeResponse(t, response)["subscriptions"].(map[string]any)["a"].(map[string]any)
	if nestedValue(item, "provider", "expires_at") != "2026-12-26T16:06:00Z" || item["refreshed_at"] != "2026-09-07T10:00:00Z" {
		t.Fatalf("missing provider metadata: %#v", item)
	}
	if strings.Contains(response.Body.String(), "DO-NOT-RETURN-NODES") || strings.Contains(response.Body.String(), "secret/path") {
		t.Fatal("node details leaked into metadata")
	}
}
