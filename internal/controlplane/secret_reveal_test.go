package controlplane

import (
	"net/http"
	"testing"
)

func TestNativeSecretRevealEndpointsReturnOnlyRequestedValue(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["subscriptions"] = []any{map[string]any{
		"id": "primary", "url_secret_ref": "subscriptions/primary.url",
	}}
	config["transports"] = []any{
		map[string]any{"id": "websocket", "kind": "ws", "path_secret_ref": "transports/websocket/path"},
		map[string]any{"id": "reality", "kind": "reality"},
	}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	if err := server.secrets.write("subscriptions/primary.url", "https://example.test/secret", false); err != nil {
		t.Fatal(err)
	}
	if err := server.secrets.write("transports/websocket/path", "/hidden-path", false); err != nil {
		t.Fatal(err)
	}

	urlResponse := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/primary/url", nil, nil, cookie)
	if urlResponse.Code != http.StatusOK {
		t.Fatalf("URL reveal failed: %d %s", urlResponse.Code, urlResponse.Body.String())
	}
	urlBody := decodeResponse(t, urlResponse)
	if urlBody["url"] != "https://example.test/secret" || len(urlBody) != 2 {
		t.Fatalf("URL reveal body = %#v", urlBody)
	}
	pathResponse := performRequest(t, server, http.MethodPost, apiPrefix+"/transports/websocket/http-path/reveal", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if pathResponse.Code != http.StatusOK {
		t.Fatalf("path reveal failed: %d %s", pathResponse.Code, pathResponse.Body.String())
	}
	pathBody := decodeResponse(t, pathResponse)
	if pathBody["path"] != "/hidden-path" || len(pathBody) != 2 {
		t.Fatalf("path reveal body = %#v", pathBody)
	}
}

func TestNativeTransportPathRevealRequiresCSRFAndHTTPKind(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["transports"] = []any{map[string]any{"id": "reality", "kind": "reality"}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	withoutCSRF := performRequest(t, server, http.MethodPost, apiPrefix+"/transports/reality/http-path/reveal", map[string]any{}, nil, cookie)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("path reveal without CSRF returned %d", withoutCSRF.Code)
	}
	unsupported := performRequest(t, server, http.MethodPost, apiPrefix+"/transports/reality/http-path/reveal", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if unsupported.Code != http.StatusUnprocessableEntity {
		t.Fatalf("Reality path reveal returned %d: %s", unsupported.Code, unsupported.Body.String())
	}
}
