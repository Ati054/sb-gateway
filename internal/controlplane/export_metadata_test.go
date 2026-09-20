package controlplane

import (
	"net/http"
	"testing"
)

func TestRemoteUserExportMetadataUsesEnabledNonExcludedTransports(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "uuid_secret_ref": "remote-users/phone/uuid", "hysteria2_password_secret_ref": "remote-users/phone/hysteria2-password",
		"excluded_transports": []any{"blocked"},
	}}
	config["transports"] = []any{
		map[string]any{"id": "vision", "kind": "reality", "enabled": true},
		map[string]any{"id": "blocked", "kind": "grpc", "enabled": true},
		map[string]any{"id": "disabled", "kind": "xhttp", "enabled": false},
		map[string]any{"id": "hy2", "kind": "hysteria2", "enabled": true},
	}
	if err := server.secrets.write("remote-users/phone/uuid", "3c5f1ff8-f6a9-4fa7-a104-831bacf7113b", false); err != nil {
		t.Fatal(err)
	}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/remote-users/phone/exports", nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("metadata failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	profiles := body["profiles"].([]any)
	if len(profiles) != 2 {
		t.Fatalf("unexpected profiles: %#v", profiles)
	}
	if profiles[0].(map[string]any)["ready"] != true || profiles[1].(map[string]any)["ready"] != false {
		t.Fatalf("secret readiness mismatch: %#v", profiles)
	}
	if body["contains_secrets"] != true || body["download_requires_reauthentication"] != true {
		t.Fatalf("security metadata missing: %#v", body)
	}
}

func TestRemoteUserExportMetadataRejectsMissingUser(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/remote-users/missing/exports", nil, nil, cookie)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing user returned %d", response.Code)
	}
}
