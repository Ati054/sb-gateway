package controlplane

import (
	"net/http"
	"testing"
)

func TestProvisionRouterOSCredentialsStoresOnlySecretReferencesInDraft(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	objectAt(config, "system")["deployment_ready"] = true
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/credentials", map[string]any{
		"base_url": "https://192.168.88.1:443/", "username": "sb-gateway", "password": "router-password-123", "ssh_port": 22,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("provision failed: %d %s", response.Code, response.Body.String())
	}
	config, err = server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	router := objectAt(config, "routeros")
	if router["base_url"] != "https://192.168.88.1:443" || router["username_secret_ref"] != "routeros/username" || router["password_secret_ref"] != "routeros/password" {
		t.Fatalf("draft references mismatch: %#v", router)
	}
	if _, leaked := router["password"]; leaked {
		t.Fatalf("password leaked into draft: %#v", router)
	}
	if objectAt(config, "system")["deployment_ready"] != false {
		t.Fatalf("credential mutation did not invalidate deployment readiness: %#v", config["system"])
	}
	if username, _ := server.secrets.read("routeros/username", true); username != "sb-gateway" {
		t.Fatalf("username secret mismatch: %q", username)
	}
	if password, _ := server.secrets.read("routeros/password", true); password != "router-password-123" {
		t.Fatalf("password secret mismatch: %q", password)
	}
}

func TestProvisionRouterOSCredentialsRejectsWeakOrMalformedInput(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	for name, body := range map[string]map[string]any{
		"weak": {"base_url": "https://192.168.88.1:443", "username": "admin", "password": "short"},
		"url":  {"base_url": "http://192.168.88.1:80", "username": "admin", "password": "router-password-123"},
		"port": {"base_url": "https://192.168.88.1:443", "username": "admin", "password": "router-password-123", "ssh_port": 0},
	} {
		t.Run(name, func(t *testing.T) {
			response := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/credentials", body, map[string]string{csrfHeader: csrf}, cookie)
			if response.Code < 400 {
				t.Fatalf("invalid input accepted: %d %s", response.Code, response.Body.String())
			}
		})
	}
}
