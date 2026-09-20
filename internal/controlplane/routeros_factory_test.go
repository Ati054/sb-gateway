package controlplane

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNewRouterOSStackResolvesCurrentSecretsAndCA(t *testing.T) {
	server := newTestServer(t)
	remote := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer remote.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw})
	for reference, value := range map[string]string{
		"routeros/username": "admin", "routeros/password": "secret",
		"routeros/backup-password": "backup", "routeros/ca.pem": string(certificate),
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	config := map[string]any{"routeros": map[string]any{
		"base_url": remote.URL, "ssh_port": 22,
		"username_secret_ref": "routeros/username", "password_secret_ref": "routeros/password",
		"backup_password_secret_ref": "routeros/backup-password", "ca_certificate_secret_ref": "routeros/ca.pem",
	}}
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		t.Fatal(err)
	}
	defer stack.REST.CloseIdleConnections()
	if stack.BackupPassword != "backup" {
		t.Fatal("backup credential was not resolved")
	}
	knownHosts, err := server.secrets.path("routeros/ssh_known_hosts")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(knownHosts); !os.IsNotExist(err) {
		t.Fatalf("transport factory eagerly touched known_hosts: %v", err)
	}
}

func TestNewRouterOSStackRejectsMissingCredentialWithoutNetwork(t *testing.T) {
	server := newTestServer(t)
	config := map[string]any{"routeros": map[string]any{
		"base_url": "https://192.0.2.1:8729", "ssh_port": 22,
		"username_secret_ref": "routeros/missing", "password_secret_ref": "routeros/password",
		"backup_password_secret_ref": "routeros/backup-password",
	}}
	if _, err := server.newRouterOSStack(config); err == nil {
		t.Fatal("missing RouterOS credential was accepted")
	}
}
