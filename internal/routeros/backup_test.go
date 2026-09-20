package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCreateBackupWritesPlainExportThenEncryptedBinary(t *testing.T) {
	var requests []map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			http.Error(response, "method", http.StatusMethodNotAllowed)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(response, "payload", http.StatusBadRequest)
			return
		}
		payload["path"] = request.URL.Path
		requests = append(requests, payload)
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/rest/system/backup/save" {
			_, _ = response.Write([]byte(`{"name":"SB-GATEWAY-20260903T123000Z-0123456789ab.backup"}`))
			return
		}
		// RouterOS 7.24 returns an empty array for a successful /export action.
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	ref, err := client.CreateBackup(context.Background(), "SB-GATEWAY-20260903T123000Z-0123456789ab", "backup-secret")
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0]["path"] != "/rest/export" || requests[1]["path"] != "/rest/system/backup/save" {
		t.Fatalf("requests = %#v", requests)
	}
	if _, exists := requests[0]["show-sensitive"]; exists || requests[0]["file"] != "SB-GATEWAY-20260903T123000Z-0123456789ab-export" {
		t.Fatalf("unsafe export payload = %#v", requests[0])
	}
	if requests[1]["password"] != "backup-secret" || requests[1]["encryption"] != "aes-sha256" || requests[1]["dont-encrypt"] != "no" {
		t.Fatalf("binary backup payload = %#v", requests[1])
	}
	if ref.Export != "SB-GATEWAY-20260903T123000Z-0123456789ab-export.rsc" || ref.Binary != "SB-GATEWAY-20260903T123000Z-0123456789ab.backup" {
		t.Fatalf("backup ref = %#v", ref)
	}
}

func TestCreateBackupAcceptsResponseLessRouterOSActions(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()

	const name = "SB-GATEWAY-20260903T123000Z-0123456789ab"
	ref, err := client.CreateBackup(context.Background(), name, "backup-secret")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Export != name+"-export.rsc" || ref.Binary != name+".backup" {
		t.Fatalf("fallback backup ref = %#v", ref)
	}
}

func TestCreateBackupUsesDedicatedActionTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		time.Sleep(75 * time.Millisecond)
		response.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/rest/system/backup/save" {
			_, _ = response.Write([]byte(`{"name":"SB-GATEWAY-20260903T123000Z-0123456789ab.backup"}`))
			return
		}
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{
		BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool,
		Timeout: 20 * time.Millisecond, ActionTimeout: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.CreateBackup(context.Background(), "SB-GATEWAY-20260903T123000Z-0123456789ab", "backup-secret"); err != nil {
		t.Fatalf("RouterOS backup action used ordinary REST timeout: %v", err)
	}
}

func TestCreateBackupRejectsUnsafeNameAndMissingPasswordBeforeNetwork(t *testing.T) {
	client := &Client{}
	for _, test := range []struct{ name, password string }{
		{"backup", "secret"},
		{"SB-GATEWAY-20260903T123000Z-0123456789ab;reboot", "secret"},
		{"SB-GATEWAY-20260903T123000Z-0123456789ab", ""},
	} {
		if _, err := client.CreateBackup(context.Background(), test.name, test.password); err == nil {
			t.Fatalf("unsafe backup input was accepted: %#v", test)
		}
	}
}
