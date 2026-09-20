package controlplane

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeFullUninstallRequiresLiveMatchingOwnedContainer(t *testing.T) {
	var scheduled bool
	router := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/container":
			_, _ = response.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root"}]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`{".id":"*2"}`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler":
			scheduled = true
			_, _ = response.Write([]byte(`{".id":"*3"}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer router.Close()

	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	configureLifecycleRouter(t, server, router)
	mismatch := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/uninstall", map[string]any{
		"confirmation": "УДАЛИТЬ SB-GATEWAY", "storage_root": "usb1/another-project",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if mismatch.Code != http.StatusConflict || scheduled {
		t.Fatalf("mismatched root scheduled: %d %s", mismatch.Code, mismatch.Body.String())
	}
	accepted := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/uninstall", map[string]any{
		"confirmation": "УДАЛИТЬ SB-GATEWAY", "storage_root": "usb1/sb-gateway",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if accepted.Code != http.StatusAccepted || !scheduled {
		t.Fatalf("uninstall not scheduled: %d %s", accepted.Code, accepted.Body.String())
	}
}

func TestManagedContainerStorageRootRejectsAmbiguity(t *testing.T) {
	if root, err := managedContainerStorageRoot([]map[string]any{{"comment": "foreign", "root-dir": "usb1/x/root"}}); err == nil || root != "" {
		t.Fatalf("foreign container root = %q, %v", root, err)
	}
	rows := []map[string]any{
		{"comment": "SB-GATEWAY container", "root-dir": "usb1/a/root"},
		{"comment": "SB-GATEWAY container", "root-dir": "usb1/b/root"},
	}
	if _, err := managedContainerStorageRoot(rows); err == nil {
		t.Fatal("ambiguous managed containers accepted")
	}
}

func configureLifecycleRouter(t *testing.T, server *Server, router *httptest.Server) {
	t.Helper()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: router.Certificate().Raw})
	for reference, value := range map[string]string{
		"routeros/username": "admin", "routeros/password": "router-secret-password", "routeros/ca": string(certificate),
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["storage"] = map[string]any{"root": "usb1/sb-gateway"}
	objectAt(objectAt(config, "system"), "networking")["container_address"] = "172.19.0.2/30"
	config["routeros"] = map[string]any{
		"base_url": router.URL, "ssh_port": 22,
		"username_secret_ref": "routeros/username", "password_secret_ref": "routeros/password",
		"backup_password_secret_ref": recoveryBackupPwdRef, "ca_certificate_secret_ref": "routeros/ca",
	}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
}
