package controlplane

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestNativeClientExportDownloadRequiresPasswordAndBuildsStoredZip(t *testing.T) {
	server, _ := configuredPublicSubscriptionServer(t)
	cookie, csrf := loginSession(t, server)

	denied := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/exports/download", map[string]any{"password": "wrong-password"}, map[string]string{csrfHeader: csrf}, cookie)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("wrong password returned %d: %s", denied.Code, denied.Body.String())
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/exports/download", map[string]any{"password": "panel-password-123"}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("download failed: %d %s", response.Code, response.Body.String())
	}
	archive, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*zip.File{}
	for _, file := range archive.File {
		files[file.Name] = file
		if file.Method != zip.Store || file.Mode().Perm() != 0o600 {
			t.Fatalf("unsafe/expensive archive entry %s method=%d mode=%o", file.Name, file.Method, file.Mode().Perm())
		}
	}
	for _, name := range []string{"client-xray.json", "client-mihomo.yaml", "xray-ws.json", "vless-ws.txt", "subscription-links.txt", "README.txt"} {
		if files[name] == nil {
			t.Fatalf("archive is missing %s: %#v", name, files)
		}
	}
	entry, err := files["vless-ws.txt"].Open()
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(entry)
	_ = entry.Close()
	if err != nil || !bytes.Contains(content, []byte("vless://")) || !bytes.Contains(content, []byte("path=%2Fclient")) {
		t.Fatalf("invalid transport link: %q (%v)", content, err)
	}
}

func TestNativeClientExportDownloadNeedsCSRFAndEnabledUser(t *testing.T) {
	server, _ := configuredPublicSubscriptionServer(t)
	cookie, csrf := loginSession(t, server)
	withoutCSRF := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/exports/download", map[string]any{"password": "panel-password-123"}, nil, cookie)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("download without CSRF returned %d", withoutCSRF.Code)
	}
	missing := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/missing/exports/download", map[string]any{"password": "panel-password-123"}, map[string]string{csrfHeader: csrf}, cookie)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing user returned %d: %s", missing.Code, missing.Body.String())
	}
}
