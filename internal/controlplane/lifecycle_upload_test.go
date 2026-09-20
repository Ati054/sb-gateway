package controlplane

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLifecycleImageUploadPreflightExplainsMissingStorageBeforeBodyUpload(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/image-upload/preflight", map[string]any{
		"filename": "sb-gateway-1.6.7-linux-arm64.tar", "size_bytes": 102633984,
	}, map[string]string{"Cookie": cookie.String(), "X-CSRF-Token": csrf})
	if response.Code != http.StatusConflict {
		t.Fatalf("missing storage preflight returned %d: %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	errorBody := objectAt(body, "error")
	if errorBody["code"] != "storage_root_required" || !strings.Contains(text(errorBody["message"]), "Settings") {
		t.Fatalf("missing storage was not actionable: %#v", body)
	}
}

func TestNativeLifecycleImageUploadStreamsValidArm64Archive(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["storage"] = map[string]any{"root": "usb1/sb-gateway"}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	archive := dockerImageArchive(t, "arm64", "1.7.2", "first-layer")
	response := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", archive)
	if response.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	digest := sha256.Sum256(archive)
	wantDigest := hex.EncodeToString(digest[:])
	if body["sha256"] != wantDigest || body["version"] != "1.7.2" || body["architecture"] != "arm64" {
		t.Fatalf("upload response = %#v", body)
	}
	wantName := "sb-gateway-upload-" + wantDigest[:16] + ".tar"
	path := filepath.Join(server.opts.DataDir, "lifecycle-uploads", wantName)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(archive)) {
		t.Fatalf("stored image = %#v, %v", info, err)
	}
	verification, err := server.repository.auxiliary("lifecycle-image-verifications")
	if err != nil || len(objectAt(verification, "images")) != 1 {
		t.Fatalf("verification state = %#v, %v", verification, err)
	}

	second := dockerImageArchive(t, "aarch64", "1.7.3-rc1", "second-layer")
	secondResponse := uploadImageRequest(t, server, cookie, csrf, "candidate-2.tar", second)
	if secondResponse.Code != http.StatusOK || decodeResponse(t, secondResponse)["superseded_uploads_removed"].(float64) != 1 {
		t.Fatalf("second upload = %d %s", secondResponse.Code, secondResponse.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(server.opts.DataDir, "lifecycle-uploads"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("retained uploads = %#v, %v", entries, err)
	}
}

func TestNativeLifecycleImageUploadRejectsWrongPlatformAndUnsafeName(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["storage"] = map[string]any{"root": "usb1/sb-gateway"}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	wrongPlatform := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", dockerImageArchive(t, "amd64", "1.7.2", "layer"))
	if wrongPlatform.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong platform accepted: %d %s", wrongPlatform.Code, wrongPlatform.Body.String())
	}
	unsafe := uploadImageRequest(t, server, cookie, csrf, "../candidate.tar", dockerImageArchive(t, "arm64", "1.7.2", "layer"))
	if unsafe.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsafe name accepted: %d", unsafe.Code)
	}
	entries, err := os.ReadDir(filepath.Join(server.opts.DataDir, "lifecycle-uploads"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected upload left files: %#v, %v", entries, err)
	}
}

func TestNativeLifecycleImageUploadEnforcesReleaseCompatibility(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["storage"] = map[string]any{"root": "usb1/sb-gateway"}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}

	for name, labels := range map[string]map[string]string{
		"missing lifecycle":      {"io.sb-gateway.lifecycle.version": ""},
		"incompatible lifecycle": {"io.sb-gateway.lifecycle.version": "2"},
		"migration gap":          {"io.sb-gateway.config.schema": "3", "io.sb-gateway.config.minimum-schema": "2"},
	} {
		t.Run(name, func(t *testing.T) {
			archive := dockerImageArchive(t, "arm64", "1.8.0", "layer", labels)
			response := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", archive)
			if response.Code != http.StatusUnprocessableEntity {
				t.Fatalf("incompatible release accepted: %d %s", response.Code, response.Body.String())
			}
		})
	}

	compatibleFuture := dockerImageArchive(t, "arm64", "1.9.0", "layer", map[string]string{
		"io.sb-gateway.config.schema": "3", "io.sb-gateway.config.minimum-schema": "1",
	})
	response := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", compatibleFuture)
	if response.Code != http.StatusOK {
		t.Fatalf("skip-release-compatible image rejected: %d %s", response.Code, response.Body.String())
	}
}

func uploadImageRequest(t *testing.T, server *Server, cookie *http.Cookie, csrf, name string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, apiPrefix+"/lifecycle/image-upload", bytes.NewReader(body))
	request.Header.Set(csrfHeader, csrf)
	request.Header.Set("X-SB-Filename", name)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}

func dockerImageArchive(t *testing.T, architecture, version, layer string, overrides ...map[string]string) []byte {
	t.Helper()
	configName := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.json"
	labels := map[string]any{
		"org.opencontainers.image.title": "sb-gateway", "org.opencontainers.image.version": version,
		"io.sb-gateway.lifecycle.version": "1", "io.sb-gateway.config.schema": "1", "io.sb-gateway.config.minimum-schema": "1",
	}
	if len(overrides) > 0 {
		for key, value := range overrides[0] {
			if value == "" {
				delete(labels, key)
			} else {
				labels[key] = value
			}
		}
	}
	imageConfig := map[string]any{
		"architecture": architecture, "os": "linux",
		"config": map[string]any{"Labels": labels},
	}
	configBody, _ := json.Marshal(imageConfig)
	manifestBody, _ := json.Marshal([]any{map[string]any{
		"Config": configName, "RepoTags": []any{"sb-gateway:" + version}, "Layers": []any{"layer.tar"},
	}})
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, entry := range []struct {
		name string
		body []byte
	}{
		{configName, configBody},
		{"layer.tar", []byte(layer)},
		{"manifest.json", manifestBody},
	} {
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o600, Size: int64(len(entry.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
