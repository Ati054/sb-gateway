package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeImageUpdateSchedulesVerifiedCandidateWithRecovery(t *testing.T) {
	var scheduled bool
	var worker string
	router := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/container":
			_, _ = response.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root"}]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/script":
			var payload map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				http.Error(response, "bad worker", http.StatusBadRequest)
				return
			}
			worker = text(payload["source"])
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
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["updates"] = map[string]any{"retain_previous_images": 1}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	upload := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", dockerImageArchive(t, "arm64", "1.7.2", "layer"))
	if upload.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", upload.Code, upload.Body.String())
	}
	reference := text(decodeResponse(t, upload)["routeros_path"])
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/image-update", map[string]any{
		"candidate_source": "local-file", "candidate_reference": reference, "confirmation": "ОБНОВИТЬ",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusAccepted || !scheduled {
		t.Fatalf("image update not scheduled: %d %s", response.Code, response.Body.String())
	}
	for _, fragment := range []string{"memory-high=$memoryHigh memory-max=$memoryMax", "root-1.7.2", "http://172.19.0.2:9080/healthz", "http://172.19.0.2:9080/traffic-ready", reference, ":local retainPrevious true"} {
		if !strings.Contains(worker, fragment) {
			t.Fatalf("worker is missing %q", fragment)
		}
	}
	operation, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil || operation["state"] != "scheduled" || operation["version"] != "1.7.2" {
		t.Fatalf("operation = %#v, %v", operation, err)
	}
	recoveryName := text(operation["recovery_archive"])
	if info, err := os.Stat(filepath.Join(server.opts.DataDir, "recovery-backups", recoveryName)); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("recovery archive = %#v, %v", info, err)
	}
}

func TestNativeImageUpdateRejectsUnverifiedCandidate(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/image-update", map[string]any{
		"candidate_source":    "local-file",
		"candidate_reference": "usb1/sb-gateway/data/lifecycle-uploads/sb-gateway-upload-0123456789abcdef.tar",
		"confirmation":        "",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusConflict {
		t.Fatalf("missing confirmation accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestNativeImageUpdateRejectsReadOnlyPersistentStorage(t *testing.T) {
	server := newTestServer(t)
	server.checkPersistentMounts = func() (bool, []string) {
		return false, []string{"/config", "/state"}
	}
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/image-update", map[string]any{
		"candidate_source": "local-file", "candidate_reference": "unused.tar", "confirmation": "ОБНОВИТЬ",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("read-only storage accepted: %d %s", response.Code, response.Body.String())
	}
	failure := objectAt(decodeResponse(t, response), "error")
	if failure["code"] != "persistent_storage_read_only" {
		t.Fatalf("unexpected read-only storage failure: %#v", failure)
	}
}

func TestNativeImageUpdateReturnsSafeRecoveryFailure(t *testing.T) {
	var scheduled bool
	router := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/container":
			_, _ = response.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root"}]`))
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
	if err := os.WriteFile(filepath.Join(server.opts.StateDir, "too-large.json"), make([]byte, recoveryMaxFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	upload := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", dockerImageArchive(t, "arm64", "1.7.2", "layer"))
	if upload.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", upload.Code, upload.Body.String())
	}
	reference := text(decodeResponse(t, upload)["routeros_path"])
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/image-update", map[string]any{
		"candidate_source": "local-file", "candidate_reference": reference, "confirmation": "ОБНОВИТЬ",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusInternalServerError || scheduled {
		t.Fatalf("recovery failure scheduled lifecycle update: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	failure := objectAt(body, "error")
	if failure["code"] != "recovery_archive_required" || strings.Contains(response.Body.String(), "too-large") {
		t.Fatalf("lifecycle failure leaked a source: %#v", body)
	}
	details, _ := failure["details"].([]any)
	if len(details) != 1 || objectAt(map[string]any{"detail": details[0]}, "detail")["action"] != "check_recovery_data" {
		t.Fatalf("lifecycle recovery diagnostic = %#v", failure)
	}
	operation, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil || len(operation) != 0 {
		t.Fatalf("lifecycle operation was persisted after recovery failure: %#v, %v", operation, err)
	}
}

func TestNativeImageUpdateSchedulesAfterBrowserDisconnectDuringRecoveryArchive(t *testing.T) {
	scheduleCalls := 0
	router := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/container":
			_, _ = response.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root"}]`))
		case request.Method == http.MethodGet && (request.URL.Path == "/rest/system/script" || request.URL.Path == "/rest/system/scheduler"):
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`{".id":"*2"}`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler":
			scheduleCalls++
			_, _ = response.Write([]byte(`{".id":"*3"}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer router.Close()

	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	configureLifecycleRouter(t, server, router)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["updates"] = map[string]any{"retain_previous_images": 1}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	upload := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", dockerImageArchive(t, "arm64", "1.7.2", "layer"))
	if upload.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", upload.Code, upload.Body.String())
	}
	reference := text(decodeResponse(t, upload)["routeros_path"])
	requestContext, cancel := context.WithCancel(context.Background())
	server.recoveryBeforeSnapshot = func(int) { cancel() }
	body, err := json.Marshal(map[string]any{
		"candidate_source": "local-file", "candidate_reference": reference, "confirmation": "ОБНОВИТЬ",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, apiPrefix+"/lifecycle/image-update", bytes.NewReader(body)).WithContext(requestContext)
	request.Header.Set(csrfHeader, csrf)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || scheduleCalls != 1 {
		t.Fatalf("disconnected request schedule = %d calls=%d body=%s", response.Code, scheduleCalls, response.Body.String())
	}
}

func TestNativeImageUpdateStopsWhenSourceChurnCleanupFails(t *testing.T) {
	var scheduled bool
	router := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/container":
			_, _ = response.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root"}]`))
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
	marker := filepath.Join(server.opts.StateDir, "marker.json")
	if err := os.WriteFile(marker, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	server.recoveryBeforeSnapshot = func(int) {
		attempts++
		if err := os.WriteFile(marker, []byte("after\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server.recoveryCleanupSnapshot = func(string) error { return errors.New("cleanup failed") }
	upload := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", dockerImageArchive(t, "arm64", "1.7.2", "layer"))
	if upload.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", upload.Code, upload.Body.String())
	}
	reference := text(decodeResponse(t, upload)["routeros_path"])
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/lifecycle/image-update", map[string]any{
		"candidate_source": "local-file", "candidate_reference": reference, "confirmation": "ОБНОВИТЬ",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusInternalServerError || scheduled || attempts != 1 {
		t.Fatalf("source churn cleanup failure = %d scheduled=%t attempts=%d body=%s", response.Code, scheduled, attempts, response.Body.String())
	}
	failure := objectAt(decodeResponse(t, response), "error")
	details, _ := failure["details"].([]any)
	if len(details) != 1 || objectAt(map[string]any{"detail": details[0]}, "detail")["classifier"] != "staging" {
		t.Fatalf("cleanup failure classifier = %#v", failure)
	}
}

func TestLifecycleStatusReconcilesCompletedRouterOSImageUpdate(t *testing.T) {
	var memoryPatch map[string]any
	router := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/container":
			_, _ = response.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root-1.7.2","memory-high":"192.0MiB","memory-max":"268435456"}]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPatch && request.URL.Path == "/rest/container/*1":
			if err := json.NewDecoder(request.Body).Decode(&memoryPatch); err != nil {
				http.Error(response, "bad memory patch", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer router.Close()
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	configureLifecycleRouter(t, server, router)
	if err := server.repository.saveAuxiliary("lifecycle-operation", map[string]any{
		"kind": "image-update", "state": "probation", "candidate_root": "usb1/sb-gateway/root-1.7.2", "previous_root": "usb1/sb-gateway/root",
	}); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/lifecycle", nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("lifecycle status failed: %d %s", response.Code, response.Body.String())
	}
	operation := objectAt(decodeResponse(t, response), "operation")
	if operation["state"] != "completed" || text(operation["completed_at"]) == "" {
		t.Fatalf("operation was not reconciled: %#v", operation)
	}
	if memoryPatch["memory-high"] != float64(lifecycleContainerMemoryHigh) || memoryPatch["memory-max"] != float64(lifecycleContainerMemoryMax) {
		t.Fatalf("memory limits were not raised after self-update: %#v", memoryPatch)
	}
}

func TestLifecycleStatusMigratesLegacyDefaultMemoryLimits(t *testing.T) {
	var memoryPatch map[string]any
	router := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/container":
			_, _ = response.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root-1.7.2","memory-high":"320.0MiB","memory-max":"384.0MiB"}]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPatch && request.URL.Path == "/rest/container/*1":
			if err := json.NewDecoder(request.Body).Decode(&memoryPatch); err != nil {
				http.Error(response, "bad memory patch", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer router.Close()
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	configureLifecycleRouter(t, server, router)
	if err := server.repository.saveAuxiliary("lifecycle-operation", map[string]any{
		"kind": "image-update", "state": "probation", "candidate_root": "usb1/sb-gateway/root-1.7.2", "previous_root": "usb1/sb-gateway/root",
	}); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/lifecycle", nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("lifecycle status failed: %d %s", response.Code, response.Body.String())
	}
	if memoryPatch["memory-high"] != float64(lifecycleContainerMemoryHigh) || memoryPatch["memory-max"] != float64(lifecycleContainerMemoryMax) {
		t.Fatalf("legacy defaults were not migrated after self-update: %#v", memoryPatch)
	}
}

func TestRouterOSByteSize(t *testing.T) {
	for _, test := range []struct {
		value any
		want  int64
	}{{"192.0MiB", 192 << 20}, {"1.5GiB", 1536 << 20}, {"402653184", 384 << 20}, {json.Number("402653184"), 384 << 20}} {
		got, ok := routerOSByteSize(test.value)
		if !ok || got != test.want {
			t.Fatalf("routerOSByteSize(%v) = %d, %t; want %d", test.value, got, ok, test.want)
		}
	}
}
