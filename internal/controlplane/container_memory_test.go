package controlplane

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestContainerMemoryRequiresConfirmationAndValidIntegers(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	for _, values := range []map[string]any{
		{"memory_high_mib": 224, "memory_max_mib": 256},
		{"memory_high_mib": 320, "memory_max_mib": 256, "confirmation": "ПЕРЕЗАПУСТИТЬ"},
		{"memory_high_mib": 224.5, "memory_max_mib": 256, "confirmation": "ПЕРЕЗАПУСТИТЬ"},
		{"memory_high_mib": float64(1<<44) + 224, "memory_max_mib": 256, "confirmation": "ПЕРЕЗАПУСТИТЬ"},
	} {
		r := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/container/memory", values, map[string]string{csrfHeader: csrf}, cookie)
		if r.Code != 409 && r.Code != 422 {
			t.Fatalf("accepted invalid memory request: %d %s", r.Code, r.Body.String())
		}
	}
	r := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/container/memory", map[string]any{"memory_high_mib": 224, "memory_max_mib": 256, "confirmation": "ПЕРЕЗАПУСТИТЬ"}, nil, cookie)
	if r.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d", r.Code)
	}
}

func activateMemoryTestRouter(t *testing.T, server *Server, router *httptest.Server) {
	t.Helper()
	configureLifecycleRouter(t, server, router)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "memory-test", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
}

func TestContainerMemoryRejectsUnsafeLiveState(t *testing.T) {
	for _, tc := range []struct {
		name, rows    string
		high, maximum int
		code          int
	}{
		{"below-usage", `[{"comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root","stopped":"false","memory-high":"224MiB","memory-max":"256MiB","memory-current":"200MiB"}]`, 180, 210, 409},
		{"stopped", `[{"comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root","stopped":"true","memory-high":"224MiB","memory-max":"256MiB","memory-current":"0"}]`, 320, 384, 409},
		{"ambiguous", `[{"comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root"},{"comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root"}]`, 320, 384, 409},
		{"unowned", `[{"comment":"other","root-dir":"/usb1/sb-gateway/root"}]`, 320, 384, 409},
		{"unchanged", `[{"comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root","stopped":"false","memory-high":"224MiB","memory-max":"256MiB","memory-current":"140MiB"}]`, 224, 256, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/rest/container" {
					t.Errorf("unexpected mutation: %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected", 404)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.rows))
			}))
			defer router.Close()
			server := newTestServer(t)
			cookie, csrf := bootstrapSession(t, server)
			activateMemoryTestRouter(t, server, router)
			r := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/container/memory", map[string]any{"memory_high_mib": tc.high, "memory_max_mib": tc.maximum, "confirmation": "ПЕРЕЗАПУСТИТЬ"}, map[string]string{csrfHeader: csrf}, cookie)
			if r.Code != tc.code {
				t.Fatalf("status %d: %s", r.Code, r.Body.String())
			}
		})
	}
}

func TestContainerMemoryReadbackRequiresRootLimitsAndHealth(t *testing.T) {
	for _, tc := range []struct{ name, root, high, healthy, deadline, state string }{
		{"completed", "/usb1/sb-gateway/root", "320MiB", "true", "future", "completed"},
		{"unhealthy", "/usb1/sb-gateway/root", "320MiB", "false", "future", "scheduled"},
		{"wrong-root", "/usb1/sb-gateway/other", "320MiB", "true", "future", "scheduled"},
		{"old-limits", "/usb1/sb-gateway/root", "224MiB", "true", "future", "scheduled"},
		{"expired", "/usb1/sb-gateway/root", "224MiB", "true", "past", "unconfirmed"},
		{"queued", "/usb1/sb-gateway/root", "320MiB", "true", "future", "scheduled"},
		{"queued-expired", "/usb1/sb-gateway/root", "320MiB", "true", "past", "unconfirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/rest/system/scheduler" {
					w.Header().Set("Content-Type", "application/json")
					if strings.HasPrefix(tc.name, "queued") {
						_, _ = w.Write([]byte(`[{"name":"SB-GATEWAY-container-memory-once"}]`))
					} else {
						_, _ = w.Write([]byte(`[]`))
					}
					return
				}
				if r.Method != "GET" || r.URL.Path != "/rest/container" {
					t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode([]map[string]any{{"comment": "SB-GATEWAY container", "root-dir": tc.root, "memory-high": tc.high, "memory-max": "384MiB", "healthy": tc.healthy}})
			}))
			defer router.Close()
			server := newTestServer(t)
			cookie, _ := bootstrapSession(t, server)
			activateMemoryTestRouter(t, server, router)
			deadline := server.now().Add(time.Minute)
			if tc.deadline == "past" {
				deadline = server.now().Add(-time.Minute)
			}
			if err := server.repository.saveAuxiliary(containerMemoryOperation, map[string]any{"pending": true, "state": "scheduled", "root_dir": "/usb1/sb-gateway/root", "high_bytes": 320 << 20, "max_bytes": 384 << 20, "deadline": deadline.UTC().Format(time.RFC3339Nano)}); err != nil {
				t.Fatal(err)
			}
			r := performRequest(t, server, http.MethodGet, apiPrefix+"/routeros/container/memory", nil, nil, cookie)
			if r.Code != 200 {
				t.Fatalf("status %d: %s", r.Code, r.Body.String())
			}
			op, err := server.repository.auxiliary(containerMemoryOperation)
			if err != nil {
				t.Fatal(err)
			}
			if op["state"] != tc.state || op["pending"] != (tc.state == "scheduled" || strings.HasPrefix(tc.name, "queued")) {
				t.Fatalf("unexpected operation: %#v", op)
			}
		})
	}
}

func TestContainerMemorySchedulesOwnedOneShotWithoutLivePatch(t *testing.T) {
	var worker string
	var scheduled bool
	router := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && r.URL.Path == "/rest/container":
			_, _ = w.Write([]byte(`[{".id":"*1","comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root","stopped":"false","memory-high":"224.0MiB","memory-max":"256.0MiB","memory-current":"140.0MiB"}]`))
		case r.Method == "GET" && (r.URL.Path == "/rest/system/script" || r.URL.Path == "/rest/system/scheduler"):
			_, _ = w.Write([]byte(`[]`))
		case r.Method == "PUT" && r.URL.Path == "/rest/system/script":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			worker = text(body["source"])
			_, _ = w.Write([]byte(`{".id":"*2"}`))
		case r.Method == "PUT" && r.URL.Path == "/rest/system/scheduler":
			scheduled = true
			_, _ = w.Write([]byte(`{".id":"*3"}`))
		default:
			t.Errorf("unexpected RouterOS call: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", 404)
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
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "memory-test", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"memory_high_mib": 320, "memory_max_mib": 384, "confirmation": "ПЕРЕЗАПУСТИТЬ"}
	r := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/container/memory", body, map[string]string{csrfHeader: csrf}, cookie)
	if r.Code != 202 || !scheduled || !strings.Contains(worker, "memory-high=335544320 memory-max=402653184") {
		t.Fatalf("memory change not scheduled: %d %s", r.Code, r.Body.String())
	}
	retry := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/container/memory", body, map[string]string{csrfHeader: csrf}, cookie)
	if retry.Code != 409 {
		t.Fatalf("duplicate change accepted: %d", retry.Code)
	}
}
