package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestExecuteDirectDeltaReusesOneAuthenticatedHTTPClient(t *testing.T) {
	var mu sync.Mutex
	requests := make([]string, 0, 3)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		username, password, ok := request.BasicAuth()
		if !ok || username != "admin" || password != "secret" {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/script":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || !strings.HasPrefix(text(payload["name"]), "SB-GATEWAY-apply-") {
				http.Error(response, "bad payload", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{".id":"*14"}`))
		case request.Method == http.MethodPost && request.URL.Path == "/rest/system/script/run":
			_, _ = response.Write([]byte(`{"ret":"ok"}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	delta := "# SB-GATEWAY generated minimal delta; complete managed sections\n# SB-GATEWAY delta sections: dns\n# SB-GATEWAY section:dns\n/ip/dns/cache/flush\n"
	result, err := client.ExecuteDirectDelta(context.Background(), "apply", delta)
	if err != nil {
		t.Fatal(err)
	}
	if result["ret"] != "ok" {
		t.Fatalf("run result = %#v", result)
	}
	want := []string{"GET /rest/system/script?.proplist=.id,name,comment", "PUT /rest/system/script", "POST /rest/system/script/run"}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestExecuteDirectDeltaUpdatesOnlyOwnedExactScript(t *testing.T) {
	var patched string
	delta := "# SB-GATEWAY generated minimal delta; complete managed sections\n# SB-GATEWAY delta sections: dns\n# SB-GATEWAY section:dns\n/ip/dns/cache/flush\n"
	name, _ := managedScriptName("rollback", delta)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodGet:
			_, _ = response.Write([]byte(`[{".id":"*2A","name":"` + name + `","comment":"SB-GATEWAY managed script ` + name + `"}]`))
		case http.MethodPatch:
			patched = request.URL.EscapedPath()
			_, _ = response.Write([]byte(`{}`))
		case http.MethodPost:
			_, _ = response.Write([]byte(`{}`))
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.ExecuteDirectDelta(context.Background(), "rollback", delta); err != nil {
		t.Fatal(err)
	}
	if patched != "/rest/system/script/*2A" {
		t.Fatalf("patched resource path = %q", patched)
	}
}

func TestRequestActionAcceptsRouterOSEmptyArray(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := client.requestAction(context.Background(), http.MethodPost, "/rest/system/script/run", map[string]any{".id": "*1"}); err != nil || len(result) != 0 {
		t.Fatalf("action result = %#v, err = %v", result, err)
	}
}

func TestManagedScriptUsesDedicatedActionTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[{".id":"*1","name":"SB-GATEWAY-apply-0123456789ab","comment":"SB-GATEWAY managed script SB-GATEWAY-apply-0123456789ab"}]`))
		case request.Method == http.MethodPost && request.URL.Path == "/rest/system/script/run":
			time.Sleep(75 * time.Millisecond)
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/resource":
			time.Sleep(75 * time.Millisecond)
			_, _ = response.Write([]byte(`{"version":"7.24"}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
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
	if _, err := client.RunManagedScript(context.Background(), "SB-GATEWAY-apply-0123456789ab"); err != nil {
		t.Fatalf("long RouterOS action used ordinary REST timeout: %v", err)
	}
	if err := client.Health(context.Background()); err == nil {
		t.Fatal("ordinary RouterOS inventory request ignored its short timeout")
	}
}

func TestEnforceStartupTrafficSafetyMigratesOwnedWatchdogBeforeFailOpen(t *testing.T) {
	var requests []string
	var patchedSource string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[
				{".id":"*10","name":"SB-GATEWAY-watchdog-config","comment":"SB-GATEWAY watchdog persisted config","source":":global \"SB_HEALTH_URL\" \"http://172.31.255.2:9080/healthz\";"},
				{".id":"*11","name":"SB-GATEWAY-startup-fail-open","comment":"SB-GATEWAY startup fail-open","source":"safe"}
			]`))
		case request.Method == http.MethodPatch && request.URL.Path == "/rest/system/script/*10":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil {
				http.Error(response, "bad payload", http.StatusBadRequest)
				return
			}
			patchedSource = text(payload["source"])
			_, _ = response.Write([]byte(`{}`))
		case request.Method == http.MethodPost && request.URL.Path == "/rest/system/script/run":
			_, _ = response.Write([]byte(`[]`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	migrated, err := client.EnforceStartupTrafficSafety(context.Background())
	if err != nil || !migrated {
		t.Fatalf("migration = %t, %v", migrated, err)
	}
	if !strings.Contains(patchedSource, ":9080/traffic-ready") || strings.Contains(patchedSource, ":9080/healthz") {
		t.Fatalf("patched source = %q", patchedSource)
	}
	want := []string{
		"GET /rest/system/script?.proplist=.id,name,comment,source",
		"PATCH /rest/system/script/*10",
		"POST /rest/system/script/run",
		"POST /rest/system/script/run",
	}
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestEnforceStartupTrafficSafetyRefusesUnownedScript(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[{".id":"*10","name":"SB-GATEWAY-watchdog-config","comment":"foreign","source":"http://172.31.255.2:9080/healthz"}]`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.EnforceStartupTrafficSafety(context.Background()); err == nil || !strings.Contains(err.Error(), "unowned") {
		t.Fatalf("unowned script accepted: %v", err)
	}
}

func TestClientRejectsUnsafeEndpointAndScript(t *testing.T) {
	badEndpoints := []string{"http://192.0.2.1:8729", "https://user@192.0.2.1:8729", "https://192.0.2.1/rest", "https://192.0.2.1"}
	for _, endpoint := range badEndpoints {
		if _, err := NewClient(Options{BaseURL: endpoint, Username: "a", Password: "b"}); err == nil {
			t.Fatalf("unsafe endpoint %q was accepted", endpoint)
		}
	}
	if err := validateDirectDelta("/system reboot\n"); err == nil {
		t.Fatal("foreign destructive script was accepted")
	}
	unsafe := "# SB-GATEWAY generated minimal delta; complete managed sections\n/remove [find]\n"
	if err := validateDirectDelta(unsafe); err == nil {
		t.Fatal("broad delete was accepted")
	}
}

func TestClientHealthUsesAuthenticatedSystemResource(t *testing.T) {
	var path string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		path = request.URL.Path
		username, password, ok := request.BasicAuth()
		if !ok || username != "admin" || password != "secret" {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = response.Write([]byte(`{"uptime":"1d2h","version":"7.20"}`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if path != "/rest/system/resource" {
		t.Fatalf("health path = %q", path)
	}
}

func TestClientListAcceptsObjectAndArrayInventory(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/rest/system/resource" {
			_, _ = response.Write([]byte(`{"version":"7.21.5"}`))
			return
		}
		_, _ = response.Write([]byte(`[{"name":"ether1"},{"name":"bridge"}]`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	resource, err := client.List(context.Background(), "/rest/system/resource")
	if err != nil || len(resource) != 1 || resource[0]["version"] != "7.21.5" {
		t.Fatalf("object inventory = %#v, %v", resource, err)
	}
	interfaces, err := client.List(context.Background(), "/rest/interface")
	if err != nil || len(interfaces) != 2 || interfaces[1]["name"] != "bridge" {
		t.Fatalf("array inventory = %#v, %v", interfaces, err)
	}
}

func TestScheduleRecoveryRestartInstallsOwnedOneShotResources(t *testing.T) {
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/script":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload["name"] != recoveryRestartWorker || !strings.Contains(text(payload["source"]), `comment="SB-GATEWAY container"`) {
				http.Error(response, "bad worker", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{".id":"*31"}`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[{".id":"*32","name":"SB-GATEWAY-recovery-restart-once","comment":"SB-GATEWAY one-shot recovery restart"}]`))
		case request.Method == http.MethodDelete && request.URL.Path == "/rest/system/scheduler/*32":
			_, _ = response.Write([]byte(`{}`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload["interval"] != "60s" || payload["on-event"] != "/system/script/run "+recoveryRestartWorker {
				http.Error(response, "bad scheduler", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{".id":"*33"}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	result, err := client.ScheduleRecoveryRestart(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result["scheduled"] != true || result["delay_seconds"] != 60 {
		t.Fatalf("restart result = %#v", result)
	}
	want := []string{
		"GET /rest/system/script?.proplist=.id,name,comment",
		"PUT /rest/system/script",
		"GET /rest/system/scheduler?.proplist=.id,name,comment",
		"DELETE /rest/system/scheduler/*32",
		"PUT /rest/system/scheduler",
	}
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestScheduleRecoveryRestartRefusesUnownedScheduler(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[{".id":"*1","name":"SB-GATEWAY-recovery-restart-worker","comment":"SB-GATEWAY managed script SB-GATEWAY-recovery-restart-worker"}]`))
		case request.Method == http.MethodPatch && request.URL.Path == "/rest/system/script/*1":
			_, _ = response.Write([]byte(`{}`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[{".id":"*2","name":"SB-GATEWAY-recovery-restart-once","comment":"foreign"}]`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.ScheduleRecoveryRestart(context.Background()); err == nil || !strings.Contains(err.Error(), "unowned") {
		t.Fatalf("unowned scheduler error = %v", err)
	}
}
