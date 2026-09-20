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

func TestArmRollbackUsesRouterClockAndOneShotOwnedScheduler(t *testing.T) {
	var payload map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/clock":
			// RouterOS 7.24 exposes singleton resources as objects.
			_, _ = response.Write([]byte(`{"date":"2026-08-17","time":"23:55:30.500"}`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler":
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				http.Error(response, "bad payload", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	name, err := client.ArmRollback(context.Background(), "SB-GATEWAY-rollback-0123456789ab", RollbackOptions{
		Delay: 10 * time.Minute, ResumeWatchdog: true, ManagedImport: "SB-GATEWAY-rollback-0123456789ab.rsc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rollbackSchedulerNamePattern.MatchString(name) {
		t.Fatalf("scheduler name = %q", name)
	}
	if payload["start-date"] != "2026-08-18" || payload["start-time"] != "00:05:30" || payload["interval"] != "0s" {
		t.Fatalf("scheduler time payload = %#v", payload)
	}
	if payload["comment"] != rollbackSchedulerComment || payload["disabled"] != "false" {
		t.Fatalf("scheduler ownership payload = %#v", payload)
	}
	if payload["policy"] != "ftp,read,write,test,policy" {
		t.Fatal("rollback must be able to update the fetch-capable health watchdog")
	}
	event := text(payload["on-event"])
	for _, expected := range []string{"/system script run SB-GATEWAY-rollback-0123456789ab", "SB-GATEWAY-health-watchdog", "SB-GATEWAY-rollback-0123456789ab.rsc", name} {
		if !strings.Contains(event, expected) {
			t.Fatalf("on-event %q does not contain %q", event, expected)
		}
	}
}

func TestManagedImportCanUpdateWatchdogWithoutSensitivePermission(t *testing.T) {
	var policy string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		policy = text(payload["policy"])
		_, _ = w.Write([]byte(`{".id":"*1"}`))
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	if _, err := client.PrepareImportScript(context.Background(), "apply", "SB-GATEWAY-apply-0123456789ab.rsc"); err != nil {
		t.Fatal(err)
	}
	if policy != "ftp,read,write,test,policy" {
		t.Fatalf("managed import permissions: %s", policy)
	}
}

func TestArmRollbackAcceptsLegacyClockArray(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/rest/system/clock" {
			_, _ = response.Write([]byte(`[{"date":"sep/04/2026","time":"15:47:00"}]`))
			return
		}
		if request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler" {
			_, _ = response.Write([]byte(`{}`))
			return
		}
		http.Error(response, "unexpected", http.StatusNotFound)
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	if _, err := client.ArmRollback(
		context.Background(),
		"SB-GATEWAY-rollback-0123456789ab",
		RollbackOptions{Delay: 10 * time.Minute},
	); err != nil {
		t.Fatal(err)
	}
}

func TestDisarmRollbackDeletesOnlyExactOwnedSchedulerOnce(t *testing.T) {
	var mu sync.Mutex
	deletes := make([]string, 0, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case http.MethodGet:
			_, _ = response.Write([]byte(`[{".id":"*2A","name":"SB-GATEWAY-safe-rollback-1234abcd","comment":"SB-GATEWAY Safe Mode rollback fallback"}]`))
		case http.MethodDelete:
			mu.Lock()
			deletes = append(deletes, request.URL.EscapedPath())
			mu.Unlock()
			response.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	if err := client.DisarmRollback(context.Background(), "SB-GATEWAY-safe-rollback-1234abcd"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deletes) != 1 || deletes[0] != "/rest/system/scheduler/*2A" {
		t.Fatalf("DELETE requests = %#v", deletes)
	}
}

func TestDisarmRollbackRejectsUnownedScheduler(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[{".id":"*3","name":"SB-GATEWAY-safe-rollback-1234abcd","comment":"foreign"}]`))
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	if err := client.DisarmRollback(context.Background(), "SB-GATEWAY-safe-rollback-1234abcd"); err == nil {
		t.Fatal("unowned scheduler was removed")
	}
}

func TestPruneCompletedRollbacksSkipsFloatingHistoryAndForeignRows(t *testing.T) {
	t.Run("floating", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`[{"floating-undo":"true"}]`))
		}))
		defer server.Close()
		client := newTestClient(t, server)
		defer client.CloseIdleConnections()
		if removed, err := client.PruneCompletedRollbacks(context.Background()); err != nil || removed != 0 {
			t.Fatalf("removed=%d err=%v", removed, err)
		}
	})

	t.Run("settled", func(t *testing.T) {
		deletes := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("Content-Type", "application/json")
			switch {
			case request.Method == http.MethodGet && request.URL.Path == "/rest/system/history":
				_, _ = response.Write([]byte(`[{"floating-undo":"false"}]`))
			case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
				_, _ = response.Write([]byte(`[{".id":"*14","name":"SB-GATEWAY-safe-rollback-1234abcd","comment":"SB-GATEWAY Safe Mode rollback fallback","run-count":"1"},{".id":"*15","name":"SB-GATEWAY-safe-rollback-deadbeef","comment":"foreign","run-count":"2"},{".id":"*16","name":"SB-GATEWAY-safe-rollback-5678abcd","comment":"SB-GATEWAY Safe Mode rollback fallback","run-count":"0"}]`))
			case request.Method == http.MethodDelete:
				deletes++
				response.WriteHeader(http.StatusNoContent)
			default:
				http.Error(response, "unexpected", http.StatusNotFound)
			}
		}))
		defer server.Close()
		client := newTestClient(t, server)
		defer client.CloseIdleConnections()
		removed, err := client.PruneCompletedRollbacks(context.Background())
		if err != nil || removed != 1 || deletes != 1 {
			t.Fatalf("removed=%d deletes=%d err=%v", removed, deletes, err)
		}
	})
}

func TestParseRouterOSClockSupportsLegacyMonthFormat(t *testing.T) {
	parsed, err := parseRouterOSClock("aug/17/2026", "23:55:30")
	if err != nil || parsed.Format("2006-01-02 15:04:05") != "2026-08-17 23:55:30" {
		t.Fatalf("parsed=%v err=%v", parsed, err)
	}
}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
