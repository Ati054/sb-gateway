package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
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
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
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
		if request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler" {
			_, _ = response.Write([]byte(`[]`))
			return
		}
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

func TestArmRollbackBlocksWhilePreviousOwnedGuardIsPending(t *testing.T) {
	putCalls := 0
	clockCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[{"name":"SB-GATEWAY-safe-rollback-1234abcd","comment":"SB-GATEWAY Safe Mode rollback fallback","run-count":"0"},{"name":"SB-GATEWAY-safe-rollback-deadbeef","comment":"foreign","run-count":"0"}]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/clock":
			clockCalls++
			_, _ = response.Write([]byte(`{"date":"2026-09-21","time":"10:00:00"}`))
		case request.Method == http.MethodPut:
			putCalls++
			_, _ = response.Write([]byte(`{}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	_, err := client.ArmRollback(context.Background(), "SB-GATEWAY-rollback-0123456789ab", RollbackOptions{})
	if !errors.Is(err, ErrRollbackGuardPending) {
		t.Fatalf("error = %v, want pending rollback guard", err)
	}
	if clockCalls != 0 || putCalls != 0 {
		t.Fatalf("blocked generation reached clock/create: clock=%d put=%d", clockCalls, putCalls)
	}
}

func TestArmRollbackAllowsCompletedOwnedGuard(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[{"name":"SB-GATEWAY-safe-rollback-1234abcd","comment":"SB-GATEWAY Safe Mode rollback fallback","run-count":"1"}]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/clock":
			_, _ = response.Write([]byte(`{"date":"2026-09-21","time":"10:00:00"}`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`{}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()
	if _, err := client.ArmRollback(context.Background(), "SB-GATEWAY-rollback-0123456789ab", RollbackOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestArmRollbackClassifiesUncertainCreation(t *testing.T) {
	for _, test := range []struct {
		name            string
		failurePath     string
		failureMethod   string
		responseKind    string
		wantUnconfirmed bool
	}{
		{name: "server failure after creation request", failurePath: "/rest/system/scheduler", failureMethod: http.MethodPut, responseKind: "server error", wantUnconfirmed: true},
		{name: "unreadable success receipt", failurePath: "/rest/system/scheduler", failureMethod: http.MethodPut, responseKind: "invalid JSON", wantUnconfirmed: true},
		{name: "creation response lost", failurePath: "/rest/system/scheduler", failureMethod: http.MethodPut, responseKind: "disconnect", wantUnconfirmed: true},
		{name: "explicit rejection", failurePath: "/rest/system/scheduler", failureMethod: http.MethodPut, responseKind: "forbidden"},
		{name: "inventory failed before creation", failurePath: "/rest/system/scheduler", failureMethod: http.MethodGet, responseKind: "server error"},
		{name: "clock failed before creation", failurePath: "/rest/system/clock", failureMethod: http.MethodGet, responseKind: "server error"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				if request.URL.Path == test.failurePath && request.Method == test.failureMethod {
					switch test.responseKind {
					case "server error":
						http.Error(response, "unavailable", http.StatusServiceUnavailable)
					case "invalid JSON":
						_, _ = response.Write([]byte(`{"incomplete":`))
					case "forbidden":
						http.Error(response, "forbidden", http.StatusForbidden)
					case "disconnect":
						connection, _, err := response.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = connection.Close()
					}
					return
				}
				switch request.URL.Path {
				case "/rest/system/scheduler":
					_, _ = response.Write([]byte(`[]`))
				case "/rest/system/clock":
					_, _ = response.Write([]byte(`{"date":"2026-10-04","time":"19:15:49"}`))
				default:
					http.Error(response, "unexpected", http.StatusNotFound)
				}
			}))
			defer server.Close()
			client := newTestClient(t, server)
			defer client.CloseIdleConnections()
			_, err := client.ArmRollback(context.Background(), "SB-GATEWAY-rollback-0123456789ab", RollbackOptions{})
			if err == nil || errors.Is(err, ErrRollbackGuardUnconfirmed) != test.wantUnconfirmed {
				t.Fatalf("unconfirmed=%t err=%v", test.wantUnconfirmed, err)
			}
			state, classified := TransactionFailureStateOf(classifyRollbackArmFailure(err))
			if classified != test.wantUnconfirmed || (classified && state != TransactionRecoveryPending) {
				t.Fatalf("state=%q classified=%t err=%v", state, classified, err)
			}
		})
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
