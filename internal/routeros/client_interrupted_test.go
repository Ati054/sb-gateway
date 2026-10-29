package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPlannedApplyRetriesOnlyExplicitInterruption(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		interruptions, status, wantRuns, wantLists int
		foreign, wantErr                           bool
	}{
		{"once", 1, 400, 2, 2, false, false},
		{"twice", 2, 400, 3, 3, false, false},
		{"bounded", 9, 400, 3, 3, false, true},
		{"ownership-changed", 1, 400, 1, 2, true, true},
		{"forbidden", 1, 403, 1, 1, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var lists, runs atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/rest/system/script" {
					n := lists.Add(1)
					comment := "SB-GATEWAY startup fail-open"
					if tc.foreign && n > 1 {
						comment = "foreign"
					}
					_ = json.NewEncoder(w).Encode([]map[string]any{{".id": fmt.Sprintf("*%d", n), "name": startupFailOpenScript, "comment": comment}})
					return
				}
				if r.URL.Path != "/rest/system/script/run" {
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				n := runs.Add(1)
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if body[".id"] != fmt.Sprintf("*%d", lists.Load()) {
					t.Error("replayed a stale resource ID")
				}
				if int(n) <= tc.interruptions {
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(`{"error":400,"detail":"interrupted","message":"Bad Request"}`))
					return
				}
				_, _ = w.Write([]byte(`[]`))
			}))
			defer server.Close()
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			err = client.EnterPlannedApplyFailOpen(context.Background())
			if (err != nil) != tc.wantErr || int(runs.Load()) != tc.wantRuns || int(lists.Load()) != tc.wantLists {
				t.Fatalf("err=%v runs=%d lists=%d", err, runs.Load(), lists.Load())
			}
		})
	}
}

func TestRESTInterruptionClassificationDoesNotExposeErrorBody(t *testing.T) {
	for _, tc := range []struct {
		status      int
		body        string
		interrupted bool
	}{
		{400, `{"detail":"interrupted"}`, true},
		{400, `{"detail":"configuration secret"}`, false},
		{400, `{"detail":"not interrupted"}`, false},
		{400, `not JSON`, false},
		{403, `{"detail":"interrupted"}`, false},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.requestAction(context.Background(), http.MethodPost, "/rest/system/script/run", map[string]any{".id": "*1"})
		var failure HTTPError
		if !errors.As(err, &failure) || failure.CommandInterrupted != tc.interrupted || DefinitiveRequestRejection(err) == tc.interrupted {
			t.Fatalf("classification=%v", err)
		}
		if strings.Contains(err.Error(), "configuration secret") {
			t.Fatal("response body leaked")
		}
		client.CloseIdleConnections()
		server.Close()
	}
}

func TestArbitraryManagedScriptIsNotReplayedAfterInterruption(t *testing.T) {
	var runs atomic.Int32
	const name = "SB-GATEWAY-apply-0123456789ab"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]map[string]any{{".id": "*1", "name": name, "comment": "SB-GATEWAY managed script " + name}})
			return
		}
		runs.Add(1)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"detail":"interrupted"}`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	_, err = client.RunManagedScript(context.Background(), name)
	if err == nil || runs.Load() != 1 || DefinitiveRequestRejection(err) {
		t.Fatalf("err=%v runs=%d", err, runs.Load())
	}
}

func TestPlannedApplyInterruptionHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`[{".id":"*1","name":"SB-GATEWAY-startup-fail-open","comment":"SB-GATEWAY startup fail-open"}]`))
			return
		}
		runs.Add(1)
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"detail":"interrupted"}`))
		cancel()
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.EnterPlannedApplyFailOpen(ctx); !errors.Is(err, context.Canceled) || runs.Load() != 1 {
		t.Fatalf("err=%v runs=%d", err, runs.Load())
	}
}
