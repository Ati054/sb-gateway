package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestWithoutFetchInfoTopicPreservesOtherLogMessages(t *testing.T) {
	for _, test := range []struct {
		before, after string
		changed       bool
	}{
		{"info", "info,!fetch", true},
		{"fetch", "fetch,!info", true},
		{"info,!script", "info,!script,!fetch", true},
		{"info,!wireguard", "info,!wireguard,!fetch", true},
		{"fetch,!script", "fetch,!script,!info", true},
		{"info,fetch,!script", "info,fetch,!script,!fetch", true},
		{"info,script", "", false},
		{"info,!info", "", false},
		{"fetch,!fetch", "", false},
		{"info,fetch", "info,fetch,!fetch", true},
		{"info,!fetch", "", false},
		{"fetch,!info", "", false},
		{"warning", "", false},
		{"error", "", false},
		{"system,info", "", false},
		{"fetch,warning", "", false},
	} {
		got, changed := withoutFetchInfoTopic(test.before)
		if got != test.after || changed != test.changed {
			t.Fatalf("topics %q: got (%q, %t), want (%q, %t)", test.before, got, changed, test.after, test.changed)
		}
	}
}

func TestSuppressFetchInfoLogsPatchesExistingRulesAndIsIdempotent(t *testing.T) {
	rules := []map[string]any{
		{".id": "*1", "topics": "info", "disabled": "false"},
		{".id": "*2", "topics": "warning", "disabled": "false"},
		{".id": "*3", "topics": "error", "disabled": "false"},
		{".id": "*4", "topics": "fetch", "disabled": "false"},
		{".id": "*5", "topics": "info", "disabled": "true"},
		{".id": "*6", "topics": "info,!wireguard", "disabled": "false"},
	}
	patches := make([]string, 0)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/logging":
			_ = json.NewEncoder(response).Encode(rules)
		case request.Method == http.MethodPatch && request.URL.Path == "/rest/system/logging/*1",
			request.Method == http.MethodPatch && request.URL.Path == "/rest/system/logging/*4",
			request.Method == http.MethodPatch && request.URL.Path == "/rest/system/logging/*6":
			var payload map[string]string
			if json.NewDecoder(request.Body).Decode(&payload) != nil {
				http.Error(response, "invalid payload", http.StatusBadRequest)
				return
			}
			patches = append(patches, request.URL.Path+" "+payload["topics"])
			for _, rule := range rules {
				if "/rest/system/logging/"+rule[".id"].(string) == request.URL.Path {
					rule["topics"] = payload["topics"]
				}
			}
			_, _ = response.Write([]byte(`{}`))
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
	changed, err := client.SuppressFetchInfoLogs(context.Background())
	if err != nil || !changed {
		t.Fatalf("first run: changed=%t err=%v", changed, err)
	}
	changed, err = client.SuppressFetchInfoLogs(context.Background())
	if err != nil || changed {
		t.Fatalf("second run: changed=%t err=%v", changed, err)
	}
	want := []string{"/rest/system/logging/*1 info,!fetch", "/rest/system/logging/*4 fetch,!info", "/rest/system/logging/*6 info,!wireguard,!fetch"}
	if !reflect.DeepEqual(patches, want) {
		t.Fatalf("patches=%v want=%v", patches, want)
	}
}
