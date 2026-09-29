package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	routerosassets "github.com/sb-gateway/sb-gateway/routeros"
)

func TestSyncInstalledScriptsUpdatesOnlyOwnedBodies(t *testing.T) {
	scripts := map[string]map[string]any{
		"*1": {".id": "*1", "name": "SB-GATEWAY-health-watchdog", "comment": "SB-GATEWAY health watchdog", "source": "old"},
		"*2": {".id": "*2", "name": "SB-GATEWAY-startup-fail-open", "comment": "SB-GATEWAY startup fail-open", "source": "old"},
		"*3": {".id": "*3", "name": "SB-GATEWAY-cloudflare-update", "comment": "SB-GATEWAY Cloudflare updater", "source": "old"},
	}
	patches := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			rows := make([]map[string]any, 0, len(scripts))
			for _, row := range scripts {
				rows = append(rows, row)
			}
			_ = json.NewEncoder(response).Encode(rows)
		case strings.HasPrefix(request.URL.Path, "/rest/system/script/"):
			id := strings.TrimPrefix(request.URL.Path, "/rest/system/script/")
			row := scripts[id]
			if row == nil {
				http.Error(response, "missing", http.StatusNotFound)
				return
			}
			if request.Method == http.MethodPatch {
				var payload map[string]any
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || len(payload) != 1 {
					http.Error(response, "unsafe patch", http.StatusBadRequest)
					return
				}
				row["source"] = payload["source"]
				patches++
			}
			_ = json.NewEncoder(response).Encode(row)
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
	if changed, err := client.SyncInstalledScripts(context.Background()); err != nil || changed != 3 {
		t.Fatalf("first sync changed=%d err=%v", changed, err)
	}
	if scripts["*1"]["source"] != routerosassets.HealthWatchdogSource() ||
		scripts["*2"]["source"] != routerosassets.StartupFailOpenSource() ||
		scripts["*3"]["source"] != routerosassets.CloudflareUpdateSource() {
		t.Fatal("installed script bodies do not match image assets")
	}
	if changed, err := client.SyncInstalledScripts(context.Background()); err != nil || changed != 0 || patches != 3 {
		t.Fatalf("repeated sync changed=%d patches=%d err=%v", changed, patches, err)
	}
}

func TestSyncInstalledScriptsWaitsForImageUpdate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/rest/system/scheduler" {
			http.Error(response, "unexpected script write", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[{"name":"SB-GATEWAY-image-update"}]`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := client.SyncInstalledScripts(context.Background()); err != ErrImageUpdateInProgress || changed != 0 {
		t.Fatalf("sync during image update changed=%d err=%v", changed, err)
	}
}

func TestSyncInstalledScriptsRejectsUnownedName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
		case "/rest/system/script":
			_, _ = response.Write([]byte(`[{".id":"*1","name":"SB-GATEWAY-health-watchdog","comment":"someone else's script"}]`))
		default:
			http.Error(response, "unexpected write", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SyncInstalledScripts(context.Background()); err == nil || !strings.Contains(err.Error(), "unowned") {
		t.Fatalf("unowned script was accepted: %v", err)
	}
}

func TestSetCloudflareUpdaterEnabledOnlyTouchesOwnedInstalledScheduler(t *testing.T) {
	disabled := "false"
	patches := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[{"name":"SB-GATEWAY-cloudflare-update","comment":"SB-GATEWAY Cloudflare updater"}]`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_ = json.NewEncoder(response).Encode([]map[string]any{{".id": "*4", "name": "SB-GATEWAY-cloudflare-update", "comment": "SB-GATEWAY Cloudflare scheduler", "disabled": disabled}})
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler/*4":
			_ = json.NewEncoder(response).Encode(map[string]any{"disabled": disabled})
		case request.Method == http.MethodPatch && request.URL.Path == "/rest/system/scheduler/*4":
			var payload map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || len(payload) != 1 {
				http.Error(response, "unsafe patch", http.StatusBadRequest)
				return
			}
			if payload["disabled"] == "true" {
				disabled = "true"
			} else {
				disabled = "false"
			}
			patches++
			_, _ = response.Write([]byte(`{}`))
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
	for _, wanted := range []bool{false, false, true} {
		if _, err := client.SetCloudflareUpdaterEnabled(context.Background(), wanted); err != nil {
			t.Fatal(err)
		}
	}
	if patches != 2 || disabled != "false" {
		t.Fatalf("scheduler patches=%d disabled=%s", patches, disabled)
	}
}
