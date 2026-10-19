package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	routerosassets "github.com/sb-gateway/sb-gateway/routeros"
)

func TestManagedScriptSyncMigratesWithoutBrowserAndRecoversJournal(t *testing.T) {
	for _, lostAck := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "lost-ack"}[lostAck], func(t *testing.T) {
			scripts := []map[string]any{
				{".id": "*1", "name": "SB-GATEWAY-health-watchdog", "comment": "SB-GATEWAY health watchdog", "source": routerosassets.HealthWatchdogSource()},
				{".id": "*2", "name": "SB-GATEWAY-startup-fail-open", "comment": "SB-GATEWAY startup fail-open", "source": routerosassets.StartupFailOpenSource()},
			}
			schedules := []map[string]any{}
			container := map[string]any{".id": "*A", "comment": "SB-GATEWAY container", "root-dir": "/usb1/sb-gateway/root-1.7.2", "start-on-boot": "true"}
			armed := 0
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
					_ = json.NewEncoder(w).Encode([]map[string]any{container})
				case r.Method == http.MethodGet && r.URL.Path == "/rest/system/scheduler":
					_ = json.NewEncoder(w).Encode(schedules)
				case r.Method == http.MethodGet && r.URL.Path == "/rest/ip/firewall/mangle":
					_, _ = w.Write([]byte(`[{"comment":"SB-GATEWAY diversion-gate","disabled":false}]`))
				case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
					_ = json.NewEncoder(w).Encode(scripts)
				case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script/job":
					_, _ = w.Write([]byte(`[]`))
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/rest/system/script/"):
					for _, script := range scripts {
						if text(script[".id"]) == strings.TrimPrefix(r.URL.Path, "/rest/system/script/") {
							_ = json.NewEncoder(w).Encode(script)
							return
						}
					}
					http.Error(w, "missing", 404)
				case r.Method == http.MethodPut && r.URL.Path == "/rest/system/script":
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					body[".id"] = "*3"
					scripts = append(scripts, body)
					_ = json.NewEncoder(w).Encode(body)
				case r.Method == http.MethodPut && r.URL.Path == "/rest/system/scheduler":
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					body[".id"] = "*B"
					schedules = append(schedules, body)
					armed++
					if lostAck {
						http.Error(w, "acknowledgement lost", 502)
						return
					}
					_ = json.NewEncoder(w).Encode(body)
				default:
					t.Errorf("unexpected mutation %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected", 400)
				}
			}))
			defer api.Close()
			server := newTestServer(t)
			bootstrapSession(t, server)
			configureLifecycleRouter(t, server, api)
			config, err := server.getDraft()
			if err != nil {
				t.Fatal(err)
			}
			config["transports"] = []any{}
			config["local_clients"] = []any{}
			revision, err := server.repository.stageGeneration(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test", CommittedAt: server.now()}); err != nil {
				t.Fatal(err)
			}
			server.checkPersistentMounts = func() (bool, []string) { return true, nil }
			marker := filepath.Join(t.TempDir(), "ready")
			t.Setenv("SB_ROUTER_READY_MARKER", marker)
			if err := os.WriteFile(marker, []byte(strconv.FormatInt(server.now().Unix(), 10)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := server.repository.saveAuxiliary("lifecycle-operation", map[string]any{"kind": "image-update", "state": "probation", "candidate_root": "usb1/sb-gateway/root-1.7.2", "previous_root": "usb1/sb-gateway/root"}); err != nil {
				t.Fatal(err)
			}
			err = server.syncRouterOSManagedScripts(context.Background())
			if err == nil || (!lostAck && !errors.Is(err, errRouterOSScriptSyncDeferred)) || armed != 1 {
				t.Fatalf("migration err=%v armed=%d", err, armed)
			}
			journal, err := server.repository.auxiliary(containerStartupOperation)
			if err != nil || journal["pending"] != true {
				t.Fatalf("missing migration ownership: %#v %v", journal, err)
			}
			update, err := server.repository.auxiliary("lifecycle-operation")
			if err != nil || update["state"] != "completed" {
				t.Fatalf("update needed a browser: %#v %v", update, err)
			}
			// Simulate RouterOS completing the one-shot while the panel restarts.
			container["start-on-boot"] = "false"
			schedules = []map[string]any{{".id": "*C", "name": "SB-GATEWAY-container-startup", "comment": "SB-GATEWAY storage-aware startup scheduler", "interval": "0s", "start-time": "startup", "on-event": "/system/script/run SB-GATEWAY-container-startup"}}
			scripts = append(scripts,
				map[string]any{".id": "*4", "name": "SB-GATEWAY-storage-ready", "comment": "SB-GATEWAY storage readiness", "source": routerosassets.ContainerStorageReadySource()},
				map[string]any{".id": "*5", "name": "SB-GATEWAY-container-startup", "comment": "SB-GATEWAY storage-aware startup", "source": routerosassets.ContainerBootSource()})
			if err := server.syncRouterOSManagedScripts(context.Background()); err != nil {
				t.Fatal(err)
			}
			journal, err = server.repository.auxiliary(containerStartupOperation)
			if err != nil || journal["pending"] != false || armed != 1 {
				t.Fatalf("journal stuck or restarted twice: %#v armed=%d err=%v", journal, armed, err)
			}
		})
	}
}
