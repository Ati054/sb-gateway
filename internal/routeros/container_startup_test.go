package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	routerosassets "github.com/sb-gateway/sb-gateway/routeros"
)

func TestStartupMigrationReconciliation(t *testing.T) {
	for _, mode := range []string{"legacy", "current", "current-clock", "disabled-current", "busy", "unowned", "duplicate", "bad-root", "bad-readback", "lost-ack"} {
		t.Run(mode, func(t *testing.T) {
			scripts := []map[string]any{}
			schedules := []map[string]any{}
			container := map[string]any{".id": "*1", "comment": "SB-GATEWAY container", "root-dir": "/usb1/sb-gateway/root-1.6.49", "start-on-boot": "true"}
			if mode == "current" || mode == "current-clock" || mode == "disabled-current" {
				container["start-on-boot"] = "false"
				scripts = append(scripts,
					map[string]any{".id": "*2", "name": "SB-GATEWAY-storage-ready", "comment": "SB-GATEWAY storage readiness", "source": routerosassets.ContainerStorageReadySource()},
					map[string]any{".id": "*3", "name": "SB-GATEWAY-container-startup", "comment": "SB-GATEWAY storage-aware startup", "source": routerosassets.ContainerBootSource()})
				schedules = append(schedules, map[string]any{".id": "*4", "name": "SB-GATEWAY-container-startup", "comment": "SB-GATEWAY storage-aware startup scheduler", "interval": "0s", "start-time": "startup", "on-event": "/system/script/run SB-GATEWAY-container-startup", "disabled": mode == "disabled-current"})
				if mode == "current-clock" {
					schedules[0]["interval"] = "00:00:00"
				}
			}
			if mode == "busy" {
				schedules = append(schedules, map[string]any{"name": imageUpdateScheduler})
			}
			if mode == "unowned" || mode == "duplicate" {
				scripts = append(scripts, map[string]any{".id": "*2", "name": "SB-GATEWAY-storage-ready", "comment": "foreign"})
				if mode == "duplicate" {
					scripts[0]["comment"] = "SB-GATEWAY storage readiness"
					scripts = append(scripts, scripts[0])
				}
			}
			if mode == "bad-root" {
				container["root-dir"] = "/usb1/sb-gateway/../foreign"
			}
			writes := 0
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
					_ = json.NewEncoder(w).Encode([]map[string]any{container})
				case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
					_ = json.NewEncoder(w).Encode(scripts)
				case r.Method == http.MethodGet && r.URL.Path == "/rest/system/scheduler":
					_ = json.NewEncoder(w).Encode(schedules)
				case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script/job":
					_, _ = w.Write([]byte(`[]`))
				case r.Method == http.MethodPut && r.URL.Path == "/rest/system/script":
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					body[".id"] = "*A"
					scripts = append(scripts, body)
					writes++
					_ = json.NewEncoder(w).Encode(body)
				case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script/*A":
					body := scripts[len(scripts)-1]
					if mode == "bad-readback" {
						body = map[string]any{"source": "truncated"}
					}
					_ = json.NewEncoder(w).Encode(body)
				case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/rest/system/script/"):
					for _, script := range scripts {
						if text(script[".id"]) == strings.TrimPrefix(r.URL.Path, "/rest/system/script/") {
							_ = json.NewEncoder(w).Encode(script)
							return
						}
					}
					http.Error(w, "missing", 404)
				case r.Method == http.MethodPut && r.URL.Path == "/rest/system/scheduler":
					var body map[string]any
					_ = json.NewDecoder(r.Body).Decode(&body)
					body[".id"] = "*B"
					schedules = append(schedules, body)
					writes++
					if mode == "lost-ack" {
						http.Error(w, "reply lost", 502)
						return
					}
					_ = json.NewEncoder(w).Encode(body)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.Error(w, "unexpected", 400)
				}
			}))
			defer api.Close()
			pool := x509.NewCertPool()
			pool.AddCert(api.Certificate())
			client, err := NewClient(Options{BaseURL: api.URL, Username: "test", Password: "test", RootCAs: pool})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			scheduled, err := client.ReconcileContainerStartup(context.Background())
			switch mode {
			case "current", "current-clock", "disabled-current":
				if err != nil || scheduled || writes != 0 {
					t.Fatalf("unchanged: %t %d %v", scheduled, writes, err)
				}
			case "legacy", "lost-ack":
				if writes != 2 || (mode == "legacy" && (err != nil || !scheduled)) || (mode == "lost-ack" && err == nil) {
					t.Fatalf("schedule: %t %d %v", scheduled, writes, err)
				}
				if pending, err := client.StartupMigrationPending(context.Background()); err != nil || !pending {
					t.Fatalf("pending=%t err=%v", pending, err)
				}
				if scheduled, err := client.ReconcileContainerStartup(context.Background()); err != nil || scheduled || writes != 2 {
					t.Fatalf("duplicate schedule: %t %d %v", scheduled, writes, err)
				}
			case "bad-readback":
				if err == nil || writes != 1 {
					t.Fatalf("readback must not arm: %d %v", writes, err)
				}
			default:
				if err == nil || writes != 0 {
					t.Fatalf("unsafe migration: %d %v", writes, err)
				}
			}
		})
	}
}

func TestStartupMigrationWorkerOrdersRecoveryBeforeNativeFlag(t *testing.T) {
	worker := renderContainerStartupMigration("usb1/sb-gateway/root-1.6.49")
	if !validFixedManagedScript(containerStartupWorker, worker) {
		t.Fatal("worker must be permitted")
	}
	last := -1
	for _, step := range []string{"[$ready $target] != true", "$setup false", "/system/scheduler/enable $boot", "/system/scheduler/remove $once\n", "/ip/firewall/mangle/disable $gate", "/container/stop $target", "stop deadline expired", "/container/set $target start-on-boot=no", "/system/script/run SB-GATEWAY-container-startup\n"} {
		at := strings.Index(worker, step)
		if at <= last {
			t.Fatalf("out of order: %s", step)
		}
		last = at
	}
	for _, guard := range []string{"root changed", "running] != true", "SB-GATEWAY-image-update-transfer", "SB-GATEWAY-container-memory-once", "^SB-GATEWAY-(apply|rollback)-", "boot policy readback failed", ":local migrate do={", ":local result [$migrate]"} {
		if !strings.Contains(worker, guard) {
			t.Fatalf("missing guard: %s", guard)
		}
	}
	for _, forbidden := range []string{"memory-high=", "memory-max=", "restart-policy=", "/file/remove", "/file/add"} {
		if strings.Contains(worker, forbidden) {
			t.Fatalf("migration changes unrelated state: %s", forbidden)
		}
	}
}

// All names are redirected before emitting a fixture for an isolated CHR container.
func TestEmitStartupMigrationCHRProbe(t *testing.T) {
	path := os.Getenv("SB_STARTUP_CHR_OUTPUT")
	if path == "" {
		t.Skip("CHR fixture output not requested")
	}
	worker := renderContainerStartupMigration("pcie1/sb-gateway-boot-probe")
	worker = strings.NewReplacer(
		containerStartupWorker, "SB-GATEWAY-probe-migrate", containerStartupOnce, "SB-GATEWAY-probe-once",
		"SB-GATEWAY-container-startup", "SB-GATEWAY-probe-startup", "SB-GATEWAY-storage-ready", "SB-GATEWAY-probe-ready",
		"SB-GATEWAY container", "SB-GATEWAY-boot-probe", "SB-GATEWAY-health-watchdog", "SB-GATEWAY-probe-watchdog",
		"SB-GATEWAY health scheduler", "SB-GATEWAY-probe watchdog", "SB-GATEWAY diversion-gate", "SB-GATEWAY-probe gate",
	).Replace(worker)
	source := `/system/script/add name="SB-GATEWAY-probe-migrate" comment="SB-GATEWAY managed script SB-GATEWAY-probe-migrate" policy=read,write,test,policy source={` + "\n" + worker + "\n}\n" +
		`/system/scheduler/add name="SB-GATEWAY-probe-once" interval=10s disabled=yes on-event="/system/script/run SB-GATEWAY-probe-migrate" policy=read,write,test,policy comment="SB-GATEWAY one-shot startup migration"` + "\n"
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}
