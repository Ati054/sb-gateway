package controlplane

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/applyguard"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestNativeNginxPublicationKeepsHealthyForwarding(t *testing.T) {
	for _, test := range []struct {
		name      string
		artifacts []string
		condition string
		wantReady bool
	}{
		{"graceful reload", []string{"nginx.conf"}, "fresh", true},
		{"expired proof", []string{"nginx.conf"}, "expired", false},
		{"unwritable state", []string{"nginx.conf"}, "unwritable", false},
		{"changed RouterOS", []string{"nginx.conf"}, "routeros", false},
		{"core restart", []string{"xray.json"}, "fresh", false},
		{"mixed core restart", []string{"nginx.conf", "xray.json"}, "fresh", false},
		{"DNS companion", []string{"nginx.conf", "policy-dns.json"}, "fresh", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t)
			config := routerOSReadyConfig(t)
			config["local_clients"] = []any{}
			revision, err := server.repository.stageGeneration(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test"}); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			marker := filepath.Join(root, "router-ready")
			guard := filepath.Join(root, "apply-in-progress")
			t.Setenv("SB_ROUTER_READY_MARKER", marker)
			leaseTime := server.now()
			if test.condition == "expired" {
				leaseTime = leaseTime.Add(-time.Hour)
			}
			if err := os.WriteFile(marker, []byte(strconv.FormatInt(leaseTime.Unix(), 10)), 0600); err != nil {
				t.Fatal(err)
			}
			server.checkPersistentMounts = func() (bool, []string) { return test.condition != "unwritable", nil }
			operation := map[string]any{"pending": true, "state": "prepared",
				"previous_routeros_source": "same", "target_routeros_source": "same"}
			if test.condition == "routeros" {
				operation["target_routeros_source"] = "different"
			}
			if err := server.repository.saveAuxiliary("apply-operation", operation); err != nil {
				t.Fatal(err)
			}
			server.plannedUnchangedApply.Store(true)
			destinations := map[string]string{}
			bodies := map[string][]byte{}
			for _, name := range test.artifacts {
				destinations[name] = filepath.Join(root, name)
				if err := os.WriteFile(destinations[name], []byte("old\n"), 0600); err != nil {
					t.Fatal(err)
				}
				bodies[name] = []byte("new\n")
			}
			store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "runtime"), destinations)
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := store.Prepare(strings.Repeat("7", 64), bodies)
			if err != nil {
				t.Fatal(err)
			}
			observed := 0
			controller := &recordingRuntimeController{observe: func() {
				observed++
				// The independent readiness publisher withdraws its lease while
				// a guarded dataplane restart is in progress.
				if applyguard.Active(guard, server.now()) {
					if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
						t.Fatal(err)
					}
				}
				response := performRequest(t, server, http.MethodGet, "/api/health/traffic-ready", nil, nil)
				want := http.StatusServiceUnavailable
				if test.wantReady {
					want = http.StatusOK
				}
				if response.Code != want {
					t.Fatalf("forwarding health during publication: %d, want %d: %s", response.Code, want, response.Body.String())
				}
			}}
			runtime := &nativeRuntime{store: store, controller: controller, options: RuntimeOptions{ApplyGuardFile: guard},
				validate: func(context.Context, runtimeconfig.RuntimeCandidate, []string) error { return nil }}
			if _, err := runtime.activateWithHooks(context.Background(), candidate, nil, nil, server.prepareNativePublication); err != nil {
				t.Fatal(err)
			}
			if observed == 0 {
				t.Fatal("reload readiness was not checked")
			}
			stored, err := server.repository.auxiliary("apply-operation")
			if err != nil || stored["pending"] != true || stored["state"] != "prepared" {
				t.Fatalf("health observation erased the recovery journal: %#v %v", stored, err)
			}
		})
	}
}
