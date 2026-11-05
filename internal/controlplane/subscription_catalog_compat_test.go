package controlplane

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogCompatibilityRealBootstrapBindsProducerBeforeCommit(t *testing.T) {
	server := newTestServer(t)
	server.opts.Runtime.XrayConfig = filepath.Join(t.TempDir(), "absent-xray.json")
	server.opts.Runtime.XrayHealthPool = filepath.Join(t.TempDir(), "absent-pool.json")
	var marker map[string]any
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var result any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
			result = []any{map[string]any{".id": "*1", "root-dir": "/disk/sb-gateway/root-current", "comment": "SB-GATEWAY container", "interface": "live", "envlist": []string{"env"}, "mountlists": []string{"live"}, "stopped": false}}
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container/mounts":
			var rows []any
			for _, dst := range []string{"/config", "/data", "/logs", "/state"} {
				rows = append(rows, map[string]any{"list": "live", "src": "/disk/sb-gateway" + dst, "dst": dst, "comment": "SB-GATEWAY storage"})
			}
			result = rows
		case r.Method == http.MethodGet && (r.URL.Path == "/rest/system/scheduler" || r.URL.Path == "/rest/system/script/job"):
			result = []any{}
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
			if marker == nil {
				result = []any{}
			} else {
				result = []any{marker}
			}
		case r.Method == http.MethodPut && r.URL.Path == "/rest/system/script":
			json.NewDecoder(r.Body).Decode(&marker)
			marker[".id"] = "*90"
			result = marker
		case r.Method == http.MethodPatch && r.URL.Path == "/rest/system/script/*90":
			json.NewDecoder(r.Body).Decode(&marker)
			marker[".id"] = "*90"
			result = marker
		default:
			w.WriteHeader(http.StatusNotFound)
			result = map[string]any{"error": "synthetic unknown endpoint"}
		}
		json.NewEncoder(w).Encode(result)
	}))
	defer remote.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw})
	for reference, value := range map[string]string{"routeros/username": "synthetic", "routeros/password": "synthetic", "routeros/ca.pem": string(certificate)} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	config := map[string]any{"storage": map[string]any{"root": "disk/sb-gateway"}, "routeros": map[string]any{"base_url": remote.URL, "username_secret_ref": "routeros/username", "password_secret_ref": "routeros/password", "ca_certificate_secret_ref": "routeros/ca.pem"}}
	if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if marker != nil {
		t.Fatal("draft-only bootstrap unexpectedly mutated RouterOS")
	}
	if err := server.prepareSubscriptionCatalogRuntimeCompatibility(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	receipt, _ := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	producer, _ := receipt["producer"].(map[string]any)
	if receipt["state"] != "prepared" || producer["root"] != "disk/sb-gateway/root-current" || marker == nil {
		t.Fatal("physical producer missing before active commit")
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "synthetic", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	if err := server.prepareSubscriptionCatalogRuntimeCompatibility(context.Background(), config); err != nil {
		t.Fatal("repeat committed no-previous proof rejected")
	}
	before, _ := json.Marshal(marker)
	if err := server.validateSubscriptionCatalogRuntimeCompatibility(context.Background(), config); err != nil {
		t.Fatal("committed bootstrap cannot reconstruct runtime")
	}
	after, _ := json.Marshal(marker)
	if string(before) != string(after) {
		t.Fatal("read-only runtime validation mutated image proof")
	}
}

func syntheticCompatRoots(t *testing.T) catalogCompatRoots {
	t.Helper()
	base := t.TempDir()
	roots := catalogCompatRoots{Config: filepath.Join(base, "config"), State: filepath.Join(base, "state"), Data: filepath.Join(base, "data")}
	for _, area := range roots.areas() {
		if err := os.Mkdir(area.path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return roots
}

func writeCompatFixture(t *testing.T, root, path string, data []byte) {
	t.Helper()
	name := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogCompatibilitySnapshotPreservesFullLegacyBaseline(t *testing.T) {
	roots := syntheticCompatRoots(t)
	id := strings.Repeat("a", 64)
	rows := make([]map[string]any, 1205)
	for i := range rows {
		rows[i] = map[string]any{"id": i, "transport": "ws"}
	}
	body, _ := json.Marshal(map[string]any{"source": map[string]any{"nodes": rows}})
	writeCompatFixture(t, roots.State, "control-plane/subscription-nodes.json", body)
	writeCompatFixture(t, roots.State, "control-plane/active.json", []byte(`{"revision":"legacy"}`))
	writeCompatFixture(t, roots.Config, "generated/urltest-pool.json", []byte(`{"version":4,"outbounds":{"node":{"protocol":"vless"}}}`))
	writeCompatFixture(t, roots.Config, "secrets/private-test", []byte("synthetic-private-value"))
	writeCompatFixture(t, roots.Data, "last-known-good/runtime.json", []byte(`{"revision":"legacy"}`))
	writeCompatFixture(t, roots.Config, "secrets/subscription-catalogs/ignored/records.bin", []byte("new-format-excluded"))
	writeCompatFixture(t, roots.Data, "lifecycle-uploads/ignored.tar", []byte("image-excluded"))
	files, err := buildCatalogCompatSnapshot(context.Background(), roots, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 5 {
		t.Fatalf("incomplete or recursive snapshot: %d", len(files))
	}
	saved, err := os.ReadFile(filepath.Join(roots.State, catalogCompatDirectory, id, "state/control-plane/subscription-nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if json.Unmarshal(saved, &decoded) != nil {
		t.Fatal("invalid saved baseline")
	}
	source := decoded["source"].(map[string]any)
	if len(source["nodes"].([]any)) != 1205 {
		t.Fatal("legacy inventory was projected/truncated")
	}
	if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, true); err != nil {
		t.Fatal(err)
	}
	writeCompatFixture(t, roots.State, "control-plane/subscription-nodes.json", []byte(`{"changed":true}`))
	if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, true); err == nil {
		t.Fatal("changed source epoch accepted")
	}
	if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, false); err != nil {
		t.Fatal("immutable original baseline lost")
	}
	if _, err := buildCatalogCompatSnapshot(context.Background(), roots, id); err == nil {
		t.Fatal("frozen baseline overwritten")
	}
}

func TestCatalogCompatibilitySnapshotRejectsUnsafeAndInterruptedInputs(t *testing.T) {
	for _, scenario := range []string{"cancel", "symlink", "oversized", "corrupt"} {
		t.Run(scenario, func(t *testing.T) {
			roots := syntheticCompatRoots(t)
			id := strings.Repeat("b", 64)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writeCompatFixture(t, roots.State, "baseline.json", []byte(`{"revision":"legacy"}`))
			switch scenario {
			case "cancel":
				cancel()
			case "symlink":
				if err := os.Symlink(filepath.Join(roots.State, "baseline.json"), filepath.Join(roots.Config, "unsafe")); err != nil {
					t.Skip("symlinks unavailable")
				}
			case "oversized":
				file, err := os.Create(filepath.Join(roots.Config, "oversized"))
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(catalogCompatMaxFileBytes + 1)
				file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			files, err := buildCatalogCompatSnapshot(ctx, roots, id)
			if scenario != "corrupt" {
				if err == nil {
					t.Fatal("unsafe snapshot accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			writeCompatFixture(t, roots.State, filepath.Join(catalogCompatDirectory, id, "state/baseline.json"), []byte(`{"revision":"broken"}`))
			if err := validateCatalogCompatSnapshot(ctx, roots, id, files, false); err == nil {
				t.Fatal("corrupt baseline accepted")
			}
		})
	}
}

func TestCatalogCompatibilityIncompleteOwnedStageCanRetry(t *testing.T) {
	roots := syntheticCompatRoots(t)
	id := strings.Repeat("c", 64)
	writeCompatFixture(t, roots.Config, "baseline.json", []byte(`{"legacy":true}`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := buildCatalogCompatSnapshot(ctx, roots, id); err == nil {
		t.Fatal("canceled copy accepted")
	}
	// The controller must additionally obtain AssertCatalogImageHandoffUnused
	// and match source epoch before invoking this scoped filesystem operation.
	if err := removeIncompleteCatalogCompatSnapshot(context.Background(), roots, id); err != nil {
		t.Fatal(err)
	}
	files, err := buildCatalogCompatSnapshot(context.Background(), roots, id)
	if err != nil {
		t.Fatal("ordinary pre-attach failure cannot retry")
	}
	if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, true); err != nil {
		t.Fatal(err)
	}
	if _, err := buildCatalogCompatSnapshot(context.Background(), roots, id); err == nil {
		t.Fatal("immutable completed copy overwritten")
	}
}

func TestCatalogCompatibilityStageRemovalRejectsUnownedOrRedirectedTree(t *testing.T) {
	for _, scenario := range []string{"unmarked-payload", "wrong-owner", "symlink", "foreign-top-level"} {
		t.Run(scenario, func(t *testing.T) {
			roots := syntheticCompatRoots(t)
			id := strings.Repeat("d", 64)
			base := filepath.Join(roots.Config, catalogCompatDirectory, id)
			if err := os.MkdirAll(filepath.Join(base, "config"), 0700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(t.TempDir(), "keep")
			if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			marker, _ := json.Marshal(map[string]any{"format_version": 1, "identifier": id, "area": "config"})
			if scenario != "unmarked-payload" {
				if scenario == "wrong-owner" {
					marker = []byte(`{"format_version":1,"identifier":"different","area":"config"}`)
				}
				if err := os.WriteFile(filepath.Join(base, ".owner.json"), marker, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "unmarked-payload":
				os.WriteFile(filepath.Join(base, "config", "partial"), []byte("partial"), 0600)
			case "symlink":
				if err := os.Symlink(sentinel, filepath.Join(base, "config", "redirect")); err != nil {
					t.Skip("symlink fixture unavailable")
				}
			case "foreign-top-level":
				os.WriteFile(filepath.Join(base, "unexpected"), []byte("keep"), 0600)
			}
			if err := removeIncompleteCatalogCompatSnapshot(context.Background(), roots, id); err == nil {
				t.Fatal("unproven stage removed")
			}
			if _, err := os.Stat(base); err != nil {
				t.Fatal("rejected stage was removed")
			}
			if body, err := os.ReadFile(sentinel); err != nil || string(body) != "keep" {
				t.Fatal("external file changed")
			}
		})
	}
}

func TestCatalogCompatibilityNoActiveReceiptRequiresNoPriorRuntime(t *testing.T) {
	server := newTestServer(t)
	server.opts.Runtime.XrayConfig = filepath.Join(t.TempDir(), "absent-xray.json")
	server.opts.Runtime.XrayHealthPool = filepath.Join(t.TempDir(), "absent-pool.json")
	if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), map[string]any{}); err != nil {
		t.Fatal(err)
	}
	receipt, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	if err != nil || receipt["state"] != "prepared" || receipt["kind"] != "no-active-revision" {
		t.Fatalf("missing explicit receipt: %v", err)
	}
	if _, ok := receipt["catalog_refs"].([]any); !ok {
		t.Fatal("legacy receipt lacks explicit ref array")
	}
	if err := server.validateSubscriptionCatalogRuntimeCompatibility(context.Background(), map[string]any{}); err != nil {
		t.Fatal("empty bootstrap proof rejected")
	}
	if err := os.WriteFile(server.opts.Runtime.XrayConfig, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), map[string]any{}); err == nil {
		t.Fatal("prior runtime bypassed compatibility proof")
	}
}
