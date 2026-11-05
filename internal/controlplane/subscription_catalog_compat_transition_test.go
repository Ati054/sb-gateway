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

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

// Authenticated REST with an actual stopped predecessor, not a bypass of the
// physical image/mount proof. The handler is configured before any requests.
func catalogCompatTransitionFixture(t *testing.T, server *Server, config map[string]any, blocked string, oldID string) *routeros.Client {
	t.Helper()
	// Match production's separate mounted roots, rather than placing state/data
	// below the config root of the general API test-server constructor.
	server.opts.SecretsDir = filepath.Join(t.TempDir(), "config", "secrets")
	secrets, err := newSecretStore(server.opts.SecretsDir)
	if err != nil {
		t.Fatal(err)
	}
	server.secrets = secrets
	root := "disk/sb-gateway"
	containers := []map[string]any{
		{".id": "*15", "root-dir": "/" + root + "/root-new", "comment": "SB-GATEWAY container", "interface": "live", "envlists": "env", "mountlists": "live"},
		{".id": "*14", "root-dir": "/" + root + "/root-old", "comment": "SB-GATEWAY container previous", "interface": "hold", "envlists": "env", "mountlists": "", "stopped": "true"},
	}
	if blocked == "no-previous" {
		containers = containers[:1]
	}
	var mounts []map[string]any
	for _, dst := range []string{"/config", "/data", "/logs", "/state"} {
		mounts = append(mounts, map[string]any{"list": "live", "src": "/" + root + dst, "dst": dst, "comment": "SB-GATEWAY storage"})
	}
	var marker map[string]any
	if blocked == "contract" {
		body, _ := json.Marshal(routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: root + "/root-new", CatalogSchema: 1, PreviousRoot: root + "/root-older", Mountlist: "sb-catalog-compat-" + oldID[:16], Handoff: oldID, MountSources: [4]string{root + "/config/.catalog-compat/" + oldID + "/config", root + "/data/.catalog-compat/" + oldID + "/data", root + "/logs", root + "/state/.catalog-compat/" + oldID + "/state"}})
		marker = map[string]any{".id": "*90", "name": routeros.CatalogImageContractName, "comment": "SB-GATEWAY catalog data compatibility", "source": string(body)}
	}
	if blocked == "mount" {
		mounts = append(mounts, map[string]any{"list": "sb-catalog-compat-" + oldID[:16], "src": "/" + root + "/config/.catalog-compat/" + oldID + "/config", "dst": "/config"})
	}
	if blocked == "container" {
		containers = append(containers, map[string]any{".id": "*99", "comment": "unrelated", "mountlists": "sb-catalog-compat-" + oldID[:16]})
	}
	if blocked == "malformed-container" {
		containers = append(containers, map[string]any{".id": "*99", "comment": "unrelated", "mountlists": map[string]any{"unknown": true}})
	}
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var result any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
			result = containers
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container/mounts":
			result = mounts
		case r.Method == http.MethodGet && (r.URL.Path == "/rest/system/scheduler" || r.URL.Path == "/rest/system/script/job"):
			result = []any{}
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
			result = []any{}
			if marker != nil && r.URL.Query().Get("name") == routeros.CatalogImageContractName {
				result = []any{marker}
			}
		case r.Method == http.MethodPut && r.URL.Path == "/rest/container/mounts":
			var row map[string]any
			json.NewDecoder(r.Body).Decode(&row)
			mounts = append(mounts, row)
			result = row
		case r.Method == http.MethodPatch && r.URL.Path == "/rest/container/*14":
			var row map[string]any
			json.NewDecoder(r.Body).Decode(&row)
			containers[1]["mountlists"] = row["mountlists"]
			result = containers[1]
		case (r.Method == http.MethodPut && r.URL.Path == "/rest/system/script") || (r.Method == http.MethodPatch && r.URL.Path == "/rest/system/script/*90"):
			json.NewDecoder(r.Body).Decode(&marker)
			marker[".id"] = "*90"
			result = marker
		default:
			w.WriteHeader(http.StatusNotFound)
			result = map[string]any{"error": "synthetic unknown request"}
		}
		json.NewEncoder(w).Encode(result)
	}))
	t.Cleanup(remote.Close)
	fixture := &catalogCompatTestREST{root: root, url: remote.URL, certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw}))}
	bindCatalogCompatibilityRESTFixture(t, server, config, fixture)
	writeCompatFixture(t, server.opts.DataDir, "compat-live/urltest-pool.json", []byte(`{"version":4}`))
	client, _, err := server.newRouterOSRESTClient(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestCatalogCompatibilityResumesNoPreviousPreparationAndRejectsUnknownKind(t *testing.T) {
	for _, kind := range []string{"no-previous", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			server := newTestServer(t)
			config := routerOSReadyConfig(t)
			catalogCompatTransitionFixture(t, server, config, "no-previous", strings.Repeat("b", 64))
			revision, err := server.repository.stageGeneration(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "synthetic", CommittedAt: server.now()}); err != nil {
				t.Fatal(err)
			}
			old := catalogCompatibilityDescriptor{FormatVersion: 1, State: "preparing", Kind: kind, ProducerCatalogSchema: 1, CatalogRefs: []subscriptioncatalog.Ref{}}
			if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
				t.Fatal(err)
			}
			err = server.ensureSubscriptionCatalogCompatibility(context.Background(), config)
			if kind == "unknown" {
				if err == nil {
					t.Fatal("unknown preparing kind accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("marker-only preparation cannot resume:", err)
			}
			value, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
			if err != nil || value["state"] != "prepared" || value["kind"] != "no-previous" {
				t.Fatal("marker-only preparation not completed")
			}
		})
	}
}

func seedInterruptedCatalogCompatibility(t *testing.T, server *Server) catalogCompatibilityDescriptor {
	t.Helper()
	oldID := strings.Repeat("b", 64)
	roots := server.catalogCompatibilityRoots()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = buildCatalogCompatSnapshot(ctx, roots, oldID)
	old := catalogCompatibilityDescriptor{FormatVersion: 1, State: "preparing", Kind: "legacy-snapshot", Identifier: oldID, SourceEpoch: strings.Repeat("c", 64), CurrentFingerprint: strings.Repeat("d", 64), ProducerCatalogSchema: 1, CatalogRefs: []subscriptioncatalog.Ref{}, Producer: routeros.CatalogImageContainer{ID: "*14", Root: "disk/sb-gateway/root-old"}, Previous: &routeros.CatalogImageContainer{ID: "*13", Root: "disk/sb-gateway/root-older", Stopped: true}}
	if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
		t.Fatal(err)
	}
	return old
}

func TestCatalogCompatibilityInterruptedCopySurvivesProducerAndEpochChange(t *testing.T) {
	for _, scenario := range []string{"producer-change", "epoch-only"} {
		t.Run(scenario, func(t *testing.T) {
			server := newTestServer(t)
			config := routerOSReadyConfig(t)
			client := catalogCompatTransitionFixture(t, server, config, "", strings.Repeat("b", 64))
			revision, err := server.repository.stageGeneration(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "synthetic", CommittedAt: server.now()}); err != nil {
				t.Fatal(err)
			}
			writeCompatFixture(t, filepath.Dir(server.opts.SecretsDir), "generated/xray.json", []byte(`{"legacy":true}`))
			old := seedInterruptedCatalogCompatibility(t, server)
			if scenario == "epoch-only" {
				inventory, err := client.InspectCatalogImageCompatibility(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				old.Producer = inventory.Current
				old.Previous = inventory.Previous
				old.CurrentFingerprint = inventory.Fingerprint
				if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), config); err != nil {
				t.Fatal("new producer could not recover unused incomplete stage:", err)
			}
			value, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
			if err != nil {
				t.Fatal(err)
			}
			var prepared catalogCompatibilityDescriptor
			body, _ := json.Marshal(value)
			if json.Unmarshal(body, &prepared) != nil {
				t.Fatal("invalid new descriptor")
			}
			if prepared.State != "prepared" || prepared.Producer.ID != "*15" || prepared.Previous == nil || prepared.Previous.ID != "*14" || prepared.Identifier == old.Identifier || prepared.SourceEpoch == old.SourceEpoch || len(prepared.Files) == 0 {
				t.Fatal("old stage reused or new proof incomplete")
			}
			for _, area := range server.catalogCompatibilityRoots().areas() {
				if _, err := os.Lstat(filepath.Join(area.path, catalogCompatDirectory, old.Identifier)); !os.IsNotExist(err) {
					t.Fatal("retired incomplete stage remains")
				}
			}
		})
	}
}

func TestCatalogCompatibilityInterruptedRetirementRequiresUnusedOwnedStage(t *testing.T) {
	for _, block := range []string{"contract", "mount", "container", "malformed-container", "unknown-owner", "recorded-files", "attached-journal"} {
		t.Run(block, func(t *testing.T) {
			server := newTestServer(t)
			config := routerOSReadyConfig(t)
			client := catalogCompatTransitionFixture(t, server, config, block, strings.Repeat("b", 64))
			old := seedInterruptedCatalogCompatibility(t, server)
			if block == "unknown-owner" {
				writeCompatFixture(t, server.catalogCompatibilityRoots().Config, filepath.Join(catalogCompatDirectory, old.Identifier, ".owner.json"), []byte(`{"format_version":1,"identifier":"unowned","area":"config"}`))
			}
			if block == "recorded-files" {
				old.Files = []catalogCompatFile{{Area: "config", Path: "baseline.json", SHA256: strings.Repeat("e", 64)}}
			}
			if block == "attached-journal" {
				old.Mountlist = "sb-catalog-compat-" + old.Identifier[:16]
			}
			inventory, err := client.InspectCatalogImageCompatibility(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			epoch, err := server.catalogCompatibilityEpoch()
			if err != nil {
				t.Fatal(err)
			}
			if err := server.retireIncompleteCatalogCompatSnapshot(context.Background(), client, inventory, epoch, old); err == nil {
				t.Fatal("unsafe stage retirement accepted")
			}
			if _, err := os.Stat(filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, old.Identifier)); err != nil {
				t.Fatal("vetoed stage removed")
			}
		})
	}
}
