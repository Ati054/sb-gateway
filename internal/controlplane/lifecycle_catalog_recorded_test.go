package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

type recordedCatalogREST struct {
	mu         sync.Mutex
	containers []map[string]any
	mounts     []map[string]any
	marker     map[string]any
	writes     int
}

func (fixture *recordedCatalogREST) serve(w http.ResponseWriter, r *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	username, password, ok := r.BasicAuth()
	if !ok || username != "synthetic" || password != "synthetic" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var result any
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
		result = fixture.containers
	case r.Method == http.MethodGet && r.URL.Path == "/rest/container/mounts":
		result = fixture.mounts
	case r.Method == http.MethodGet && (r.URL.Path == "/rest/system/scheduler" || r.URL.Path == "/rest/system/script/job"):
		result = []any{}
	case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
		result = []any{}
		if fixture.marker != nil && r.URL.Query().Get("name") == routeros.CatalogImageContractName {
			result = []any{fixture.marker}
		}
	case r.Method == http.MethodPut && r.URL.Path == "/rest/container/mounts":
		var row map[string]any
		if json.NewDecoder(r.Body).Decode(&row) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fixture.writes++
		fixture.mounts = append(fixture.mounts, row)
		result = row
	case r.Method == http.MethodPatch && r.URL.Path == "/rest/container/*14":
		var row map[string]any
		if json.NewDecoder(r.Body).Decode(&row) != nil || len(row) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// A REST write must use the scalar list spelling. Read-side list
		// normalization does not prove that an array write is effective.
		if _, ok := row["mountlists"].(string); !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lists, err := recordedCatalogMountlists(row["mountlists"])
		if err != nil || len(lists) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fixture.writes++
		fixture.containers[1]["mountlists"] = row["mountlists"]
		result = fixture.containers[1]
	case (r.Method == http.MethodPut && r.URL.Path == "/rest/system/script") || (r.Method == http.MethodPatch && r.URL.Path == "/rest/system/script/*90"):
		if json.NewDecoder(r.Body).Decode(&fixture.marker) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fixture.writes++
		fixture.marker[".id"] = "*90"
		result = fixture.marker
	default:
		w.WriteHeader(http.StatusNotFound)
		result = map[string]any{"error": "synthetic unexpected request"}
	}
	json.NewEncoder(w).Encode(result)
}

func recordedCatalogLifecycleFixture(t *testing.T, rowCount int, attached bool) (*Server, map[string]any, catalogCompatibilityDescriptor, *recordedCatalogREST) {
	t.Helper()
	server := newTestServer(t)
	server.opts.SecretsDir = filepath.Join(t.TempDir(), "config", "secrets")
	var err error
	server.secrets, err = newSecretStore(server.opts.SecretsDir)
	if err != nil {
		t.Fatal(err)
	}
	config := routerOSReadyConfig(t)
	const root = "disk/sb-gateway"
	fixture := &recordedCatalogREST{containers: []map[string]any{
		{".id": "*15", "root-dir": "/" + root + "/root-new", "comment": "SB-GATEWAY container", "interface": "live", "envlists": "env", "mountlists": "live"},
		{".id": "*14", "root-dir": "/" + root + "/root-old", "comment": "SB-GATEWAY container previous", "interface": "hold", "envlists": "env", "mountlists": "", "stopped": "true"},
	}}
	for _, dst := range []string{"/config", "/data", "/logs", "/state"} {
		fixture.mounts = append(fixture.mounts, map[string]any{"list": "live", "src": "/" + root + dst, "dst": dst, "comment": "SB-GATEWAY storage"})
	}
	remote := httptest.NewTLSServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(remote.Close)
	bindCatalogCompatibilityRESTFixture(t, server, config, &catalogCompatTestREST{root: root, url: remote.URL, certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw}))})
	writeCompatFixture(t, server.opts.DataDir, "compat-live/urltest-pool.json", []byte(`{"version":4}`))
	if err := server.secrets.write("management-api-token", "management-test-token", false); err != nil {
		t.Fatal(err)
	}
	_, _ = bootstrapSession(t, server)
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "synthetic", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	writeCompatFixture(t, filepath.Dir(server.opts.SecretsDir), "generated/legacy.json", []byte(`{"legacy":true}`))
	client, _, err := server.newRouterOSRESTClient(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	inventory, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := server.catalogCompatibilityEpoch()
	if err != nil {
		t.Fatal(err)
	}
	previous := *inventory.Previous
	previous.Mountlists = nil
	seed, _ := canonicalJSON(map[string]any{"epoch": epoch, "current": inventory.Current, "previous": previous})
	sum := sha256.Sum256(seed)
	old := catalogCompatibilityDescriptor{FormatVersion: 1, State: "preparing", Kind: "legacy-snapshot", Identifier: hex.EncodeToString(sum[:]), SourceEpoch: epoch, Producer: inventory.Current, Previous: inventory.Previous, CurrentFingerprint: inventory.Fingerprint, ProducerCatalogSchema: 1, CatalogRefs: []subscriptioncatalog.Ref{}}
	if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
		t.Fatal(err)
	}
	old.Files, err = buildCatalogCompatSnapshot(context.Background(), server.catalogCompatibilityRoots(), old.Identifier)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
		t.Fatal(err)
	}
	list := "sb-catalog-compat-" + old.Identifier[:16]
	fixture.mu.Lock()
	for _, mount := range catalogCompatibilityMounts(inventory, old.Identifier)[:rowCount] {
		fixture.mounts = append(fixture.mounts, map[string]any{"list": list, "src": "/" + mount.Source, "dst": mount.Destination, "comment": "SB-GATEWAY catalog data compatibility " + old.Identifier, "disabled": false})
	}
	if attached {
		fixture.containers[1]["mountlists"] = list
	}
	fixture.mu.Unlock()
	return server, config, old, fixture
}

func TestLifecycleResumesRecordedCatalogBaselineWithoutRebuild(t *testing.T) {
	for _, scenario := range []struct {
		name               string
		rows               int
		attached, contract bool
	}{
		{"no-mounts", 0, false, false}, {"partial-mounts", 2, false, false}, {"all-mounts", 4, false, false}, {"already-attached", 4, true, false}, {"contract-published", 4, true, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server, config, old, fixture := recordedCatalogLifecycleFixture(t, scenario.rows, scenario.attached)
			if scenario.contract {
				setRecordedCatalogContract(t, fixture, old, false)
			}
			stage := filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, old.Identifier)
			before, err := os.Stat(stage)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.subscriptionCatalogReferences(context.Background()); !errors.Is(err, errSubscriptionCatalogReferencesPending) {
				t.Fatal("ordinary graph permitted pending manifest")
			}
			if err := lifecyclePrepareCatalogAdmitted(server, config, 1); err != nil {
				t.Fatal("recorded resume failed:", err)
			}
			after, err := os.Stat(stage)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("recorded stage replaced")
			}
			value, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
			if err != nil {
				t.Fatal(err)
			}
			var prepared catalogCompatibilityDescriptor
			body, _ := json.Marshal(value)
			if json.Unmarshal(body, &prepared) != nil || prepared.State != "prepared" || prepared.Identifier != old.Identifier || !reflect.DeepEqual(prepared.Files, old.Files) {
				t.Fatal("recorded manifest rebuilt or not committed")
			}
			if _, err := server.subscriptionCatalogReferences(context.Background()); err != nil {
				t.Fatal("strict final scan failed:", err)
			}
			if err := validateCatalogCompatSnapshot(context.Background(), server.catalogCompatibilityRoots(), old.Identifier, old.Files, true); err != nil {
				t.Fatal(err)
			}
			fixture.mu.Lock()
			writes := fixture.writes
			fixture.mu.Unlock()
			wantedWrites := 4 - scenario.rows + 1
			if !scenario.attached {
				wantedWrites++
			}
			if scenario.contract {
				wantedWrites--
			}
			if writes != wantedWrites {
				t.Fatalf("unexpected handoff writes: got %d want %d", writes, wantedWrites)
			}
		})
	}
}

func setRecordedCatalogContract(t *testing.T, fixture *recordedCatalogREST, old catalogCompatibilityDescriptor, unknown bool) {
	t.Helper()
	inventory := routeros.CatalogImageInventory{Current: old.Producer, Previous: old.Previous}
	for _, dst := range []string{"/config", "/data", "/logs", "/state"} {
		inventory.Mounts = append(inventory.Mounts, routeros.CatalogImageMount{Source: "disk/sb-gateway" + dst, Destination: dst})
	}
	contract := routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: old.Producer.Root, CatalogSchema: 1, PreviousRoot: old.Previous.Root, Mountlist: "sb-catalog-compat-" + old.Identifier[:16], Handoff: old.Identifier}
	for i, mount := range catalogCompatibilityMounts(inventory, old.Identifier) {
		contract.MountSources[i] = mount.Source
	}
	body, _ := json.Marshal(contract)
	if unknown {
		var value map[string]any
		json.Unmarshal(body, &value)
		value["unknown_capability"] = true
		body, _ = json.Marshal(value)
	}
	fixture.mu.Lock()
	fixture.marker = map[string]any{".id": "*90", "name": routeros.CatalogImageContractName, "comment": "SB-GATEWAY catalog data compatibility", "source": string(body)}
	fixture.mu.Unlock()
}

func TestLifecycleRecordedCatalogResumeRejectsBeforeAnyMutation(t *testing.T) {
	for _, scenario := range []string{"manifest", "source", "copied-file", "epoch", "identifier", "fingerprint", "producer", "previous", "foreign-row", "extra-row", "duplicate-row", "disabled-row", "foreign-consumer", "foreign-alias", "malformed-source", "malformed-consumer", "foreign-contract", "unknown-contract", "unowned-stage", "actual-ref", "v5"} {
		t.Run(scenario, func(t *testing.T) {
			rows, attached := 2, false
			if scenario == "unknown-contract" {
				rows, attached = 4, true
			}
			server, config, old, fixture := recordedCatalogLifecycleFixture(t, rows, attached)
			stage := filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, old.Identifier)
			before, err := os.Stat(stage)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "manifest":
				old.Files[0].SHA256 = strings.Repeat("e", 64)
			case "source":
				writeCompatFixture(t, server.catalogCompatibilityRoots().Config, "generated/legacy.json", []byte(`{"legacy":false}`))
			case "copied-file":
				writeCompatFixture(t, server.catalogCompatibilityRoots().Config, filepath.Join(catalogCompatDirectory, old.Identifier, "config", "generated/legacy.json"), []byte(`{"legacy":false}`))
			case "epoch":
				old.SourceEpoch = strings.Repeat("e", 64)
			case "identifier":
				old.Identifier = strings.Repeat("e", 64)
			case "fingerprint":
				old.CurrentFingerprint = strings.Repeat("e", 64)
			case "producer":
				old.Producer.Interface = "changed"
			case "previous":
				old.Previous.Interface = "changed"
			case "unowned-stage":
				writeCompatFixture(t, server.catalogCompatibilityRoots().Config, filepath.Join(catalogCompatDirectory, old.Identifier, ".owner.json"), []byte(`{"format_version":1,"identifier":"unknown","area":"config"}`))
			case "actual-ref":
				ref := recoveryCatalogFixture(t, server, 1, 0)
				if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"feed": map[string]any{"catalog_ref": ref}}); err != nil {
					t.Fatal(err)
				}
			case "v5":
				if err := os.WriteFile(server.opts.Runtime.XrayHealthPool, []byte(`{"version":5}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-contract", "unknown-contract":
				setRecordedCatalogContract(t, fixture, old, scenario == "unknown-contract")
				if scenario == "foreign-contract" {
					fixture.mu.Lock()
					fixture.marker["source"] = `{"format_version":1,"state":"prepared","producer_root":"disk/sb-gateway/other","catalog_schema":1}`
					fixture.mu.Unlock()
				}
			default:
				fixture.mu.Lock()
				last := fixture.mounts[len(fixture.mounts)-1]
				switch scenario {
				case "foreign-row":
					last["comment"] = "unowned"
				case "extra-row":
					fixture.mounts = append(fixture.mounts, map[string]any{"list": last["list"], "src": last["src"], "dst": "/unexpected", "comment": last["comment"]})
				case "duplicate-row":
					duplicate := make(map[string]any)
					for k, v := range last {
						duplicate[k] = v
					}
					fixture.mounts = append(fixture.mounts, duplicate)
				case "disabled-row":
					last["disabled"] = true
				case "foreign-consumer":
					fixture.containers = append(fixture.containers, map[string]any{".id": "*99", "mountlists": last["list"]})
				case "foreign-alias":
					fixture.mounts = append(fixture.mounts, map[string]any{"list": "custom", "src": "/disk/sb-gateway/config/.catalog-compat/other/../" + old.Identifier + "/config", "dst": "/config"})
				case "malformed-source":
					fixture.mounts = append(fixture.mounts, map[string]any{"list": "custom", "src": false, "dst": "/config"})
				case "malformed-consumer":
					fixture.containers = append(fixture.containers, map[string]any{".id": "*99", "mountlists": false})
				}
				fixture.mu.Unlock()
			}
			value := catalogCompatJSON(old)
			if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, value); err != nil {
				t.Fatal(err)
			}
			if err := lifecyclePrepareCatalogAdmitted(server, config, 1); err == nil {
				t.Fatal("unsafe recorded preparation resumed")
			}
			fixture.mu.Lock()
			writes := fixture.writes
			fixture.mu.Unlock()
			if writes != 0 {
				t.Fatal("REST mutation preceded recorded validation")
			}
			after, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
			if err != nil || !equalJSONObject(value, after) {
				t.Fatal("veto rewrote pending journal")
			}
			stageAfter, err := os.Stat(stage)
			if err != nil || !os.SameFile(before, stageAfter) {
				t.Fatal("veto deleted or replaced recorded stage")
			}
		})
	}
}
