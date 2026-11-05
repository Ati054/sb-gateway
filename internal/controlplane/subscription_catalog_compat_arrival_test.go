package controlplane

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

type catalogArrivalREST struct {
	mu                   sync.Mutex
	marker, arrival      map[string]any
	containers, mounts   []map[string]any
	writes, arrivalReads int
}

func catalogArrivalRESTFixture(t *testing.T, server *Server, config map[string]any, pool int) (*catalogArrivalREST, routeros.CatalogImageInventory) {
	t.Helper()
	root := "disk/sb-gateway"
	f := &catalogArrivalREST{containers: []map[string]any{
		{".id": "*17", "root-dir": "/" + root + "/root-next", "comment": "SB-GATEWAY container", "interface": "live", "envlists": "env", "mountlists": "live", "stopped": false},
		{".id": "*14", "root-dir": "/" + root + "/root-prior", "comment": "SB-GATEWAY container previous", "interface": "hold", "envlists": "env", "mountlists": "", "stopped": true},
	}}
	for _, dst := range []string{"/config", "/data", "/logs", "/state"} {
		f.mounts = append(f.mounts, map[string]any{"list": "live", "src": "/" + root + dst, "dst": dst, "comment": "SB-GATEWAY storage"})
	}
	contract := routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: root + "/root-prior", CatalogSchema: 1, PreviousRoot: root + "/root-legacy", PreviousCatalogSchema: 0, Mountlist: "sb-catalog-compat-" + strings.Repeat("a", 16), Handoff: strings.Repeat("a", 64), MountSources: [4]string{root + "/config/.catalog-compat/" + strings.Repeat("a", 64) + "/config", root + "/data/.catalog-compat/" + strings.Repeat("a", 64) + "/data", root + "/logs", root + "/state/.catalog-compat/" + strings.Repeat("a", 64) + "/state"}}
	body, _ := json.Marshal(contract)
	f.marker = map[string]any{".id": "*90", "name": routeros.CatalogImageContractName, "comment": "SB-GATEWAY catalog data compatibility", "source": string(body)}
	body, _ = json.Marshal(map[string]any{"candidate-id": "*17", "candidate-root": "/" + root + "/root-next", "previous-id": "*14", "previous-root": "/" + root + "/root-prior", "catalog-schema": 1, "phase": "completed", "live-if": "live", "mountlists": []string{"live"}})
	f.arrival = map[string]any{".id": "*91", "name": routeros.CatalogImageArrivalName, "comment": "SB-GATEWAY catalog image arrival", "source": string(body)}
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var value any = []any{}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
			value = f.containers
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container/mounts":
			value = f.mounts
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
			switch r.URL.Query().Get("name") {
			case routeros.CatalogImageContractName:
				if f.marker != nil {
					value = []any{f.marker}
				}
			case routeros.CatalogImageArrivalName:
				f.arrivalReads++
				if f.arrival != nil {
					value = []any{f.arrival}
				}
			}
		case r.Method != http.MethodGet:
			f.writes++
			if r.URL.Path == "/rest/system/script" || r.URL.Path == "/rest/system/script/*90" {
				if json.NewDecoder(r.Body).Decode(&f.marker) != nil {
					w.WriteHeader(400)
					return
				}
				f.marker[".id"] = "*90"
				value = f.marker
			} else {
				w.WriteHeader(400)
				value = map[string]any{"error": "unexpected mutation"}
			}
		}
		_ = json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(remote.Close)
	bindCatalogCompatibilityRESTFixture(t, server, config, &catalogCompatTestREST{root: root, url: remote.URL, certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw}))})
	writeCompatFixture(t, server.opts.DataDir, "compat-live/urltest-pool.json", []byte(fmt.Sprintf(`{"version":%d}`, pool)))
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "synthetic", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	client, _, err := server.newRouterOSRESTClient(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	inventory, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return f, inventory
}

func seedArrivalPreparing(t *testing.T, server *Server, inventory routeros.CatalogImageInventory) catalogCompatibilityDescriptor {
	t.Helper()
	epoch, err := server.catalogCompatibilityEpoch()
	if err != nil {
		t.Fatal(err)
	}
	id := catalogCompatibilitySnapshotIdentifier(epoch, inventory.Current, *inventory.Previous)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = buildCatalogCompatSnapshot(ctx, server.catalogCompatibilityRoots(), id)
	old := catalogCompatibilityDescriptor{FormatVersion: 1, State: "preparing", Kind: "legacy-snapshot", Identifier: id, ProducerCatalogSchema: 1, Producer: inventory.Current, Previous: inventory.Previous, SourceEpoch: epoch, CurrentFingerprint: inventory.Fingerprint, CatalogRefs: []subscriptioncatalog.Ref{}}
	if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
		t.Fatal(err)
	}
	return old
}

func TestCatalogArrivalPoolFormatDoesNotDefineImageCapability(t *testing.T) {
	for _, pool := range []int{3, 4, 5} {
		for _, journal := range []string{"prepared-prior", "preparing-current", "promoted-marker"} {
			t.Run(fmt.Sprintf("%d/%s", pool, journal), func(t *testing.T) {
				server := newTestServer(t)
				config := routerOSReadyConfig(t)
				f, inventory := catalogArrivalRESTFixture(t, server, config, pool)
				preserved := filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, strings.Repeat("a", 64), "baseline-preserved")
				writeCompatFixture(t, filepath.Dir(preserved), filepath.Base(preserved), []byte("frozen legacy baseline"))
				var old catalogCompatibilityDescriptor
				if journal == "prepared-prior" {
					old = catalogCompatibilityDescriptor{FormatVersion: 1, State: "prepared", Kind: "no-previous", ProducerCatalogSchema: 1, Producer: *inventory.Previous, CurrentFingerprint: strings.Repeat("e", 64), CatalogRefs: []subscriptioncatalog.Ref{}}
					if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
						t.Fatal(err)
					}
				} else {
					old = seedArrivalPreparing(t, server, inventory)
				}
				if journal == "promoted-marker" {
					marker := routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: inventory.Current.Root, CatalogSchema: 1, PreviousRoot: inventory.Previous.Root, PreviousCatalogSchema: 1}
					body, _ := json.Marshal(marker)
					f.mu.Lock()
					f.marker["source"] = string(body)
					f.mu.Unlock()
				}
				if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), config); err != nil {
					t.Fatal(err)
				}
				value, _ := server.repository.auxiliary(catalogCompatibilityAuxiliary)
				var prepared catalogCompatibilityDescriptor
				body, _ := json.Marshal(value)
				if json.Unmarshal(body, &prepared) != nil || prepared.State != "prepared" || prepared.Kind != "catalog-capable" || prepared.Producer.Root != inventory.Current.Root || prepared.Previous == nil || prepared.Previous.Root != inventory.Previous.Root || len(prepared.Files) != 0 || prepared.Mountlist != "" {
					t.Fatal("arrival did not publish a truthful catalogue-capable descriptor")
				}
				if _, err := server.subscriptionCatalogReferences(context.Background()); err != nil {
					t.Fatal("normal graph remains stuck after preparation:", err)
				}
				if _, err := os.Stat(preserved); err != nil {
					t.Fatal("retained older baseline was removed")
				}
				if journal != "prepared-prior" {
					for _, area := range server.catalogCompatibilityRoots().areas() {
						if _, err := os.Stat(filepath.Join(area.path, catalogCompatDirectory, old.Identifier)); !os.IsNotExist(err) {
							t.Fatal("unreferenced incomplete copy was reused")
						}
					}
				}
				f.mu.Lock()
				reads, writes := f.arrivalReads, f.writes
				f.mu.Unlock()
				if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), config); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				changed := f.arrivalReads != reads || f.writes != writes
				f.mu.Unlock()
				if changed {
					t.Fatal("unchanged prepared descriptor repeated the expensive arrival proof")
				}
			})
		}
	}
}

func TestCatalogArrivalRejectsUnprovenOrRecordedTransitionsBeforeWrites(t *testing.T) {
	for _, scenario := range []string{"missing-arrival", "malformed-arrival", "recorded-files", "recorded-empty-files", "attached-journal", "global-reference", "unknown-v5", "wrong-id", "unknown-field", "no-catalog-refs"} {
		t.Run(scenario, func(t *testing.T) {
			server := newTestServer(t)
			config := routerOSReadyConfig(t)
			pool := 4
			if scenario == "unknown-v5" {
				pool = 5
			}
			f, inventory := catalogArrivalRESTFixture(t, server, config, pool)
			old := seedArrivalPreparing(t, server, inventory)
			originalStageID := old.Identifier
			value, _ := server.repository.auxiliary(catalogCompatibilityAuxiliary)
			f.mu.Lock()
			switch scenario {
			case "missing-arrival":
				f.arrival = nil
			case "malformed-arrival":
				f.arrival["source"] = `{"phase":"probation"}`
			case "recorded-files":
				old.Files = []catalogCompatFile{{Area: "config", Path: "recorded.json", SHA256: strings.Repeat("e", 64)}}
				value = catalogCompatJSON(old)
			case "recorded-empty-files":
				value["files"] = []any{}
			case "attached-journal":
				old.Mountlist = "sb-catalog-compat-" + old.Identifier[:16]
				value = catalogCompatJSON(old)
			case "global-reference":
				ref := recoveryCatalogFixture(t, server, 1, 0)
				body, _ := json.Marshal(ref)
				decoded, _ := decodeObject(body)
				if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"feed": map[string]any{"catalog_ref": decoded}}); err != nil {
					t.Fatal(err)
				}
				epoch, _ := server.catalogCompatibilityEpoch()
				old.SourceEpoch = epoch
				old.Identifier = catalogCompatibilitySnapshotIdentifier(epoch, inventory.Current, *inventory.Previous)
				value = catalogCompatJSON(old)
			case "unknown-v5":
				f.marker = nil
				f.arrival = nil
			case "wrong-id":
				old.Identifier = strings.Repeat("f", 64)
				value = catalogCompatJSON(old)
			case "unknown-field":
				value["foreign_owner"] = true
			case "no-catalog-refs":
				delete(value, "catalog_refs")
			}
			if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, value); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(filepath.Join(server.repository.root, catalogCompatibilityAuxiliary+".json"))
			f.mu.Unlock()
			if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), config); err == nil {
				t.Fatal("unsafe successor transition accepted")
			}
			after, _ := os.ReadFile(filepath.Join(server.repository.root, catalogCompatibilityAuxiliary+".json"))
			f.mu.Lock()
			writes := f.writes
			f.mu.Unlock()
			if string(before) != string(after) || writes != 0 {
				t.Fatal("vetoed transition changed a journal or RouterOS")
			}
			if _, err := os.Stat(filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, originalStageID)); err != nil {
				t.Fatal("vetoed transition removed an existing stage")
			}
		})
	}
}

func TestCatalogArrivalPreparedNoPreviousDoesNotPollArrival(t *testing.T) {
	server := newTestServer(t)
	config := routerOSReadyConfig(t)
	f, inventory := catalogArrivalRESTFixture(t, server, config, 4)
	f.mu.Lock()
	f.containers = f.containers[:1]
	f.arrival = nil
	marker := routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: inventory.Current.Root, CatalogSchema: 1}
	body, _ := json.Marshal(marker)
	f.marker["source"] = string(body)
	f.mu.Unlock()
	old := catalogCompatibilityDescriptor{FormatVersion: 1, State: "prepared", Kind: "no-previous", Producer: inventory.Current, ProducerCatalogSchema: 1, CurrentFingerprint: inventory.Fingerprint, CatalogRefs: []subscriptioncatalog.Ref{}}
	if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
		t.Fatal(err)
	}
	if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.arrivalReads != 0 || f.writes != 0 {
		t.Fatal("stable prepared no-predecessor state polled arrival or wrote metadata")
	}
}
