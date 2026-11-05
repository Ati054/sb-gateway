package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

func TestCatalogLegacyFallbackCannotSnapshotAuthoritativeSourcesBeforeApply(t *testing.T) {
	for _, pool := range []int{3, 4} {
		for _, contract := range []string{"missing", "nonpositive"} {
			t.Run(fmt.Sprintf("%d/%s", pool, contract), func(t *testing.T) {
				server := newTestServer(t)
				config := routerOSReadyConfig(t)
				f, inventory := catalogArrivalRESTFixture(t, server, config, pool)
				ref := recoveryCatalogFixture(t, server, 1, 0)
				body, _ := json.Marshal(ref)
				refObject, _ := decodeObject(body)
				if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"feed": map[string]any{"catalog_ref": refObject}}); err != nil {
					t.Fatal(err)
				}
				revisions, err := server.subscriptionRetentionRevisions()
				if err != nil {
					t.Fatal(err)
				}
				for _, revision := range revisions {
					if err := server.repository.saveAuxiliary("subscription-nodes-"+revision, map[string]any{"revision": revision, "nodes": []any{}}); err != nil {
						t.Fatal(err)
					}
				}
				epoch, err := server.catalogCompatibilityEpoch()
				if err != nil {
					t.Fatal(err)
				}
				old := catalogCompatibilityDescriptor{FormatVersion: 1, State: "prepared", Kind: "catalog-capable", SourceEpoch: epoch, Producer: inventory.Current, ProducerCatalogSchema: 1, CurrentFingerprint: inventory.Fingerprint, Previous: inventory.Previous, CatalogRefs: []subscriptioncatalog.Ref{ref}}
				if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(old)); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				if contract == "missing" {
					f.marker = nil
				} else {
					marker := routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: inventory.Current.Root, CatalogSchema: 1}
					body, _ := json.Marshal(marker)
					f.marker["source"] = string(body)
				}
				f.mu.Unlock()
				preserved := filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, strings.Repeat("c", 64), "preserved")
				writeCompatFixture(t, filepath.Dir(preserved), filepath.Base(preserved), []byte("unchanged baseline"))
				journalPath := filepath.Join(server.repository.root, catalogCompatibilityAuxiliary+".json")
				sourcePath := filepath.Join(server.repository.root, "subscription-nodes.json")
				beforeJournal := mustReadFile(t, journalPath)
				beforeSource := mustReadFile(t, sourcePath)
				// Ensure the regression reaches a real, valid graph containing a Ref,
				// rather than passing merely because the graph is malformed.
				refs, err := server.subscriptionCatalogReferences(context.Background())
				if err != nil || len(refs) != 1 {
					t.Fatalf("invalid reference fixture: %v", err)
				}
				if err := server.ensureSubscriptionCatalogCompatibility(context.Background(), config); err == nil {
					t.Fatal("authoritative catalogue was treated as complete legacy data")
				}
				if string(mustReadFile(t, journalPath)) != string(beforeJournal) || string(mustReadFile(t, sourcePath)) != string(beforeSource) {
					t.Fatal("legacy veto changed authoritative state")
				}
				if string(mustReadFile(t, preserved)) != "unchanged baseline" {
					t.Fatal("legacy veto changed a retained baseline")
				}
				newID := catalogCompatibilitySnapshotIdentifier(epoch, inventory.Current, *inventory.Previous)
				for _, area := range server.catalogCompatibilityRoots().areas() {
					if _, err := os.Stat(filepath.Join(area.path, catalogCompatDirectory, newID)); !os.IsNotExist(err) {
						t.Fatal("legacy veto started an incomplete new baseline")
					}
				}
				f.mu.Lock()
				writes := f.writes
				f.mu.Unlock()
				if writes != 0 {
					t.Fatal("legacy veto wrote RouterOS before proof")
				}
				reader, err := subscriptioncatalog.Open(server.secrets.subscriptionCatalogRoot(), ref)
				if err != nil {
					t.Fatal("legacy veto lost private catalogue data")
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestCatalogLegacyReferenceAbsencePreservesUnrecordedAndRecordedResume(t *testing.T) {
	for _, mode := range []string{"no-journal", "unrecorded-old-producer", "recorded"} {
		t.Run(mode, func(t *testing.T) {
			server := newTestServer(t)
			config := routerOSReadyConfig(t)
			catalogArrivalRESTFixture(t, server, config, 4)
			value := map[string]any{}
			old := catalogCompatibilityDescriptor{}
			if mode != "no-journal" {
				old = seedInterruptedCatalogCompatibility(t, server)
				if mode == "recorded" {
					old.Files = []catalogCompatFile{{Area: "config", Path: "recorded.json", SHA256: strings.Repeat("e", 64)}}
				}
				value = catalogCompatJSON(old)
				if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, value); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.validateCatalogLegacyReferenceAbsence(context.Background(), value, old); err != nil {
				t.Fatal("valid empty graph cannot proceed to separate ownership/checksum checks:", err)
			}
			if mode != "no-journal" {
				if _, err := server.subscriptionCatalogReferences(context.Background()); err == nil {
					t.Fatal("absence proof made an incomplete journal prepared")
				}
				if _, err := os.Stat(filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, old.Identifier)); err != nil {
					t.Fatal("absence proof retired a stage")
				}
			}
		})
	}
}

func TestCatalogLegacyReferenceAbsenceKeepsStrictPendingShape(t *testing.T) {
	for _, field := range []string{"unknown", "missing-refs", "null-files", "empty-files"} {
		t.Run(field, func(t *testing.T) {
			server := newTestServer(t)
			old := seedInterruptedCatalogCompatibility(t, server)
			value := catalogCompatJSON(old)
			switch field {
			case "unknown":
				value["unrecognized"] = true
			case "missing-refs":
				delete(value, "catalog_refs")
			case "null-files":
				value["files"] = nil
			case "empty-files":
				value["files"] = []any{}
			}
			if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, value); err != nil {
				t.Fatal(err)
			}
			if err := server.validateCatalogLegacyReferenceAbsence(context.Background(), value, old); err == nil {
				t.Fatal("malformed pending graph was declared empty")
			}
			if _, err := os.Stat(filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, old.Identifier)); err != nil {
				t.Fatal("read-only absence proof removed a stage")
			}
		})
	}
}
