package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lifecycleIncompleteCatalogFixture(t *testing.T, blocked string) (*Server, map[string]any, catalogCompatibilityDescriptor) {
	t.Helper()
	server := newTestServer(t)
	config := routerOSReadyConfig(t)
	client := catalogCompatTransitionFixture(t, server, config, blocked, strings.Repeat("b", 64))
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
	old := seedInterruptedCatalogCompatibility(t, server)
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
	return server, config, old
}

func lifecyclePrepareCatalogAdmitted(server *Server, config map[string]any, schema int) error {
	server.mutationMu.Lock()
	defer server.mutationMu.Unlock()
	return server.prepareLifecycleCatalogCompatibility(context.Background(), config, schema)
}

func TestLifecycleCompletesOnlyUnpublishedLegacyCatalogPreparationBeforeBackup(t *testing.T) {
	server, config, old := lifecycleIncompleteCatalogFixture(t, "")
	if _, err := server.subscriptionCatalogReferences(context.Background()); !errors.Is(err, errSubscriptionCatalogReferencesPending) {
		t.Fatal("strict collector unexpectedly permitted incomplete preparation")
	}
	if _, err := server.createRecoveryArchive(); err == nil {
		t.Fatal("ordinary recovery relaxed incomplete preparation")
	}
	if err := lifecyclePrepareCatalogAdmitted(server, config, 1); err != nil {
		t.Fatal("admitted lifecycle could not finish checked legacy baseline:", err)
	}
	refs, err := server.subscriptionCatalogReferences(context.Background())
	if err != nil || len(refs) != 0 {
		t.Fatal("strict graph did not settle after repair:", err)
	}
	value, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	if err != nil {
		t.Fatal(err)
	}
	var prepared catalogCompatibilityDescriptor
	body, _ := json.Marshal(value)
	if json.Unmarshal(body, &prepared) != nil {
		t.Fatal("invalid prepared descriptor")
	}
	if prepared.State != "prepared" || prepared.Kind != "legacy-snapshot" || len(prepared.Files) == 0 || prepared.Mountlist == "" || prepared.Previous == nil {
		t.Fatal("repair bypassed baseline or mount handoff")
	}
	if err := validateCatalogCompatSnapshot(context.Background(), server.catalogCompatibilityRoots(), prepared.Identifier, prepared.Files, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, old.Identifier)); !os.IsNotExist(err) {
		t.Fatal("unused old stage was not retired")
	}
	if _, err := server.createRecoveryArchive(); err != nil {
		t.Fatal("normal backup remained blocked after checked repair:", err)
	}
}

func TestLifecycleIncompleteCatalogRepairPreservesStrictVetoes(t *testing.T) {
	for _, scenario := range []string{"recorded-files", "attached-journal", "unknown-kind", "unknown-field", "unknown-producer", "actual-ref", "v5", "missing-pool", "apply-pending", "subscription-pending", "startup-pending", "memory-pending", "lifecycle-pending", "foreign-mount", "incompatible-image"} {
		t.Run(scenario, func(t *testing.T) {
			blocked := ""
			if scenario == "foreign-mount" {
				blocked = "mount"
			}
			server, config, old := lifecycleIncompleteCatalogFixture(t, blocked)
			value := catalogCompatJSON(old)
			schema := 1
			switch scenario {
			case "recorded-files":
				value["files"] = []any{map[string]any{"area": "config", "path": "baseline.json", "bytes": 0, "sha256": strings.Repeat("e", 64)}}
			case "attached-journal":
				value["mountlist"] = "sb-catalog-compat-" + old.Identifier[:16]
			case "unknown-kind":
				value["kind"] = "unknown"
			case "unknown-field":
				value["unknown_capability"] = true
			case "unknown-producer":
				producer := value["producer"].(map[string]any)
				producer["role"] = "unknown"
			case "actual-ref":
				ref := recoveryCatalogFixture(t, server, 1, 0)
				if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"feed": map[string]any{"catalog_ref": ref}}); err != nil {
					t.Fatal(err)
				}
			case "v5":
				if err := os.WriteFile(server.opts.Runtime.XrayHealthPool, []byte(`{"version":5}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-pool":
				if err := os.Remove(server.opts.Runtime.XrayHealthPool); err != nil {
					t.Fatal(err)
				}
			case "apply-pending":
				if err := server.repository.saveAuxiliary("apply-operation", map[string]any{"pending": true}); err != nil {
					t.Fatal(err)
				}
			case "subscription-pending":
				if err := server.repository.saveAuxiliary("subscription-runtime-operation", map[string]any{"pending": true}); err != nil {
					t.Fatal(err)
				}
			case "startup-pending":
				if err := server.repository.saveAuxiliary(containerStartupOperation, map[string]any{"pending": true}); err != nil {
					t.Fatal(err)
				}
			case "memory-pending":
				if err := server.repository.saveAuxiliary(containerMemoryOperation, map[string]any{"pending": true}); err != nil {
					t.Fatal(err)
				}
			case "lifecycle-pending":
				if err := server.repository.saveAuxiliary("lifecycle-operation", map[string]any{"kind": "image-update", "state": "probation"}); err != nil {
					t.Fatal(err)
				}
			case "incompatible-image":
				schema = 0
			}
			if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, value); err != nil {
				t.Fatal(err)
			}
			if err := lifecyclePrepareCatalogAdmitted(server, config, schema); err == nil {
				t.Fatal("unsafe lifecycle repair accepted")
			}
			after, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
			if err != nil || !equalJSONObject(value, after) {
				t.Fatal("vetoed preparation journal changed")
			}
			if _, err := os.Stat(filepath.Join(server.catalogCompatibilityRoots().Config, catalogCompatDirectory, old.Identifier)); err != nil {
				t.Fatal("vetoed old stage removed")
			}
		})
	}
}
