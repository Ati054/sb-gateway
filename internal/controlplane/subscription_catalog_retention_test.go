package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

func catalogRetentionServer(t *testing.T) *Server {
	t.Helper()
	server := newTestServer(t)
	if err := server.repository.saveAuxiliary("subscription-catalog-compatibility", map[string]any{
		"format_version": 1, "state": "prepared", "kind": "no-previous", "catalog_refs": []any{},
	}); err != nil {
		t.Fatal(err)
	}
	return server
}

func catalogRetentionGeneration(t *testing.T, server *Server, number int) subscriptioncatalog.Ref {
	t.Helper()
	builder, err := subscriptioncatalog.NewBuilder(server.secrets.subscriptionCatalogRoot(), subscriptioncatalog.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	id := fmt.Sprintf("synthetic-%d", number)
	node, err := json.Marshal(map[string]any{"id": id})
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.Append(context.Background(), subscriptioncatalog.Record{ID: id, Node: node, Metadata: node, Secrets: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	ref, err := builder.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func catalogRetentionAge(t *testing.T, server *Server, ref subscriptioncatalog.Ref, when time.Time) {
	t.Helper()
	directory := filepath.Join(server.secrets.subscriptionCatalogRoot(), ref.Generation)
	for _, name := range catalogRetentionFiles {
		if err := os.Chtimes(filepath.Join(directory, name), when, when); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(directory, when, when); err != nil {
		t.Fatal(err)
	}
}

func catalogRetentionIntact(t *testing.T, server *Server, ref subscriptioncatalog.Ref) {
	t.Helper()
	reader, err := subscriptioncatalog.Open(server.secrets.subscriptionCatalogRoot(), ref)
	if err != nil {
		t.Fatalf("generation was not preserved: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSubscriptionCatalogReferencesCoverSourceSnapshotsPoolAndCompatibility(t *testing.T) {
	server := catalogRetentionServer(t)
	refs := make([]subscriptioncatalog.Ref, 8)
	for index := range refs {
		refs[index] = catalogRetentionGeneration(t, server, index)
	}
	if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"source": map[string]any{"catalog_ref": refs[0]}}); err != nil {
		t.Fatal(err)
	}
	revisions := []string{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)}
	for index, revision := range revisions {
		if err := server.repository.saveAuxiliary("subscription-nodes-"+revision, map[string]any{"revision": revision, "nodes": []any{map[string]any{subscriptionCatalogSentinel: refs[index+1]}}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.repository.saveAuxiliary("active", map[string]any{"revision": revisions[0]}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("last-known-good", map[string]any{"revision": revisions[1]}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("apply-metadata", map[string]any{"previous_revision": revisions[2], "node_snapshot_revision": revisions[3], "previous_node_snapshot_revision": revisions[4]}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("subscription-catalog-compatibility", map[string]any{"format_version": 1, "state": "prepared", "kind": "catalog-capable", "catalog_refs": []any{refs[6]}}); err != nil {
		t.Fatal(err)
	}
	server.opts.Runtime.XrayHealthPool = filepath.Join(t.TempDir(), "pool.json")
	pool := map[string]any{
		"version": 5, "catalogs": map[string]any{refs[7].Generation: refs[7]},
		"catalog_definitions": map[string]any{"node": runtimeconfig.CatalogDefinition{Generation: refs[7].Generation, Fingerprint: strings.Repeat("1", 64), FingerprintKind: runtimeconfig.CatalogFingerprintKind}},
	}
	if err := server.repository.writeJSON(server.opts.Runtime.XrayHealthPool, pool); err != nil {
		t.Fatal(err)
	}
	// An obsolete snapshot must not become a persisted recovery root.
	obsolete := catalogRetentionGeneration(t, server, 99)
	if err := server.repository.saveAuxiliary("subscription-nodes-"+strings.Repeat("f", 64), map[string]any{"revision": strings.Repeat("f", 64), "nodes": []any{map[string]any{subscriptionCatalogSentinel: obsolete}}}); err != nil {
		t.Fatal(err)
	}
	actual, err := server.subscriptionCatalogReferences(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(refs) {
		t.Fatalf("reachable refs=%d want=%d", len(actual), len(refs))
	}
	for _, ref := range refs {
		if actual[ref.Generation] != ref {
			t.Fatal("persisted reachable generation omitted")
		}
	}
	if _, included := actual[obsolete.Generation]; included {
		t.Fatal("obsolete snapshot leaked into recovery graph")
	}
}

func TestSubscriptionCatalogRetentionGraceCacheAndUntrackedLease(t *testing.T) {
	server := catalogRetentionServer(t)
	now := time.Now()
	server.now = func() time.Time { return now }
	refs := make([]subscriptioncatalog.Ref, 6)
	for index := range refs {
		refs[index] = catalogRetentionGeneration(t, server, index)
		if index != 5 {
			catalogRetentionAge(t, server, refs[index], now.Add(-25*time.Hour))
		}
	}
	if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"source": map[string]any{"catalog_ref": refs[0]}}); err != nil {
		t.Fatal(err)
	}
	_, activeRelease, err := server.secrets.catalogReaders.acquire(server.secrets.subscriptionCatalogRoot(), refs[1])
	if err != nil {
		t.Fatal(err)
	}
	defer activeRelease()
	_, idleRelease, err := server.secrets.catalogReaders.acquire(server.secrets.subscriptionCatalogRoot(), refs[2])
	if err != nil {
		t.Fatal(err)
	}
	idleRelease()
	untracked, err := subscriptioncatalog.Open(server.secrets.subscriptionCatalogRoot(), refs[3])
	if err != nil {
		t.Fatal(err)
	}
	defer untracked.Close()
	preparation := filepath.Join(server.secrets.subscriptionCatalogRoot(), ".prepare-synthetic")
	if err := os.Mkdir(preparation, 0700); err != nil {
		t.Fatal(err)
	}
	report, err := server.pruneSubscriptionCatalogs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Removed != 2 || report.KeptReferenced != 1 || report.KeptRecent != 1 || report.KeptBusy != 2 {
		t.Fatalf("unexpected retention report: %+v", report)
	}
	for _, index := range []int{0, 1, 3, 5} {
		catalogRetentionIntact(t, server, refs[index])
	}
	for _, index := range []int{2, 4} {
		if _, err := os.Lstat(filepath.Join(server.secrets.subscriptionCatalogRoot(), refs[index].Generation)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unreferenced generation remains: %v", err)
		}
	}
	if _, err := os.Lstat(preparation); err != nil {
		t.Fatal("preparation directory was touched")
	}
	if entry := server.secrets.catalogReaders.entries[refs[2].Generation]; entry != nil {
		t.Fatal("idle reader cache entry not evicted")
	}
}

func TestSubscriptionCatalogRetentionIncompleteGraphNeverDeletes(t *testing.T) {
	for _, kind := range []string{"bad-reference", "bad-pointer", "missing-snapshot", "pending-apply", "pending-subscription", "preparing-compatibility", "missing-compatibility", "missing-pool-ref", "trailing-json", "malformed-unreferenced-generation"} {
		t.Run(kind, func(t *testing.T) {
			server := catalogRetentionServer(t)
			old := catalogRetentionGeneration(t, server, 1)
			catalogRetentionAge(t, server, old, time.Now().Add(-48*time.Hour))
			switch kind {
			case "bad-reference":
				if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"source": map[string]any{"catalog_ref": map[string]any{}}}); err != nil {
					t.Fatal(err)
				}
			case "bad-pointer":
				if err := server.repository.saveAuxiliary("apply-metadata", map[string]any{"previous_revision": 17}); err != nil {
					t.Fatal(err)
				}
			case "missing-snapshot":
				if err := server.repository.saveAuxiliary("active", map[string]any{"revision": strings.Repeat("a", 64)}); err != nil {
					t.Fatal(err)
				}
				if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"source": map[string]any{"catalog_ref": old}}); err != nil {
					t.Fatal(err)
				}
			case "pending-apply", "pending-subscription":
				name := "apply-operation"
				if kind == "pending-subscription" {
					name = "subscription-runtime-operation"
				}
				if err := server.repository.saveAuxiliary(name, map[string]any{"pending": true}); err != nil {
					t.Fatal(err)
				}
			case "preparing-compatibility":
				if err := server.repository.saveAuxiliary("subscription-catalog-compatibility", map[string]any{"format_version": 1, "state": "preparing", "catalog_refs": []any{}}); err != nil {
					t.Fatal(err)
				}
			case "missing-compatibility":
				if err := os.Remove(filepath.Join(server.repository.root, "subscription-catalog-compatibility.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-pool-ref":
				server.opts.Runtime.XrayHealthPool = filepath.Join(t.TempDir(), "pool.json")
				if err := server.repository.writeJSON(server.opts.Runtime.XrayHealthPool, map[string]any{"catalog_definitions": map[string]any{"node": runtimeconfig.CatalogDefinition{Generation: old.Generation, Fingerprint: strings.Repeat("1", 64), FingerprintKind: runtimeconfig.CatalogFingerprintKind}}}); err != nil {
					t.Fatal(err)
				}
			case "trailing-json":
				if err := os.WriteFile(filepath.Join(server.repository.root, "subscription-nodes.json"), []byte(`{} {}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "malformed-unreferenced-generation":
				if err := os.Mkdir(filepath.Join(server.secrets.subscriptionCatalogRoot(), strings.Repeat("a", 64)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := server.pruneSubscriptionCatalogs(context.Background()); err == nil {
				t.Fatal("incomplete reference proof allowed cleanup")
			}
			catalogRetentionIntact(t, server, old)
		})
	}
}

func TestSubscriptionCatalogCandidateCleanupIsExactAndLeaseProtected(t *testing.T) {
	server := catalogRetentionServer(t)
	first := catalogRetentionGeneration(t, server, 1)
	second := catalogRetentionGeneration(t, server, 2)
	reader, err := subscriptioncatalog.Open(server.secrets.subscriptionCatalogRoot(), first)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	report, err := server.pruneSubscriptionCatalogCandidate(context.Background(), first)
	if err != nil || report.KeptBusy != 1 || report.Removed != 0 {
		t.Fatalf("leased candidate: %+v err=%v", report, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	report, err = server.pruneSubscriptionCatalogCandidate(context.Background(), first)
	if err != nil || report.Removed != 1 {
		t.Fatalf("unpublished complete candidate: %+v err=%v", report, err)
	}
	catalogRetentionIntact(t, server, second)
	if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"source": map[string]any{"catalog_ref": second}}); err != nil {
		t.Fatal(err)
	}
	report, err = server.pruneSubscriptionCatalogCandidate(context.Background(), second)
	if err != nil || report.Removed != 0 || report.KeptReferenced != 1 {
		t.Fatalf("published candidate: %+v err=%v", report, err)
	}
}

func TestSubscriptionCatalogRetentionCancelledBeforeListing(t *testing.T) {
	server := catalogRetentionServer(t)
	ref := catalogRetentionGeneration(t, server, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.pruneSubscriptionCatalogs(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled retention: %v", err)
	}
	catalogRetentionIntact(t, server, ref)
}
