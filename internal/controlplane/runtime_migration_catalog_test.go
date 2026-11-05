package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

func startupCatalogProbeFixture(t *testing.T, count, disabled int, mixed bool) (*Server, map[string][]byte, subscriptioncatalog.Ref, *catalogCompatTestREST) {
	t.Helper()
	server, config, _ := startupProbeMigrationFixture(t, nil)
	options := server.opts.Runtime
	proof := installCatalogCompatibilityRESTFixture(t, server, config)
	server.opts.Runtime = options
	subscription := map[string]any{"id": "feed", "enabled": true, "display_name": "Synthetic catalogue"}
	config["subscriptions"] = []any{subscription}
	nodes, err := parseProxySubscription(catalogIntegrationFeed(count, catalogIntegrationUUID), max(1, count))
	if err != nil {
		t.Fatal(err)
	}
	builder, err := subscriptioncatalog.NewBuilder(server.secrets.subscriptionCatalogRoot(), subscriptioncatalog.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	for index, node := range nodes {
		if index < disabled {
			node["enabled"] = false
		}
		record, err := subscriptionCatalogRecord(subscription, node, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := builder.Append(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := builder.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rows := []map[string]any{subscriptionCatalogNode(subscription, ref)}
	if mixed {
		rows = append(rows, map[string]any{
			"id": "legacy-other", "subscription_id": "old-feed", "country": "DE", "protocol": "vless",
			"server": "legacy.example.test", "server_port": 443, "uuid_secret_ref": "nodes/uuid",
		})
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.saveSubscriptionSnapshot(revision, rows); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, RuntimeRevision: strings.Repeat("1", 64), NodeSnapshotRevision: revision, Actor: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	if err := server.prepareSubscriptionCatalogRuntimeCompatibility(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	native, err := newNativeRuntimeStore(options, server.secrets)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := native.prepare(config, rows)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.store.Activate(candidate); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, RuntimeRevision: candidate.Revision, NodeSnapshotRevision: revision, Actor: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	draft := cloneJSONObject(config)
	objects(draft["policies"])[0]["display_name"] = "Unapplied draft name"
	if _, err := server.repository.saveDraft(draft); err != nil {
		t.Fatal(err)
	}
	expected := make(map[string][]byte, len(candidate.Files))
	for name, path := range candidate.Files {
		expected[name] = mustReadFile(t, path)
	}
	return server, expected, ref, proof
}

func startupCatalogProbePreservedFiles(t *testing.T, server *Server, artifacts map[string][]byte) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for name := range artifacts {
		path := filepath.Join(server.opts.DataDir, "live", name)
		result[path] = mustReadFile(t, path)
	}
	for _, name := range []string{"active.json", "draft.json", "apply-metadata.json"} {
		path := filepath.Join(server.repository.root, name)
		result[path] = mustReadFile(t, path)
	}
	return result
}

func assertStartupCatalogProbePreserved(t *testing.T, before map[string][]byte) {
	t.Helper()
	for path, want := range before {
		if !bytes.Equal(mustReadFile(t, path), want) {
			t.Fatalf("startup changed %s", filepath.Base(path))
		}
	}
}

func TestStartupCatalogProbeCurrentContractDoesNotRenderAgain(t *testing.T) {
	for _, tc := range []struct {
		name            string
		count, disabled int
		mixed           bool
	}{
		{"all catalogue", 12, 0, false},
		{"small catalogue", 3, 0, false},
		{"disabled records", 4, 3, false},
		{"all records disabled", 3, 3, false},
		{"mixed legacy", 3, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, expected, _, proof := startupCatalogProbeFixture(t, tc.count, tc.disabled, tc.mixed)
			before := startupCatalogProbePreservedFiles(t, server, expected)
			server.opts.Runtime.NginxTemplate = "/must-not-render-current-catalogue"
			writes := proof.mutations.Load()
			for range 2 {
				if migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts); err != nil || migrated {
					t.Fatalf("current catalogue migration=%t, %v", migrated, err)
				}
			}
			assertStartupCatalogProbePreserved(t, before)
			if proof.mutations.Load() != writes {
				t.Fatal("read-only startup changed RouterOS image proof")
			}
		})
	}
}

func TestStartupCatalogProbeRepairsObsoleteContractThenStaysUnchanged(t *testing.T) {
	for _, kind := range []string{"pool lanes", "core lanes", "core port", "core binding", "core protocol", "policy batch", "retired speed", "legacy pool version"} {
		t.Run(kind, func(t *testing.T) {
			server, expected, _, proof := startupCatalogProbeFixture(t, 12, 0, false)
			pool, err := decodeObject(expected["urltest-pool.json"])
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "pool lanes":
				pool["probe_lanes"] = 1
			case "legacy pool version":
				pool["version"] = 4
			case "core lanes", "core port", "core binding", "core protocol":
				xray, err := decodeObject(expected["xray.json"])
				if err != nil {
					t.Fatal(err)
				}
				var inbounds []any
				for _, inbound := range objects(xray["inbounds"]) {
					if kind == "core lanes" && text(inbound["tag"]) == "outbound-health-background-10" {
						continue
					}
					if text(inbound["tag"]) == "outbound-health-probe" {
						switch kind {
						case "core port":
							inbound["port"] = 19000
						case "core binding":
							inbound["listen"] = "0.0.0.0"
						case "core protocol":
							inbound["protocol"] = "socks"
						}
					}
					inbounds = append(inbounds, inbound)
				}
				xray["inbounds"] = inbounds
				writeStartupProbeJSON(t, server.opts.Runtime.XrayConfig, xray)
			case "policy batch", "retired speed":
				policy := pool["health_policies"].(map[string]any)["best"].(map[string]any)
				settings := policy["policy"].(map[string]any)
				if kind == "policy batch" {
					settings["probe_batch_size"] = 1
				} else {
					settings["speed_check_enabled"] = true
				}
			}
			writeStartupProbeJSON(t, server.opts.Runtime.XrayHealthPool, pool)
			draft, _ := server.getDraft()
			writes := proof.mutations.Load()
			if migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts); err != nil || !migrated {
				t.Fatalf("obsolete catalogue migration=%t, %v", migrated, err)
			}
			if !bytes.Equal(mustReadFile(t, server.opts.Runtime.XrayConfig), expected["xray.json"]) || !bytes.Equal(mustReadFile(t, server.opts.Runtime.XrayHealthPool), expected["urltest-pool.json"]) {
				t.Fatal("catalogue listeners and health pool were not repaired together")
			}
			currentDraft, _ := server.getDraft()
			if !equalJSONObject(draft, currentDraft) || proof.mutations.Load() != writes {
				t.Fatal("startup changed unapplied settings or physical image proof")
			}
			server.opts.Runtime.NginxTemplate = "/must-not-render-repaired-catalogue"
			if migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts); err != nil || migrated {
				t.Fatalf("repaired catalogue migration=%t, %v", migrated, err)
			}
		})
	}
}

func TestStartupCatalogProbeMissingOrCorruptReferenceFailsClosed(t *testing.T) {
	for _, kind := range []string{"missing generation", "corrupt records", "missing image proof", "future pool version"} {
		t.Run(kind, func(t *testing.T) {
			server, expected, ref, proof := startupCatalogProbeFixture(t, 3, 0, false)
			generation := filepath.Join(server.secrets.subscriptionCatalogRoot(), ref.Generation)
			switch kind {
			case "missing generation":
				if err := os.Rename(generation, generation+"-missing"); err != nil {
					t.Fatal(err)
				}
			case "corrupt records":
				path := filepath.Join(generation, "records.bin")
				body := mustReadFile(t, path)
				body[len(body)/2] ^= 1
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing image proof":
				if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, map[string]any{}); err != nil {
					t.Fatal(err)
				}
			case "future pool version":
				pool, err := decodeObject(expected["urltest-pool.json"])
				if err != nil {
					t.Fatal(err)
				}
				pool["version"] = 6
				writeStartupProbeJSON(t, server.opts.Runtime.XrayHealthPool, pool)
			}
			before := startupCatalogProbePreservedFiles(t, server, expected)
			writes := proof.mutations.Load()
			migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
			if migrated || !errors.Is(err, ErrProbeContractMigration) {
				t.Fatalf("invalid catalogue migration=%t, %v", migrated, err)
			}
			assertStartupCatalogProbePreserved(t, before)
			if proof.mutations.Load() != writes {
				t.Fatal("rejected startup changed physical image proof")
			}
		})
	}
}

func TestStartupCatalogProbeUsesCommittedSnapshotNotNewSource(t *testing.T) {
	server, expected, _, _ := startupCatalogProbeFixture(t, 3, 0, false)
	// A newer source is not the active runtime until Apply commits its snapshot.
	// It must not replace the exact committed generation during startup.
	if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"feed": map[string]any{"catalog_ref": map[string]any{"schema": 0}}}); err != nil {
		t.Fatal(err)
	}
	before := startupCatalogProbePreservedFiles(t, server, expected)
	server.opts.Runtime.NginxTemplate = "/must-not-render-unapplied-source"
	if migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts); err != nil || migrated {
		t.Fatalf("unapplied source changed startup contract: %t, %v", migrated, err)
	}
	assertStartupCatalogProbePreserved(t, before)
}
