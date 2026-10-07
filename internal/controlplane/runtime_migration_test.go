package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
)

func startupProbeMigrationFixture(t *testing.T, global any) (*Server, map[string]any, map[string][]byte) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("runtime validation fixture uses /bin/true; run the Linux suite")
	}
	server := newTestServer(t)
	config := map[string]any{
		"system": map[string]any{
			"networking": map[string]any{
				"routeros_gateway": "192.168.3.1", "container_address": "198.18.0.2/29",
				"tun_address": "198.18.0.1/30", "tun_mtu": 1400, "tun_stack": "system", "remote_ipv6_mode": "proxy_only",
			},
			"management": map[string]any{},
		},
		"dns": map[string]any{
			"internal_server": "192.168.3.1",
			"direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
		},
		"ingress": map[string]any{"tls_profile_id": "public"},
		"tls_profiles": []any{map[string]any{
			"id": "public", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key",
		}},
		"watchdog": map[string]any{"interval_seconds": 5, "failure_threshold": 3, "recovery_threshold": 3, "max_restarts_per_hour": 6},
		"policies": []any{
			map[string]any{"id": "priority", "mode": "priority", "selection_order": []any{"country:DE"}, "probe_batch_size": 3},
			map[string]any{"id": "best", "mode": "best", "selection_order": []any{"country:DE"}, "probe_batch_size": 2},
		},
	}
	if global != nil {
		config["system"].(map[string]any)["routing_monitor"] = global
	}
	if err := server.secrets.write("nodes/uuid", "123e4567-e89b-42d3-a456-426614174000", false); err != nil {
		t.Fatal(err)
	}
	nodes := make([]map[string]any, 12)
	for index := range nodes {
		nodes[index] = map[string]any{
			"id": fmt.Sprintf("node-%d", index), "subscription_id": "feed", "country": "DE", "protocol": "vless",
			"server": "edge.example.test", "server_port": 443, "uuid_secret_ref": "nodes/uuid",
		}
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.saveSubscriptionSnapshot(revision, nodes); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{
		Revision: revision, RuntimeRevision: strings.Repeat("1", 64), RouterOSSource: "committed-routeros", Actor: "admin", CommittedAt: server.now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	root := server.opts.DataDir
	server.opts.Runtime = RuntimeOptions{
		CandidateDir: filepath.Join(root, "candidates"), RuleSetDir: filepath.Join(root, "rulesets"),
		NginxTemplate: "../../templates/nginx.conf.j2",
		XrayConfig:    filepath.Join(root, "live", "xray.json"), XrayHealthPool: filepath.Join(root, "live", "urltest-pool.json"),
		NginxConfig: filepath.Join(root, "live", "nginx.conf"), PolicyDNSConfig: filepath.Join(root, "live", "policy-dns.json"),
		WatchdogEnvironment: filepath.Join(root, "live", "watchdog.env"), ClientTelemetryNFT: filepath.Join(root, "live", "client-telemetry.nft"),
		TransparentExclusions: filepath.Join(root, "live", "transparent-exclusions.txt"),
		XrayBinary:            "/bin/true", NginxBinary: "/bin/true", NFTBinary: "/bin/true",
	}
	native, err := newNativeRuntimeStore(server.opts.Runtime, server.secrets)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := native.prepare(config, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.store.Activate(candidate); err != nil {
		t.Fatal(err)
	}
	expected := make(map[string][]byte, len(candidate.Files))
	for name, path := range candidate.Files {
		expected[name] = mustReadFile(t, path)
	}
	return server, config, expected
}

func writeStartupProbeJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func makeStartupProbeLegacy(t *testing.T, server *Server, oldLanes bool) {
	t.Helper()
	pool, err := decodeObject(mustReadFile(t, server.opts.Runtime.XrayHealthPool))
	if err != nil {
		t.Fatal(err)
	}
	policies := pool["health_policies"].(map[string]any)
	policies["priority"].(map[string]any)["policy"].(map[string]any)["probe_batch_size"] = 3
	policies["best"].(map[string]any)["policy"].(map[string]any)["probe_batch_size"] = 2
	if oldLanes {
		delete(pool, "probe_lanes")
		pool["probe_budget"] = 5
		xray, err := decodeObject(mustReadFile(t, server.opts.Runtime.XrayConfig))
		if err != nil {
			t.Fatal(err)
		}
		inbounds := []any{}
		for _, inbound := range objects(xray["inbounds"]) {
			port, _ := jsonInteger(inbound["port"])
			if !strings.HasPrefix(text(inbound["tag"]), "outbound-health-background") || port <= 19085 {
				inbounds = append(inbounds, inbound)
			}
		}
		xray["inbounds"] = inbounds
		writeStartupProbeJSON(t, server.opts.Runtime.XrayConfig, xray)
	}
	writeStartupProbeJSON(t, server.opts.Runtime.XrayHealthPool, pool)
}

func TestStartupProbeMigrationReconcilesCommittedRuntime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		global   any
		oldLanes bool
	}{
		{"42 absent global", nil, true},
		{"42 empty global", map[string]any{}, true},
		{"42 auto global", map[string]any{"probe_batch_size": 0}, true},
		{"42 explicit five", map[string]any{"probe_batch_size": 5}, true},
		{"43 pool only", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, config, expected := startupProbeMigrationFixture(t, tc.global)
			envelope, err := server.draftEnvelope(config)
			if err != nil || envelope["pending_change_count"] != 0 {
				t.Fatalf("fixture must reproduce pending=0: %v, %v", envelope, err)
			}
			makeStartupProbeLegacy(t, server, tc.oldLanes)
			draft := cloneJSONObject(config)
			draft["unapplied"] = "keep this user change"
			if _, err := server.repository.saveDraft(draft); err != nil {
				t.Fatal(err)
			}
			beforeDraft := mustReadFile(t, filepath.Join(server.repository.root, "draft.json"))
			beforeActive, _ := server.repository.metadata()
			generation := mustReadFile(t, filepath.Join(server.repository.generations, text(beforeActive["revision"])+".json"))
			// A same-version pool-only repair must not invoke the core validator.
			if !tc.oldLanes {
				server.opts.Runtime.XrayBinary = "/missing-core-validator"
			}
			migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
			if err != nil || !migrated {
				t.Fatalf("migration=%t, %v", migrated, err)
			}
			for name, want := range expected {
				if got := mustReadFile(t, filepath.Join(server.opts.DataDir, "live", name)); !bytes.Equal(got, want) {
					t.Fatalf("artifact %s was not rebuilt from committed inputs", name)
				}
			}
			active, _ := server.repository.metadata()
			if active["revision"] != beforeActive["revision"] || active["routeros_source"] != "committed-routeros" || active["runtime_revision"] == beforeActive["runtime_revision"] {
				t.Fatalf("unexpected migration metadata: %v", active)
			}
			if !bytes.Equal(beforeDraft, mustReadFile(t, filepath.Join(server.repository.root, "draft.json"))) ||
				!bytes.Equal(generation, mustReadFile(t, filepath.Join(server.repository.generations, text(active["revision"])+".json"))) {
				t.Fatal("migration modified draft or immutable committed configuration")
			}
			// Prove the current-boot fast path does not render or invoke a binary.
			server.opts.Runtime.NginxTemplate = "/missing-template"
			migrated, err = MigrateLegacyDynamicRuntime(context.Background(), server.opts)
			if err != nil || migrated {
				t.Fatalf("idempotent fast path=%t, %v", migrated, err)
			}
		})
	}
}

func TestStartupProbeMigrationFailurePreservesRuntime(t *testing.T) {
	for _, failure := range []string{"validation", "commit rollback", "cancelled", "snapshot", "malformed"} {
		t.Run(failure, func(t *testing.T) {
			server, _, expected := startupProbeMigrationFixture(t, nil)
			makeStartupProbeLegacy(t, server, true)
			ctx := context.Background()
			switch failure {
			case "validation":
				server.opts.Runtime.XrayBinary = "/missing-core-validator"
			case "commit rollback":
				if err := os.WriteFile(filepath.Join(server.opts.Runtime.CandidateDir, "runtime-lkg"), []byte("blocked LKG directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "snapshot":
				metadata, _ := server.repository.metadata()
				if err := server.repository.saveAuxiliary("subscription-nodes-"+text(metadata["revision"]), map[string]any{}); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(server.opts.Runtime.XrayHealthPool, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := map[string][]byte{}
			for name := range expected {
				path := filepath.Join(server.opts.DataDir, "live", name)
				before[path] = mustReadFile(t, path)
			}
			for _, name := range []string{"active.json", "draft.json"} {
				path := filepath.Join(server.repository.root, name)
				before[path] = mustReadFile(t, path)
			}
			migrated, err := MigrateLegacyDynamicRuntime(ctx, server.opts)
			if migrated || !errors.Is(err, ErrProbeContractMigration) {
				t.Fatalf("unsafe reconciliation result=%t, %v", migrated, err)
			}
			if failure == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation cause lost: %v", err)
			}
			for path, want := range before {
				if !bytes.Equal(mustReadFile(t, path), want) {
					t.Fatalf("failed migration modified %s", filepath.Base(path))
				}
			}
		})
	}
}

func TestStartupProbeMigrationDefersToPendingRecovery(t *testing.T) {
	for _, journal := range []string{"apply-operation", "subscription-runtime-operation"} {
		t.Run(journal, func(t *testing.T) {
			server, _, _ := startupProbeMigrationFixture(t, nil)
			makeStartupProbeLegacy(t, server, true)
			if err := server.repository.saveAuxiliary(journal, map[string]any{"pending": true, "state": "recovery_pending"}); err != nil {
				t.Fatal(err)
			}
			pool := mustReadFile(t, server.opts.Runtime.XrayHealthPool)
			core := mustReadFile(t, server.opts.Runtime.XrayConfig)
			operation := mustReadFile(t, filepath.Join(server.repository.root, journal+".json"))
			server.opts.Runtime.NginxTemplate = "/must-not-render-pending-recovery"
			migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
			if migrated || err != nil {
				t.Fatalf("pending recovery was not deferred: %t, %v", migrated, err)
			}
			if !bytes.Equal(pool, mustReadFile(t, server.opts.Runtime.XrayHealthPool)) ||
				!bytes.Equal(core, mustReadFile(t, server.opts.Runtime.XrayConfig)) ||
				!bytes.Equal(operation, mustReadFile(t, filepath.Join(server.repository.root, journal+".json"))) {
				t.Fatal("migration interfered with pending recovery ownership")
			}
		})
	}
}

func TestStartupProbeMigrationReconcilesDeclaredLaneInventory(t *testing.T) {
	for _, declared := range []int{3, 10} {
		t.Run(fmt.Sprintf("declared%d_actual3_inventory12", declared), func(t *testing.T) {
			server, _, expected := startupProbeMigrationFixture(t, nil)
			makeStartupProbeLegacy(t, server, true)
			pool, err := decodeObject(expected["urltest-pool.json"])
			if err != nil {
				t.Fatal(err)
			}
			// Both policies already say 10. Check a stale declared inventory and
			// a partially published pool whose core still has three listeners.
			pool["probe_lanes"] = declared
			writeStartupProbeJSON(t, server.opts.Runtime.XrayHealthPool, pool)
			migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
			if !migrated || err != nil {
				t.Fatalf("lane reconciliation=%t, %v", migrated, err)
			}
			if !bytes.Equal(expected["xray.json"], mustReadFile(t, server.opts.Runtime.XrayConfig)) ||
				!bytes.Equal(expected["urltest-pool.json"], mustReadFile(t, server.opts.Runtime.XrayHealthPool)) {
				t.Fatal("core and pool were not published from one committed inventory")
			}
		})
	}
}

func TestStartupProbeMigrationSkipsUnprovisionedDisabledAndAbsentRuntime(t *testing.T) {
	t.Run("first provisioning", func(t *testing.T) {
		server := newTestServer(t)
		migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
		if migrated || err != nil {
			t.Fatalf("first provisioning was blocked: %t, %v", migrated, err)
		}
	})
	for _, scenario := range []string{"disabled", "absent core", "absent pool"} {
		t.Run(scenario, func(t *testing.T) {
			server, config, _ := startupProbeMigrationFixture(t, nil)
			switch scenario {
			case "disabled":
				for _, policy := range objects(config["policies"]) {
					policy["enabled"] = false
				}
				revision, err := server.repository.stageGeneration(config)
				if err != nil {
					t.Fatal(err)
				}
				if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test", CommittedAt: server.now()}); err != nil {
					t.Fatal(err)
				}
			case "absent core":
				if err := os.Remove(server.opts.Runtime.XrayConfig); err != nil {
					t.Fatal(err)
				}
			case "absent pool":
				if err := os.Remove(server.opts.Runtime.XrayHealthPool); err != nil {
					t.Fatal(err)
				}
			}
			server.opts.Runtime.NginxTemplate = "/must-not-render-without-runtime"
			migrated, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
			if migrated || err != nil {
				t.Fatalf("inactive probe runtime was blocked: %t, %v", migrated, err)
			}
		})
	}
}

func TestRuntimeMigrationRejectsNonRegularInput(t *testing.T) {
	path := t.TempDir()
	if present, err := runtimeMigrationInputsPresent(path); present || err == nil {
		t.Fatalf("non-regular input admitted: %t, %v", present, err)
	}
	if _, err := readRuntimeMigrationArtifact(path); err == nil {
		t.Fatal("non-regular input opened as a bounded artifact")
	}
}

func TestLegacyDynamicRuntimeRequiresExactHealthPoolOverlap(t *testing.T) {
	root := t.TempDir()
	xray := filepath.Join(root, "xray.json")
	pool := filepath.Join(root, "urltest-pool.json")
	if err := os.WriteFile(xray, []byte(`{"outbounds":[{"tag":"direct-wan"},{"tag":"provider-de"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pool, []byte(`{"outbounds":{"provider-de":{"tag":"provider-de"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := legacyDynamicRuntime(xray, pool)
	if err != nil || !legacy {
		t.Fatalf("legacy runtime = %t, %v", legacy, err)
	}
	if err := os.WriteFile(pool, []byte(`{"outbounds":{"provider-fi":{"tag":"provider-fi"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err = legacyDynamicRuntime(xray, pool)
	if err != nil || legacy {
		t.Fatalf("unrelated runtime = %t, %v", legacy, err)
	}
}

func TestLegacyGeoIPRuntimeMigratesOnlySelectedUntaggedRules(t *testing.T) {
	root := t.TempDir()
	repository, err := newStateRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"policies":      []any{map[string]any{"id": "all", "enabled": true, "direct_services": []any{"geoip-cn"}}},
		"service_packs": []any{map[string]any{"id": "geoip-cn", "upstream_name": "geoip-cn", "enabled": true}},
	}
	revision, err := revisionFor(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.writeJSON(filepath.Join(repository.generations, revision+".json"), config); err != nil {
		t.Fatal(err)
	}
	if err := repository.writeJSON(filepath.Join(root, "active.json"), map[string]any{"revision": revision}); err != nil {
		t.Fatal(err)
	}
	xray := filepath.Join(root, "xray.json")
	if err := os.WriteFile(xray, []byte(`{"routing":{"rules":[{"type":"field","ip":["203.0.113.0/24"]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := legacyGeoIPRouting(root, xray, root)
	if err != nil || !legacy {
		t.Fatalf("untagged GeoIP must migrate: %t, %v", legacy, err)
	}
	if err := os.WriteFile(xray, []byte(`{"routing":{"rules":[{"type":"field","ruleTag":"sb-geoip-geoip-cn-0-0","ip":["203.0.113.0/24"]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err = legacyGeoIPRouting(root, xray, root)
	if err != nil || !legacy {
		t.Fatalf("tagged inline GeoIP must migrate: %t, %v", legacy, err)
	}
	if err := os.WriteFile(xray, []byte(`{"routing":{"rules":[{"type":"field","ruleTag":"sb-geoip-geoip-cn-0-0","ip":["ext:sb-geoip-cn-`+strings.Repeat("a", 64)+`.dat:cn"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if legacy, err := legacyGeoIPRouting(root, xray, root); err != nil || !legacy {
		t.Fatalf("missing binary GeoIP did not migrate: %t %v", legacy, err)
	}
	reference, err := geoipasset.Publish(root, "geoip-cn", []byte(`{"rules":[{"ip_cidr":["203.0.113.0/24"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(xray, []byte(`{"routing":{"rules":[{"ruleTag":"sb-geoip-geoip-cn-0-0","ip":["`+reference+`"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if legacy, err := legacyGeoIPRouting(root, xray, root); err != nil || legacy {
		t.Fatalf("verified binary asset migrated again: %t %v", legacy, err)
	}
	name, _ := geoipasset.ReferenceName(reference)
	if err := os.WriteFile(filepath.Join(root, name), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if legacy, err := legacyGeoIPRouting(root, xray, root); err != nil || !legacy {
		t.Fatalf("damaged binary asset did not require reconciliation: %t %v", legacy, err)
	}
}

func TestUpdateRuntimeRevisionPreservesActiveMetadata(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"system": map[string]any{"deployment_ready": true}}
	configRevision, err := revisionFor(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.writeJSON(filepath.Join(repository.generations, configRevision+".json"), config); err != nil {
		t.Fatal(err)
	}
	active := map[string]any{
		"revision":         configRevision,
		"runtime_revision": repeatedText("3", 64), "actor": "admin", "routeros_source": "source",
	}
	if err := repository.writeJSON(filepath.Join(repository.root, "active.json"), active); err != nil {
		t.Fatal(err)
	}
	next := repeatedText("4", 64)
	if err := repository.updateRuntimeRevision(next); err != nil {
		t.Fatal(err)
	}
	got, err := repository.readJSON(filepath.Join(repository.root, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got["runtime_revision"] != next || got["previous_runtime_revision"] != repeatedText("3", 64) || got["actor"] != "admin" || got["routeros_source"] != "source" {
		t.Fatalf("active metadata changed unexpectedly: %#v", got)
	}
}

func repeatedText(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
