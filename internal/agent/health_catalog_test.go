package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

func syntheticAgentCatalog(t *testing.T, count int) (string, subscriptioncatalog.Ref) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "private-catalog")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	builder, err := subscriptioncatalog.NewBuilder(root, subscriptioncatalog.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("feed-node-%03d", i)
		baseID := fmt.Sprintf("node-%03d", i)
		node, _ := json.Marshal(map[string]any{"id": baseID, "subscription_id": "feed", "protocol": "vless", "server": "example.test", "server_port": 443, "uuid_secret_ref": "@catalog:uuid"})
		metadata, _ := json.Marshal(map[string]any{"id": id, "provider_node_id": baseID, "subscription_id": "feed", "definition_fingerprint": strings.Repeat("b", 64)})
		if err := builder.Append(context.Background(), subscriptioncatalog.Record{ID: id, Node: node, Metadata: metadata, Secrets: json.RawMessage(`{"@catalog:uuid":"123e4567-e89b-42d3-a456-426614174000"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := builder.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return root, ref
}

func TestCatalogDefinitionLookupIsLazySharedAndBounded(t *testing.T) {
	root, ref := syntheticAgentCatalog(t, 40)
	cache := &catalogDefinitionCache{}
	defer cache.close()
	definition := runtimeconfig.CatalogDefinition{Generation: ref.Generation, Fingerprint: strings.Repeat("b", 64), FingerprintKind: runtimeconfig.CatalogFingerprintKind}
	first, err := cache.lookup(context.Background(), root, "feed-node-000", definition, ref)
	if err != nil {
		t.Fatal(err)
	}
	again, err := cache.lookup(context.Background(), root, "feed-node-000", definition, ref)
	if err != nil {
		t.Fatal(err)
	}
	if &first[0] != &again[0] || len(cache.bodies) != 1 || len(cache.readers) != 1 {
		t.Fatal("same definition was decoded or copied per lookup")
	}
	for i := 1; i < 40; i++ {
		if _, err := cache.lookup(context.Background(), root, fmt.Sprintf("feed-node-%03d", i), definition, ref); err != nil {
			t.Fatal(err)
		}
	}
	if len(cache.bodies) > catalogDefinitionCacheEntries || cache.bytes > catalogDefinitionCacheBytes {
		t.Fatal("definition cache exceeded its byte/entry bounds")
	}
	changed := definition
	changed.Fingerprint = strings.Repeat("c", 64)
	if _, err := cache.lookup(context.Background(), root, "feed-node-000", changed, ref); err == nil {
		t.Fatal("mixed pool/catalog fingerprints accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.lookup(ctx, root, "feed-node-000", definition, ref); err == nil {
		t.Fatal("cancelled definition lookup accepted")
	}
	cache.close()
	if _, err := cache.lookup(context.Background(), root, "feed-node-000", definition, ref); err == nil {
		t.Fatal("closed readers reopened")
	}
}

func TestV5HealthPoolSharesTypedMetadataAndKeepsLegacyTagAlgorithm(t *testing.T) {
	generation := strings.Repeat("a", 64)
	fingerprint := strings.Repeat("b", 64)
	body := fmt.Sprintf(`{"version":5,"catalogs":{"%s":{"generation":"%s"}},"catalog_definitions":{"node":{"generation":"%s","fingerprint":"%s","fingerprint_kind":"connection-node-secrets-v1"}},"nodes":{"node":{"label":"Node","fingerprint":"connection-node-secrets-v1:%s"}},"health_policies":{"one":{"candidates":["node"]},"two":{"candidates":["node"]}}}`, generation, generation, generation, fingerprint, fingerprint)
	var pool healthPool
	if err := json.Unmarshal([]byte(body), &pool); err != nil {
		t.Fatal(err)
	}
	one, two := pool.HealthPolicies["one"].Nodes, pool.HealthPolicies["two"].Nodes
	one["alias"] = healthNode{Label: "shared"}
	if two["alias"].Label != "shared" {
		t.Fatal("metadata was copied per policy")
	}
	delete(one, "alias")
	encoded, err := json.Marshal(pool)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	_ = json.Unmarshal(encoded, &decoded)
	for _, raw := range decoded["health_policies"].(map[string]any) {
		if raw.(map[string]any)["nodes"] != nil {
			t.Fatal("shared index serialized per policy")
		}
	}
	runtime := newXraySelectorRuntime(Options{})
	runtime.pool = pool
	want := runtimeconfig.CatalogDynamicOutboundTag("prefix-", "node", pool.CatalogDefinitions["node"])
	if got := runtime.dynamicTag("prefix-", "node"); got != want {
		t.Fatal("catalog tag mismatch")
	}
	legacy := json.RawMessage(`{"tag":"node","protocol":"freedom"}`)
	runtime.pool = healthPool{Version: 4, Outbounds: map[string]json.RawMessage{"node": legacy}}
	if got := runtime.dynamicTag("prefix-", "node"); got != runtimeconfig.DynamicOutboundTag("prefix-", "node", legacy) {
		t.Fatal("v4 tag algorithm changed")
	}
}

func TestCatalogStorageGenerationAloneDoesNotResetHotEndpointContract(t *testing.T) {
	definition := runtimeconfig.CatalogDefinition{Generation: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), FingerprintKind: runtimeconfig.CatalogFingerprintKind}
	previous := healthPool{Version: 5, CatalogDefinitions: map[string]runtimeconfig.CatalogDefinition{"node": definition}}
	definition.Generation = strings.Repeat("c", 64)
	target := healthPool{Version: 5, CatalogDefinitions: map[string]runtimeconfig.CatalogDefinition{"node": definition}}
	if !healthSettingsOnly(previous, target) {
		t.Fatal("unchanged endpoint reset due only to new disk generation")
	}
	definition.Fingerprint = strings.Repeat("d", 64)
	target.CatalogDefinitions["node"] = definition
	if healthSettingsOnly(previous, target) {
		t.Fatal("changed endpoint treated as a settings-only reload")
	}
}

func TestCatalogCurrentDoesNotMaterializeCandidateInventory(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{SubscriptionCatalogRoot: "must-not-be-opened"})
	definitions := make(map[string]runtimeconfig.CatalogDefinition)
	candidates := make([]string, 10000)
	for i := range candidates {
		id := fmt.Sprintf("feed-node-%05d", i)
		candidates[i] = id
		definitions[id] = runtimeconfig.CatalogDefinition{Generation: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), FingerprintKind: runtimeconfig.CatalogFingerprintKind}
	}
	prefix := "sb-urltest-test-"
	runtime.pool = healthPool{Version: 5, CatalogDefinitions: definitions, HealthPolicies: map[string]healthPolicyContract{"best": {Candidates: candidates}}, PolicyPrefixes: map[string]string{"best": prefix}}
	want := candidates[len(candidates)-1]
	tag := runtime.dynamicTag(prefix, want)
	runtime.loadedDynamic[tag] = true
	runtime.verifiedDynamic[tag] = time.Now()
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "bi" {
			return selectorInfo(tag), nil
		}
		return nil, fmt.Errorf("unexpected control command")
	}
	got, err := runtime.Current("best")
	if err != nil || got != want {
		t.Fatalf("current=%q err=%v", got, err)
	}
	if runtime.poolCache.definitions != nil {
		t.Fatal("Current opened the private definition source while scanning compact candidate identities")
	}
}
