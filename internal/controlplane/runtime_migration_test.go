package controlplane

import (
	"os"
	"path/filepath"
	"testing"
)

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
	legacy, err := legacyGeoIPRouting(root, xray)
	if err != nil || !legacy {
		t.Fatalf("untagged GeoIP must migrate: %t, %v", legacy, err)
	}
	if err := os.WriteFile(xray, []byte(`{"routing":{"rules":[{"type":"field","ruleTag":"sb-geoip-geoip-cn-0-0","ip":["203.0.113.0/24"]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err = legacyGeoIPRouting(root, xray)
	if err != nil || legacy {
		t.Fatalf("tagged GeoIP migrated again: %t, %v", legacy, err)
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
