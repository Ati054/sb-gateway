package rulesets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCatalogAndOfflineSeeds(t *testing.T) {
	packs, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(packs) != 43 || packs[0].Name != "Госуслуги и государственные сайты" {
		t.Fatalf("embedded catalog is incomplete or incorrectly encoded: %d %#v", len(packs), packs[0])
	}
	root := t.TempDir()
	created, err := EnsureSeeds(root, packs)
	if err != nil || len(created) != len(packs) {
		t.Fatalf("seed creation failed: %d/%d, %v", len(created), len(packs), err)
	}
	telegram := readRule(t, filepath.Join(root, "telegram.json"))
	if !sliceContains(telegram["ip_cidr"], "149.154.160.0/20") || !sliceContains(telegram["ip_cidr"], "2001:b28:f23d::/48") {
		t.Fatalf("Telegram networks missing: %#v", telegram)
	}
	calls := readRule(t, filepath.Join(root, "calls.json"))
	if calls["network"] != "udp" || !sliceContains(calls["port_range"], "16393:16402") {
		t.Fatalf("reviewed call ranges missing: %#v", calls)
	}
}

func TestCompileDomainListRecursiveIncludes(t *testing.T) {
	sources := map[string]string{
		"root":   "example.com\nfull:api.example.net\ninclude:shared\n",
		"shared": "domain:cdn.example.org\nkeyword:video-edge\nregexp:^img[0-9]+\\.example\\.org$\n",
	}
	payload, err := CompileDomainList("root", func(name string) (string, error) {
		value, exists := sources[name]
		if !exists {
			return "", errors.New("missing source")
		}
		return value, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := payload["rules"].([]any)
	rule := rules[0].(map[string]any)
	if !reflect.DeepEqual(rule["domain"], []string{"api.example.net"}) ||
		!reflect.DeepEqual(rule["domain_suffix"], []string{"cdn.example.org", "example.com"}) {
		t.Fatalf("unexpected compiled rules: %#v", rule)
	}
}

func TestRefreshFailureKeepsLastKnownGood(t *testing.T) {
	packs, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	index := catalogIndex(packs)
	root := t.TempDir()
	if _, err := EnsureSeeds(root, packs); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "ozon.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshPack(index["ozon"], root, func(string) (string, error) {
		return "", errors.New("offline")
	}); err == nil {
		t.Fatal("offline refresh unexpectedly succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("last-known-good ruleset changed after refresh failure")
	}
}

func TestActivePacksFollowDependencies(t *testing.T) {
	packs, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	config := map[string]any{
		"policies": []any{map[string]any{
			"id": "main", "enabled": true, "direct_services": []any{"ru-marketplaces"},
			"service_routes": map[string]any{"telegram": "proxy"},
		}},
		"local_clients": []any{}, "remote_users": []any{}, "service_packs": []any{},
	}
	revision := writeGeneration(t, state, config)
	if err := writeJSON(filepath.Join(state, "active.json"), map[string]any{"revision": revision}); err != nil {
		t.Fatal(err)
	}
	active, err := ActivePacks(state, packs)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(active))
	for index, pack := range active {
		ids[index] = pack.ID
	}
	expected := []string{"ozon", "ru-delivery", "ru-marketplaces", "ru-retail", "telegram"}
	if !reflect.DeepEqual(ids, expected) {
		t.Fatalf("unexpected active packs: %#v", ids)
	}
}

func TestReleaseCatalogPinsTelecomAndBinanceFallbackDomains(t *testing.T) {
	packs, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	index := catalogIndex(packs)
	for _, domain := range []string{"211.ru", "sibset.ru", "sibseti.ru", "lk.sibseti.ru"} {
		if !containsString(index["ru-telecom"].FallbackDomains, domain) {
			t.Fatalf("ru-telecom release fallback misses %q: %#v", domain, index["ru-telecom"])
		}
	}
	for _, domain := range []string{"binance.com", "binance.vision", "token.awswaf.com"} {
		if !containsString(index["binance"].FallbackDomains, domain) {
			t.Fatalf("Binance release fallback misses %q: %#v", domain, index["binance"])
		}
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func readRule(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := readObject(path, maxSourceBytes)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := payload["rules"].([]any)
	if len(rules) == 0 {
		t.Fatalf("rules missing in %s", path)
	}
	return rules[0].(map[string]any)
}

func sliceContains(value any, wanted string) bool {
	values, _ := value.([]any)
	for _, item := range values {
		if item == wanted {
			return true
		}
	}
	return false
}

func writeGeneration(t *testing.T, state string, config map[string]any) string {
	t.Helper()
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Bytes(body)
	path := filepath.Join(state, "generations", digest+".json")
	if err := writeJSON(path, config); err != nil {
		t.Fatal(err)
	}
	return digest
}

func sha256Bytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
