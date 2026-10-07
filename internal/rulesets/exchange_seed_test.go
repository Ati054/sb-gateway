package rulesets

import (
	"path/filepath"
	"testing"
)

func TestExchangeSeedsUpgradeExistingAPIListsWithoutLosingRules(t *testing.T) {
	packs, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, id := range []string{"bybit-api", "gateio-api"} {
		if err := writeJSON(filepath.Join(root, id+".json"), map[string]any{"version": 3, "rules": []any{map[string]any{"domain_suffix": []any{"retained.example"}}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := EnsureSeeds(root, packs); err != nil {
		t.Fatal(err)
	}
	for id, hosts := range map[string][]string{
		"bybit-api":  {"api.bybit.com", "api-testnet.manepa.jp", "api.spark-fintech.com", "api-testnet.spark-fintech.com", "stream.spark-fintech.com"},
		"gateio-api": {"api.gateio.ws", "api-testnet.gateapi.io"},
	} {
		rule := readRule(t, filepath.Join(root, id+".json"))
		for _, host := range append(hosts, "retained.example") {
			if !sliceContains(rule["domain_suffix"], host) {
				t.Errorf("upgraded %s lost %s", id, host)
			}
		}
	}
	changed, err := EnsureSeeds(root, packs)
	if err != nil || len(changed) != 0 {
		t.Fatalf("seed upgrade is not idempotent: %v, %v", changed, err)
	}
}
