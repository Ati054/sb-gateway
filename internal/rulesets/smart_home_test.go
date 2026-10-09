package rulesets

import (
	"path/filepath"
	"testing"
)

func TestSmartHomeSeedsAreSeparateAndPreserveExistingRules(t *testing.T) {
	packs, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	index := catalogIndex(packs)
	for _, id := range []string{"ewelink", "xiaomi-home", "tuya", "aqara", "shelly"} {
		pack, ok := index[id]
		if !ok {
			t.Fatalf("missing card %s", id)
		}
		if pack.AlwaysDirect || pack.Broad || pack.UpstreamName != nil || pack.UpdateMode != "official" || len(pack.IncludedPackIDs) != 0 {
			t.Fatalf("card %s forces routing or external dependencies", id)
		}
		if len(pack.IPCIDRs)+len(pack.TCPPorts)+len(pack.UDPPorts)+len(pack.TCPPortRanges)+len(pack.UDPPortRanges)+len(pack.SniffedProtocols) != 0 {
			t.Fatalf("card %s captures unrelated IP or protocol traffic", id)
		}
		if err := writeJSON(filepath.Join(root, id+".json"), map[string]any{"version": 3, "rules": []any{map[string]any{"domain_suffix": []any{"retained.example"}}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := EnsureSeeds(root, packs); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"ewelink", "xiaomi-home", "tuya", "aqara", "shelly"} {
		rule := readRule(t, filepath.Join(root, id+".json"))
		for _, domain := range append(index[id].FallbackDomains, "retained.example") {
			if !sliceContains(rule["domain_suffix"], domain) {
				t.Errorf("%s lost %s", id, domain)
			}
		}
	}
	changed, err := EnsureSeeds(root, packs)
	if err != nil || len(changed) != 0 {
		t.Fatalf("not idempotent: %v, %v", changed, err)
	}
}
