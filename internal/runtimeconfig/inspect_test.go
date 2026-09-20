package runtimeconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadXrayPlans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.json")
	body := []byte(`{
  "outbounds": [
    {"protocol":"freedom","tag":"wg-egress-b","sendThrough":"198.18.0.20"},
    {"protocol":"freedom","tag":"direct"},
    {"protocol":"freedom","tag":"wg-egress-a","inet4_bind_address":"198.18.0.10"}
  ],
  "routing":{"balancers":[
    {"tag":"clients","selector":["outbound-a","outbound-b"]},
    {"tag":"empty","selector":[]}
  ]}
}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	balancers, egress, err := ReadXray(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(balancers) != 1 || balancers[0].Tag != "clients" || balancers[0].Outbound != "outbound-a" {
		t.Fatalf("unexpected balancers: %#v", balancers)
	}
	if len(egress) != 2 || egress[0].Address != "198.18.0.10" || egress[0].Priority != 1001 || egress[1].Priority != 1002 {
		t.Fatalf("unexpected WireGuard plan: %#v", egress)
	}
}

func TestReadXrayRejectsUnsafeWireGuardAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[{"protocol":"freedom","tag":"wg-egress-bad","sendThrough":"192.0.2.1"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadXray(path); err == nil {
		t.Fatal("unsafe WireGuard source address accepted")
	}
}

func TestReadXrayRejectsDuplicateWireGuardAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, []byte(`{"outbounds":[
{"protocol":"freedom","tag":"wg-egress-a","sendThrough":"198.18.0.2"},
{"protocol":"freedom","tag":"wg-egress-b","sendThrough":"198.18.0.2"}
]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadXray(path); err == nil {
		t.Fatal("duplicate WireGuard source address accepted")
	}
}
