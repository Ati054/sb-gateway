package runtimeconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConvertXrayRulesPreservesPolicyAndTerminalBlock(t *testing.T) {
	rules, err := ConvertXrayRules([]any{
		map[string]any{"action": "sniff", "inbound": []any{"tun-routeros"}},
		map[string]any{"action": "hijack-dns", "network": []any{"tcp", "udp"}},
		map[string]any{
			"action": "route", "outbound": "europe", "inbound": []any{"tun-routeros"},
			"auth_user": []any{"alice"}, "domain_suffix": []any{"example.com"}, "domain": []any{"exact.example"},
			"network": []any{"tcp", "udp"}, "port": []any{443}, "port_range": []any{"8000:8010"}, "ip_version": 6,
		},
		map[string]any{"action": "reject", "source_ip_cidr": []any{"192.168.3.0/24"}},
	}, map[string]struct{}{"europe": {}}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("rules = %#v", rules)
	}
	first := rules[0]
	if first["balancerTag"] != "europe" || first["network"] != "tcp,udp" || first["port"] != "443,8000-8010" {
		t.Fatalf("route conversion changed: %#v", first)
	}
	if !reflect.DeepEqual(first["domain"], []string{"domain:example.com", "full:exact.example"}) || !reflect.DeepEqual(first["ip"], []string{"::/0"}) {
		t.Fatalf("domain/IP conversion changed: %#v", first)
	}
	if rules[1]["outboundTag"] != "block" || !reflect.DeepEqual(rules[1]["source"], []string{"192.168.3.0/24"}) {
		t.Fatalf("reject conversion changed: %#v", rules[1])
	}
	wantTerminal := map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "block"}
	if !reflect.DeepEqual(rules[2], wantTerminal) {
		t.Fatalf("terminal rule = %#v", rules[2])
	}
}

func TestConvertXrayRulesExpandsRulesetOnce(t *testing.T) {
	root := t.TempDir()
	body := `{"rules":[{"domain_suffix":["video.example"]},{"ip_cidr":["203.0.113.0/24"],"port":[443],"network":"tcp"}]}`
	if err := os.WriteFile(filepath.Join(root, "video.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := ConvertXrayRules([]any{map[string]any{
		"action": "route", "outbound": "vpn", "auth_user": []any{"alice"}, "rule_set": []any{"service-video"},
	}}, nil, map[string]PolicyDNSRuleSetDescriptor{"service-video": {Path: "/config/rulesets/video.srs"}}, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || !reflect.DeepEqual(rules[0]["domain"], []string{"domain:video.example"}) {
		t.Fatalf("expanded rules = %#v", rules)
	}
	if !reflect.DeepEqual(rules[1]["ip"], []string{"203.0.113.0/24"}) || rules[1]["port"] != "443" || rules[1]["network"] != "tcp" {
		t.Fatalf("ruleset conditions changed: %#v", rules[1])
	}
	if !reflect.DeepEqual(rules[1]["user"], []string{"alice"}) {
		t.Fatalf("base identity was not preserved: %#v", rules[1])
	}
}

func TestConvertXrayRulesRejectsBrokenRuleset(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "empty.json"), []byte(`{"rules":[{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ConvertXrayRules([]any{map[string]any{
		"action": "route", "outbound": "vpn", "rule_set": []any{"service-empty"},
	}}, nil, nil, root)
	if err == nil || !strings.Contains(err.Error(), "no usable match conditions") {
		t.Fatalf("empty ruleset was accepted: %v", err)
	}
}
