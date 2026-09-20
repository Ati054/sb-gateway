package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildPolicyDNSSourceFromCurrentConfig(t *testing.T) {
	selector := policyServiceSelectorTag("europe", "claude")
	config := map[string]any{
		"dns": map[string]any{
			"internal_server": "192.168.88.1",
			"direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "dot"},
			"internal_zones":  []any{"lan.example"},
		},
		"policies": []any{map[string]any{
			"id": "europe", "enabled": true, "mode": "priority",
			"traffic_mode":          "vless_with_wan_exceptions",
			"candidate_service_ids": []any{"claude", "claude"},
			"direct_domains":        []any{"https://Example.COM/path"},
		}},
		"local_clients": []any{
			map[string]any{"id": "all-lan", "enabled": true, "policy_id": "europe", "source_kind": "lan", "source_scope": "lan-all", "source_cidrs": []any{"10.0.0.0/24"}},
			map[string]any{"id": "phone", "enabled": true, "policy_id": "europe", "source_kind": "lan", "source_cidrs": []any{"10.0.0.2/32"}},
		},
		"remote_users": []any{
			map[string]any{"id": "admin", "enabled": true, "role": "trusted-full", "policy_id": "europe"},
			map[string]any{"id": "guest", "enabled": true},
		},
	}
	source, err := BuildPolicyDNSSource(config, map[string]struct{}{"europe": {}, selector: {}})
	if err != nil {
		t.Fatal(err)
	}
	if source.Final != "direct-public-dns" || len(source.Servers) != 5 {
		t.Fatalf("unexpected DNS source header: %#v", source)
	}
	if source.Servers[1].Tag != "direct-public-dns" || source.Servers[1].Type != "https" || !source.Servers[1].DoTFallback {
		t.Fatalf("direct resolver contract changed: %#v", source.Servers[1])
	}
	if source.Servers[2].Tag != "subscription-update-dns" || source.Servers[2].Type != "tls" {
		t.Fatalf("VPN resolver contract changed: %#v", source.Servers[2])
	}

	wantIdentity := []string{"10.0.0.2/32"}
	assertPolicyDNSRule(t, source.Rules, func(rule PolicyDNSSourceRule) bool {
		return reflect.DeepEqual(rule.SourceCIDR, wantIdentity) && reflect.DeepEqual(rule.DomainSuffix, []string{"example.com"}) && rule.Server == "direct-public-dns"
	}, "normalized direct-domain rule")
	assertPolicyDNSRule(t, source.Rules, func(rule PolicyDNSSourceRule) bool {
		return reflect.DeepEqual(rule.SourceCIDR, wantIdentity) && reflect.DeepEqual(rule.RuleSet, []string{"service-torrent"}) && rule.Server == "direct-public-dns"
	}, "automatic direct torrent rule")
	assertPolicyDNSRule(t, source.Rules, func(rule PolicyDNSSourceRule) bool {
		return reflect.DeepEqual(rule.SourceCIDR, wantIdentity) && reflect.DeepEqual(rule.RuleSet, []string{"service-claude"}) && rule.Server == "policy-dns-"+selector
	}, "candidate service selector rule")
	assertPolicyDNSRule(t, source.Rules, func(rule PolicyDNSSourceRule) bool {
		return reflect.DeepEqual(rule.SourceCIDR, wantIdentity) && len(rule.RuleSet) == 0 && len(rule.DomainSuffix) == 0 && rule.Server == "policy-dns-europe"
	}, "local policy final")
	exactFinal, allLANFinal := -1, -1
	for index, rule := range source.Rules {
		if rule.Server != "policy-dns-europe" || len(rule.DomainSuffix) != 0 || len(rule.RuleSet) != 0 {
			continue
		}
		if reflect.DeepEqual(rule.SourceCIDR, []string{"10.0.0.2/32"}) {
			exactFinal = index
		}
		if reflect.DeepEqual(rule.SourceCIDR, []string{"10.0.0.0/24"}) {
			allLANFinal = index
		}
	}
	if exactFinal < 0 || allLANFinal < 0 || exactFinal >= allLANFinal {
		t.Fatalf("specific DNS policy must precede all-LAN fallback: exact=%d all=%d", exactFinal, allLANFinal)
	}
	assertPolicyDNSRule(t, source.Rules, func(rule PolicyDNSSourceRule) bool {
		return reflect.DeepEqual(rule.AuthUser, []string{"admin"}) && reflect.DeepEqual(rule.DomainSuffix, []string{"lan.example"}) && rule.Server == "routeros-dns"
	}, "trusted internal DNS rule")
	assertPolicyDNSRule(t, source.Rules, func(rule PolicyDNSSourceRule) bool {
		return reflect.DeepEqual(rule.AuthUser, []string{"guest"}) && rule.Action == "reject" && len(rule.DomainSuffix) == 0
	}, "unassigned remote fail-closed rule")
}

func TestBuildPolicyDNSSourceRejectsLegacyAndInvalidResolvers(t *testing.T) {
	base := func(provider, protocol string) map[string]any {
		return map[string]any{"dns": map[string]any{
			"internal_server": "192.168.88.1",
			"direct_resolver": map[string]any{"provider": provider, "protocol": protocol},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
		}}
	}
	if _, err := BuildPolicyDNSSource(base("routeros", "doh"), nil); err == nil || !strings.Contains(err.Error(), "provider") {
		t.Fatalf("legacy resolver was not rejected: %v", err)
	}
	if _, err := BuildPolicyDNSSource(base("cloudflare", "plain"), nil); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("invalid protocol was not rejected: %v", err)
	}
	invalid := base("cloudflare", "doh")
	invalid["dns"].(map[string]any)["internal_server"] = "not-an-ip"
	if _, err := BuildPolicyDNSSource(invalid, nil); err == nil || !strings.Contains(err.Error(), "internal_server") {
		t.Fatalf("invalid internal resolver was not rejected: %v", err)
	}
}

func TestDirectPublicDNSServerUsesSelectedEncryptedProfile(t *testing.T) {
	config := map[string]any{"dns": map[string]any{
		"direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"},
	}}
	resolver, err := DirectPublicDNSServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.Type != "https" || resolver.Server != "77.88.8.8" || resolver.TLS.ServerName != "common.dot.dns.yandex.net" || resolver.ServerPort != 443 || resolver.Path != "/dns-query" || !resolver.DoTFallback {
		t.Fatalf("unexpected DoH resolver: %#v", resolver)
	}
	config["dns"].(map[string]any)["direct_resolver"] = map[string]any{"provider": "quad9", "protocol": "dot"}
	resolver, err = DirectPublicDNSServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.Type != "tls" || resolver.Server != "9.9.9.9" || resolver.ServerPort != 853 || resolver.DoTFallback {
		t.Fatalf("unexpected DoT resolver: %#v", resolver)
	}
}

func TestRenderPolicyDNSComposesSourceAndRuntime(t *testing.T) {
	config := map[string]any{"dns": map[string]any{
		"internal_server": "192.168.88.1",
		"direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"},
		"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "dot"},
	}}
	artifacts, body, err := RenderPolicyDNS(config, PolicyDNSCompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.Runtime.Lanes) != 3 {
		t.Fatalf("expected two updater identities and one catch-all lane: %#v", artifacts.Runtime.Lanes)
	}
	if !strings.HasSuffix(string(body), "\n") || !strings.Contains(string(body), `"direct-public-dns"`) {
		t.Fatalf("unexpected rendered policy DNS: %s", body)
	}
}

func assertPolicyDNSRule(t *testing.T, rules []PolicyDNSSourceRule, match func(PolicyDNSSourceRule) bool, name string) {
	t.Helper()
	for _, rule := range rules {
		if match(rule) {
			return
		}
	}
	t.Fatalf("missing %s in %#v", name, rules)
}
