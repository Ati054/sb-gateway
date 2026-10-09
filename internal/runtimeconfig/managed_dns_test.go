package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestManagedDNSIngressPreservesClientPolicyAndRejectsUnknownSources(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		t.Run(mode, func(t *testing.T) {
			config := map[string]any{
				"system": map[string]any{"networking": map[string]any{"container_address": "198.18.0.2/29"}},
				"dns": map[string]any{
					"internal_server": "192.0.2.1", "internal_zones": []any{"home.test"},
					"direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"},
					"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
				},
				"policies": []any{map[string]any{"id": "vpn", "mode": mode, "traffic_mode": "vless_with_wan_exceptions", "torrent_direct": false, "direct_domains": []any{"wan.test"}}},
				"local_clients": []any{
					map[string]any{"id": "specific", "policy_id": "vpn", "source_cidrs": []any{"192.0.2.10/32"}},
					map[string]any{"id": "direct", "final": "direct-wan", "source_cidrs": []any{"192.0.2.0/24", "203.0.113.0/24"}},
					map[string]any{"id": "disabled", "enabled": false, "source_cidrs": []any{"198.51.100.0/24"}},
				},
			}
			source, err := BuildPolicyDNSSource(config, map[string]struct{}{"vpn": {}})
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := CompilePolicyDNS(source, PolicyDNSCompileOptions{Selectable: map[string]struct{}{"vpn": {}}, RuleSetRoot: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			inbound, rules := managedDNSIngress("198.18.0.2", compiled.XrayRules)
			if inbound["listen"] != "198.18.0.2" || inbound["port"] != ManagedDNSPort || objectValue(inbound["settings"])["network"] != "tcp,udp" {
				t.Fatalf("DNS must bind only the container address, TCP and UDP: %#v", inbound)
			}
			if len(rules) != 3 || !reflect.DeepEqual(stringSlice(rules[0]["source"]), []string{"192.0.2.10/32"}) || !reflect.DeepEqual(stringSlice(rules[1]["source"]), []string{"192.0.2.0/24", "203.0.113.0/24"}) {
				t.Fatalf("source-specific DNS lanes or specificity were lost: %#v", rules)
			}
			if rules[2]["outboundTag"] != "block" || !reflect.DeepEqual(stringSlice(rules[2]["inboundTag"]), []string{managedDNSInbound}) {
				t.Fatalf("unknown sources must not reach the catch-all resolver: %#v", rules)
			}
			lanes := map[string]PolicyDNSLane{}
			for _, lane := range compiled.Runtime.Lanes {
				lanes[lane.ID] = lane
			}
			vpn := lanes[textValue(rules[0]["outboundTag"])]
			direct := lanes[textValue(rules[1]["outboundTag"])]
			if vpn.Final != "policy-dns-vpn" || direct.Final != "direct-public-dns" {
				t.Fatalf("wrong DNS defaults: %#v / %#v", vpn, direct)
			}
			for _, lane := range []PolicyDNSLane{vpn, direct} {
				found := false
				for _, rule := range lane.Rules {
					if containsText(rule.DomainSuffix, "home.test") && rule.Server == "routeros-dns" {
						found = true
					}
				}
				if !found {
					t.Fatal("internal zones no longer use RouterOS DNS")
				}
			}
			foundWAN := false
			for _, rule := range vpn.Rules {
				if containsText(rule.DomainSuffix, "wan.test") && rule.Server == "direct-public-dns" {
					foundWAN = true
				}
			}
			if !foundWAN {
				t.Fatal("explicit WAN DNS exception was lost")
			}
		})
	}
}

func TestManagedDNSNoClientsHasNoResolverFallback(t *testing.T) {
	_, rules := managedDNSIngress("198.18.0.2", []map[string]any{{"port": "53", "outboundTag": "global-dns"}})
	if len(rules) != 1 || rules[0]["outboundTag"] != "block" {
		t.Fatalf("empty allowlist must reject: %#v", rules)
	}
}

func TestRouterOSManagedDNSUsesSharedGateAndPreservesLocalBypass(t *testing.T) {
	config := routerOSModelConfig()
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		`src-address-list="SB_MANAGED_CLIENTS" src-address="!172.31.255.2" disabled=yes`,
		`/ip/firewall/mangle/unset $gate dst-address-type`,
		`chain="sb-gateway-divert" action=return disabled=no dst-address-type=local`,
		`chain="sb-gateway-divert" action=return disabled=no dst-address-list="SB_INTERNAL_NETWORKS"`,
	} {
		if !strings.Contains(source, fragment) {
			t.Fatalf("missing scope or bypass %q", fragment)
		}
	}
	for _, proto := range []string{"udp", "tcp"} {
		want := `connection-mark="sb-managed" dst-address-type=local protocol=` + proto + ` dst-port=53 to-addresses="172.31.255.2" to-ports=1053 disabled=no`
		if !strings.Contains(source, want) {
			t.Fatalf("DNS NAT must require the shared connection mark: %s", proto)
		}
	}
	objectValue(config["dns"])["hijack_managed_clients"] = false
	disabled, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(disabled, `to-ports=1053 disabled=no`) {
		t.Fatal("disabled DNS hijack still diverts DNS")
	}
}

func TestManagedDNSPortCannotBeUsedByPublicTransportOrPanel(t *testing.T) {
	config := routerOSModelConfig()
	objectValue(objectValue(config["system"])["management"])["routeros_panel_port"] = ManagedDNSPort
	if _, err := BuildRouterOSRenderModel(config, nil); err == nil {
		t.Fatal("panel may not occupy the internal DNS port")
	}
	if err := ValidateSharedIngress(map[string]any{"transports": []any{map[string]any{"enabled": true, "kind": "hysteria2", "listen_port": ManagedDNSPort}}}); err == nil {
		t.Fatal("public UDP transport may not occupy the internal DNS port")
	}
}
