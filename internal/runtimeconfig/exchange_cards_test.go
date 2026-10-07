package runtimeconfig

import (
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

// Public REST/WS hosts from the exchanges' official documentation, reviewed
// 2026-10-07. Paths, TLS and nonstandard WS ports must not change routing.
func TestExchangeCardsRouteOfficialEndpointsThroughWAN(t *testing.T) {
	packs, err := rulesets.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if _, err := rulesets.EnsureSeeds(root, packs); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		card, dependency string
		hosts            []string
	}{
		{"bybit", "bybit-api", []string{
			"api.bybit.com", "api.bytick.com", "stream.bybit.com", "api-testnet.bybit.com", "stream-testnet.bybit.com",
			"api-demo.bybit.com", "stream-demo.bybit.com", "api.bybit.tr", "stream.bybit.tr", "api.bybit.kz", "stream.bybit.kz",
			"api.bybitgeorgia.ge", "stream.bybitgeorgia.ge", "api.bybit.ae", "api.bybit.eu", "api.bybit.id", "stream.bybit.id",
			"api.manepa.jp", "api-testnet.manepa.jp", "stream.manepa.jp", "api.spark-fintech.com", "api-testnet.spark-fintech.com", "stream.spark-fintech.com",
		}},
		{"gateio", "gateio-api", []string{"api.gateio.ws", "fx-api.gateio.ws", "fx-api-testnet.gateio.ws", "api-testnet.gateapi.io", "ws-testnet.gate.com"}},
		{"okx", "okx-api", []string{"openapi.okx.com", "www.okx.com", "ws.okx.com", "wspap.okx.com", "us.okx.com", "eea.okx.com", "tr.okx.com", "wsus.okx.com", "wseea.okx.com"}},
		{"binance", "", []string{"api.binance.com", "api1.binance.com", "api4.binance.com", "stream.binance.com", "ws-api.binance.com", "fapi.binance.com", "fstream.binance.com", "dapi.binance.com", "dstream.binance.com", "data-api.binance.vision", "data-stream.binance.vision", "testnet.binance.vision"}},
	}
	for _, test := range cases {
		t.Run(test.card, func(t *testing.T) {
			config := map[string]any{
				"dns": map[string]any{
					"internal_server": "192.168.88.1",
					"direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"},
					"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "dot"},
				},
				"policies":      []any{map[string]any{"id": "route", "enabled": true, "mode": "urltest", "traffic_mode": "vless_with_wan_exceptions", "direct_services": []any{test.card}, "torrent_direct": false}},
				"local_clients": []any{map[string]any{"id": "bot", "enabled": true, "policy_id": "route", "source_cidrs": []any{"192.168.88.10/32"}}},
			}
			route, err := BuildXrayRouteSource(config, nil, []map[string]any{{"tag": "route"}, {"tag": "direct-wan"}, {"tag": "block"}})
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := ConvertXrayRules(route["rules"], map[string]struct{}{"route": {}}, xrayRuleSetDescriptors(route["rule_set"]), root)
			if err != nil {
				t.Fatal(err)
			}
			for _, host := range test.hosts {
				matched := false
				for _, rule := range compiled {
					if rule["outboundTag"] != "direct-wan" || !containsText(stringSlice(rule["source"]), "192.168.88.10/32") {
						continue
					}
					for _, domain := range stringSlice(rule["domain"]) {
						suffix := strings.TrimPrefix(domain, "domain:")
						if strings.HasPrefix(domain, "domain:") && (host == suffix || strings.HasSuffix(host, "."+suffix)) {
							if rule["port"] != nil || rule["protocol"] != nil {
								t.Fatal("REST/WebSocket rule was narrowed by port or protocol")
							}
							matched = true
						}
					}
				}
				if !matched {
					t.Errorf("official endpoint %s does not route through WAN", host)
				}
			}
			dns, err := BuildPolicyDNSSource(config, map[string]struct{}{"route": {}})
			if err != nil {
				t.Fatal(err)
			}
			assertPolicyDNSRule(t, dns.Rules, func(rule PolicyDNSSourceRule) bool {
				return containsText(rule.SourceCIDR, "192.168.88.10/32") && rule.Server == "direct-public-dns" && containsText(rule.RuleSet, "service-"+test.card) && (test.dependency == "" || containsText(rule.RuleSet, "service-"+test.dependency))
			}, "parent card and its API dependency use WAN DNS")
			artifacts, err := CompilePolicyDNS(dns, PolicyDNSCompileOptions{Selectable: map[string]struct{}{"route": {}}, RuleSetRoot: root})
			if err != nil {
				t.Fatal(err)
			}
			for _, host := range test.hosts {
				matched := false
				for _, lane := range artifacts.Runtime.Lanes {
					for _, rule := range lane.Rules {
						if rule.Server != "direct-public-dns" {
							continue
						}
						for _, suffix := range rule.DomainSuffix {
							if host == suffix || strings.HasSuffix(host, "."+suffix) {
								matched = true
							}
						}
						if containsText(rule.Domain, host) {
							matched = true
						}
					}
				}
				if !matched {
					t.Errorf("official endpoint %s lacks compiled WAN DNS rule", host)
				}
			}
		})
	}
}

func TestExchangeCardDNSDependenciesForPolicyAndClientOverrides(t *testing.T) {
	for _, placement := range []string{"policy-direct", "client-direct", "policy-route", "client-route"} {
		for _, target := range []string{"direct-wan", "other", "missing"} {
			if strings.HasSuffix(placement, "direct") && target != "direct-wan" {
				continue
			}
			t.Run(placement+"/"+target, func(t *testing.T) {
				policy := map[string]any{"id": "route", "enabled": true, "mode": "urltest", "torrent_direct": false}
				client := map[string]any{"id": "bot", "enabled": true, "policy_id": "route", "source_cidrs": []any{"192.168.88.10/32"}}
				owner := policy
				if strings.HasPrefix(placement, "client") {
					owner = client
				}
				if strings.HasSuffix(placement, "direct") {
					owner["direct_services"] = []any{"bybit"}
				} else {
					owner["service_routes"] = map[string]any{"bybit": target}
				}
				source, err := BuildPolicyDNSSource(map[string]any{
					"dns":      map[string]any{"internal_server": "192.168.88.1", "direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"}, "vpn_resolver": map[string]any{"provider": "cloudflare", "protocol": "dot"}},
					"policies": []any{policy}, "local_clients": []any{client},
				}, map[string]struct{}{"route": {}, "other": {}})
				if err != nil {
					t.Fatal(err)
				}
				wantAction, wantServer := "route", "direct-public-dns"
				if target == "other" {
					wantServer = "policy-dns-other"
				} else if target == "missing" {
					wantAction, wantServer = "reject", ""
				}
				assertPolicyDNSRule(t, source.Rules, func(rule PolicyDNSSourceRule) bool {
					return containsText(rule.SourceCIDR, "192.168.88.10/32") && containsText(rule.RuleSet, "service-bybit") && containsText(rule.RuleSet, "service-bybit-api") && rule.Action == wantAction && rule.Server == wantServer
				}, "card dependencies retain identity, detour and fail-closed behavior")
			})
		}
	}
}
