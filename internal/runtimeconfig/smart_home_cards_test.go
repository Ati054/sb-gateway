package runtimeconfig

import (
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

func smartHomeHostMatches(host string, domains []string) bool {
	for _, raw := range domains {
		domain := strings.TrimPrefix(raw, "domain:")
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func TestSmartHomeCardsRouteTrafficAndDNSTogether(t *testing.T) {
	packs, err := rulesets.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if _, err := rulesets.EnsureSeeds(root, packs); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id    string
		hosts []string
	}{
		{"ewelink", []string{"eu-disp.coolkit.cc", "eu-dispa.coolkit.cc", "eu-dispd.coolkit.cc", "eu-apia.coolkit.cc", "us-pconnect3.coolkit.cc", "cn-apia.coolkit.cn"}},
		{"xiaomi-home", []string{"api.io.mi.com", "ru.ha.api.io.mi.com", "de-ha.mqtt.io.mi.com", "ot.io.mi.com", "iot.mi.com", "account.xiaomi.com"}},
		{"tuya", []string{"openapi.tuyaeu.com", "m1.tuyacn.com", "m1.tuyaus.com", "m1-weaz.tuyaeu.com", "m1.tuyain.com", "m1-sg.iotbing.com", "smartlife.app.tuya.com", "tuyasmart.com"}},
		{"aqara", []string{"rpc-ger.aqara.com", "coap-ru.aqara.com", "open-usa.aqara.com", "aiot-coap.aqara.cn", "aiot-rpc.ankasa.cn"}},
		{"shelly", []string{"shelly-20-eu.shelly.cloud", "shelly-api-eu.shelly.cloud", "control.shelly.cloud"}},
	}
	for _, card := range cases {
		for _, mode := range []string{"vless_with_wan_exceptions", "wan_with_vless_exceptions"} {
			for _, placement := range []string{"policy", "client"} {
				for _, target := range []string{"direct-wan", "other", "missing"} {
					t.Run(card.id+"/"+mode+"/"+placement+"/"+target, func(t *testing.T) {
						policy := map[string]any{"id": "route", "enabled": true, "mode": "urltest", "traffic_mode": mode, "torrent_direct": false}
						client := map[string]any{"id": "device", "enabled": true, "policy_id": "route", "source_cidrs": []any{"192.168.88.10/32"}}
						owner := policy
						if placement == "client" {
							owner = client
						}
						if target == "direct-wan" {
							owner["direct_services"] = []any{card.id}
						} else {
							owner["service_routes"] = map[string]any{card.id: target}
						}
						config := map[string]any{
							"dns":           map[string]any{"internal_server": "192.168.88.1", "direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"}, "vpn_resolver": map[string]any{"provider": "cloudflare", "protocol": "dot"}},
							"policies":      []any{policy, map[string]any{"id": "other", "enabled": true, "mode": "priority", "torrent_direct": false}},
							"local_clients": []any{client},
						}
						selectable := map[string]struct{}{"route": {}, "other": {}}
						source, err := BuildXrayRouteSource(config, nil, []map[string]any{{"tag": "route"}, {"tag": "other"}, {"tag": "direct-wan"}, {"tag": "block"}})
						if err != nil {
							t.Fatal(err)
						}
						traffic, err := ConvertXrayRules(source["rules"], selectable, xrayRuleSetDescriptors(source["rule_set"]), root)
						if err != nil {
							t.Fatal(err)
						}
						dns, err := BuildPolicyDNSSource(config, selectable)
						if err != nil {
							t.Fatal(err)
						}
						compiled, err := CompilePolicyDNS(dns, PolicyDNSCompileOptions{Selectable: selectable, RuleSetRoot: root})
						if err != nil {
							t.Fatal(err)
						}
						for _, host := range card.hosts {
							matchedTraffic, matchedDNS := false, false
							for _, rule := range traffic {
								if !containsText(stringSlice(rule["source"]), "192.168.88.10/32") || !smartHomeHostMatches(host, stringSlice(rule["domain"])) {
									continue
								}
								matchedTraffic = true
								switch target {
								case "direct-wan":
									if rule["outboundTag"] != "direct-wan" {
										t.Fatalf("%s did not choose WAN: %#v", host, rule)
									}
								case "other":
									if rule["balancerTag"] != "other" {
										t.Fatalf("%s did not choose VLESS list: %#v", host, rule)
									}
								default:
									if rule["outboundTag"] != "block" {
										t.Fatalf("%s did not fail closed: %#v", host, rule)
									}
								}
								if rule["port"] != nil || rule["protocol"] != nil || rule["network"] != nil {
									t.Fatalf("card constrained by port or protocol: %#v", rule)
								}
							}
							for _, lane := range compiled.Runtime.Lanes {
								for _, rule := range lane.Rules {
									if !smartHomeHostMatches(host, rule.DomainSuffix) {
										continue
									}
									matchedDNS = true
									switch target {
									case "direct-wan":
										if rule.Server != "direct-public-dns" {
											t.Fatalf("%s DNS not WAN", host)
										}
									case "other":
										if rule.Server != "policy-dns-other" {
											t.Fatalf("%s DNS not VLESS", host)
										}
									default:
										if rule.Action != "reject" {
											t.Fatalf("%s DNS not rejected", host)
										}
									}
								}
							}
							if !matchedTraffic || !matchedDNS {
								t.Fatalf("%s missing traffic=%v DNS=%v", host, matchedTraffic, matchedDNS)
							}
						}
					})
				}
			}
		}
	}
}
