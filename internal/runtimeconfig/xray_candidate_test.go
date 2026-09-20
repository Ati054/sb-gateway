package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestRenderXrayCandidateComposesNativeArtifacts(t *testing.T) {
	config := map[string]any{
		"system": map[string]any{"networking": map[string]any{
			"container_address": "172.31.255.2/30", "remote_ipv6_mode": "proxy_only",
		}},
		"dns": map[string]any{
			"internal_server": "192.168.88.1",
			"direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "dot"},
		},
		"policies":            []any{map[string]any{"id": "europe", "enabled": true, "mode": "best"}},
		"reverse_vless_exits": []any{map[string]any{"id": "home", "enabled": true}},
	}
	source := map[string]any{
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-routeros", "interface_name": "sb-tun0",
			"address": []any{"172.31.255.2/30"}, "mtu": 1400,
		}},
		"outbounds": []any{
			map[string]any{"type": "selector", "tag": "europe", "outbounds": []any{"provider-de", "reverse-vless-home"}},
			map[string]any{"type": "selector", "tag": "outbound-health-probe", "outbounds": []any{"provider-de"}},
			map[string]any{"type": "direct", "tag": "direct-wan"},
			map[string]any{"type": "block", "tag": "block"},
			map[string]any{"type": "direct", "tag": "reverse-vless-home"},
			map[string]any{
				"type": "vless", "tag": "provider-de", "server": "de.example", "server_port": 443,
				"uuid": "11111111-1111-1111-1111-111111111111",
			},
		},
		"route": map[string]any{"rules": []any{
			map[string]any{"action": "route", "outbound": "europe", "inbound": []any{"tun-routeros"}},
		}},
	}
	artifacts, err := RenderXrayCandidate(config, source, XrayCandidateOptions{RuleSetRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	inbounds := objectSlice(artifacts.Config["inbounds"])
	if inbounds[len(inbounds)-1]["tag"] != "xray-api" {
		t.Fatalf("API inbound is not last: %#v", inbounds)
	}
	outbounds := objectSlice(artifacts.Config["outbounds"])
	for _, outbound := range outbounds {
		if outbound["tag"] == "reverse-vless-home" {
			t.Fatalf("reverse tag was replaced by Freedom: %#v", outbound)
		}
	}
	routing := objectValue(artifacts.Config["routing"])
	balancers := objectSlice(routing["balancers"])
	if !containsText(stringSlice(balancers[0]["selector"]), urlTestPolicyPrefix("europe")) {
		t.Fatalf("URLTest prefix missing: %#v", balancers[0])
	}
	if !containsText(stringSlice(balancers[0]["selector"]), "reverse-vless-home") {
		t.Fatalf("reverse exit is not selectable for internet routing: %#v", balancers[0])
	}
	if !containsText(stringSlice(balancers[1]["selector"]), "sb-urltest-") {
		t.Fatalf("health URLTest prefix missing: %#v", balancers[1])
	}
	rules := objectSlice(routing["rules"])
	if !reflect.DeepEqual(rules[0], map[string]any{
		"type": "field", "inboundTag": []string{"xray-api"}, "outboundTag": "xray-api",
	}) {
		t.Fatalf("API route changed: %#v", rules[0])
	}
	if len(artifacts.PolicyDNS.Lanes) == 0 || !strings.HasSuffix(string(artifacts.PolicyDNSBody), "\n") {
		t.Fatalf("policy DNS was not rendered: %#v", artifacts.PolicyDNS)
	}
	policy := objectValue(artifacts.Config["policy"])
	levelZero := objectValue(objectValue(policy["levels"])["0"])
	if levelZero["bufferSize"] != xrayConnectionBufferKiB {
		t.Fatalf("ARM64 connection buffer is not optimized: %#v", levelZero)
	}
	body, err := MarshalXrayCandidate(artifacts.Config)
	if err != nil || !strings.HasSuffix(string(body), "\n") || !strings.Contains(string(body), `"domainMatcher": "hybrid"`) {
		t.Fatalf("canonical Xray JSON changed: %v\n%s", err, body)
	}
}

func TestRenderXrayCandidateRequiresContainerIPv4(t *testing.T) {
	config := map[string]any{
		"system": map[string]any{"networking": map[string]any{"container_address": "2001:db8::2/64"}},
	}
	_, err := RenderXrayCandidate(config, nil, XrayCandidateOptions{})
	if err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Fatalf("IPv6 container address was accepted: %v", err)
	}
}

func TestAddURLTestSelectorsAllowsDynamicPriorityAndServiceMembers(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{
		"id": "europe", "enabled": true, "mode": "priority", "candidate_service_ids": []any{"claude"},
	}}}
	serviceTag := policyServiceSelectorTag("europe", "claude")
	balancers := []map[string]any{
		{"tag": "europe", "selector": []any{"block", "provider-old"}},
		{"tag": serviceTag, "selector": []any{policyServiceBlockTag("europe"), "provider-old"}},
	}
	addURLTestSelectors(config, balancers)
	prefix := urlTestPolicyPrefix("europe")
	for _, balancer := range balancers {
		if !containsText(stringSlice(balancer["selector"]), prefix) {
			t.Fatalf("dynamic prefix missing from %s: %#v", balancer["tag"], balancer)
		}
	}
}
