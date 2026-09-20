package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestConvertXrayOutboundsFlattensSelectorsAndBindsDirectWAN(t *testing.T) {
	values := []map[string]any{
		{"type": "selector", "tag": "europe", "outbounds": []any{"germany", "france", "block"}},
		{"type": "selector", "tag": "priority", "outbounds": []any{"europe", "france", "reverse-vless-home"}},
		{"type": "direct", "tag": "direct-wan"},
		{"type": "direct", "tag": "wireguard", "inet4_bind_address": "198.18.0.2"},
		{"type": "block", "tag": "block"},
		{"type": "direct", "tag": "reverse-vless-home"},
	}
	set, err := ConvertXrayOutbounds(values, "172.31.255.2", []string{"192.168.3.0/24"}, map[string]struct{}{"reverse-vless-home": {}})
	if err != nil {
		t.Fatal(err)
	}
	if got := objectValue(set.Balancers[1])["selector"]; !reflect.DeepEqual(got, []string{"germany", "france", "reverse-vless-home"}) {
		t.Fatalf("flattened selector = %#v", got)
	}
	if _, ok := set.Selectable["priority"]; !ok {
		t.Fatal("selector was not marked selectable")
	}
	if set.Outbounds[0]["sendThrough"] != "172.31.255.2" || set.Outbounds[1]["sendThrough"] != "198.18.0.2" {
		t.Fatalf("direct binds changed: %#v", set.Outbounds)
	}
	if len(set.Outbounds) != 3 {
		t.Fatalf("reverse outbound was emitted: %#v", set.Outbounds)
	}
	settings := objectValue(set.Outbounds[0]["settings"])
	sockopt := objectValue(objectValue(set.Outbounds[0]["streamSettings"])["sockopt"])
	if settings["domainStrategy"] != nil || sockopt["domainStrategy"] != "AsIs" || len(settings["finalRules"].([]any)) != 3 {
		t.Fatalf("direct WAN safety rules changed: %#v", settings)
	}
}

func TestConvertXrayOutboundsRejectsSelectorCycle(t *testing.T) {
	_, err := ConvertXrayOutbounds([]map[string]any{
		{"type": "selector", "tag": "a", "outbounds": []any{"b"}},
		{"type": "selector", "tag": "b", "outbounds": []any{"a"}},
	}, "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "a -> b -> a") {
		t.Fatalf("selector cycle was accepted: %v", err)
	}
}

func TestConvertXrayVLESSAndHysteriaOutbounds(t *testing.T) {
	set, err := ConvertXrayOutbounds([]map[string]any{
		{
			"type": "vless", "tag": "vless-reality", "server": "edge.example", "server_port": 443,
			"uuid": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision",
			"tls": map[string]any{"enabled": true, "server_name": "edge.example", "reality": map[string]any{
				"enabled": true, "public_key": "public", "short_id": "abcd",
			}},
		},
		{
			"type": "hysteria2", "tag": "hy2", "server": "hy.example", "server_port": 8443, "password": "secret",
			"tls":  map[string]any{"server_name": "hy.example", "alpn": []any{"h3"}},
			"obfs": map[string]any{"type": "salamander", "password": "mask"},
		},
	}, "172.31.255.2", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if objectValue(set.Outbounds[0]["settings"])["flow"] != "xtls-rprx-vision" || objectValue(set.Outbounds[0]["streamSettings"])["security"] != "reality" {
		t.Fatalf("VLESS outbound changed: %#v", set.Outbounds[0])
	}
	hyStream := objectValue(set.Outbounds[1]["streamSettings"])
	if hyStream["method"] != "hysteria" || objectValue(hyStream["tlsSettings"])["serverName"] != "hy.example" || hyStream["finalmask"] == nil {
		t.Fatalf("Hysteria outbound changed: %#v", set.Outbounds[1])
	}
	_, err = ConvertXrayOutbounds([]map[string]any{{
		"type": "hysteria2", "tag": "unsafe", "server_port": 443,
		"tls": map[string]any{"insecure": true},
	}}, "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot use allowInsecure") {
		t.Fatalf("unsafe Hysteria TLS was accepted: %v", err)
	}
	providerSet, err := ConvertXrayOutbounds([]map[string]any{{
		"type": "hysteria2", "tag": "provider-hy2", "server": "provider.example", "server_port": 443,
		"password": "secret",
		"tls":      map[string]any{"server_name": "provider.example", "pinned_peer_cert_sha256": "ea1f9d54f3955fa404e7fd3135319e93b4b7d2c719bdfd249aed20f470de131c"},
	}}, "", nil, nil)
	if err != nil || objectValue(objectValue(providerSet.Outbounds[0]["streamSettings"])["tlsSettings"])["pinnedPeerCertSha256"] == "" {
		t.Fatalf("provider Hysteria TLS pin was not rendered: %#v, err=%v", providerSet.Outbounds, err)
	}
}

func TestDirectPrivateAllowCIDRsUsesOnlyAuthenticatedDirectRules(t *testing.T) {
	values := []any{
		map[string]any{"action": "route", "outbound": "direct-wan", "auth_user": []any{"alice"}, "ip_cidr": []any{
			"192.168.3.42/24", "10.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "8.8.8.8/32", "192.168.3.0/24",
		}},
		map[string]any{"action": "route", "outbound": "direct-wan", "ip_cidr": []any{"172.16.0.0/12"}},
		map[string]any{"action": "route", "outbound": "vpn", "auth_user": []any{"alice"}, "ip_cidr": []any{"169.254.0.0/16"}},
	}
	got, err := DirectPrivateAllowCIDRs(values)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.168.3.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("private allows = %#v, want %#v", got, want)
	}
	if _, err := DirectPrivateAllowCIDRs([]any{map[string]any{
		"action": "route", "outbound": "direct-wan", "auth_user": []any{"alice"}, "ip_cidr": []any{"not-a-cidr"},
	}}); err == nil {
		t.Fatal("invalid private CIDR was accepted")
	}
}
