package runtimeconfig

import "testing"

func TestBuildXrayCandidateFromSchemaKeepsReverseAsDynamicInternetLeaf(t *testing.T) {
	config := map[string]any{
		"system": map[string]any{"networking": map[string]any{
			"tun_address": "198.18.0.1/30", "container_address": "198.18.0.2/29",
			"tun_mtu": 1400, "tun_stack": "system", "remote_ipv6_mode": "proxy_only",
		}},
		"dns": map[string]any{
			"internal_server": "192.168.3.1",
			"direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
		},
		"transports": []any{map[string]any{
			"id": "ws-public", "enabled": true, "kind": "ws", "path_secret_ref": "transport/ws-path",
		}},
		"remote_users": []any{map[string]any{
			"id": "phone", "enabled": true, "uuid_secret_ref": "user/phone", "policy_id": "europe",
		}},
		"reverse_vless_exits": []any{map[string]any{
			"id": "home", "enabled": true, "uuid_secret_ref": "reverse/home", "transport_ids": []any{"ws-public"},
		}},
		"policies": []any{map[string]any{
			"id": "europe", "enabled": true, "mode": "priority", "selection_order": []any{"reverse:home"},
		}},
	}
	artifacts, err := BuildXrayCandidateFromSchema(config, nil, inboundSecretReader(map[string]string{
		"transport/ws-path": "/reverse", "user/phone": "018f7b76-7cdb-4a08-9f0a-7514a1d90a11",
		"reverse/home": "123e4567-e89b-42d3-a456-426614174000",
	}), inboundSecretPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logConfig := objectValue(artifacts.Config["log"])
	if logConfig["access"] != "none" || logConfig["error"] != "/logs/xray-error.log" || logConfig["loglevel"] != "warning" {
		t.Fatalf("Xray logging must suppress per-connection access noise and preserve warnings: %#v", logConfig)
	}
	for _, outbound := range objectSlice(artifacts.Config["outbounds"]) {
		if outbound["tag"] == "reverse-vless-home" {
			t.Fatalf("dynamic reverse leaf was replaced by a static outbound: %#v", outbound)
		}
	}
	routing := objectValue(artifacts.Config["routing"])
	balancers := objectSlice(routing["balancers"])
	europe := findXraySourceRule(balancers, func(value map[string]any) bool { return value["tag"] == "europe" })
	if europe == nil || !containsText(stringSlice(europe["selector"]), "reverse-vless-home") {
		t.Fatalf("Reverse VLESS is not selectable as the Europe internet route: %#v", europe)
	}
	ws := findXraySourceRule(objectSlice(artifacts.Config["inbounds"]), func(value map[string]any) bool { return value["tag"] == "vless-ws" })
	users := objectSlice(objectValue(ws["settings"])["users"])
	reverse := findXraySourceRule(users, func(value map[string]any) bool { return value["email"] == "reverse-vless-home" })
	if reverse == nil || objectValue(reverse["reverse"])["tag"] != "reverse-vless-home" {
		t.Fatalf("Reverse handler user is missing: %#v", users)
	}
	if len(artifacts.PolicyDNSBody) == 0 || len(artifacts.PolicyDNS.Lanes) == 0 || artifacts.PolicyDNS.Lanes[0].Final == "" {
		t.Fatal("policy DNS was not built with the Xray candidate")
	}
	body, err := MarshalXrayCandidate(artifacts.Config)
	if err != nil || len(body) == 0 {
		t.Fatalf("marshal Xray candidate: %v", err)
	}
}

func TestBuildXrayCandidateUsesConfiguredLogLevel(t *testing.T) {
	config := map[string]any{
		"system": map[string]any{
			"logging": map[string]any{"xray_level": "info"},
			"networking": map[string]any{
				"tun_address": "198.18.0.1/30", "container_address": "198.18.0.2/29",
				"tun_mtu": 1400, "tun_stack": "system", "remote_ipv6_mode": "proxy_only",
			},
		},
		"dns": map[string]any{
			"internal_server": "192.168.3.1",
			"direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
		},
	}
	artifacts, err := BuildXrayCandidateFromSchema(config, nil, inboundSecretReader(nil), inboundSecretPath, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if level := objectValue(artifacts.Config["log"])["loglevel"]; level != "info" {
		t.Fatalf("configured Xray log level was ignored: %#v", level)
	}
}
