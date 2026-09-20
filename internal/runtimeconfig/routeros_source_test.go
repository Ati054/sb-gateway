package runtimeconfig

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestBuildRouterOSRenderModelNormalizesCurrentSchema(t *testing.T) {
	config := routerOSModelConfig()
	model, err := BuildRouterOSRenderModel(config, []map[string]any{
		{"server": "203.0.113.7"}, {"server": "edge.example"}, {"server": "2001:db8::7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(model.Managed4, []string{"192.168.3.14/32", "192.168.3.22/32"}) || !reflect.DeepEqual(model.Managed6, []string{"2001:db8:1::14/128"}) {
		t.Fatalf("managed lists = %#v / %#v", model.Managed4, model.Managed6)
	}
	if !reflect.DeepEqual(model.FailClosed4, []string{"192.168.3.14/32"}) || !reflect.DeepEqual(model.FailClosed6, []string{"2001:db8:1::14/128"}) {
		t.Fatalf("fail-closed lists = %#v / %#v", model.FailClosed4, model.FailClosed6)
	}
	if !containsText(model.ContainerAllowed4, "192.168.3.0/24") || !containsText(model.ContainerAllowed4, "10.10.0.0/24") ||
		!containsText(model.ContainerAllowed4, "10.0.0.0/8") || !containsText(model.ContainerAllowed4, "172.16.0.0/12") ||
		!containsText(model.ContainerAllowed4, "192.168.0.0/16") {
		t.Fatalf("container allowlist = %#v", model.ContainerAllowed4)
	}
	if !reflect.DeepEqual(model.BypassEndpoints4, []string{"203.0.113.7/32"}) {
		t.Fatalf("bypass endpoints = %#v", model.BypassEndpoints4)
	}
	if model.ContainerIP != "172.31.255.2" || model.ContainerNetwork != "172.31.255.0/30" || model.TunNetwork != "172.31.254.0/30" || model.RouterOSGateway != "192.168.3.1" {
		t.Fatalf("runtime network = %#v", model)
	}
	if model.RESTPort != 8729 || model.SSHPort != 2222 {
		t.Fatalf("management ports = %d/%d", model.RESTPort, model.SSHPort)
	}
	if model.DNSServers != "1.1.1.1,1.0.0.1" || model.DNSDoHURL != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("RouterOS DNS = %q / %q", model.DNSServers, model.DNSDoHURL)
	}
	if model.WatchdogCooldownTicks != 13 {
		t.Fatalf("cooldown ticks = %d", model.WatchdogCooldownTicks)
	}
	if len(model.WireGuardExits) != 1 {
		t.Fatalf("WireGuard exits = %#v", model.WireGuardExits)
	}
	exit := model.WireGuardExits[0]
	address := netip.MustParseAddr(exit.SourceAddress)
	if !netip.MustParsePrefix("198.18.0.0/15").Contains(address) || exit.RoutingTable == "" || exit.Interface != "wg-office" {
		t.Fatalf("WireGuard runtime identity = %#v", exit)
	}
	second, err := BuildRouterOSRenderModel(config, nil)
	if err != nil || second.WireGuardExits[0] != exit {
		t.Fatalf("WireGuard identity is not deterministic: %#v / %v", second.WireGuardExits, err)
	}
}

func TestBuildRouterOSRenderModelDefaultsToNoAdditionalRecoveryCooldown(t *testing.T) {
	config := routerOSModelConfig()
	delete(objectValue(config["watchdog"]), "recovery_cooldown_seconds")
	model, err := BuildRouterOSRenderModel(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if model.WatchdogCooldownTicks != 0 {
		t.Fatalf("default cooldown ticks = %d, want 0", model.WatchdogCooldownTicks)
	}
}

func TestBuildRouterOSRenderModelPublishesDirectGRPCTLSPinPort(t *testing.T) {
	config := routerOSModelConfig()
	config["transports"] = []any{map[string]any{
		"id": "grpc-tls-pin", "kind": "grpc-tls", "enabled": true,
		"listen_port": 2445, "wan_destination_address": "198.51.100.10",
	}}
	model, err := BuildRouterOSRenderModel(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.PublicIngress) != 1 {
		t.Fatalf("public ingress = %#v", model.PublicIngress)
	}
	ingress := model.PublicIngress[0]
	if ingress.Key == "" || ingress.Protocol != "tcp" || ingress.PublicPort != 2445 || ingress.TargetPort != 2445 || ingress.DestinationAddress != "198.51.100.10" {
		t.Fatalf("gRPC TLS Pin ingress = %#v", ingress)
	}
}

func TestBuildRouterOSRenderModelRejectsUnsafeOrIncompleteRuntimeFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"ingress", func(config map[string]any) {
			objectValue(objectValue(config["system"])["management"])["allowed_ingress_interfaces"] = []any{}
		}},
		{"bridge", func(config map[string]any) {
			objectValue(objectValue(config["system"])["networking"])["bridge_name"] = "bad\nname"
		}},
		{"REST", func(config map[string]any) {
			objectValue(config["routeros"])["base_url"] = "http://192.168.3.1:8729/rest"
		}},
		{"container", func(config map[string]any) {
			objectValue(objectValue(config["system"])["networking"])["container_address"] = "fd00::2/64"
		}},
		{"WireGuard", func(config map[string]any) {
			objectSlice(objectValue(objectValue(config["system"])["networking"])["wireguard_egress_exits"])[0]["interface"] = "bad\nwg"
		}},
		{"WireGuard pool overlap", func(config map[string]any) {
			objectValue(objectValue(config["system"])["networking"])["container_address"] = "198.18.0.2/29"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := routerOSModelConfig()
			test.mutate(config)
			if _, err := BuildRouterOSRenderModel(config, nil); err == nil {
				t.Fatal("unsafe RouterOS runtime input was accepted")
			}
		})
	}
}

func routerOSModelConfig() map[string]any {
	return map[string]any{
		"system": map[string]any{
			"management": map[string]any{
				"allowed_source_cidrs": []any{"192.168.3.0/24"}, "allowed_ingress_interfaces": []any{"bridge-lan"},
			},
			"networking": map[string]any{
				"container_address": "172.31.255.2/30", "tun_address": "172.31.254.1/30", "routeros_gateway": "192.168.3.1",
				"bridge_name": "sb-containers", "veth_name": "veth-sb", "routing_table": "to-sb-gateway", "ipv6_mode": "block_managed",
				"wireguard_egress_enabled": true,
				"wireguard_egress_exits":   []any{map[string]any{"id": "office", "enabled": true, "interface": "wg-office"}},
			},
		},
		"routeros": map[string]any{"base_url": "https://192.168.3.1:8729", "ssh_port": 2222},
		"dns": map[string]any{
			"direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"},
		},
		"watchdog": map[string]any{
			"interval_seconds": 5, "failure_threshold": 3, "recovery_threshold": 4, "recovery_cooldown_seconds": 61,
		},
		"networks": []any{
			map[string]any{"id": "lan", "enabled": true, "kind": "internal", "cidrs": []any{"192.168.3.0/24", "2001:db8:1::/64"}},
			map[string]any{"id": "admin", "enabled": true, "kind": "management", "cidrs": []any{"10.10.0.0/24"}},
		},
		"policies": []any{map[string]any{"id": "closed", "enabled": true, "container_outage": "lan_only"}},
		"local_clients": []any{
			map[string]any{"id": "phone", "enabled": true, "policy_id": "closed", "source_cidrs": []any{"192.168.3.14/32", "2001:db8:1::14/128"}},
			map[string]any{"id": "laptop", "enabled": true, "source_cidrs": []any{"192.168.3.22/32"}},
		},
		"remote_users": []any{
			map[string]any{"id": "full", "enabled": true, "role": "trusted-full"},
			map[string]any{"id": "limited", "enabled": true, "role": "trusted-limited", "allowed_network_ids": []any{"admin"}},
		},
	}
}
