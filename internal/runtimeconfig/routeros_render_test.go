package runtimeconfig

import (
	"strings"
	"testing"
)

func TestRenderRouterOSTrafficCandidateConnectsManagedTrafficToContainerAndWireGuard(t *testing.T) {
	config := routerOSModelConfig()
	first, err := RenderRouterOSTrafficCandidate(config, []map[string]any{{"server": "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"address-list", "address-list-timeout"} {
		if strings.Contains(first, `/ip/firewall/filter/unset $publicGuardRule `+field+"\n") {
			t.Fatalf("cannot unset action-dependent %s on return/drop rules", field)
		}
	}
	second, err := RenderRouterOSTrafficCandidate(config, []map[string]any{{"server": "203.0.113.7"}})
	if err != nil || first != second {
		t.Fatalf("RouterOS candidate is not deterministic: %v", err)
	}
	previous := -1
	for _, section := range routerOSSectionOrder {
		index := strings.Index(first, routerOSSectionPrefix+section)
		if index <= previous {
			t.Fatalf("section %q is absent or out of order", section)
		}
		previous = index
	}
	for _, expected := range []string{
		`new-routing-mark="to-sb-gateway"`,
		`gateway="172.31.255.2@main" routing-table="to-sb-gateway"`,
		`list="SB_MANAGED_CLIENTS" address=$candidateAddress`,
		`list="SB_BYPASS_ENDPOINTS" address=$candidateAddress`,
		`use-doh-server="https://cloudflare-dns.com/dns-query"`,
		`action=lookup-only-in-table table="sb-wg-`,
		`src-address-list="SB_WG_EGRESS_SOURCES" out-interface-list="SB_WG_EGRESS" disabled=no`,
		`chain=srcnat action=masquerade src-address="172.31.255.0/30" dst-address-list="SB_CONTAINER_ALLOWED_INTERNAL" disabled=no`,
		`/system/script/run SB-GATEWAY-startup-fail-open`,
	} {
		if !strings.Contains(first, expected) {
			t.Fatalf("RouterOS candidate lacks %q", expected)
		}
	}
	if strings.Contains(first, "python") || strings.Contains(first, "legacy") {
		t.Fatal("native RouterOS candidate contains an obsolete runtime path")
	}
}

func TestRenderRouterOSContainerLANMasqueradeIsRestrictedToAllowedDestinations(t *testing.T) {
	config := routerOSModelConfig()
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `/ip/firewall/nat/set $containerLanMasquerade chain=srcnat action=masquerade src-address="172.31.255.0/30" dst-address-list="SB_CONTAINER_ALLOWED_INTERNAL" disabled=no`
	if strings.Count(source, want) != 1 {
		t.Fatalf("container LAN masquerade is absent or duplicated")
	}
	if strings.Contains(source, `/ip/firewall/nat/set $containerLanMasquerade chain=srcnat action=masquerade src-address="172.31.255.0/30" disabled=no`) {
		t.Fatal("container LAN masquerade lost its destination allowlist")
	}
}

func TestRenderRouterOSAddressListsReuseForeignMembershipWithoutClaimingIt(t *testing.T) {
	config := routerOSModelConfig()
	source, err := RenderRouterOSTrafficCandidate(config, []map[string]any{{"server": "203.0.113.7"}})
	if err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		`/ip/firewall/address-list/find where list="SB_MANAGED_CLIENTS" and comment=$commentManaged`,
		`/ip/firewall/address-list/find where list="SB_MANAGED_CLIENTS" and address=$candidateAddress]] = 0`,
		`/ipv6/firewall/address-list/find where list="SB_MANAGED_CLIENTS_V6" and comment=$commentManagedV6`,
		`/ipv6/firewall/address-list/find where list="SB_MANAGED_CLIENTS_V6" and address=$address]] = 0`,
	} {
		if !strings.Contains(source, expected) {
			t.Fatalf("RouterOS address-list reconciliation lacks %q", expected)
		}
	}
	for _, forbidden := range []string{
		`list="SB_MANAGED_CLIENTS" and address=$candidateAddress and comment=`,
		`list="SB_MANAGED_CLIENTS_V6" and address=$address and comment=`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("RouterOS address-list addition still requires ownership comment: %q", forbidden)
		}
	}
}

func TestRenderRouterOSTrafficCandidateDisablesRemovedWireGuardEgress(t *testing.T) {
	config := routerOSModelConfig()
	networking := objectValue(objectValue(config["system"])["networking"])
	networking["wireguard_egress_enabled"] = false
	networking["wireguard_egress_exits"] = []any{}
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`disabled=yes comment="SB-GATEWAY WireGuard egress masquerade"`,
		`out-interface-list="SB_WG_EGRESS" disabled=yes`,
		`:local wantedWgRuleComments [:toarray ""]`,
	} {
		if !strings.Contains(source, expected) {
			t.Fatalf("WireGuard removal candidate lacks %q", expected)
		}
	}
}

func TestRenderRouterOSPublicIngressUsesCurrentPortsAndScopedProtection(t *testing.T) {
	config := routerOSModelConfig()
	config["public_exposure"] = map[string]any{"connection_guard": map[string]any{
		"enabled": true, "new_connection_rate": 37, "burst": 91, "quarantine_seconds": 777,
	}}
	config["ingress"] = map[string]any{
		"status_hostname": "", "subscription_hostname": "sub.example.test", "subscription_listen_port": 9444,
		"subscription_endpoint_mode": "direct", "require_cloudflare_source_ranges": true,
	}
	config["transports"] = []any{
		map[string]any{
			"id": "xhttp", "kind": "xhttp", "enabled": true,
			"cdn_deployments": []any{map[string]any{
				"id": "cloudflare", "enabled": true, "cdn_provider": "cloudflare", "listen_port": 443,
				"origin_port": 2053, "origin_protection_mode": "auto-cidr",
			}},
		},
		map[string]any{
			"id": "grpc", "kind": "grpc", "enabled": true,
			"cdn_deployments": []any{map[string]any{
				"id": "manual", "enabled": true, "cdn_provider": "other", "listen_port": 443,
				"origin_port": 8443, "origin_protection_mode": "manual-cidr",
				"origin_allowed_cidrs": []any{"203.0.113.0/24"},
			}},
		},
		map[string]any{
			"id": "xhttp-reality", "kind": "xhttp-reality", "enabled": true,
			"listen_port": 2446, "wan_destination_address": "198.51.100.9",
		},
		map[string]any{"id": "hy2", "kind": "hysteria2", "enabled": true, "listen_port": 9443},
	}

	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`protocol=tcp dst-port=2053 dst-address-type=local src-address-list="SB_CLOUDFLARE_V4"`,
		`protocol=tcp dst-port=8443 dst-address-type=local src-address-list="SB_PUBLIC_`,
		`list="SB_PUBLIC_TRUSTED_V4" address=$candidateAddress`,
		`{"203.0.113.0/24"}`,
		`protocol=tcp dst-port=2446 dst-address="198.51.100.9"`,
		`protocol=udp dst-port=9443 dst-address-type=local`,
		`protocol=tcp dst-port=9444 dst-address-type=local`,
		`dst-limit=37/1s,91,src-address/10s`,
		`address-list-timeout=777s`,
		`connection-state=new connection-nat-state=dstnat disabled=no`,
		`SB-GATEWAY obsolete public NAT rule is ambiguous`,
	} {
		if !strings.Contains(source, expected) {
			t.Fatalf("public RouterOS candidate lacks %q:\n%s", expected, source)
		}
	}
	for _, forbidden := range []string{
		`protocol=tcp dst-port=443 dst-address-type=local src-address-list="SB_CLOUDFLARE_V4"`,
		`/ip/service/`,
		`dst-port=8291`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("public RouterOS candidate contains stale or unscoped rule %q", forbidden)
		}
	}
}

func TestRenderRouterOSHysteriaUDPHopRangeTargetsSingleInbound(t *testing.T) {
	config := routerOSModelConfig()
	config["ingress"] = map[string]any{"status_hostname": "", "subscription_endpoint_enabled": false}
	config["transports"] = []any{map[string]any{
		"id": "hy2", "kind": "hysteria2", "enabled": true, "listen_port": 20443,
		"xray_hysteria": map[string]any{"udp_hop": map[string]any{
			"enabled": true, "port_start": 20000, "port_end": 20100,
			"interval_min": 15, "interval_max": 45, "excluded_ports": "20053",
		}},
	}}

	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`# SB-GATEWAY section:public-port-check`,
		`/interface/wireguard/get $wireguard listen-port`,
		`overlaps NAT`,
		`exclude the port`,
		`protocol=udp dst-port=20000-20052 dst-address-type=local`,
		`protocol=udp dst-port=20054-20100 dst-address-type=local`,
		`to-ports=20443`,
		`protocol=udp dst-port=20443 connection-state=new,established,related connection-nat-state=dstnat`,
	} {
		if !strings.Contains(source, expected) {
			t.Fatalf("UDP hopping candidate lacks %q:\n%s", expected, source)
		}
	}
	for _, forbidden := range []string{`protocol=udp dst-port=20443 dst-address-type=local`, `dst-port=20000-20100`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("UDP hopping emitted forbidden matcher %q:\n%s", forbidden, source)
		}
	}
	if strings.Contains(source, `:for publicPort`) || !strings.Contains(source, `publicIngressRangesOverlap`) {
		t.Fatalf("UDP hopping conflict guard must compare ranges without scanning every port:\n%s", source)
	}
}

func TestRenderRouterOSPublicIngressSkipsDisabledSubscriptionOnly(t *testing.T) {
	config := routerOSModelConfig()
	config["ingress"] = map[string]any{
		"status_hostname": "status.example.test", "status_listen_port": 18443,
		"subscription_endpoint_enabled": false, "subscription_endpoint_mode": "direct",
		"subscription_hostname": "subscription.example.test", "subscription_listen_port": 9444,
	}
	config["transports"] = []any{map[string]any{
		"id": "reality", "kind": "reality", "enabled": true, "listen_port": 2443,
	}}
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(source, `protocol=tcp dst-port=9444 dst-address-type=local`) {
		t.Fatal("disabled subscription RouterOS ingress remained")
	}
	for _, expected := range []string{
		`protocol=tcp dst-port=18443 dst-address-type=local`,
		`protocol=tcp dst-port=2443 dst-address-type=local`,
	} {
		if !strings.Contains(source, expected) {
			t.Fatalf("disabled subscription removed unrelated ingress %q", expected)
		}
	}
}

func TestRenderRouterOSPublicIngressAllowsDistinctVirtualHostBoundaries(t *testing.T) {
	config := routerOSModelConfig()
	config["ingress"] = map[string]any{
		"status_hostname": "status.example.test", "status_listen_port": 18443,
		"require_cloudflare_source_ranges": true,
		"subscription_hostname":            "subscription.example.test", "subscription_listen_port": 18443,
		"subscription_endpoint_mode": "direct",
	}
	config["transports"] = []any{}

	if _, err := RenderRouterOSTrafficCandidate(config, nil); err != nil {
		t.Fatalf("distinct virtual host boundaries rejected: %v", err)
	}
}

func TestRenderRouterOSSubscriptionUsesOriginPortNotCDNEdgePort(t *testing.T) {
	config := routerOSModelConfig()
	config["ingress"] = map[string]any{
		"subscription_endpoint_enabled":       true,
		"subscription_endpoint_mode":          "separate",
		"subscription_hostname":               "edge.cdn.example.test",
		"subscription_origin_server_name":     "origin.example.test",
		"subscription_cdn_provider":           "gcore",
		"subscription_origin_protection_mode": "auto-cidr",
		"subscription_public_port":            443,
		"subscription_listen_port":            18443,
	}
	config["transports"] = []any{}
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(source, `protocol=tcp dst-port=18443 dst-address-type=local`) || strings.Contains(source, `protocol=tcp dst-port=443 dst-address-type=local`) {
		t.Fatalf("RouterOS did not isolate subscription origin port:\n%s", source)
	}
}

func TestRenderRouterOSPublicSettingsChangeAndRemovalAreNotNoOps(t *testing.T) {
	config := routerOSModelConfig()
	config["public_exposure"] = map[string]any{"connection_guard": map[string]any{
		"enabled": true, "new_connection_rate": 40, "burst": 80, "quarantine_seconds": 600,
	}}
	transport := map[string]any{
		"id": "reality", "kind": "reality", "enabled": true, "listen_port": 2443,
	}
	config["transports"] = []any{transport}
	before, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport["listen_port"] = 25443
	guard := objectValue(objectValue(config["public_exposure"])["connection_guard"])
	guard["new_connection_rate"] = 55
	after, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if before == after || !strings.Contains(after, "dst-port=25443") || !strings.Contains(after, "dst-limit=55/1s") || strings.Contains(after, `protocol=tcp dst-port=2443 dst-address-type=local`) {
		t.Fatalf("public port/guard mutation did not reach RSC")
	}
	transport["enabled"] = false
	removed, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(removed, `protocol=tcp dst-port=25443 dst-address-type=local`) || !strings.Contains(removed, `:local wantedPublicDstnatComments [:toarray ""]`) {
		t.Fatalf("disabled public transport remained active")
	}
}
