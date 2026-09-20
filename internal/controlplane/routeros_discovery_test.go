package controlplane

import (
	"context"
	"net/http"
	"testing"
)

func TestBuildRouterOSDiscoveryProducesClientInventories(t *testing.T) {
	inventory := map[string][]map[string]any{
		"resources": {{"version": "7.21.5 (stable)", "architecture-name": "arm64"}},
		"update":    {{"channel": "stable"}},
		"ipv4_addresses": {
			{"address": "192.168.88.1/24", "interface": "bridge"},
			{"address": "192.168.77.1/24", "interface": "bridge", "invalid": "true"},
			{"address": "198.51.100.2/24", "interface": "ether1"},
			{"address": "192.168.0.15/24", "interface": "dual-role"},
			{"address": "10.12.0.39/32", "interface": "wg-road"},
			{"address": "10.13.0.1/24", "interface": "wg-road"},
		},
		"interface_members": {
			{"list": "WAN", "interface": "ether1"},
			{"list": "LAN", "interface": "bridge"},
			{"list": "LAN", "interface": "dual-role"},
			{"list": "WAN", "interface": "dual-role"},
			{"list": "LAN", "interface": "wg-road"},
			{"list": "WireGuard", "interface": "wg-road"},
		},
		"dhcp_clients":         {{"interface": "lte1", "disabled": "false"}},
		"ipv4_routes":          {{"dst-address": "192.168.90.0/24", "routing-table": "main", "active": "true"}, {"dst-address": "203.0.113.0/24", "gateway": "198.51.100.1%ether1", "dynamic": "true", "active": "true"}},
		"dhcp_leases":          {{"address": "192.168.88.20", "host-name": "phone", "server": "lan", "dynamic": "false"}},
		"wireguard_interfaces": {{"name": "wg-road", "disabled": "false"}},
		"wireguard_peers":      {{".id": "*4", "name": "remote", "interface": "wg-road", "allowed-address": "10.50.0.2/32,0.0.0.0/0"}},
		"ppp_secrets":          {{"name": "vpn-user", "service": "l2tp", "remote-address": "10.60.0.2"}},
		"containers":           {{"name": "sb-gateway", "comment": "SB-GATEWAY container", "healthy": "true", "memory-current": "123456"}},
	}
	complete := map[string]bool{"interface_members": true, "ipv4_addresses": true, "dhcp_leases": true, "wireguard_interfaces": true, "wireguard_peers": true, "ppp_secrets": true, "containers": true, "ipv4_routes": true, "ipv6_routes": true}
	result := buildRouterOSDiscovery(inventory, complete)
	if result["detected_version"] != "7.21.5" || result["architecture"] != "arm64" {
		t.Fatalf("resource facts mismatch: %#v", result)
	}
	sources := result["client_sources"].(map[string]any)
	if len(sources["lan"].([]any)) != 1 || len(sources["wireguard"].([]any)) != 1 || len(sources["ppp-vpn"].([]any)) != 1 {
		t.Fatalf("client inventories mismatch: %#v", sources)
	}
	wg := sources["wireguard"].([]any)[0].(map[string]any)
	if cidrs := wg["source_cidrs"].([]any); len(cidrs) != 1 || cidrs[0] != "10.50.0.2/32" {
		t.Fatalf("WireGuard default route was not excluded: %#v", wg)
	}
	if result["container"].(map[string]any)["healthy"] != true {
		t.Fatalf("managed container missing: %#v", result["container"])
	}
	if result["wireguard_egress_inventory_complete"] != true {
		t.Fatalf("complete WireGuard inventory was reported unavailable: %#v", result)
	}
	lanSources := result["lan_source_cidrs"].([]any)
	if result["lan_source_inventory_complete"] != true || len(lanSources) != 1 || lanSources[0] != "192.168.88.0/24" {
		t.Fatalf("LAN source networks mismatch: %#v", result)
	}
	egress := result["wireguard_egress_candidates"].([]any)
	if len(egress) != 1 || egress[0].(map[string]any)["interface"] != "wg-road" || egress[0].(map[string]any)["eligible"] != true || egress[0].(map[string]any)["reason"] != "ready" {
		t.Fatalf("WireGuard egress candidate mismatch: %#v", egress)
	}
	for _, value := range result["networks"].([]any) {
		if value == "198.51.100.0/24" || value == "203.0.113.0/24" {
			t.Fatalf("WAN network leaked into internal inventory: %#v", result["networks"])
		}
	}
}

func TestBuildRouterOSDiscoveryDerivesContainerHealthAndFindsRollback(t *testing.T) {
	inventory := map[string][]map[string]any{
		"resources": {{"version": "7.21.5 (long-term)", "architecture-name": "arm64"}},
		"update":    {{"channel": "long-term"}},
		"containers": {
			{
				"name":               "sb-gateway-1-5-30",
				"comment":            "SB-GATEWAY container",
				"healthcheck-status": "good, output: ",
				"root-dir":           "/pcie1/sb-gateway/root-1.5.31",
				"tag":                "sb-gateway:1.5.31",
			},
			{
				"name":     "sb-gateway-rollback",
				"comment":  "SB-GATEWAY container rollback",
				"root-dir": "/pcie1/sb-gateway/root-1.5.29",
			},
		},
	}
	result := buildRouterOSDiscovery(inventory, map[string]bool{"containers": true})
	container := result["container"].(map[string]any)
	if container["healthy"] != true {
		t.Fatalf("healthcheck-status good was not reflected as healthy: %#v", container)
	}
	if container["rollback_retained"] != true || container["rollback_root_dir"] != "/pcie1/sb-gateway/root-1.5.29" {
		t.Fatalf("lifecycle rollback container was not discovered: %#v", container)
	}
	if container["tag"] != "sb-gateway:1.5.31" {
		t.Fatalf("current container facts mismatch: %#v", container)
	}
}

func TestWireGuardEgressCandidatesReportPreparationAndAmbiguity(t *testing.T) {
	interfaces := []map[string]any{
		{"name": "wg-ready", "comment": "Road exit"},
		{"name": "wg-ambiguous"},
		{"name": "wg-disabled", "disabled": "true"},
	}
	peers := []map[string]any{
		{"interface": "wg-ready", "allowed-address": "10.20.0.2/32"},
		{"interface": "wg-ambiguous", "allowed-address": "10.30.0.2/32"},
		{"interface": "wg-ambiguous", "allowed-address": "10.30.0.3/32"},
		{"interface": "wg-disabled", "allowed-address": "0.0.0.0/0"},
	}
	routes := []map[string]any{
		{"dst-address": "0.0.0.0/0", "gateway": "wg-ready@main", "routing-table": "road", "active": "true"},
	}
	candidates := wireGuardEgressCandidates(interfaces, peers, routes)
	byName := make(map[string]map[string]any, len(candidates))
	for _, item := range candidates {
		candidate := item.(map[string]any)
		byName[candidate["interface"].(string)] = candidate
	}
	if byName["wg-ready"]["reason"] != "will_prepare" || byName["wg-ready"]["eligible"] != true {
		t.Fatalf("single peer should be preparable: %#v", byName["wg-ready"])
	}
	if tables := byName["wg-ready"]["active_default_route_tables"].([]any); len(tables) != 1 || tables[0] != "road" {
		t.Fatalf("default route table was not discovered: %#v", byName["wg-ready"])
	}
	if byName["wg-ambiguous"]["reason"] != "ambiguous_peers" || byName["wg-ambiguous"]["eligible"] != false {
		t.Fatalf("ambiguous peers should be rejected: %#v", byName["wg-ambiguous"])
	}
	if byName["wg-disabled"]["reason"] != "interface_disabled" || byName["wg-disabled"]["eligible"] != false {
		t.Fatalf("disabled interface should be rejected: %#v", byName["wg-disabled"])
	}
}

func TestRouterOSDiscoveryEndpointUsesConfiguredNativeReader(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	credentials := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/credentials", map[string]any{
		"base_url": "https://192.168.88.1:443", "username": "admin", "password": "router-password-123",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if credentials.Code != http.StatusOK {
		t.Fatalf("credentials failed: %d %s", credentials.Code, credentials.Body.String())
	}
	server.discoverRouterOS = func(_ context.Context, _ map[string]any) (map[string]any, error) {
		return map[string]any{"detected_version": "7.21.5", "client_sources": map[string]any{}}, nil
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/routeros/discover", nil, nil, cookie)
	if response.Code != http.StatusOK || decodeResponse(t, response)["routeros"].(map[string]any)["detected_version"] != "7.21.5" {
		t.Fatalf("discovery failed: %d %s", response.Code, response.Body.String())
	}
}

func TestRouterOSContainerStatusEndpointUsesLightweightNativeReader(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	credentials := performRequest(t, server, http.MethodPost, apiPrefix+"/routeros/credentials", map[string]any{
		"base_url": "https://192.168.88.1:443", "username": "admin", "password": "router-password-123",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if credentials.Code != http.StatusOK {
		t.Fatalf("credentials failed: %d %s", credentials.Code, credentials.Body.String())
	}
	server.discoverRouterOSContainer = func(_ context.Context, _ map[string]any) (map[string]any, error) {
		return map[string]any{"present": true, "restart_count": "2", "status": "running"}, nil
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/routeros/container-status", nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("container status failed: %d %s", response.Code, response.Body.String())
	}
	container := decodeResponse(t, response)["container"].(map[string]any)
	if container["restart_count"] != "2" || container["status"] != "running" {
		t.Fatalf("unexpected container status: %#v", container)
	}
}
