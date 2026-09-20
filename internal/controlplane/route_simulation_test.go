package controlplane

import (
	"net/http"
	"testing"
)

func TestRouteSimulationPrefersSpecificLANClientOverAllLANFallback(t *testing.T) {
	config := map[string]any{"local_clients": []any{
		map[string]any{"id": "all-lan", "enabled": true, "source_kind": "lan", "source_scope": "lan-all", "source_cidrs": []any{"192.168.88.0/24"}},
		map[string]any{"id": "phone", "enabled": true, "source_kind": "lan", "source_cidrs": []any{"192.168.88.20/32"}},
	}}
	source, err := (&routeSimulator{}).resolveSource(config, "local", map[string]any{"source_ip": "192.168.88.20"})
	if err != nil {
		t.Fatal(err)
	}
	if source["id"] != "phone" {
		t.Fatalf("specific client did not override all-LAN fallback: %#v", source)
	}
	newDevice, err := (&routeSimulator{}).resolveSource(config, "local", map[string]any{"source_ip": "192.168.88.99"})
	if err != nil {
		t.Fatal(err)
	}
	if newDevice["id"] != "all-lan" {
		t.Fatalf("new LAN address did not inherit the all-LAN fallback: %#v", newDevice)
	}
}

func TestRouteSimulationPreservesOutageBoundaries(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["local_clients"] = []any{map[string]any{"id": "phone", "policy_id": "europe", "source_cidrs": []any{"192.168.88.20/32"}, "container_outage": "direct"}}
	config["remote_users"] = []any{map[string]any{"id": "remote-phone", "policy_id": "europe"}}
	config["policies"] = []any{map[string]any{"id": "europe", "enabled": true, "selected_outbound": "reverse-xhttp", "final": "direct"}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}

	local := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
		"source_type": "local", "source_id": "phone", "destination_kind": "public", "container_healthy": false,
	}, nil, cookie)
	if local.Code != http.StatusOK {
		t.Fatalf("local simulation failed: %d %s", local.Code, local.Body.String())
	}
	if body := decodeResponse(t, local); body["action"] != "wan-direct" || body["fail_mode"] != "open" {
		t.Fatalf("local outage leaked contract: %#v", body)
	}

	remote := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
		"source_type": "remote", "source_id": "remote-phone", "destination_kind": "public", "container_healthy": false,
	}, nil, cookie)
	if body := decodeResponse(t, remote); body["action"] != "drop" || body["outbound"] != nil || body["fail_mode"] != "closed" {
		t.Fatalf("remote outage failed open: %#v", body)
	}
}

func TestRouteSimulationUsesPolicyModeAndInternalNetworks(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["local_clients"] = []any{map[string]any{"id": "phone", "policy_id": "europe"}}
	config["remote_users"] = []any{map[string]any{"id": "remote-phone", "policy_id": "europe", "allow_internal": false}}
	config["policies"] = []any{map[string]any{
		"id": "europe", "enabled": true, "traffic_mode": "vless_with_wan_exceptions", "direct_domains": []any{"status.example"}, "selected_outbound": "reverse-xhttp",
	}}
	config["networks"] = []any{map[string]any{"id": "lan", "kind": "internal", "enabled": true, "cidrs": []any{"192.168.88.0/24"}}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}

	exception := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
		"source_type": "local", "source_id": "phone", "destination_kind": "public", "destination_domain": "api.status.example",
	}, nil, cookie)
	if body := decodeResponse(t, exception); body["action"] != "wan-direct" || body["matched_rule"] != "local-direct-domain" {
		t.Fatalf("domain exception mismatch: %#v", body)
	}

	ordinary := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
		"source_type": "local", "source_id": "phone", "destination_kind": "public", "destination_domain": "ordinary.example",
	}, nil, cookie)
	if body := decodeResponse(t, ordinary); body["action"] != "vless" || body["outbound"] != "europe" {
		t.Fatalf("full tunnel mismatch: %#v", body)
	}

	internal := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
		"source_type": "remote", "source_id": "remote-phone", "destination_kind": "public", "destination_ip": "192.168.88.9",
	}, nil, cookie)
	if body := decodeResponse(t, internal); body["action"] != "drop" || body["matched_rule"] != "internal-destination-bypass" {
		t.Fatalf("remote internal boundary mismatch: %#v", body)
	}
}

func TestRouteSimulationRejectsMalformedInput(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
		"source_type": "local", "source_ip": "not-an-ip", "destination_kind": "public",
	}, nil, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("malformed simulation accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestRouteSimulationUsesReleasePinnedTelecomAndBinanceDomains(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["remote_users"] = []any{map[string]any{"id": "phone", "policy_id": "main"}}
	config["policies"] = []any{map[string]any{
		"id": "main", "enabled": true, "traffic_mode": "vless_with_wan_exceptions",
		"direct_services": []any{"ru-telecom", "binance"}, "selected_outbound": "proxy",
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}

	for _, domain := range []string{"sibset.ru", "www.211.ru", "sibseti.ru", "lk.sibseti.ru", "www.binance.com", "captcha.token.awswaf.com"} {
		response := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
			"source_type": "remote", "source_id": "phone", "destination_kind": "public", "destination_domain": domain,
		}, nil, cookie)
		body := decodeResponse(t, response)
		if body["action"] != "wan-direct" || body["matched_rule"] != "remote-direct-service" {
			t.Fatalf("release-pinned domain %q did not use direct service route: %#v", domain, body)
		}
	}
}

func TestRouteSimulationHonorsTorrentWANInBothTrafficModes(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["local_clients"] = []any{map[string]any{"id": "phone", "policy_id": "europe"}}
	policy := map[string]any{
		"id": "europe", "enabled": true, "traffic_mode": "wan_with_vless_exceptions",
		"service_routes": map[string]any{"torrent": "europe"}, "torrent_direct": true,
		"selected_outbound": "reverse-xhttp",
	}
	config["policies"] = []any{policy}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}

	assertAction := func(want string) {
		t.Helper()
		response := performRequest(t, server, http.MethodPost, apiPrefix+"/route/simulate", map[string]any{
			"source_type": "local", "source_id": "phone", "destination_kind": "service", "service": "torrent",
		}, nil, cookie)
		body := decodeResponse(t, response)
		if body["action"] != want {
			t.Fatalf("torrent action = %v, want %s: %#v", body["action"], want, body)
		}
	}
	assertAction("wan-direct")

	policy["torrent_direct"] = false
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	assertAction("vless")

	policy["traffic_mode"] = "vless_with_wan_exceptions"
	policy["service_routes"] = map[string]any{}
	policy["direct_services"] = []any{}
	policy["torrent_direct"] = true
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	assertAction("wan-direct")

	policy["torrent_direct"] = false
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	assertAction("vless")
}
