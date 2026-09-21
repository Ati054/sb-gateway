package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestSubscriptionRefreshRequestDeadlineScope(t *testing.T) {
	for _, item := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodPost, apiPrefix + "/subscriptions/provider/refresh", true},
		{http.MethodGet, apiPrefix + "/subscriptions/provider/refresh", false},
		{http.MethodPost, apiPrefix + "/subscriptions/provider", false},
		{http.MethodPost, apiPrefix + "/remote-users/provider/refresh", false},
	} {
		request := httptest.NewRequest(item.method, item.path, nil)
		if got := isSubscriptionRefreshRequest(request); got != item.want {
			t.Fatalf("%s %s: got %v, want %v", item.method, item.path, got, item.want)
		}
	}
	if subscriptionRefreshResponseTimeout <= 60*time.Second {
		t.Fatalf("response timeout %s must cover one queued and one active bounded refresh", subscriptionRefreshResponseTimeout)
	}
}

func TestNativeSubscriptionRefreshCommitsSecretsAndReturnsPublicMetadata(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	created := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{
		"id": "provider", "display_name": "Provider", "enabled": true,
		"url": "https://provider.example.test/private", "max_nodes": 10,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("subscription create failed: %d %s", created.Code, created.Body.String())
	}
	const uuid = "2f1c08fc-3f43-4e95-8f57-f8bded750a1a"
	body := []byte("vless://" + uuid + "@de.example.test:443?security=reality&sni=de.example.test&pbk=public&type=xhttp&mode=packet-up#DE%20Berlin")
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return body, http.Header{"Subscription-Userinfo": []string{"upload=10; download=20; total=100; expire=1893456000"}}, nil
	}
	refresh := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", refresh.Code, refresh.Body.String())
	}
	result := decodeResponse(t, refresh)
	if result["nodes"] != float64(1) || result["activated"] != false {
		t.Fatalf("refresh result = %#v", result)
	}
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	entry := state["provider"].(map[string]any)
	node := entry["nodes"].([]any)[0].(map[string]any)
	if _, leaked := node["_uuid"]; leaked {
		t.Fatalf("state leaked UUID: %#v", node)
	}
	reference, ok := node["uuid_secret_ref"].(string)
	if !ok || reference == "" {
		t.Fatalf("state has no UUID reference: %#v", node)
	}
	stored, err := server.secrets.read(reference, true)
	if err != nil || stored != uuid {
		t.Fatalf("stored UUID = %q, err=%v", stored, err)
	}

	metadata := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/provider/nodes", nil, nil, cookie)
	if metadata.Code != http.StatusOK {
		t.Fatalf("nodes failed: %d %s", metadata.Code, metadata.Body.String())
	}
	publicNode := decodeResponse(t, metadata)["nodes"].([]any)[0].(map[string]any)
	if publicNode["protocol"] != "reality" || publicNode["city"] != "DE Berlin" || publicNode["subscription_display_name"] != "Provider" {
		t.Fatalf("public node = %#v", publicNode)
	}
	if _, leaked := publicNode["uuid_secret_ref"]; leaked {
		t.Fatalf("metadata leaked secret reference: %#v", publicNode)
	}
	provider := decodeResponse(t, metadata)["provider"].(map[string]any)
	usage := provider["usage"].(map[string]any)
	if usage["remaining_bytes"] != float64(70) {
		t.Fatalf("provider usage = %#v", usage)
	}
}

func TestNativeSubscriptionRefreshFailureKeepsLastKnownGoodNodes(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	created := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{
		"id": "provider", "enabled": true, "url": "https://provider.example.test/private",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("subscription create failed: %d %s", created.Code, created.Body.String())
	}
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return []byte("vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@de.example.test:443?security=tls#DE"), nil, nil
	}
	first := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if first.Code != http.StatusOK {
		t.Fatalf("initial refresh failed: %d %s", first.Code, first.Body.String())
	}
	before, _ := server.repository.auxiliary("subscription-nodes")
	fingerprint := before["provider"].(map[string]any)["fingerprint"]
	for name, invalidBody := range map[string][]byte{
		"empty":          {},
		"html error":     []byte("<!doctype html><title>upstream error</title>"),
		"truncated json": []byte(`{"nodes":[`),
		"damaged base64": []byte("%%%not-a-subscription%%%"),
		"invalid node":   []byte("hy2://secret@invalid.example.test:443?obfs=salamander"),
	} {
		t.Run(name, func(t *testing.T) {
			server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
				return invalidBody, nil, nil
			}
			failed := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
			if failed.Code != http.StatusUnprocessableEntity {
				t.Fatalf("unsafe refresh returned %d: %s", failed.Code, failed.Body.String())
			}
			after, _ := server.repository.auxiliary("subscription-nodes")
			if after["provider"].(map[string]any)["fingerprint"] != fingerprint {
				t.Fatal("failed or empty refresh replaced last-known-good nodes")
			}
		})
	}
}

func TestNativeSubscriptionRefreshRetainsProviderTLSPin(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	created := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{
		"id": "provider", "enabled": true, "url": "https://provider.example.test/private",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("subscription create failed: %d %s", created.Code, created.Body.String())
	}
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return []byte("vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@provider.example.test:443?security=tls&type=grpc&serviceName=edge&fp=edge&pcs=EA:1F:9D:54:F3:95:5F:A4:04:E7:FD:31:35:31:9E:93:B4:B7:D2:C7:19:BD:FD:24:9A:ED:20:F4:70:DE:13:1C#Provider"), nil, nil
	}
	refresh := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", refresh.Code, refresh.Body.String())
	}
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	node := state["provider"].(map[string]any)["nodes"].([]any)[0].(map[string]any)
	if node["tls"].(map[string]any)["pinned_peer_cert_sha256"] != "ea1f9d54f3955fa404e7fd3135319e93b4b7d2c719bdfd249aed20f470de131c" {
		t.Fatalf("stored node lost provider TLS pin: %#v", node)
	}
}

func TestNativeSubscriptionRefreshUsesHealthyReverseFallback(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	created := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{
		"id": "provider", "enabled": true, "url": "https://provider.example.test/private",
		"refresh_via_direct": false, "refresh_via_vpn": true, "refresh_via_active_outbounds": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("subscription create failed: %d %s", created.Code, created.Body.String())
	}
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["reverse_vless_exits"] = []any{map[string]any{"id": "home", "enabled": true}}
	revision, err := server.repository.stageGeneration(config)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate fixture: revision=%q err=%v", revision, err)
	}
	if err := server.repository.saveAuxiliary("selector-health", map[string]any{
		"europe": map[string]any{"selected": "reverse-vless-home", "availability_ok": map[string]any{"reverse-vless-home": true}},
	}); err != nil {
		t.Fatal(err)
	}
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		t.Fatal("direct refresh was used although it is disabled")
		return nil, nil, nil
	}
	selected := ""
	server.selectUpdateExit = func(_ context.Context, _ map[string]any, outbound string) error {
		selected = outbound
		return nil
	}
	server.fetchViaProxy = func(_ context.Context, _ string, proxy string, _ int) ([]byte, http.Header, error) {
		if proxy != "http://127.0.0.1:19080" {
			t.Fatalf("proxy = %q", proxy)
		}
		return []byte("vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@de.example.test:443?security=tls#DE"), nil, nil
	}
	refresh := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if refresh.Code != http.StatusOK {
		t.Fatalf("reverse fallback refresh failed: %d %s", refresh.Code, refresh.Body.String())
	}
	channel := decodeResponse(t, refresh)["update_channel"].(map[string]any)
	if selected != "reverse-vless-home" || channel["kind"] != "active-vpn" || channel["outbound"] != selected {
		t.Fatalf("selected=%q channel=%#v", selected, channel)
	}
}

func TestPublicSubscriptionIPRejectsRouterAndReservedNetworks(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "192.168.88.1", "198.18.0.1", "203.0.113.1", "::1", "fd00::1"} {
		if publicSubscriptionIP(netip.MustParseAddr(value)) {
			t.Fatalf("%s accepted as public", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicSubscriptionIP(netip.MustParseAddr(value)) {
			t.Fatalf("%s rejected as non-public", value)
		}
	}
}

func TestRouterOSPlanNodesFlattensEnabledSubscriptionState(t *testing.T) {
	server := newTestServer(t)
	config := currentConfigFixture(t)
	config["subscriptions"] = []any{
		map[string]any{"id": "one", "display_name": "One", "enabled": true},
		map[string]any{"id": "off", "enabled": false},
	}
	if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{
		"one": map[string]any{"nodes": []any{map[string]any{
			"id": "node", "enabled": true, "protocol": "vless", "location_key": "location", "selection_identity": "identity",
		}}},
		"off": map[string]any{"nodes": []any{map[string]any{"id": "hidden", "enabled": true}}},
	}); err != nil {
		t.Fatal(err)
	}
	nodes, err := server.routerOSPlanNodes(config)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("runtime nodes = %#v, err=%v", nodes, err)
	}
	if nodes[0]["id"] != "one-node" || nodes[0]["subscription_id"] != "one" || nodes[0]["selection_key"] == "" {
		t.Fatalf("scoped node = %#v", nodes[0])
	}
}
