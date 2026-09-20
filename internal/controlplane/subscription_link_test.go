package controlplane

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestNativeRemoteSubscriptionLinkReturnsBothConfiguredAddressesAndRotates(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_mode"] = "direct-and-cdn"
	ingress["subscription_primary_endpoint"] = "cdn"
	ingress["subscription_hostname"] = "direct.example.test"
	ingress["subscription_listen_port"] = 8443
	ingress["subscription_transport_id"] = "websocket"
	ingress["subscription_deployment_id"] = "edge"
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "enabled": true,
		"subscription_path_secret_ref": "remote-users/phone.subscription-path",
	}}
	config["transports"] = []any{map[string]any{
		"id": "websocket", "kind": "ws", "enabled": true,
		"cdn_deployments": []any{map[string]any{
			"id": "edge", "enabled": true, "hostname": "cdn.example.test", "listen_port": 443,
		}},
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}

	response := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/subscription-link", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("subscription link failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	urls := body["urls"].([]any)
	if len(urls) != 2 || urls[0].(map[string]any)["id"] != "cdn" || urls[0].(map[string]any)["primary"] != true {
		t.Fatalf("subscription URLs = %#v", urls)
	}
	firstURL := body["url"].(string)
	if !strings.HasPrefix(firstURL, "https://cdn.example.test/") || body["transport_count"].(float64) != 1 || body["active"] != false {
		t.Fatalf("subscription link = %#v", body)
	}
	firstToken := strings.TrimPrefix(firstURL, "https://cdn.example.test/")
	if !subscriptionTokenPattern.MatchString(firstToken) {
		t.Fatalf("token = %q", firstToken)
	}
	if second := urls[1].(map[string]any)["url"].(string); second != "https://direct.example.test:8443/"+firstToken {
		t.Fatalf("direct URL = %q", second)
	}

	rotated := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/subscription-link/rotate", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate failed: %d %s", rotated.Code, rotated.Body.String())
	}
	secondURL := decodeResponse(t, rotated)["url"].(string)
	if secondURL == firstURL || !strings.HasPrefix(secondURL, "https://cdn.example.test/") {
		t.Fatalf("rotated URL = %q", secondURL)
	}
}

func TestSubscriptionBaseURLsReturnsDirectAndDedicatedCDNAddresses(t *testing.T) {
	config := map[string]any{
		"ingress": map[string]any{
			"subscription_endpoint_enabled": true,
			"subscription_endpoint_mode":    "direct-and-cdn",
			"subscription_primary_endpoint": "cdn",
			"subscription_hostname":         "origin.example.test",
			"subscription_cdn_hostname":     "edge.cdn.example.test",
			"subscription_listen_port":      18443,
			"subscription_public_port":      443,
		},
	}
	endpoints, err := subscriptionBaseURLs(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 || endpoints[0].ID != "cdn" || endpoints[0].BaseURL != "https://edge.cdn.example.test" {
		t.Fatalf("dedicated CDN endpoints = %#v", endpoints)
	}
	if endpoints[1].ID != "direct" || endpoints[1].BaseURL != "https://origin.example.test:18443" {
		t.Fatalf("direct endpoint = %#v", endpoints[1])
	}
}

func TestSubscriptionBaseURLsSeparatesCDNEdgePortFromOriginPort(t *testing.T) {
	config := map[string]any{"ingress": map[string]any{
		"subscription_endpoint_enabled":   true,
		"subscription_endpoint_mode":      "separate",
		"subscription_hostname":           "edge.cdn.example.test",
		"subscription_origin_server_name": "origin.example.test",
		"subscription_public_port":        443,
		"subscription_listen_port":        18443,
	}}
	endpoints, err := subscriptionBaseURLs(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0].BaseURL != "https://edge.cdn.example.test" {
		t.Fatalf("separate CDN endpoint = %#v", endpoints)
	}
}

func TestSubscriptionBaseURLsKeepsLegacyPortWithoutPublicPort(t *testing.T) {
	config := map[string]any{"ingress": map[string]any{
		"subscription_endpoint_enabled": true,
		"subscription_endpoint_mode":    "separate",
		"subscription_hostname":         "edge.cdn.example.test",
		"subscription_listen_port":      8443,
	}}
	endpoints, err := subscriptionBaseURLs(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0].BaseURL != "https://edge.cdn.example.test:8443" {
		t.Fatalf("legacy endpoint = %#v", endpoints)
	}
}

func TestNativeRemoteSubscriptionLinkKeepsSeparateCDNEdgePublic(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_mode"] = "separate"
	ingress["subscription_hostname"] = "edge.cdn.example.test"
	ingress["subscription_origin_server_name"] = "origin.example.test"
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "enabled": true,
		"subscription_path_secret_ref": "remote-users/phone.subscription-path",
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}

	response := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/subscription-link", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("subscription link failed: %d %s", response.Code, response.Body.String())
	}
	url := decodeResponse(t, response)["url"].(string)
	if !strings.HasPrefix(url, "https://edge.cdn.example.test/") || strings.Contains(url, "origin.example.test") {
		t.Fatalf("separate subscription exported origin instead of CDN edge: %q", url)
	}
}

func TestSubscriptionBaseURLsRequiresConfiguredHostname(t *testing.T) {
	config := map[string]any{
		"ingress": map[string]any{
			"subscription_endpoint_enabled": true,
			"subscription_endpoint_mode":    "separate",
		},
	}
	endpoints, err := subscriptionBaseURLs(config)
	if len(endpoints) != 0 {
		t.Fatalf("unexpected endpoints = %#v", endpoints)
	}
	var failure subscriptionLinkError
	if !errors.As(err, &failure) || failure.code != "subscription_hostname_missing" {
		t.Fatalf("missing hostname error = %#v", err)
	}
}

func TestNativeRemoteSubscriptionLinkRequiresCSRFAndPublicHostname(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["remote_users"] = []any{map[string]any{"id": "phone", "enabled": true}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	withoutCSRF := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/subscription-link", map[string]any{}, nil, cookie)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("link without CSRF returned %d", withoutCSRF.Code)
	}
	missingHostname := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/subscription-link", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if missingHostname.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing hostname returned %d: %s", missingHostname.Code, missingHostname.Body.String())
	}
	if server.secrets.exists("remote-users/phone.subscription-path") {
		t.Fatal("hostname failure generated a token")
	}
}

func TestNativeRemoteSubscriptionLinkRejectsDisabledPublicationBeforeTokenMutation(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["ingress"].(map[string]any)["subscription_endpoint_enabled"] = false
	config["remote_users"] = []any{map[string]any{"id": "phone", "enabled": true, "subscription_path_secret_ref": "remote-users/phone.subscription-path"}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/subscription-link/rotate", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusConflict {
		t.Fatalf("disabled publication returned %d: %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	if body["error"].(map[string]any)["code"] != "subscription_publication_disabled" || server.secrets.exists("remote-users/phone.subscription-path") {
		t.Fatalf("disabled publication rotated or obscured the token: %#v", body)
	}
}
