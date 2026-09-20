package runtimeconfig

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRenderNginxCandidateBuildsDirectAndCDNSubscriptionWithoutDuplicateLocations(t *testing.T) {
	templateBody, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"system": map[string]any{
			"networking": map[string]any{"routeros_gateway": "192.168.3.1"},
			"management": map[string]any{},
		},
		"ingress": map[string]any{
			"tls_profile_id": "public", "status_hostname": "status.example.test", "status_listen_port": 443,
			"subscription_endpoint_mode": "direct-and-cdn", "subscription_hostname": "subscribe.example.test",
			"subscription_listen_port": 4443, "subscription_tls_profile_id": "public",
			"subscription_transport_id": "ws", "subscription_deployment_id": "cloudflare",
		},
		"tls_profiles": []any{
			map[string]any{"id": "public", "enabled": true, "certificate_secret_ref": "tls/public-cert", "private_key_secret_ref": "tls/public-key"},
			map[string]any{"id": "origin", "enabled": true, "certificate_secret_ref": "tls/origin-cert", "private_key_secret_ref": "tls/origin-key"},
		},
		"transports": []any{
			map[string]any{
				"id": "ws", "enabled": true, "kind": "ws", "path_secret_ref": "transport/ws-path",
				"hostname": "cdn.example.test", "origin_server_name": "origin.example.test", "origin_port": 443,
				"cdn_deployments": []any{
					map[string]any{
						"id": "cloudflare", "enabled": true, "hostname": "cdn.example.test", "origin_port": 443,
						"origin_server_name": "origin.example.test", "tls_profile_id": "origin",
						"origin_protection_mode": "secret-header", "origin_header_name": "X-SB-Origin", "origin_header_secret_ref": "origin/cf",
					},
					map[string]any{
						"id": "yandex", "enabled": true, "hostname": "cdn-y.example.test", "origin_port": 443,
						"origin_server_name": "origin.example.test", "tls_profile_id": "origin",
						"origin_protection_mode": "secret-header", "origin_header_name": "X-SB-Origin", "origin_header_secret_ref": "origin/ya",
					},
				},
			},
			map[string]any{
				"id": "grpc", "enabled": true, "kind": "grpc", "service_name_secret_ref": "transport/grpc-service",
				"hostname": "grpc.example.test", "origin_server_name": "origin.example.test", "origin_port": 443,
				"cdn_deployments": []any{map[string]any{
					"id": "grpc-cdn", "enabled": true, "hostname": "grpc.example.test", "origin_port": 443,
					"origin_server_name": "grpc-origin.example.test", "tls_profile_id": "origin", "origin_protection_mode": "auto-cidr",
				}},
			},
			map[string]any{
				"id": "reality", "enabled": true, "kind": "reality", "listen_port": 2443,
				"server_name": "api.example.test", "server_names": []any{"api-alt.example.test"},
				"cover_mode": "api", "tls_profile_id": "public",
			},
		},
	}
	secrets := map[string]string{
		"management-api-token": "management-token", "transport/ws-path": "/private-ws",
		"transport/grpc-service": "private-grpc", "origin/cf": "cloudflare-secret", "origin/ya": "yandex-secret",
	}
	reads := make(map[string]int)
	read := func(reference string) (string, error) {
		reads[reference]++
		value, exists := secrets[reference]
		if !exists {
			return "", errors.New("secret not found")
		}
		return value, nil
	}
	result, err := RenderNginxCandidate(config, read, inboundSecretPath, NginxRenderOptions{Template: string(templateBody)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "${") {
		t.Fatal("Nginx candidate contains unresolved variables")
	}
	if strings.Count(result, "location = /private-ws {") != 1 {
		t.Fatalf("shared origin rendered duplicate WS locations:\n%s", result)
	}
	if !strings.Contains(result, `$http_x_sb_origin = "cloudflare-secret"`) || !strings.Contains(result, `$http_x_sb_origin = "yandex-secret"`) {
		t.Fatal("shared origin did not retain every accepted protection secret")
	}
	// One private relay location is part of the base template; the other two
	// are the direct public endpoint and the selected CDN origin.
	if !strings.Contains(result, "server_name subscribe.example.test;") || strings.Count(result, `location ~ "^/[A-Za-z0-9_-]{43,128}$"`) != 3 {
		t.Fatal("direct-and-CDN subscription did not expose both addresses")
	}
	if !strings.Contains(result, "listen 443 ssl;\n        http2 on;") || !strings.Contains(result, "grpc_pass grpc://127.0.0.1:11002;") {
		t.Fatal("coalesced HTTP/2 origin server is incomplete")
	}
	if !strings.Contains(result, "listen 127.0.0.1:16448 ssl default_server;\n        http2 on;") || !strings.Contains(result, "server_name api-alt.example.test api.example.test;") || !strings.Contains(result, "nginx-api-decoy.inc") {
		t.Fatal("managed API cover for known TLS/REALITY SNI is incomplete")
	}
	if !strings.Contains(result, "ssl_certificate /run/secrets/tls/origin-cert;") || !strings.Contains(result, `Authorization "Bearer management-token"`) {
		t.Fatal("resolved TLS/token values are missing")
	}
	for reference, count := range reads {
		if count != 1 {
			t.Fatalf("secret %q was read %d times in one render", reference, count)
		}
	}
}

func TestRenderNginxCandidateUsesBootstrapTLSForClientOnlyManagement(t *testing.T) {
	templateBody, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"system": map[string]any{
			"networking": map[string]any{"routeros_gateway": "172.31.255.1"},
			"management": map[string]any{},
		},
		"ingress": map[string]any{
			"tls_profile_id": "cdn-default", "status_hostname": "",
			"subscription_endpoint_enabled": false,
		},
		"tls_profiles": []any{map[string]any{
			"id": "cdn-default", "enabled": false,
			"certificate_secret_ref": "", "private_key_secret_ref": "",
		}},
		"transports": []any{},
	}
	result, err := RenderNginxCandidate(
		config,
		func(reference string) (string, error) {
			if reference == "management-api-token" {
				return "management-token", nil
			}
			return "", errors.New("secret not found")
		},
		inboundSecretPath,
		NginxRenderOptions{
			Template:                string(templateBody),
			BootstrapTLSCertificate: "/config/certs/bootstrap.pem",
			BootstrapTLSPrivateKey:  "/config/certs/bootstrap.key",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "ssl_certificate /config/certs/bootstrap.pem;") ||
		!strings.Contains(result, "ssl_certificate_key /config/certs/bootstrap.key;") {
		t.Fatalf("client-only management did not retain bootstrap TLS:\n%s", result)
	}
	if strings.Contains(result, "listen 443 ssl") {
		t.Fatalf("client-only candidate exposed an unintended public TLS listener:\n%s", result)
	}
}

func TestNginxRealityAPICoverAdvertisesHTTP2ForEveryRealityTransport(t *testing.T) {
	config := map[string]any{
		"tls_profiles": []any{map[string]any{
			"id": "public", "enabled": true,
			"certificate_secret_ref": "tls/public-cert", "private_key_secret_ref": "tls/public-key",
		}},
		"transports": []any{
			map[string]any{"kind": "reality", "enabled": true, "cover_mode": "api", "tls_profile_id": "public", "server_name": "raw.example.test"},
			map[string]any{"kind": "reality-grpc", "enabled": true, "cover_mode": "api", "tls_profile_id": "public", "server_name": "grpc.example.test"},
			map[string]any{"kind": "xhttp-reality", "enabled": true, "cover_mode": "api", "tls_profile_id": "public", "server_name": "xhttp.example.test"},
		},
	}
	result, err := nginxRealityCoverServers(config, "/run/secrets/default-cert", "/run/secrets/default-key", inboundSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(result, "listen 127.0.0.1:16448 ssl;\n        http2 on;") != 1 {
		t.Fatalf("known-SNI API cover must expose one HTTP/2 TLS listener:\n%s", result)
	}
	if !strings.Contains(result, "server_name grpc.example.test raw.example.test xhttp.example.test;") {
		t.Fatalf("API cover did not coalesce every REALITY transport onto the HTTP/2 listener:\n%s", result)
	}
	if !strings.Contains(result, "ssl_certificate /run/secrets/tls/public-cert;") ||
		!strings.Contains(result, "ssl_certificate_key /run/secrets/tls/public-key;") {
		t.Fatalf("API cover did not use the certificate selected for its SNI:\n%s", result)
	}
}

func TestNginxDualDedicatedCDNUsesTheDirectOriginListener(t *testing.T) {
	config := map[string]any{"ingress": map[string]any{
		"subscription_endpoint_enabled": true,
		"subscription_endpoint_mode":    "direct-and-cdn",
		"subscription_hostname":         "origin.example.test",
		"subscription_cdn_hostname":     "edge.cdn.example.test",
		"subscription_listen_port":      18443,
		"subscription_public_port":      443,
		"subscription_tls_profile_id":   "public",
	}}
	endpoints, err := nginxSubscriptionEndpoints(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 1 || endpoints[0].Mode != "direct" || endpoints[0].Hostname != "origin.example.test" || endpoints[0].Port != 18443 {
		t.Fatalf("dual dedicated CDN listeners = %#v", endpoints)
	}
}

func TestRenderNginxCandidateSeparatesSubscriptionEdgeFromOriginAndRetainsSharedStatusHeaderGuard(t *testing.T) {
	templateBody, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"system": map[string]any{
			"networking": map[string]any{"routeros_gateway": "192.168.3.1"},
			"management": map[string]any{},
		},
		"ingress": map[string]any{
			"tls_profile_id": "public", "status_hostname": "origin.example.test", "status_listen_port": 443,
			"require_cloudflare_source_ranges": false,
			"subscription_endpoint_mode":       "separate", "subscription_hostname": "edge.cdn.example.test",
			"subscription_origin_server_name": "origin.example.test", "subscription_listen_port": 443, "subscription_public_port": 8443,
			"subscription_tls_profile_id": "public", "subscription_origin_protection_mode": "secret-header",
			"subscription_origin_header_name": "X-SB-Origin", "subscription_origin_header_secret_ref": "ingress/subscription-origin",
		},
		"tls_profiles": []any{map[string]any{
			"id": "public", "enabled": true, "certificate_secret_ref": "tls/public-cert", "private_key_secret_ref": "tls/public-key",
		}},
	}
	read := func(reference string) (string, error) {
		switch reference {
		case "management-api-token":
			return "management-token", nil
		case "ingress/subscription-origin":
			return "origin-secret", nil
		default:
			return "", errors.New("missing")
		}
	}
	result, err := RenderNginxCandidate(config, read, inboundSecretPath, NginxRenderOptions{Template: string(templateBody)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "server_name origin.example.test;") || strings.Contains(result, "server_name edge.cdn.example.test;") {
		t.Fatalf("separate subscription did not use its explicit origin:\n%s", result)
	}
	if strings.Contains(result, "listen 8443 ssl") {
		t.Fatalf("CDN edge port leaked into the origin listener:\n%s", result)
	}
	health := strings.Index(result, "location = /healthz")
	traffic := strings.Index(result, "location = /traffic-ready")
	guard := strings.Index(result, `$http_x_sb_origin != "origin-secret"`)
	if health < 0 || traffic < 0 || guard < health || !strings.Contains(result[traffic:], "proxy_pass http://127.0.0.1:8080/api/health/traffic-ready;") || !strings.Contains(result, `if ($http_x_sb_origin != "origin-secret") { return 404; }`) {
		t.Fatalf("shared status lost the subscription header guard:\n%s", result)
	}

	ingress := config["ingress"].(map[string]any)
	for _, invalid := range []string{"", "*.example.test", "192.0.2.10"} {
		ingress["subscription_origin_server_name"] = invalid
		if _, err := RenderNginxCandidate(config, read, inboundSecretPath, NginxRenderOptions{Template: string(templateBody)}); err == nil || !strings.Contains(err.Error(), "concrete DNS origin") {
			t.Fatalf("invalid separate origin %q was rendered: %v", invalid, err)
		}
	}
}

func TestRenderNginxCandidateSkipsDisabledSubscriptionPublication(t *testing.T) {
	templateBody, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"separate", "direct", "reuse-cdn", "direct-and-cdn"} {
		t.Run(mode, func(t *testing.T) {
			config := map[string]any{
				"system": map[string]any{
					"networking": map[string]any{"routeros_gateway": "192.168.3.1"},
					"management": map[string]any{},
				},
				"ingress": map[string]any{
					"tls_profile_id": "public", "status_hostname": "status.example.test", "status_listen_port": 443,
					"subscription_endpoint_enabled": false, "subscription_endpoint_mode": mode,
					"subscription_hostname": "subscription.example.test", "subscription_origin_server_name": "",
					"subscription_listen_port": 4443, "subscription_tls_profile_id": "",
					"subscription_transport_id": "ws", "subscription_deployment_id": "cdn",
				},
				"tls_profiles": []any{
					map[string]any{"id": "public", "enabled": true, "certificate_secret_ref": "tls/public-cert", "private_key_secret_ref": "tls/public-key"},
					map[string]any{"id": "origin", "enabled": true, "certificate_secret_ref": "tls/origin-cert", "private_key_secret_ref": "tls/origin-key"},
				},
				"transports": []any{map[string]any{
					"id": "ws", "enabled": true, "kind": "ws", "path_secret_ref": "transport/ws-path",
					"hostname": "cdn.example.test", "origin_server_name": "origin.example.test", "origin_port": 8443,
					"cdn_deployments": []any{map[string]any{
						"id": "cdn", "enabled": true, "hostname": "cdn.example.test", "origin_server_name": "origin.example.test", "origin_port": 8443,
						"tls_profile_id": "origin", "origin_protection_mode": "secret-header", "origin_header_secret_ref": "origin/cdn",
					}},
				}},
			}
			result, err := RenderNginxCandidate(config, func(reference string) (string, error) {
				switch reference {
				case "management-api-token":
					return "management-token", nil
				case "transport/ws-path":
					return "/private", nil
				case "origin/cdn":
					return "origin-secret", nil
				default:
					return "", errors.New("unexpected secret read: " + reference)
				}
			}, inboundSecretPath, NginxRenderOptions{Template: string(templateBody)})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(result, "subscription.example.test") || strings.Count(result, `location ~ "^/[A-Za-z0-9_-]{43,128}$"`) != 1 {
				t.Fatalf("disabled %s subscription remained in nginx: %s", mode, result)
			}
			for _, expected := range []string{"server_name status.example.test;", "location = /private {"} {
				if !strings.Contains(result, expected) {
					t.Fatalf("disabled %s subscription removed unrelated listener %q", mode, expected)
				}
			}
		})
	}
}

func TestRenderNginxCandidateRequiresCurrentDeploymentShape(t *testing.T) {
	templateBody, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"system":  map[string]any{"networking": map[string]any{"routeros_gateway": "192.168.3.1"}},
		"ingress": map[string]any{"tls_profile_id": "public"},
		"tls_profiles": []any{map[string]any{
			"id": "public", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key",
		}},
		"transports": []any{map[string]any{
			"id": "legacy", "enabled": true, "kind": "ws", "path_secret_ref": "ws-path", "hostname": "legacy.example.test",
		}},
	}
	read := func(reference string) (string, error) {
		if reference == "management-api-token" {
			return "management-test-token", nil
		}
		return "", errors.New("missing")
	}
	if _, err := RenderNginxCandidate(config, read, inboundSecretPath, NginxRenderOptions{Template: string(templateBody)}); err == nil || !strings.Contains(err.Error(), "cdn_deployments") {
		t.Fatalf("legacy transport shape was accepted: %v", err)
	}
}

func TestRenderNginxCandidateRejectsPublicRelaySource(t *testing.T) {
	config := map[string]any{
		"system":  map[string]any{"networking": map[string]any{"routeros_gateway": "192.168.3.1"}},
		"ingress": map[string]any{"tls_profile_id": "public"},
		"tls_profiles": []any{map[string]any{
			"id": "public", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key",
		}},
	}
	_, err := RenderNginxCandidate(config, func(string) (string, error) { return "token", nil }, inboundSecretPath, NginxRenderOptions{
		Template: "${MANAGEMENT_TOKEN}", SubscriptionRelaySource: "8.8.8.8/32",
	})
	if err == nil {
		t.Fatal("public subscription relay source was accepted")
	}
}
