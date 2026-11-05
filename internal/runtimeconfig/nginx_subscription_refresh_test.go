package runtimeconfig

import (
	"os"
	"strings"
	"testing"
)

const nginxRefreshTestAPI = `location /api/ {
 proxy_http_version 1.1;
 proxy_set_header Host $host;
 proxy_set_header Authorization $http_authorization;
 proxy_set_header X-Synthetic-Guard "kept; { }";
 proxy_buffering off;
 proxy_pass http://127.0.0.1:8080;
}`

func TestNginxSubscriptionRefreshTimeoutMigration(t *testing.T) {
	for _, variant := range []string{"ordinary", "spacing", "generic-timeout", "already-scoped", "stale-scoped", "comments"} {
		t.Run(variant, func(t *testing.T) {
			api := nginxRefreshTestAPI
			prefix := ""
			switch variant {
			case "spacing":
				api = strings.ReplaceAll(api, "location /api/ {", "location\n '/api/'\t{")
			case "generic-timeout":
				api = strings.Replace(api, "proxy_buffering off;", "proxy_buffering off; proxy_read_timeout 60s;", 1)
			case "already-scoped", "stale-scoped":
				prefix = strings.Replace(api, "location /api/", "location ~ \""+nginxSubscriptionRefreshPattern+"\"", 1)
				duration := "180s"
				if variant == "stale-scoped" {
					duration = "60s"
				}
				prefix = strings.Replace(prefix, "proxy_buffering off;", "proxy_buffering off; proxy_read_timeout "+duration+";", 1)
			case "comments":
				prefix = "# location ~ " + nginxSubscriptionRefreshPattern + " { proxy_read_timeout 180s; }\n"
			}
			original := "http { server { listen 443 ssl; " + nginxRefreshTestAPI + " } server { listen\n9443\tssl; " + prefix + api + " } }"
			updated, err := UpgradeNginxSubscriptionRefreshTimeout(original)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(updated, api) {
				t.Fatal("ordinary API policy changed")
			}
			blocks, err := nginxRefreshBlocks(updated)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, block := range blocks {
				if len(block.words) == 3 && block.words[0] == "location" && block.words[2] == nginxSubscriptionRefreshPattern {
					count++
					body := updated[block.body : block.end-1]
					if !strings.Contains(body, "proxy_read_timeout 180s;") || !strings.Contains(body, "Authorization $http_authorization;") || !strings.Contains(body, `X-Synthetic-Guard "kept; { }";`) || strings.Contains(body, "Bearer") {
						t.Fatal("refresh timeout or saved authentication/guards changed")
					}
				}
			}
			if count != 1 {
				t.Fatalf("refresh scope count=%d", count)
			}
			again, err := UpgradeNginxSubscriptionRefreshTimeout(updated)
			if err != nil || again != updated {
				t.Fatalf("not idempotent: %v", err)
			}
			if variant == "already-scoped" && updated != original {
				t.Fatal("current config was changed")
			}
		})
	}
}

func TestNginxSubscriptionRefreshRejectsUnsafeMigration(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"duplicate-api", nginxRefreshTestAPI + nginxRefreshTestAPI},
		{"external-policy", strings.Replace(nginxRefreshTestAPI, "proxy_buffering off;", "include /synthetic-policy;", 1)},
		{"external-routing", "include /synthetic-policy; " + nginxRefreshTestAPI},
		{"bootstrap-token", strings.Replace(nginxRefreshTestAPI, "$http_authorization", `"Bearer synthetic-token"`, 1)},
		{"custom-regex", `location ~ ^/api/ { return 403; } ` + nginxRefreshTestAPI},
		{"blocking-prefix", `location ^~ /api/ { return 403; } ` + nginxRefreshTestAPI},
		{"subscription-prefix", `location /api/v1/subscriptions/ { return 403; } ` + nginxRefreshTestAPI},
		{"exact-refresh", `location = /api/v1/subscriptions/source/refresh { return 403; } ` + nginxRefreshTestAPI},
		{"ambiguous-timeout", strings.Replace(nginxRefreshTestAPI, "proxy_buffering off;", "proxy_read_timeout 60s; proxy_read_timeout 90s;", 1)},
		{"malformed", nginxRefreshTestAPI + " location /unterminated {"},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := "http { server { listen 9443 ssl; " + test.body + " } }"
			updated, err := UpgradeNginxSubscriptionRefreshTimeout(original)
			if err == nil || updated != original {
				t.Fatal("unsafe/ambiguous configuration changed")
			}
			if strings.Contains(err.Error(), "synthetic-token") || strings.Contains(err.Error(), "synthetic-policy") {
				t.Fatal("migration error disclosed config content")
			}
		})
	}
}

func TestGeneratedNginxHasScopedSubscriptionRefreshTimeout(t *testing.T) {
	template, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"system": map[string]any{"networking": map[string]any{"routeros_gateway": "192.0.2.1"}, "management": map[string]any{}}, "ingress": map[string]any{"subscription_endpoint_enabled": false}}
	read := func(string) (string, error) { return "synthetic-management-token", nil }
	result, err := RenderNginxCandidate(config, read, inboundSecretPath, NginxRenderOptions{Template: string(template), BootstrapTLSCertificate: "/synthetic/cert.pem", BootstrapTLSPrivateKey: "/synthetic/key.pem"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := UpgradeNginxSubscriptionRefreshTimeout(result)
	if err != nil || updated != result {
		t.Fatalf("generated scope is not current: %v", err)
	}
	blocks, err := nginxRefreshBlocks(result)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, block := range blocks {
		if len(block.words) == 3 && block.words[2] == nginxSubscriptionRefreshPattern {
			count++
			body := result[block.body : block.end-1]
			if !strings.Contains(body, "proxy_read_timeout 180s;") || strings.Contains(body, "Bearer") {
				t.Fatal("scoped refresh auth/timeout invalid")
			}
		}
		if len(block.words) == 2 && block.words[1] == "/api/" {
			if strings.Contains(result[block.body:block.end-1], "proxy_read_timeout") {
				t.Fatal("ordinary API timeout broadened")
			}
		}
	}
	if count != 1 {
		t.Fatalf("generated refresh scopes=%d", count)
	}
}
