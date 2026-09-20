package runtimeconfig

import (
	"encoding/json"
	"os"
	"testing"
)

func TestBuildNativeRuntimeArtifactsProducesCompleteContainerSet(t *testing.T) {
	templateBody, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"system": map[string]any{
			"networking": map[string]any{
				"routeros_gateway": "192.168.3.1", "container_address": "198.18.0.2/29",
				"tun_address": "198.18.0.1/30", "tun_mtu": 1400, "tun_stack": "system", "remote_ipv6_mode": "proxy_only",
			},
			"management": map[string]any{},
		},
		"dns": map[string]any{
			"internal_server": "192.168.3.1",
			"direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
		},
		"ingress": map[string]any{"tls_profile_id": "public"},
		"tls_profiles": []any{map[string]any{
			"id": "public", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key",
		}},
		"watchdog": map[string]any{"interval_seconds": 5, "failure_threshold": 3, "recovery_threshold": 3, "max_restarts_per_hour": 6},
	}
	artifacts, err := BuildNativeRuntimeArtifacts(config, nil, func(reference string) (string, error) {
		if reference == "management-api-token" {
			return "management-token", nil
		}
		return "", os.ErrNotExist
	}, inboundSecretPath, NativeArtifactOptions{
		RuleSetRoot: t.TempDir(), Nginx: NginxRenderOptions{Template: string(templateBody)},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"xray.json", "urltest-pool.json", "policy-dns.json", "nginx.conf", "watchdog.env", "client-telemetry.nft", "transparent-exclusions.txt"}
	if len(artifacts) != len(want) {
		t.Fatalf("artifact count = %d, want %d", len(artifacts), len(want))
	}
	for _, name := range want {
		if _, exists := artifacts[name]; !exists {
			t.Fatalf("native artifact %q is missing", name)
		}
	}
	var xray map[string]any
	if err := json.Unmarshal(artifacts["xray.json"], &xray); err != nil || xray["routing"] == nil {
		t.Fatalf("invalid Xray artifact: %v", err)
	}
	var healthPool map[string]any
	if err := json.Unmarshal(artifacts["urltest-pool.json"], &healthPool); err != nil || healthPool["version"] != float64(4) {
		t.Fatalf("invalid health-pool artifact: %v %#v", err, healthPool)
	}
	var policyDNS map[string]any
	if err := json.Unmarshal(artifacts["policy-dns.json"], &policyDNS); err != nil || policyDNS["lanes"] == nil {
		t.Fatalf("invalid policy DNS artifact: %v", err)
	}
}
