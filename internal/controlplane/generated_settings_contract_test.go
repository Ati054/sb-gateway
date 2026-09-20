package controlplane

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

// This contract uses reserved example.test names: it proves that a complete
// CDN/system form reaches every local runtime artifact and the RouterOS script
// without depending on public DNS or a real CDN account.
func TestSyntheticCDNAndSystemSettingsReachGeneratedArtifacts(t *testing.T) {
	config := routerOSReadyConfig(t)
	networking := config["system"].(map[string]any)["networking"].(map[string]any)
	networking["tun_mtu"] = float64(1388)
	dns := config["dns"].(map[string]any)
	dns["direct_resolver"] = map[string]any{"provider": "yandex", "protocol": "doh"}
	dns["vpn_resolver"] = map[string]any{"provider": "quad9", "protocol": "dot"}
	dns["force_tcp_for_proxy_services"] = true
	watchdog := config["watchdog"].(map[string]any)
	watchdog["interval_seconds"] = float64(11)
	watchdog["failure_threshold"] = float64(4)
	watchdog["recovery_threshold"] = float64(5)
	watchdog["recovery_cooldown_seconds"] = float64(77)
	watchdog["max_restarts_per_hour"] = float64(8)

	secrets := map[string]string{
		"management-api-token": "0123456789abcdef0123456789abcdef",
		"transport/ws-path":    "/synthetic-ws-path",
		"transport/grpc-name":  "synthetic-grpc-service",
	}
	for _, raw := range config["transports"].([]any) {
		transport := raw.(map[string]any)
		deployments, _ := transport["cdn_deployments"].([]any)
		if len(deployments) != 0 {
			deployment := deployments[0].(map[string]any)
			transport["hostname"] = deployment["hostname"]
			transport["origin_server_name"] = deployment["origin_server_name"]
			transport["origin_port"] = deployment["origin_port"]
		}
		switch transport["kind"] {
		case "ws":
			transport["path_secret_ref"] = "transport/ws-path"
		case "grpc":
			transport["service_name_secret_ref"] = "transport/grpc-name"
		}
	}
	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("synthetic deployable configuration failed validation: %#v", result.Errors)
	}

	templateBody, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	readSecret := func(reference string) (string, error) {
		value, exists := secrets[reference]
		if !exists {
			return "", errors.New("secret not found")
		}
		return value, nil
	}
	secretPath := func(reference string) (string, error) {
		if strings.TrimSpace(reference) == "" {
			return "", errors.New("empty secret reference")
		}
		return "/run/secrets/" + reference, nil
	}
	artifacts, err := runtimeconfig.BuildNativeRuntimeArtifacts(
		config,
		nil,
		readSecret,
		secretPath,
		runtimeconfig.NativeArtifactOptions{
			RuleSetRoot: t.TempDir(),
			Nginx:       runtimeconfig.NginxRenderOptions{Template: string(templateBody)},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var xray map[string]any
	if err := json.Unmarshal(artifacts["xray.json"], &xray); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := xray["inbounds"].([]any)
	seenTransparent, seenWS, seenGRPC := false, false, false
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		switch inbound["tag"] {
		case "tun-routeros":
			settings, _ := inbound["settings"].(map[string]any)
			seenTransparent = inbound["protocol"] == "dokodemo-door" && inbound["port"] == float64(12345) && settings["network"] == "tcp,udp" && settings["followRedirect"] == true
		case "vless-ws":
			stream, _ := inbound["streamSettings"].(map[string]any)
			settings, _ := stream["wsSettings"].(map[string]any)
			seenWS = settings["path"] == "/synthetic-ws-path"
		case "vless-grpc":
			stream, _ := inbound["streamSettings"].(map[string]any)
			settings, _ := stream["grpcSettings"].(map[string]any)
			seenGRPC = settings["serviceName"] == "synthetic-grpc-service"
		}
	}
	if !seenTransparent || !seenWS || !seenGRPC {
		t.Fatalf("Xray did not receive TPROXY/WS/gRPC settings: tproxy=%t ws=%t grpc=%t", seenTransparent, seenWS, seenGRPC)
	}

	policyDNS := string(artifacts["policy-dns.json"])
	if !strings.Contains(policyDNS, `"server":"9.9.9.9"`) || !strings.Contains(policyDNS, `"server_port":853`) {
		t.Fatalf("VPN Quad9/DoT setting did not reach policy DNS: %s", policyDNS)
	}
	watchdogEnvironment := string(artifacts["watchdog.env"])
	for _, expected := range []string{
		"SB_WATCHDOG_INTERVAL_SECONDS=11",
		"SB_WATCHDOG_FAILURE_THRESHOLD=4",
		"SB_WATCHDOG_RECOVERY_THRESHOLD=5",
		"SB_WATCHDOG_MAX_RESTARTS_PER_HOUR=8",
	} {
		if !strings.Contains(watchdogEnvironment, expected) {
			t.Fatalf("watchdog setting %q did not reach watchdog.env: %s", expected, watchdogEnvironment)
		}
	}
	nginx := string(artifacts["nginx.conf"])
	for _, expected := range []string{
		"server_name origin-0.example.test;",
		"listen 9443 ssl;",
		"location = /synthetic-ws-path {",
		"synthetic-grpc-service",
	} {
		if !strings.Contains(nginx, expected) {
			t.Fatalf("CDN setting %q did not reach nginx.conf", expected)
		}
	}

	routerOS, err := runtimeconfig.RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`use-doh-server="https://common.dot.dns.yandex.net/dns-query"`,
		`protocol=tcp dst-port=18443 dst-address-type=local src-address-list="SB_CLOUDFLARE_V4"`,
		`:global \"SB_HEALTH_COOLDOWN_TICKS\" 7;`,
	} {
		if !strings.Contains(routerOS, expected) {
			t.Fatalf("system/CDN setting %q did not reach RouterOS candidate", expected)
		}
	}
}
