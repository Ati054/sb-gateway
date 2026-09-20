package controlplane

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func currentConfigFixture(t *testing.T) map[string]any {
	t.Helper()
	config, err := decodeObject(defaultConfigJSON)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func testTransportByKind(t *testing.T, config map[string]any, kind string) (map[string]any, int) {
	t.Helper()
	for index, transport := range objects(config["transports"]) {
		if text(transport["kind"]) == kind {
			return transport, index
		}
	}
	t.Fatalf("transport kind %q not found", kind)
	return nil, -1
}

func TestValidateCurrentConfigAcceptsShippedDefault(t *testing.T) {
	result := validateCurrentConfig(currentConfigFixture(t))
	if !result.Valid {
		t.Fatalf("shipped default failed current-schema validation: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigValidatesHappProviderID(t *testing.T) {
	config := currentConfigFixture(t)
	subscription := config["public_exposure"].(map[string]any)["subscription"].(map[string]any)
	subscription["happ_provider_id"] = "provider-123"
	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid Happ Provider ID rejected: %#v", result.Errors)
	}

	subscription["happ_provider_id"] = " provider 123 "
	result := validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, "public_exposure.subscription.happ_provider_id") {
		t.Fatalf("invalid Happ Provider ID accepted: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigValidatesPerUserHappTunnelSettings(t *testing.T) {
	config := currentConfigFixture(t)
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "display_name": "Phone", "role": "internet-only", "enabled": false,
		"client_tun_address": "172.19.0.1/30", "uuid_secret_ref": "remote-users/phone.uuid",
		"allowed_network_ids": []any{}, "allowed_cidrs": []any{},
		"happ_include_all_networks": true, "happ_exclude_local_networks": true,
		"happ_exclude_apns": true,
	}}
	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid per-user Happ settings rejected: %#v", result.Errors)
	}

	config["remote_users"].([]any)[0].(map[string]any)["happ_exclude_apns"] = "true"
	result := validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, "remote_users[0].happ_exclude_apns") {
		t.Fatalf("non-boolean per-user Happ setting accepted: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsOldSchemaAndBrokenReferences(t *testing.T) {
	config := currentConfigFixture(t)
	config["schema_version"] = 0
	config["networks"] = []any{
		map[string]any{"id": "lan", "cidrs": []any{"192.168.1.0/24"}},
		map[string]any{"id": "lan", "cidrs": []any{"not-a-cidr"}},
	}
	config["policies"] = []any{map[string]any{"id": "home", "final": "home"}}
	config["local_clients"] = []any{map[string]any{
		"id": "phone", "source_cidrs": []any{"192.168.1.20/32"}, "policy_id": "missing",
	}}
	config["routeros"].(map[string]any)["password_secret_ref"] = "../password"

	result := validateCurrentConfig(config)
	if result.Valid || len(result.Errors) < 5 {
		t.Fatalf("invalid current config was accepted: %#v", result.Errors)
	}
	for _, wanted := range []string{"schema_version", "networks[1].id", "networks[1].cidrs[0]", "policies[0].final", "local_clients[0].policy_id", "routeros.password_secret_ref"} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %s: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigRejectsInvalidTransportAndWireGuard(t *testing.T) {
	config := currentConfigFixture(t)
	config["transports"].([]any)[0].(map[string]any)["listen_port"] = 70000
	config["transports"].([]any)[0].(map[string]any)["kind"] = "legacy"
	networking := config["system"].(map[string]any)["networking"].(map[string]any)
	networking["wireguard_egress_enabled"] = true
	networking["wireguard_egress_exits"] = []any{}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{"transports[0].listen_port", "transports[0].kind", "system.networking.wireguard_egress_exits"} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %s: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigReservesRealityAPICoverPort(t *testing.T) {
	config := currentConfigFixture(t)
	reality := config["transports"].([]any)[4].(map[string]any)
	reality["enabled"] = true
	reality["listen_port"] = 16448

	result := validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, "public_exposure.shared_tcp_443") {
		t.Fatalf("REALITY API cover port was not reserved: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRequiresOwnedCertificateForRealityAPICover(t *testing.T) {
	config := currentConfigFixture(t)
	profile := config["tls_profiles"].([]any)[0].(map[string]any)
	profile["certificate_metadata"] = map[string]any{"dns_names": []any{"api.example.test", "*.owned.example.test"}}
	reality := config["transports"].([]any)[4].(map[string]any)
	reality["enabled"] = true
	reality["cover_mode"] = "api"
	reality["tls_profile_id"] = profile["id"]
	reality["server_name"] = "api.example.test"
	reality["server_names"] = []any{"edge.owned.example.test"}

	if result := validateCurrentConfig(config); hasValidationPath(result.Errors, "transports[4].server_name") || hasValidationPath(result.Errors, "transports[4].server_names[0]") {
		t.Fatalf("certificate-covered REALITY API SNI rejected: %#v", result.Errors)
	}

	reality["server_name"] = "www.microsoft.com"
	reality["server_names"] = []any{"nested.edge.owned.example.test"}
	result := validateCurrentConfig(config)
	for _, path := range []string{"transports[4].server_name", "transports[4].server_names[0]"} {
		if !hasValidationPath(result.Errors, path) {
			t.Fatalf("foreign REALITY API SNI accepted at %s: %#v", path, result.Errors)
		}
	}
}

func TestValidateCurrentConfigTreatsMissingEnabledAsActiveLikeRuntime(t *testing.T) {
	config := currentConfigFixture(t)
	config["local_clients"] = []any{map[string]any{
		"id": "phone", "source_kind": "lan", "source_cidrs": []any{"192.168.88.20/32"},
	}}
	config["remote_users"] = []any{map[string]any{
		"id": "remote", "role": "trusted-full", "uuid_secret_ref": "users/remote.uuid",
	}}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{"local_clients[0].policy_id", "remote_users[0].policy_id", "remote_users[0].client_tun_address"} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("runtime-active object without enabled flag escaped validation at %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigRejectsDNSChoicesThatCannotBeApplied(t *testing.T) {
	config := currentConfigFixture(t)
	dns := config["dns"].(map[string]any)
	dns["direct_resolver"] = map[string]any{"provider": "cloudflare", "protocol": "dot"}
	dns["vpn_resolver"] = map[string]any{"provider": "unknown", "protocol": "udp"}
	dns["internal_zones"] = []any{"valid.home.arpa", "not a domain"}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"dns.direct_resolver.protocol",
		"dns.vpn_resolver.provider",
		"dns.vpn_resolver.protocol",
		"dns.internal_zones[1]",
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %s: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigRequiresInternalDNSOnlyWhenDeploymentIsReady(t *testing.T) {
	config := currentConfigFixture(t)
	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("setup draft without internal DNS should remain valid: %#v", result.Errors)
	}
	config["system"].(map[string]any)["deployment_ready"] = true
	result := validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, "dns.internal_server") {
		t.Fatalf("ready deployment accepted without internal DNS: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRequiresActiveTLSMaterialForEveryReadyListener(t *testing.T) {
	config := currentConfigFixture(t)
	config["system"].(map[string]any)["deployment_ready"] = true
	config["dns"].(map[string]any)["internal_server"] = "172.19.0.1"
	profile := config["tls_profiles"].([]any)[0].(map[string]any)
	profile["enabled"] = false
	config["ingress"].(map[string]any)["status_hostname"] = "status.example.test"
	hysteria, hysteriaIndex := testTransportByKind(t, config, "hysteria2")
	hysteria["enabled"] = true
	hysteria["tls_profile_id"] = "cdn-default"
	hysteria["tls_server_name"] = "hysteria.example.test"

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"transports[0].tls_profile_id",
		"transports[1].tls_profile_id",
		fmt.Sprintf("transports[%d].tls_profile_id", hysteriaIndex),
		"ingress.tls_profile_id",
		"ingress.subscription_tls_profile_id",
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("ready listener accepted inactive TLS profile at %q: %#v", wanted, result.Errors)
		}
	}

	profile["enabled"] = true
	profile["certificate_secret_ref"] = "tls/certificate.pem"
	profile["private_key_secret_ref"] = "tls/private-key.pem"
	result = validateCurrentConfig(config)
	for _, issue := range result.Errors {
		if strings.Contains(issue.Path, "tls_profile") || strings.Contains(issue.Path, "tls_profiles") {
			t.Fatalf("provisioned TLS profile was rejected: %#v", result.Errors)
		}
	}
}

func TestValidateCurrentConfigAllowsClientOnlyApplyWithoutPublicTLS(t *testing.T) {
	config := currentConfigFixture(t)
	config["system"].(map[string]any)["deployment_ready"] = true
	config["dns"].(map[string]any)["internal_server"] = "172.19.0.1"
	ingress := config["ingress"].(map[string]any)
	ingress["status_hostname"] = ""
	ingress["subscription_endpoint_enabled"] = false
	config["tls_profiles"].([]any)[0].(map[string]any)["enabled"] = false
	for _, transport := range objects(config["transports"]) {
		transport["enabled"] = false
	}

	result := validateCurrentConfig(config)
	for _, issue := range result.Errors {
		if strings.Contains(issue.Path, "tls_profile") || strings.Contains(issue.Path, "tls_profiles") {
			t.Fatalf("client-only draft retained an unused TLS requirement: %#v", result.Errors)
		}
	}
}

func TestValidateCurrentConfigRequiresGRPCTLSPinSNIFromSelectedCertificate(t *testing.T) {
	config := currentConfigFixture(t)
	profile := config["tls_profiles"].([]any)[0].(map[string]any)
	profile["certificate_metadata"] = map[string]any{"dns_names": []any{"gateway.example.test"}}
	transport, index := testTransportByKind(t, config, "grpc-tls")
	transport["enabled"] = true
	transport["hostname"] = "198.51.100.10"
	transport["tls_profile_id"] = profile["id"]
	transport["tls_server_name"] = "gateway.example.test"

	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid gRPC TLS Pin transport rejected: %#v", result.Errors)
	}
	transport["tls_server_name"] = "other.example.test"
	result := validateCurrentConfig(config)
	path := fmt.Sprintf("transports[%d].tls_server_name", index)
	if !hasValidationPath(result.Errors, path) {
		t.Fatalf("certificate/SNI mismatch accepted: %#v", result.Errors)
	}
	transport["tls_server_name"] = "198.51.100.10"
	result = validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, path) {
		t.Fatalf("IP address accepted as gRPC TLS SNI: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsTransportValuesTheRuntimeCannotHonor(t *testing.T) {
	config := currentConfigFixture(t)
	transports := config["transports"].([]any)
	xhttp := transports[3].(map[string]any)
	xhttp["mode"] = "made-up"
	xhttp["uplink_chunk_size"] = "4096-2048"
	xhttp["server_max_header_bytes"] = 128
	xhttp["headers"] = map[string]any{"Bad\nHeader": "value"}
	xhttp["xmux_max_connections"] = "3"
	xhttp["xmux_max_concurrency"] = "8"

	reality := transports[4].(map[string]any)
	reality["min_client_ver"] = "latest"
	reality["xver"] = 3
	reality["reality_fallback_upload_bytes_per_sec"] = -1
	grpc := transports[1].(map[string]any)
	grpc["tcp_user_timeout"] = -1

	hysteria, hysteriaIndex := testTransportByKind(t, config, "hysteria2")
	hysteria["xray_hysteria"] = map[string]any{
		"udp_idle_timeout": 1,
		"quic_params": map[string]any{
			"congestion":           "unknown",
			"max_idle_timeout":     3,
			"keep_alive_period":    1,
			"max_incoming_streams": 7,
		},
		"masquerade": map[string]any{"type": "proxy", "url": "https://example.com/"},
	}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"transports[3].mode",
		"transports[3].uplink_chunk_size",
		"transports[3].server_max_header_bytes",
		"transports[3].headers.Bad\nHeader",
		"transports[3].xmux_max_concurrency",
		"transports[4].min_client_ver",
		"transports[4].xver",
		"transports[4].reality_fallback_upload_bytes_per_sec",
		"transports[1].tcp_user_timeout",
		fmt.Sprintf("transports[%d].xray_hysteria.udp_idle_timeout", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.quic_params.congestion", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.quic_params.max_idle_timeout", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.quic_params.keep_alive_period", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.quic_params.max_incoming_streams", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.masquerade.url", hysteriaIndex),
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigAcceptsOperationalAdvancedTransportValues(t *testing.T) {
	config := currentConfigFixture(t)
	transports := config["transports"].([]any)
	xhttp := transports[3].(map[string]any)
	xhttp["mode"] = "packet-up"
	xhttp["uplink_chunk_size"] = "2048-3072"
	xhttp["server_max_header_bytes"] = 16384
	xhttp["headers"] = map[string]any{"Cache-Control": "no-store"}
	xhttp["xmux_max_connections"] = "3"
	xhttp["xmux_max_concurrency"] = "0"

	reality := transports[4].(map[string]any)
	reality["min_client_ver"] = "26.3.27"
	reality["max_client_ver"] = "26.9.1"
	reality["xver"] = 2
	reality["tcp_keep_alive_idle"] = 45
	reality["tcp_keep_alive_interval"] = 45
	reality["tcp_user_timeout"] = 60000
	grpc := transports[1].(map[string]any)
	grpc["tcp_keep_alive_enabled"] = true
	grpc["tcp_keep_alive_idle"] = 30
	grpc["tcp_keep_alive_interval"] = 10
	grpc["tcp_user_timeout"] = 0

	hysteria, _ := testTransportByKind(t, config, "hysteria2")
	hysteria["xray_hysteria"] = map[string]any{
		"udp_idle_timeout": 60,
		"udp_hop": map[string]any{
			"enabled": true, "port_start": 20000, "port_end": 20100,
			"interval_min": 15, "interval_max": 45,
		},
		"quic_params": map[string]any{
			"congestion":                       "brutal",
			"brutal_up_mbps":                   100,
			"brutal_down_mbps":                 100,
			"brutal_disable_loss_compensation": true,
			"disable_gso":                      true,
			"disable_stateless_reset":          true,
			"max_idle_timeout":                 30,
			"keep_alive_period":                10,
			"max_incoming_streams":             1024,
			"max_connection_receive_window":    20971520,
		},
		"masquerade": map[string]any{"type": "proxy", "url": "http://127.0.0.1:8080/", "rewrite_host": true, "x_forwarded": true},
	}

	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid advanced transport settings were rejected: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsInvalidHysteriaUDPHop(t *testing.T) {
	config := currentConfigFixture(t)
	hysteria, hysteriaIndex := testTransportByKind(t, config, "hysteria2")
	hysteria["xray_hysteria"] = map[string]any{
		"udp_hop": map[string]any{
			"enabled": true, "port_start": 21000, "port_end": 20000,
			"interval_min": 4, "interval_max": 3, "excluded_ports": "19999",
		},
		"quic_params": map[string]any{}, "masquerade": map[string]any{"type": "api"},
	}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		fmt.Sprintf("transports[%d].xray_hysteria.udp_hop.port_end", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.udp_hop.interval_min", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.udp_hop.interval_max", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.udp_hop", hysteriaIndex),
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing UDP hopping validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigRejectsMisplacedOrInvalidXrayV2699HysteriaControls(t *testing.T) {
	config := currentConfigFixture(t)
	hysteria, hysteriaIndex := testTransportByKind(t, config, "hysteria2")
	hysteria["xray_hysteria"] = map[string]any{
		"quic_params": map[string]any{
			"congestion": "bbr", "brutal_disable_loss_compensation": true,
			"disable_gso": "yes", "disable_stateless_reset": 1,
		},
		"masquerade": map[string]any{
			"type": "website", "url": "https://example.test/", "x_forwarded": true,
		},
	}
	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		fmt.Sprintf("transports[%d].xray_hysteria.quic_params.brutal_disable_loss_compensation", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.quic_params.disable_gso", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.quic_params.disable_stateless_reset", hysteriaIndex),
		fmt.Sprintf("transports[%d].xray_hysteria.masquerade.x_forwarded", hysteriaIndex),
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigAllowsXForwardedOnlyForLocalMasqueradeProxy(t *testing.T) {
	for _, mode := range []string{"", "string", "website"} {
		t.Run("reject "+mode, func(t *testing.T) {
			config := currentConfigFixture(t)
			hysteria, hysteriaIndex := testTransportByKind(t, config, "hysteria2")
			masquerade := map[string]any{"type": mode, "x_forwarded": false}
			if mode == "website" {
				masquerade["url"] = "https://example.test/"
			}
			if mode == "string" {
				masquerade["content"] = "Not found"
			}
			hysteria["xray_hysteria"] = map[string]any{
				"quic_params": map[string]any{}, "masquerade": masquerade,
			}
			result := validateCurrentConfig(config)
			if !hasValidationPath(result.Errors, fmt.Sprintf("transports[%d].xray_hysteria.masquerade.x_forwarded", hysteriaIndex)) {
				t.Fatalf("%q accepted x_forwarded: %#v", mode, result.Errors)
			}
		})
	}

	config := currentConfigFixture(t)
	hysteria, _ := testTransportByKind(t, config, "hysteria2")
	hysteria["xray_hysteria"] = map[string]any{
		"quic_params": map[string]any{},
		"masquerade": map[string]any{
			"type": "proxy", "url": "http://127.0.0.1:8080/", "x_forwarded": true,
		},
	}
	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("local proxy rejected x_forwarded: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsVisibleSystemSettingsThatCannotBeApplied(t *testing.T) {
	config := currentConfigFixture(t)
	system := config["system"].(map[string]any)
	system["deployment_ready"] = true
	management := system["management"].(map[string]any)
	management["allowed_source_cidrs"] = []any{"0.0.0.0/0"}
	management["allowed_ingress_interfaces"] = []any{"bad/interface"}
	networking := system["networking"].(map[string]any)
	networking["tun_mtu"] = 9000
	networking["ipv6_mode"] = "passthrough"
	networking["remote_ipv6_mode"] = "leak-to-wan"
	networking["wireguard_egress_enabled"] = "yes"
	watchdog := config["watchdog"].(map[string]any)
	watchdog["interval_seconds"] = 1
	watchdog["failure_threshold"] = 0
	watchdog["recovery_threshold"] = 21
	watchdog["recovery_cooldown_seconds"] = -1
	watchdog["max_restarts_per_hour"] = 61
	config["storage"].(map[string]any)["root"] = "flash"
	config["dns"].(map[string]any)["internal_server"] = "172.19.0.1"

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"system.management.allowed_source_cidrs[0]",
		"system.management.allowed_ingress_interfaces[0]",
		"system.networking.tun_mtu",
		"system.networking.ipv6_mode",
		"system.networking.remote_ipv6_mode",
		"system.networking.wireguard_egress_enabled",
		"watchdog.interval_seconds",
		"watchdog.failure_threshold",
		"watchdog.recovery_threshold",
		"watchdog.recovery_cooldown_seconds",
		"watchdog.max_restarts_per_hour",
		"storage.root",
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigRejectsContainerBridgeAsManagementIngress(t *testing.T) {
	config := currentConfigFixture(t)
	system := config["system"].(map[string]any)
	networking := system["networking"].(map[string]any)
	networking["bridge_name"] = "sb-gateway"
	system["management"].(map[string]any)["allowed_ingress_interfaces"] = []any{"sb-gateway"}

	result := validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, "system.management.allowed_ingress_interfaces[0]") {
		t.Fatalf("container bridge was accepted as management ingress: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsPolicyValuesTheSelectorWouldOtherwiseClamp(t *testing.T) {
	config := currentConfigFixture(t)
	config["policies"] = []any{map[string]any{
		"id": "europe", "enabled": "yes", "mode": "random", "traffic_mode": "proxy_everything",
		"domain_strategy": "Magic", "on_all_unavailable": "direct", "selection_order": []any{"country:DE", "country:DE"},
		"quality_window": 2, "max_packet_loss_percent": 101, "max_latency_ms": 30001,
		"failure_threshold": 0, "recovery_threshold": 21, "switch_cooldown_seconds": -1,
		"switch_improvement_ms": 30001, "speed_improvement_percent": 101,
		"speed_check_interval_seconds": 299, "speed_probe_bytes": 1024, "speed_candidate_count": 6,
		"active_check_interval_seconds": 300, "backup_check_interval_seconds": 60, "full_scan_interval_seconds": 30,
		"max_active_candidates": 11, "max_probe_candidates": 0, "probe_batch_size": 11,
		"candidate_service_access": map[string]any{"country:DE": "claude"},
	}}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"policies[0].enabled", "policies[0].mode", "policies[0].traffic_mode", "policies[0].domain_strategy",
		"policies[0].on_all_unavailable", "policies[0].selection_order", "policies[0].quality_window",
		"policies[0].max_packet_loss_percent", "policies[0].max_latency_ms", "policies[0].failure_threshold",
		"policies[0].recovery_threshold", "policies[0].switch_cooldown_seconds", "policies[0].switch_improvement_ms",
		"policies[0].speed_improvement_percent", "policies[0].speed_check_interval_seconds", "policies[0].speed_probe_bytes",
		"policies[0].speed_candidate_count", "policies[0].backup_check_interval_seconds", "policies[0].full_scan_interval_seconds",
		"policies[0].max_active_candidates", "policies[0].max_probe_candidates", "policies[0].probe_batch_size",
		"policies[0].candidate_service_access.country:DE",
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigAcceptsEveryVisiblePolicyControlAtItsBoundary(t *testing.T) {
	config := currentConfigFixture(t)
	config["policies"] = []any{map[string]any{
		"id": "europe", "enabled": true, "mode": "best", "traffic_mode": "vless_with_wan_exceptions",
		"domain_strategy": "IPIfNonMatch", "on_all_unavailable": "block", "torrent_direct": true,
		"pinpoint_domains_enabled": true, "speed_check_enabled": true, "return_to_primary": true,
		"interrupt_exist_connections": false, "countries": []any{"DE"}, "locations": []any{"de-berlin"},
		"selection_order": []any{"country:DE"}, "outbounds": []any{"reverse-vless-home"},
		"direct_domains": []any{"example.com"}, "direct_services": []any{"torrent"},
		"candidate_service_ids": []any{"claude"}, "hidden_service_packs": []any{"youtube"},
		"candidate_service_access": map[string]any{"country:DE": []any{"claude"}},
		"service_routes":           map[string]any{"telegram": "europe"},
		"quality_window":           60, "max_packet_loss_percent": 100, "max_latency_ms": 30000,
		"failure_threshold": 20, "recovery_threshold": 20, "switch_cooldown_seconds": 86400,
		"switch_improvement_ms": 30000, "speed_improvement_percent": 100,
		"speed_check_interval_seconds": 86400, "speed_probe_bytes": 10 * 1024 * 1024, "speed_candidate_count": 5,
		"active_check_interval_seconds": 3600, "backup_check_interval_seconds": 3600, "full_scan_interval_seconds": 86400,
		"max_active_candidates": 10, "max_probe_candidates": 10, "probe_batch_size": 10,
	}}

	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid policy controls were rejected: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsClientSettingsTheRuntimeCannotHonor(t *testing.T) {
	config := currentConfigFixture(t)
	config["policies"] = []any{map[string]any{"id": "europe", "enabled": true}}
	config["local_clients"] = []any{map[string]any{
		"id": "phone", "enabled": true, "policy_id": "", "source_kind": "bluetooth",
		"source_cidrs": []any{"192.168.88.20/32"}, "source_peer_refs": []any{"peer-1"},
		"container_outage": "maybe",
	}}
	config["remote_users"] = []any{map[string]any{
		"id": "remote", "enabled": true, "role": "trusted-limited", "policy_id": "",
		"client_tun_address": "", "client_tun_stack": "fast", "client_fingerprint": "netscape", "client_individual_routing": "yes", "client_auto_fallback": 1,
		"client_adblock": "yes", "allowed_cidrs": []any{}, "allowed_network_ids": []any{},
		"uuid_secret_ref": "remote-users/remote.uuid",
	}}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"local_clients[0].source_kind", "local_clients[0].source_peer_refs",
		"local_clients[0].container_outage", "local_clients[0].policy_id",
		"remote_users[0].policy_id", "remote_users[0].client_tun_address", "remote_users[0].client_tun_stack", "remote_users[0].client_fingerprint",
		"remote_users[0].client_individual_routing", "remote_users[0].client_auto_fallback",
		"remote_users[0].client_adblock", "remote_users[0].allowed_cidrs",
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigAcceptsOperationalClientSettings(t *testing.T) {
	config := currentConfigFixture(t)
	config["policies"] = []any{map[string]any{"id": "europe", "enabled": true}}
	config["local_clients"] = []any{map[string]any{
		"id": "phone", "enabled": true, "policy_id": "europe", "source_kind": "wireguard",
		"source_cidrs": []any{"10.20.0.2/32"}, "source_peer_refs": []any{"wg/peer-1"},
		"container_outage": "lan_only",
	}}
	config["remote_users"] = []any{map[string]any{
		"id": "remote", "enabled": true, "role": "trusted-limited", "policy_id": "europe",
		"client_tun_address": "172.30.0.2/30", "client_tun_stack": "mixed", "client_fingerprint": "ios", "client_individual_routing": true,
		"client_auto_fallback": true, "client_adblock": true,
		"allowed_cidrs": []any{"192.168.88.0/24"}, "allowed_network_ids": []any{},
		"uuid_secret_ref": "remote-users/remote.uuid",
	}}

	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid client settings were rejected: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsDuplicateOrNonLANAllDeviceScope(t *testing.T) {
	config := currentConfigFixture(t)
	config["policies"] = []any{map[string]any{"id": "europe", "enabled": true}}
	config["local_clients"] = []any{
		map[string]any{"id": "all-a", "enabled": true, "policy_id": "europe", "source_kind": "lan", "source_scope": "lan-all", "source_cidrs": []any{"192.168.88.0/24"}},
		map[string]any{"id": "all-b", "enabled": true, "policy_id": "europe", "source_kind": "wireguard", "source_scope": "lan-all", "source_cidrs": []any{"10.0.0.2/32"}},
	}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{"local_clients", "local_clients[1].source_scope"} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigRejectsCDNControlsTheRuntimeCannotHonor(t *testing.T) {
	config := currentConfigFixture(t)
	transport := config["transports"].([]any)[1].(map[string]any)
	transport["cdn_deployments"] = []any{
		map[string]any{
			"id": "bad-grpc", "enabled": true, "cdn_provider": "unknown",
			"hostname": "bad host", "origin_server_name": "*.origin.example.test",
			"listen_port": 8443, "origin_port": 18443, "tls_profile_id": "cdn-default",
			"tls_server_name": "https://bad.example", "grpc_authority": "bad/path",
			"origin_protection_mode": "secret-header", "origin_header_name": "Bad Header",
		},
	}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"transports[1].cdn_deployments[0].cdn_provider",
		"transports[1].cdn_deployments[0].hostname",
		"transports[1].cdn_deployments[0].origin_server_name",
		"transports[1].cdn_deployments[0].tls_server_name",
		"transports[1].cdn_deployments[0].grpc_authority",
		"transports[1].cdn_deployments[0].origin_header_name",
		"transports[1].cdn_deployments[0].origin_header_secret_ref",
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigIgnoresDormantSettingsOfDisabledTransport(t *testing.T) {
	config := currentConfigFixture(t)
	transport := config["transports"].([]any)[1].(map[string]any)
	transport["enabled"] = false
	transport["cdn_deployments"] = []any{map[string]any{
		"id": "dormant-edge", "enabled": true, "cdn_provider": "unknown",
		"hostname": "not configured", "origin_server_name": "not configured",
		"listen_port": 0, "origin_port": 70000, "tls_profile_id": "missing",
		"origin_protection_mode": "manual-cidr", "origin_allowed_cidrs": []any{"invalid"},
	}}

	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("disabled transport blocked unrelated Apply with dormant settings: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigAcceptsSyntheticCDNDeploymentWithoutExternalDNS(t *testing.T) {
	config := currentConfigFixture(t)
	transport := config["transports"].([]any)[0].(map[string]any)
	transport["cdn_deployments"] = []any{map[string]any{
		"id": "edge", "enabled": true, "cdn_provider": "cloudflare",
		"hostname": "edge.example.test", "origin_server_name": "origin.example.test",
		"listen_port": 8443, "origin_port": 18443, "tls_profile_id": "cdn-default",
		"tls_server_name": "tls.example.test", "http_host": "host.example.test:8443",
		"origin_protection_mode": "auto-cidr",
	}}

	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid synthetic CDN controls were rejected: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigAllowsSharedNginxPortWithDistinctDomains(t *testing.T) {
	config := currentConfigFixture(t)
	config["transports"] = []any{map[string]any{
		"id": "edge", "kind": "xhttp", "enabled": true, "listen_port": 11000,
		"cdn_deployments": []any{map[string]any{
			"id": "cf", "enabled": true, "cdn_provider": "cloudflare",
			"hostname": "edge.example.test", "origin_server_name": "origin.example.test",
			"listen_port": 443, "origin_port": 18443, "tls_profile_id": "cdn-default",
			"origin_protection_mode": "auto-cidr",
		}},
	}}
	ingress := config["ingress"].(map[string]any)
	ingress["status_hostname"] = "status.example.test"
	ingress["status_listen_port"] = 18443
	ingress["require_cloudflare_source_ranges"] = true
	ingress["subscription_hostname"] = "subscription.example.test"
	ingress["subscription_endpoint_mode"] = "direct"
	ingress["subscription_listen_port"] = 18443

	result := validateCurrentConfig(config)
	if hasValidationPath(result.Errors, "ingress.subscription_listen_port") {
		t.Fatalf("distinct origin domains cannot share a port: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRequiresExplicitDedicatedSubscriptionOrigin(t *testing.T) {
	config := currentConfigFixture(t)
	config["system"].(map[string]any)["deployment_ready"] = true
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_mode"] = "separate"
	ingress["subscription_hostname"] = "edge.cdn.example.test"
	ingress["subscription_origin_server_name"] = ""
	if result := validateCurrentConfig(config); !hasValidationPath(result.Errors, "ingress.subscription_origin_server_name") {
		t.Fatalf("missing dedicated origin was accepted: %#v", result.Errors)
	}

	for _, invalid := range []string{"*.example.test", "192.0.2.10"} {
		ingress["subscription_origin_server_name"] = invalid
		if result := validateCurrentConfig(config); !hasValidationPath(result.Errors, "ingress.subscription_origin_server_name") {
			t.Fatalf("invalid dedicated origin %q was accepted: %#v", invalid, result.Errors)
		}
	}
	ingress["subscription_origin_server_name"] = "Origin.Example.test."
	if result := validateCurrentConfig(config); hasValidationPath(result.Errors, "ingress.subscription_origin_server_name") {
		t.Fatalf("concrete dedicated origin was rejected: %#v", result.Errors)
	}

	for _, mode := range []string{"direct", "reuse-cdn"} {
		ingress["subscription_endpoint_mode"] = mode
		ingress["subscription_origin_server_name"] = ""
		if result := validateCurrentConfig(config); hasValidationPath(result.Errors, "ingress.subscription_origin_server_name") {
			t.Fatalf("%s unexpectedly requires a separate origin: %#v", mode, result.Errors)
		}
	}
}

func TestValidateCurrentConfigAcceptsDedicatedCDNInDualMode(t *testing.T) {
	config := currentConfigFixture(t)
	config["system"].(map[string]any)["deployment_ready"] = true
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_mode"] = "direct-and-cdn"
	ingress["subscription_hostname"] = "origin.example.test"
	ingress["subscription_cdn_hostname"] = "edge.cdn.example.test"
	ingress["subscription_transport_id"] = ""
	ingress["subscription_deployment_id"] = ""
	if result := validateCurrentConfig(config); hasValidationPath(result.Errors, "ingress.subscription_deployment_id") || hasValidationPath(result.Errors, "ingress.subscription_cdn_hostname") {
		t.Fatalf("dedicated CDN dual endpoint was rejected: %#v", result.Errors)
	}

	ingress["subscription_cdn_hostname"] = "not a hostname"
	result := validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, "ingress.subscription_cdn_hostname") {
		t.Fatalf("invalid dedicated CDN hostname was accepted: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigAllowsTypedDisabledSubscriptionPublicationOnly(t *testing.T) {
	config := currentConfigFixture(t)
	config["system"].(map[string]any)["deployment_ready"] = true
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_mode"] = "separate"
	ingress["subscription_hostname"] = "edge.cdn.example.test"
	ingress["subscription_origin_server_name"] = ""
	ingress["subscription_tls_profile_id"] = ""
	ingress["subscription_origin_protection_mode"] = "invalid"
	ingress["subscription_endpoint_enabled"] = false
	if result := validateCurrentConfig(config); hasValidationPath(result.Errors, "ingress.subscription_origin_server_name") || hasValidationPath(result.Errors, "ingress.subscription_tls_profile_id") || hasValidationPath(result.Errors, "ingress.subscription_origin_protection_mode") {
		t.Fatalf("disabled subscription retained publication requirements: %#v", result.Errors)
	}

	for _, invalid := range []any{"false", 0} {
		ingress["subscription_endpoint_enabled"] = invalid
		result := validateCurrentConfig(config)
		if !hasValidationPath(result.Errors, "ingress.subscription_endpoint_enabled") || !hasValidationPath(result.Errors, "ingress.subscription_origin_server_name") {
			t.Fatalf("non-boolean disable value %T was accepted: %#v", invalid, result.Errors)
		}
	}
}

func TestAutomaticCIDRProviderValidation(t *testing.T) {
	for _, provider := range []string{"cloudflare", "gcore", "edgecenter", "yandex", "beeline", "timeweb", "vk", "cdnetworks", "custom"} {
		t.Run(provider, func(t *testing.T) {
			config := currentConfigFixture(t)
			config["transports"] = []any{map[string]any{"id": "cdn", "kind": "ws", "enabled": true, "cdn_deployments": []any{map[string]any{
				"id": "primary", "enabled": true, "cdn_provider": provider, "origin_protection_mode": "auto-cidr", "origin_port": 8443, "listen_port": 443,
				"hostname": "cdn.example.test", "origin_server_name": "origin.example.test", "tls_profile_id": "cdn-default",
			}}}}
			ingress := config["ingress"].(map[string]any)
			ingress["subscription_cdn_provider"] = provider
			ingress["subscription_origin_protection_mode"] = "auto-cidr"
			ingress["subscription_endpoint_mode"] = "separate"
			ingress["subscription_listen_port"] = 18443
			result := validateCurrentConfig(config)
			wantError := provider == "vk" || provider == "cdnetworks" || provider == "custom"
			for _, path := range []string{"transports[0].cdn_deployments[0].origin_protection_mode", "ingress.subscription_origin_protection_mode"} {
				if hasValidationPath(result.Errors, path) != wantError {
					t.Fatalf("%s: %#v", path, result.Errors)
				}
			}
		})
	}
}

func TestSubscriptionCDNValidatesPublicPortSeparatelyFromOriginPort(t *testing.T) {
	config := currentConfigFixture(t)
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_mode"] = "separate"
	ingress["subscription_hostname"] = "edge.cdn.example.test"
	ingress["subscription_origin_server_name"] = "origin.example.test"
	ingress["subscription_cdn_provider"] = "cloudflare"
	ingress["subscription_public_port"] = 443
	ingress["subscription_listen_port"] = 18443
	if result := validateCurrentConfig(config); hasValidationPath(result.Errors, "ingress.subscription_public_port") || hasValidationPath(result.Errors, "ingress.subscription_listen_port") {
		t.Fatalf("valid split subscription ports were rejected: %#v", result.Errors)
	}

	ingress["subscription_public_port"] = 18443
	if result := validateCurrentConfig(config); !hasValidationPath(result.Errors, "ingress.subscription_public_port") {
		t.Fatalf("unsupported Cloudflare edge port was accepted: %#v", result.Errors)
	}

	ingress["subscription_cdn_provider"] = "gcore"
	if result := validateCurrentConfig(config); hasValidationPath(result.Errors, "ingress.subscription_public_port") {
		t.Fatalf("generic CDN public port was incorrectly constrained: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigRejectsSubscriptionControlsThatWouldBeClampedOrIgnored(t *testing.T) {
	config := currentConfigFixture(t)
	config["subscription_reserves"] = []any{map[string]any{"id": "backup", "enabled": true}}
	config["subscriptions"] = []any{map[string]any{
		"id": "provider", "enabled": true, "refresh_minutes": 10081,
		"refresh_via_direct": false, "refresh_via_vpn": true,
		"refresh_via_active_outbounds": false, "refresh_via_independent_reserves": true,
		"allowed_countries": "DE", "location_overrides": map[string]any{"node": map[string]any{"city": ""}},
	}}

	result := validateCurrentConfig(config)
	for _, wanted := range []string{
		"subscription_reserves[0].node", "subscriptions[0].refresh_minutes",
		"subscriptions[0].allowed_countries", "subscriptions[0].location_overrides.node",
	} {
		if !hasValidationPath(result.Errors, wanted) {
			t.Fatalf("missing validation error for %q: %#v", wanted, result.Errors)
		}
	}
}

func TestValidateCurrentConfigRejectsSubscriptionWithoutUsableRefreshPath(t *testing.T) {
	config := currentConfigFixture(t)
	config["subscriptions"] = []any{map[string]any{
		"id": "provider", "enabled": true, "refresh_minutes": 60,
		"refresh_via_direct": false, "refresh_via_vpn": false,
		"refresh_via_active_outbounds": false, "refresh_via_independent_reserves": false,
	}}

	result := validateCurrentConfig(config)
	if !hasValidationPath(result.Errors, "subscriptions[0].refresh_via_direct") {
		t.Fatalf("unusable refresh routes were accepted: %#v", result.Errors)
	}
}

func TestValidateCurrentConfigAcceptsOperationalSubscriptionControls(t *testing.T) {
	config := currentConfigFixture(t)
	config["subscription_reserves"] = []any{map[string]any{
		"id": "backup", "enabled": true, "node": map[string]any{"id": "node"},
	}}
	config["subscriptions"] = []any{map[string]any{
		"id": "provider", "enabled": true, "refresh_minutes": 10080,
		"refresh_via_direct": false, "refresh_via_vpn": true,
		"refresh_via_active_outbounds": false, "refresh_via_independent_reserves": true,
		"allowed_countries": []any{}, "allowed_locations": []any{},
		"location_overrides": map[string]any{"node": map[string]any{"city": "Berlin"}},
	}}

	if result := validateCurrentConfig(config); !result.Valid {
		t.Fatalf("valid subscription settings were rejected: %#v", result.Errors)
	}
}

func TestDraftCheckUsesCurrentSchemaValidator(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config := currentConfigFixture(t)
	config["schema_version"] = 0
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/check", map[string]any{"config": config}, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("check failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	if body["valid"] != false {
		t.Fatalf("old schema was accepted: %#v", body)
	}
}

func TestDraftCheckWithoutBodyChecksStoredDraft(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/check", nil, nil, cookie)
	if response.Code != http.StatusOK || decodeResponse(t, response)["valid"] != true {
		t.Fatalf("stored draft check failed: %d %s", response.Code, response.Body.String())
	}
}

func TestPutAndPatchDraftValidateOnceAndPersist(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config := currentConfigFixture(t)
	config["system"].(map[string]any)["name"] = "Native Go"
	put := performRequest(t, server, http.MethodPut, apiPrefix+"/drafts/current", config, map[string]string{csrfHeader: csrf}, cookie)
	if put.Code != http.StatusOK {
		t.Fatalf("put draft failed: %d %s", put.Code, put.Body.String())
	}
	patch := performRequest(t, server, http.MethodPatch, apiPrefix+"/drafts/current", map[string]any{
		"section": "watchdog", "value": map[string]any{
			"enabled": true, "failure_threshold": 4, "interval_seconds": 5, "local_fail_mode": "direct",
			"max_restarts_per_hour": 6, "recovery_cooldown_seconds": 180, "recovery_threshold": 2,
			"remote_fail_mode": "closed", "routeros_auto_restart_seconds": 300,
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if patch.Code != http.StatusOK {
		t.Fatalf("patch draft failed: %d %s", patch.Code, patch.Body.String())
	}
	stored, err := server.repository.loadDraft()
	if err != nil || nestedValue(stored, "system", "name") != "Native Go" || nestedValue(stored, "watchdog", "failure_threshold") != json.Number("4") {
		t.Fatalf("draft did not persist atomically: %#v, %v", stored, err)
	}
	invalid := performRequest(t, server, http.MethodPatch, apiPrefix+"/drafts/current", map[string]any{
		"section": "unknown", "value": map[string]any{},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown section accepted: %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestResetDraftRequiresAndRestoresActiveGeneration(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	missing := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/reset", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if missing.Code != http.StatusConflict {
		t.Fatalf("reset without active config returned %d", missing.Code)
	}
	config := currentConfigFixture(t)
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	config["system"].(map[string]any)["name"] = "Changed draft"
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	reset := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/reset", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset failed: %d %s", reset.Code, reset.Body.String())
	}
	stored, err := server.repository.loadDraft()
	if err != nil || nestedValue(stored, "system", "name") == "Changed draft" {
		t.Fatalf("active generation was not restored: %#v, %v", stored, err)
	}
}

func BenchmarkValidateCurrentConfig(b *testing.B) {
	config, err := decodeObject(defaultConfigJSON)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !validateCurrentConfig(config).Valid {
			b.Fatal("default config became invalid")
		}
	}
}

func hasValidationPath(issues []validationIssue, path string) bool {
	for _, issue := range issues {
		if issue.Path == path {
			return true
		}
	}
	return false
}
