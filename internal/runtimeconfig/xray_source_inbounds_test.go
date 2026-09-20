package runtimeconfig

import (
	"errors"
	"reflect"
	"testing"
)

func TestInboundTCPStabilityIndependentTimeout(t *testing.T) {
	for _, kind := range []string{"reality", "reality-grpc", "xhttp-reality"} {
		for _, enabled := range []bool{true, false} {
			for _, timeout := range []any{nil, 0, 120000} {
				transport := map[string]any{
					"id": "direct", "kind": kind, "enabled": true,
					"server_name": "example.test", "tcp_keep_alive_enabled": enabled,
					"path_secret_ref": "transport/path", "service_name_secret_ref": "transport/service",
					"secret_refs": map[string]any{"reality_private_key": "transport/key", "reality_short_id": "transport/short"},
				}
				if timeout != nil {
					transport["tcp_user_timeout"] = timeout
				}
				config := inboundSourceBaseConfig()
				config["transports"] = []any{transport}
				source, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{
					"transport/path": "/path", "transport/service": "service",
					"transport/key": "private-key", "transport/short": "0123456789abcdef",
				}), inboundSecretPath)
				if err != nil {
					t.Fatal(err)
				}
				tag := "vless-" + kind
				stream, err := ConvertXrayStream(inboundSourceByTag(source.Inbounds)[tag], true, nil, source.Options.RealitySettingsByTag[tag])
				if err != nil {
					t.Fatal(err)
				}
				idle, interval := 30, 10
				if !enabled {
					idle, interval = 0, 0
				}
				if timeout == nil {
					timeout = 60000
				}
				want := map[string]any{"tcpKeepAliveIdle": idle, "tcpKeepAliveInterval": interval, "tcpUserTimeout": timeout}
				got := objectValue(stream["sockopt"])
				if !enabled && timeout == 0 {
					if len(got) != 0 {
						t.Fatalf("both disabled: %#v", got)
					}
				} else if !reflect.DeepEqual(got, want) {
					t.Fatalf("%s enabled=%v: got %#v, want %#v", kind, enabled, got, want)
				}
			}
		}
	}
}

func TestBuildXrayInboundSourceBuildsDirectGRPCTLSPin(t *testing.T) {
	config := inboundSourceBaseConfig()
	config["tls_profiles"] = []any{map[string]any{
		"id": "direct-private", "enabled": true,
		"certificate_secret_ref": "tls/direct/certificate.pem",
		"private_key_secret_ref": "tls/direct/private-key.pem",
	}}
	config["transports"] = []any{map[string]any{
		"id": "grpc-tls-pin", "enabled": true, "kind": "grpc-tls", "listen_port": 2445,
		"tls_profile_id": "direct-private", "tls_server_name": "gateway.example.test",
		"service_name_secret_ref": "transport/grpc-tls-service",
		"tcp_keep_alive_enabled":  true, "tcp_keep_alive_idle": 30,
		"tcp_keep_alive_interval": 10, "tcp_user_timeout": 60000,
	}}
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "enabled": true, "uuid_secret_ref": "user/phone",
	}}
	source, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{
		"transport/grpc-tls-service": "private-grpc",
		"user/phone":                 "018f7b76-7cdb-4a08-9f0a-7514a1d90a11",
	}), inboundSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	inbound := inboundSourceByTag(source.Inbounds)["vless-grpc-tls-pin"]
	if inbound == nil || inbound["listen"] != "0.0.0.0" || inbound["listen_port"] != 2445 {
		t.Fatalf("direct gRPC TLS inbound = %#v", inbound)
	}
	if transport := objectValue(inbound["transport"]); transport["type"] != "grpc" || transport["service_name"] != "private-grpc" {
		t.Fatalf("direct gRPC transport = %#v", transport)
	}
	stream, err := ConvertXrayStream(inbound, true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if textValue(stream["method"]) != "grpc" || stream["security"] != "tls" {
		t.Fatalf("direct gRPC TLS stream = %#v", stream)
	}
	tls := objectValue(stream["tlsSettings"])
	certificates := objectSlice(tls["certificates"])
	if tls["serverName"] != "gateway.example.test" || !reflect.DeepEqual(tls["alpn"], []string{"h2"}) || len(certificates) != 1 || certificates[0]["certificateFile"] != "/run/secrets/tls/direct/certificate.pem" || certificates[0]["keyFile"] != "/run/secrets/tls/direct/private-key.pem" {
		t.Fatalf("direct gRPC TLS settings = %#v", tls)
	}
	if sockopt := objectValue(stream["sockopt"]); sockopt["tcpKeepAliveIdle"] != 30 || sockopt["tcpKeepAliveInterval"] != 10 || sockopt["tcpUserTimeout"] != 60000 {
		t.Fatalf("direct gRPC TCP stability = %#v", sockopt)
	}
}

func TestBuildXrayInboundSourceBuildsBaseAndScopedReverseUsers(t *testing.T) {
	config := inboundSourceBaseConfig()
	config["networks"] = []any{
		map[string]any{"id": "lan", "enabled": true, "kind": "internal", "cidrs": []any{"192.168.3.0/24"}},
		map[string]any{"id": "disabled", "enabled": false, "kind": "management", "cidrs": []any{"10.0.0.0/8"}},
	}
	config["transports"] = []any{
		map[string]any{"id": "ws-public", "enabled": true, "kind": "ws", "path_secret_ref": "transport/ws-path"},
		map[string]any{
			"id": "reality-public", "enabled": true, "kind": "reality", "listen_port": 2443,
			"server_name": "edge.example", "server_names": []any{"edge-alt.example", "edge.example"},
			"handshake_server": "2001:db8::1", "handshake_port": 443,
			"tcp_keep_alive_idle": 30, "tcp_keep_alive_interval": 15, "tcp_user_timeout": 60000,
			"reality_show": true, "xver": 2, "min_client_ver": "26.3.27", "max_client_ver": "26.9.1", "max_time_diff": 1500,
			"reality_fallback_upload_after_bytes": 100, "reality_fallback_upload_bytes_per_sec": 200, "reality_fallback_upload_burst_bytes_per_sec": 300,
			"reality_fallback_download_after_bytes": 400, "reality_fallback_download_bytes_per_sec": 500, "reality_fallback_download_burst_bytes_per_sec": 600,
			"reality_mldsa65_enabled": true,
			"secret_refs": map[string]any{
				"reality_private_key": "transport/reality-private", "reality_short_id": "transport/reality-short",
				"reality_mldsa65_seed": "transport/reality-mldsa-seed",
			},
		},
	}
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "enabled": true, "uuid_secret_ref": "user/phone",
	}}
	config["reverse_vless_exits"] = []any{map[string]any{
		"id": "home", "enabled": true, "uuid_secret_ref": "reverse/home", "transport_ids": []any{"ws-public"},
	}}
	result, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{
		"transport/ws-path":            "/private-ws",
		"transport/reality-private":    "private-key",
		"transport/reality-short":      "0123456789abcdef",
		"transport/reality-mldsa-seed": "mldsa-seed",
		"user/phone":                   "018f7b76-7cdb-7a08-9f0a-7514a1d90a11",
		"reverse/home":                 "123e4567-e89b-42d3-a456-426614174000",
	}), inboundSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	byTag := inboundSourceByTag(result.Inbounds)
	if len(result.Inbounds) != 9 || byTag["tun-routeros"] == nil || byTag["subscription-update-vpn"] == nil {
		t.Fatalf("base inbounds are incomplete: %#v", result.Inbounds)
	}
	for tag, port := range map[string]int{
		"outbound-health-background":   19083,
		"outbound-health-background-2": 19084,
		"outbound-health-background-3": 19085,
	} {
		if bg := byTag[tag]; bg["listen"] != "127.0.0.1" || bg["listen_port"] != port {
			t.Fatalf("background health %s must remain loopback-only: %#v", tag, bg)
		}
	}
	transparent := byTag["tun-routeros"]
	if transparent["type"] != "transparent" || transparent["listen_port"] != 12345 {
		t.Fatalf("transparent RouterOS inbound = %#v", transparent)
	}
	wsUsers := objectSlice(byTag["vless-ws"]["users"])
	if len(wsUsers) != 2 || textValue(wsUsers[1]["name"]) != "reverse-vless-home" {
		t.Fatalf("WS users = %#v", wsUsers)
	}
	realityUsers := objectSlice(byTag["vless-reality"]["users"])
	if len(realityUsers) != 1 || textValue(realityUsers[0]["flow"]) != "xtls-rprx-vision" {
		t.Fatalf("Reality users = %#v", realityUsers)
	}
	if sockopt := objectValue(byTag["vless-reality"]["sockopt"]); sockopt["tcp_keep_alive_idle"] != 30 || sockopt["tcp_keep_alive_interval"] != 15 || sockopt["tcp_user_timeout"] != 60000 {
		t.Fatalf("Reality keepalive = %#v", sockopt)
	}
	settings := result.Options.RealitySettingsByTag["vless-reality"]
	if settings["target"] != "[2001:db8::1]:443" || settings["privateKey"] != "private-key" || settings["show"] != true || settings["xver"] != 2 {
		t.Fatalf("Reality runtime settings = %#v", settings)
	}
	if settings["minClientVer"] != "26.3.27" || settings["maxClientVer"] != "26.9.1" || settings["maxTimeDiff"] != 1500 || settings["mldsa65Seed"] != "mldsa-seed" {
		t.Fatalf("Reality advanced settings = %#v", settings)
	}
	serverNames := stringSlice(settings["serverNames"])
	if len(serverNames) != 2 || serverNames[0] != "edge.example" || serverNames[1] != "edge-alt.example" {
		t.Fatalf("Reality server names = %#v", serverNames)
	}
	upload := objectValue(settings["limitFallbackUpload"])
	download := objectValue(settings["limitFallbackDownload"])
	if upload["afterBytes"] != 100 || upload["bytesPerSec"] != 200 || upload["burstBytesPerSec"] != 300 ||
		download["afterBytes"] != 400 || download["bytesPerSec"] != 500 || download["burstBytesPerSec"] != 600 {
		t.Fatalf("Reality fallback limits = %#v / %#v", upload, download)
	}
}

func TestBuildXrayInboundSourceBuildsXHTTPAndHysteriaOptions(t *testing.T) {
	config := inboundSourceBaseConfig()
	config["transports"] = []any{
		map[string]any{
			"id": "xhttp-public", "enabled": true, "kind": "xhttp", "path_secret_ref": "transport/xhttp-path",
			"hostname": "xhttp.example", "mode": "packet-up", "x_padding_bytes": "200-900", "x_padding_obfs_mode": true,
			"x_padding_key": "_padding", "x_padding_header": "X-Padding", "x_padding_placement": "header", "x_padding_method": "repeat-x",
			"uplink_http_method": "PUT", "uplink_data_placement": "body", "uplink_data_key": "X-Data", "uplink_chunk_size": "2048-3072",
			"session_id_placement": "cookie", "session_id_key": "_sid", "session_id_table": "sessions", "session_id_length": 24,
			"seq_placement": "query", "seq_key": "_seq", "server_max_header_bytes": 32768,
			"headers": map[string]any{"Cache-Control": "no-store"}, "no_grpc_header": true, "no_sse_header": true,
			"sc_max_each_post_bytes": "65536-131072", "sc_min_posts_interval_ms": "10-20", "sc_max_buffered_posts": 30,
			"sc_stream_up_server_secs": "20-40", "xmux_max_connections": "3", "xmux_h_max_request_times": "600-900",
			"vless_encryption_enabled": true,
			"secret_refs":              map[string]any{"vless_decryption": "transport/vless-decryption"},
		},
		map[string]any{
			"id": "hy-public", "enabled": true, "kind": "hysteria2", "listen_port": 8443,
			"tls_profile_id": "tls-main", "obfs_enabled": true,
			"secret_refs": map[string]any{"hysteria2_obfs_password": "transport/hy-obfs"},
			"xray_hysteria": map[string]any{
				"udp_idle_timeout": 90,
				"quic_params": map[string]any{
					"congestion": "brutal", "brutal_up_mbps": 120, "brutal_down_mbps": 240,
					"brutal_disable_loss_compensation": true,
					"init_stream_receive_window":       4194304, "max_stream_receive_window": 8388608,
					"init_connection_receive_window": 10485760, "max_connection_receive_window": 20971520,
					"max_idle_timeout": 30, "keep_alive_period": 10, "max_incoming_streams": 1024,
					"disable_path_mtu_discovery": true, "disable_gso": true, "disable_stateless_reset": true,
				},
				"masquerade": map[string]any{
					"type": "proxy", "url": "http://127.0.0.1:8080/", "x_forwarded": true,
				},
			},
		},
	}
	config["tls_profiles"] = []any{map[string]any{
		"id": "tls-main", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key",
	}}
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "enabled": true, "uuid_secret_ref": "user/phone", "hysteria2_password_secret_ref": "user/phone-hy",
	}}
	result, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{
		"transport/xhttp-path":       "/private-xhttp",
		"transport/vless-decryption": "decryption-key",
		"transport/hy-obfs":          "obfs-password",
		"user/phone":                 "018f7b76-7cdb-4a08-9f0a-7514a1d90a11",
		"user/phone-hy":              "hy-password",
	}), inboundSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	byTag := inboundSourceByTag(result.Inbounds)
	xhttp := byTag["vless-xhttp"]
	if transport := objectValue(xhttp["transport"]); transport["path"] != "/private-xhttp" || transport["x_padding_bytes"] != "200-900" {
		t.Fatalf("XHTTP transport = %#v", transport)
	}
	if users := objectSlice(xhttp["users"]); len(users) != 1 || users[0]["flow"] != "xtls-rprx-vision" {
		t.Fatalf("XHTTP encrypted users = %#v", users)
	}
	xhttpExtra := result.Options.XHTTPExtraByTag["vless-xhttp"]
	if result.Options.VLESSDecryptionByTag["vless-xhttp"] != "decryption-key" || xhttpExtra["xPaddingBytes"] != "200-900" || xhttpExtra["uplinkChunkSize"] != "2048-3072" {
		t.Fatalf("XHTTP options = %#v", result.Options)
	}
	if xhttpExtra["xPaddingObfsMode"] != true || xhttpExtra["sessionIDLength"] != 24 || xhttpExtra["serverMaxHeaderBytes"] != 32768 || xhttpExtra["noGRPCHeader"] != true || xhttpExtra["noSSEHeader"] != true {
		t.Fatalf("XHTTP advanced options = %#v", xhttpExtra)
	}
	if headers, ok := xhttpExtra["headers"].(map[string]string); !ok || headers["Cache-Control"] != "no-store" {
		t.Fatalf("XHTTP headers = %#v", headers)
	}
	if xmux := objectValue(xhttpExtra["xmux"]); xmux["maxConnections"] != "3" || xmux["hMaxRequestTimes"] != "600-900" {
		t.Fatalf("XHTTP XMUX = %#v", xmux)
	}
	hysteria := byTag["hysteria2-direct"]
	if tls := objectValue(hysteria["tls"]); tls["certificate_path"] != "/run/secrets/tls/cert" || tls["key_path"] != "/run/secrets/tls/key" {
		t.Fatalf("Hysteria TLS = %#v", tls)
	}
	if users := objectSlice(hysteria["users"]); len(users) != 1 || users[0]["password"] != "hy-password" {
		t.Fatalf("Hysteria users = %#v", users)
	}
	if objectValue(hysteria["obfs"])["password"] != "obfs-password" || result.Options.HysteriaSettingsByTag["hysteria2-direct"]["udp_idle_timeout"] != 90 {
		t.Fatalf("Hysteria settings = %#v / %#v", hysteria, result.Options.HysteriaSettingsByTag)
	}
	hysteriaOptions, quicOptions, err := xrayHysteriaOptions(result.Options.HysteriaSettingsByTag["hysteria2-direct"])
	if err != nil {
		t.Fatal(err)
	}
	if hysteriaOptions["udpIdleTimeout"] != 90 || objectValue(hysteriaOptions["masquerade"])["xForwarded"] != true {
		t.Fatalf("Hysteria runtime options = %#v", hysteriaOptions)
	}
	if quicOptions["congestion"] != "brutal" || quicOptions["brutalUp"] != "120mbps" || quicOptions["brutalDown"] != "240mbps" ||
		quicOptions["brutalDisableLossCompensation"] != true || quicOptions["maxIdleTimeout"] != 30 || quicOptions["keepAlivePeriod"] != 10 || quicOptions["maxIncomingStreams"] != 1024 || quicOptions["disablePathMTUDiscovery"] != true || quicOptions["disableGSO"] != true || quicOptions["disableStatelessReset"] != true {
		t.Fatalf("Hysteria QUIC options = %#v", quicOptions)
	}
}

func TestXrayHysteriaNewCoreOptionsAreExplicitAndWebsiteIsIsolated(t *testing.T) {
	defaults, defaultQUIC, err := xrayHysteriaOptions(map[string]any{
		"masquerade":  map[string]any{"type": "proxy", "url": "http://127.0.0.1:8080/"},
		"quic_params": map[string]any{"congestion": "brutal"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"brutalDisableLossCompensation", "disableGSO", "disableStatelessReset"} {
		if _, exists := defaultQUIC[field]; exists {
			t.Fatalf("default unexpectedly rendered %s: %#v", field, defaultQUIC)
		}
	}
	if _, exists := objectValue(defaults["masquerade"])["xForwarded"]; exists {
		t.Fatalf("default local proxy unexpectedly rendered xForwarded: %#v", defaults)
	}

	website, websiteQUIC, err := xrayHysteriaOptions(map[string]any{
		"masquerade": map[string]any{"type": "website", "url": "https://example.test/", "x_forwarded": true},
		"quic_params": map[string]any{
			"congestion": "brutal", "brutal_disable_loss_compensation": true,
			"disable_gso": true, "disable_stateless_reset": true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if websiteQUIC["brutalDisableLossCompensation"] != true || websiteQUIC["disableGSO"] != true || websiteQUIC["disableStatelessReset"] != true {
		t.Fatalf("explicit QUIC options = %#v", websiteQUIC)
	}
	if _, exists := objectValue(website["masquerade"])["xForwarded"]; exists {
		t.Fatalf("website masquerade forwarded local-proxy header setting: %#v", website)
	}
}

func TestRealityRuntimeSettingsOmitUnsetClientVersionLimit(t *testing.T) {
	transport := map[string]any{
		"server_name": "edge.example", "handshake_server": "origin.example", "handshake_port": 443,
		"secret_refs": map[string]any{"reality_private_key": "private", "reality_short_id": "short"},
	}
	settings, err := realityRuntimeSettings(transport, inboundSecretReader(map[string]string{"private": "private-key", "short": "0123456789abcdef"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := settings["minClientVer"]; exists {
		t.Fatalf("unset minimum version rendered a hidden floor: %#v", settings)
	}
	transport["min_client_ver"] = "26.3.27"
	settings, err = realityRuntimeSettings(transport, inboundSecretReader(map[string]string{"private": "private-key", "short": "0123456789abcdef"}))
	if err != nil || settings["minClientVer"] != "26.3.27" {
		t.Fatalf("explicit minimum version changed: %#v / %v", settings, err)
	}
}

func TestRealityRuntimeSettingsUseLocalManagedAPICover(t *testing.T) {
	transport := map[string]any{
		"server_name": "api.example.test", "cover_mode": "api",
		"handshake_server": "external.example.test", "handshake_port": 443,
		"secret_refs": map[string]any{"reality_private_key": "private", "reality_short_id": "short"},
	}
	settings, err := realityRuntimeSettings(transport, inboundSecretReader(map[string]string{"private": "private-key", "short": "0123456789abcdef"}))
	if err != nil {
		t.Fatal(err)
	}
	if settings["target"] != "127.0.0.1:16448" {
		t.Fatalf("REALITY API cover target = %#v", settings["target"])
	}
	legacy, err := realitySourceTLS(transport, inboundSecretReader(map[string]string{"private": "private-key", "short": "0123456789abcdef"}))
	if err != nil {
		t.Fatal(err)
	}
	handshake := objectValue(objectValue(legacy["reality"])["handshake"])
	if handshake["server"] != "127.0.0.1" || handshake["server_port"] != RealityCoverPort {
		t.Fatalf("REALITY source API cover handshake = %#v", handshake)
	}
}

func TestBuildXrayInboundSourceDefaultsDirectXHTTPRealityToAuto(t *testing.T) {
	config := inboundSourceBaseConfig()
	config["transports"] = []any{map[string]any{
		"id": "xhttp-reality", "enabled": true, "kind": "xhttp-reality", "listen_port": 2446,
		"path_secret_ref": "transport/xhttp-reality-path", "server_name": "edge.example",
		"handshake_server": "www.example.com", "handshake_port": 443,
		"uplink_data_placement": "header", "uplink_http_method": "GET",
		"secret_refs": map[string]any{
			"reality_private_key": "transport/reality-private",
			"reality_short_id":    "transport/reality-short",
		},
	}}
	result, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{
		"transport/xhttp-reality-path": "/private-xhttp",
		"transport/reality-private":    "private-key",
		"transport/reality-short":      "0123456789abcdef",
	}), inboundSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	transport := objectValue(inboundSourceByTag(result.Inbounds)["vless-xhttp-reality"]["transport"])
	if transport["mode"] != "auto" {
		t.Fatalf("XHTTP Reality mode = %#v", transport["mode"])
	}
	extra := result.Options.XHTTPExtraByTag["vless-xhttp-reality"]
	if extra["uplinkDataPlacement"] != "auto" || extra["uplinkHTTPMethod"] != "POST" {
		t.Fatalf("XHTTP Reality auto extras = %#v", extra)
	}
}

func TestBuildXrayInboundSourceRejectsInvalidCurrentValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"UUID", func(config map[string]any) {
			config["remote_users"] = []any{map[string]any{"id": "bad", "enabled": true, "uuid_secret_ref": "bad-uuid"}}
		}},
		{"ingress path", func(config map[string]any) {
			config["transports"] = []any{map[string]any{"id": "ws", "enabled": true, "kind": "ws", "path_secret_ref": "bad-path"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := inboundSourceBaseConfig()
			test.mutate(config)
			_, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{"bad-uuid": "not-a-uuid", "bad-path": "missing-leading-slash"}), inboundSecretPath)
			if err == nil {
				t.Fatal("invalid current-schema value was accepted")
			}
		})
	}
}

func TestBuildXrayInboundSourceDoesNotRestoreLegacyReverseTransport(t *testing.T) {
	config := inboundSourceBaseConfig()
	config["transports"] = []any{map[string]any{"id": "ws", "enabled": true, "kind": "ws", "path_secret_ref": "ws-path"}}
	config["reverse_vless_exits"] = []any{map[string]any{
		"id": "legacy", "enabled": true, "uuid_secret_ref": "reverse", "transport_id": "ws",
	}}
	result, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{
		"ws-path": "/ws", "reverse": "123e4567-e89b-42d3-a456-426614174000",
	}), inboundSecretPath)
	if err != nil {
		t.Fatal(err)
	}
	if users := objectSlice(inboundSourceByTag(result.Inbounds)["vless-ws"]["users"]); len(users) != 0 {
		t.Fatalf("legacy transport_id was restored: %#v", users)
	}
}

func inboundSourceBaseConfig() map[string]any {
	return map[string]any{
		"system": map[string]any{"networking": map[string]any{
			"tun_address": "198.18.0.1/30", "container_address": "198.18.0.2/29", "tun_mtu": 1400,
			"tun_stack": "system", "remote_ipv6_mode": "proxy_only",
		}},
	}
}

func inboundSecretReader(values map[string]string) SecretReader {
	return func(reference string) (string, error) {
		value, exists := values[reference]
		if !exists {
			return "", errors.New("secret not found")
		}
		return value, nil
	}
}

func inboundSecretPath(reference string) (string, error) {
	if reference == "" {
		return "", errors.New("empty secret reference")
	}
	return "/run/secrets/" + reference, nil
}

func inboundSourceByTag(inbounds []map[string]any) map[string]map[string]any {
	result := make(map[string]map[string]any, len(inbounds))
	for _, inbound := range inbounds {
		result[textValue(inbound["tag"])] = inbound
	}
	return result
}
