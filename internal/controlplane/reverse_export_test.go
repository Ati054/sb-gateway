package controlplane

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestReverseVLESSClientConfigBuildsPublicInternetBridge(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	privateKey, publicKey, err := generateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["transports"] = []any{map[string]any{
		"id": "reality-public", "kind": "reality", "enabled": true,
		"hostname": "reverse.example.test", "listen_port": 443,
		"server_name": "www.example.com", "public_key": publicKey, "fingerprint": "qq",
		"secret_refs": map[string]any{
			"reality_private_key": "transports/reality-public/private",
			"reality_short_id":    "transports/reality-public/short-id",
		},
	}}
	config["reverse_vless_exits"] = []any{map[string]any{
		"id": "home", "enabled": true, "transport_ids": []any{"reality-public"},
		"uuid_secret_ref": "reverse-vless-exits/home.uuid",
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	for reference, value := range map[string]string{
		"transports/reality-public/private":  privateKey,
		"transports/reality-public/short-id": "0123456789abcdef",
		"reverse-vless-exits/home.uuid":      "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}

	response := performRequest(t, server, http.MethodGet, apiPrefix+"/reverse-vless-exits/home/client-config", nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("export failed: %d %s", response.Code, response.Body.String())
	}
	if disposition := response.Header().Get("Content-Disposition"); disposition != `attachment; filename="xray-reverse-home.json"` {
		t.Fatalf("content disposition = %q", disposition)
	}
	if required := response.Header().Get("X-SB-Gateway-Reverse-Xray-Version"); required != "26.7.28" {
		t.Fatalf("required reverse Xray version = %q", required)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	outbounds := payload["outbounds"].([]any)
	if len(outbounds) != 3 {
		t.Fatalf("outbounds = %#v", outbounds)
	}
	reverse := outbounds[0].(map[string]any)
	settings := reverse["settings"].(map[string]any)
	stream := reverse["streamSettings"].(map[string]any)
	if reverse["protocol"] != "vless" || settings["address"] != "reverse.example.test" || settings["id"] != "2f1c08fc-3f43-4e95-8f57-f8bded750a1a" {
		t.Fatalf("reverse outbound = %#v", reverse)
	}
	if settings["reverse"].(map[string]any)["tag"] != "reverse-in-home" {
		t.Fatalf("reverse tag = %#v", settings["reverse"])
	}
	if stream["network"] != "tcp" || stream["security"] != "reality" || stream["method"] != nil {
		t.Fatalf("reverse transport = %#v", stream)
	}
	if settings["flow"] != "xtls-rprx-vision" || stream["realitySettings"].(map[string]any)["fingerprint"] != "chrome" {
		t.Fatalf("direct REALITY settings = %#v / %#v", settings, stream)
	}
	direct := outbounds[1].(map[string]any)
	finalRules := direct["settings"].(map[string]any)["finalRules"].([]any)
	directSockopt := direct["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	blocked := finalRules[0].(map[string]any)["ip"].([]any)
	if direct["protocol"] != "freedom" || directSockopt["domainStrategy"] != "AsIs" || !containsAnyString(blocked, "192.168.0.0/16") || finalRules[1].(map[string]any)["action"] != "allow" {
		t.Fatalf("public-only direct policy = %#v", direct)
	}
	if strings.Contains(response.Body.String(), "websocket") {
		t.Fatalf("direct REALITY export contains WebSocket: %s", response.Body.String())
	}
}

func TestReverseVLESSClientConfigBuildsDirectGRPCReality(t *testing.T) {
	server := newTestServer(t)
	privateKey, publicKey, err := generateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["transports"] = []any{map[string]any{
		"id": "grpc-public", "kind": "reality-grpc", "enabled": true,
		"hostname": "reverse.example.test", "listen_port": 2444,
		"server_name": "www.example.com", "public_key": publicKey, "fingerprint": "chrome",
		"service_name_secret_ref": "transports/grpc-public/service",
		"grpc_authority":          "grpc-authority.example.test", "grpc_user_agent": "sb-gateway-acceptance",
		"grpc_multi_mode": true, "grpc_idle_timeout": 45, "grpc_health_check_timeout": 20,
		"grpc_permit_without_stream": true, "grpc_initial_windows_size": 1048576,
		"secret_refs": map[string]any{
			"reality_private_key": "transports/grpc-public/private",
			"reality_short_id":    "transports/grpc-public/short-id",
		},
	}}
	config["reverse_vless_exits"] = []any{map[string]any{
		"id": "home", "enabled": true, "transport_ids": []any{"grpc-public"},
		"uuid_secret_ref": "reverse-vless-exits/home.uuid",
	}}
	for reference, value := range map[string]string{
		"transports/grpc-public/private":  privateKey,
		"transports/grpc-public/short-id": "0123456789abcdef",
		"transports/grpc-public/service":  "reverse-grpc",
		"reverse-vless-exits/home.uuid":   "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	body, err := server.buildReverseVLESSClientConfig(config, "home")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	outbounds := payload["outbounds"].([]any)
	if len(outbounds) != 3 || outbounds[0].(map[string]any)["settings"].(map[string]any)["address"] != "reverse.example.test" {
		t.Fatalf("direct gRPC outbounds = %#v", outbounds)
	}
	for _, raw := range outbounds[:1] {
		stream := raw.(map[string]any)["streamSettings"].(map[string]any)
		if stream["network"] != "grpc" || stream["method"] != nil {
			t.Fatalf("expanded reverse transport = %#v", stream)
		}
		grpc := stream["grpcSettings"].(map[string]any)
		if grpc["serviceName"] != "reverse-grpc" || grpc["authority"] != "grpc-authority.example.test" || grpc["user_agent"] != "sb-gateway-acceptance" ||
			grpc["multiMode"] != true || positiveInt(grpc["idle_timeout"], 0) != 45 || positiveInt(grpc["health_check_timeout"], 0) != 20 ||
			grpc["permit_without_stream"] != true || positiveInt(grpc["initial_windows_size"], 0) != 1048576 {
			t.Fatalf("gRPC client settings = %#v", grpc)
		}
		if _, exists := stream["sockopt"]; !exists || stream["security"] != "reality" {
			t.Fatalf("Reverse gRPC REALITY transport is incomplete: %#v", stream)
		}
	}
}

func TestReverseVLESSClientConfigDefaultsXHTTPRealityToAuto(t *testing.T) {
	server := newTestServer(t)
	privateKey, publicKey, err := generateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["transports"] = []any{map[string]any{
		"id": "xhttp-reality", "kind": "xhttp-reality", "enabled": true,
		"hostname": "reverse.example.test", "listen_port": 2446,
		"tcp_keep_alive_idle": 30, "tcp_keep_alive_interval": 10, "tcp_user_timeout": 60000,
		"server_name": "www.example.com", "public_key": publicKey, "fingerprint": "firefox", "spider_x": "/spider",
		"reality_mldsa65_enabled": true, "mldsa65_verify": "mldsa-verify",
		"uplink_data_placement": "header", "uplink_http_method": "GET",
		"headers": map[string]any{"Cache-Control": "no-store"}, "x_padding_bytes": "100-500",
		"xmux_max_connections": "3", "download_settings": map[string]any{"address": "download.example.test", "port": 443},
		"path_secret_ref": "transports/xhttp-reality/path",
		"secret_refs": map[string]any{
			"reality_private_key": "transports/xhttp-reality/private",
			"reality_short_id":    "transports/xhttp-reality/short-id",
		},
	}}
	config["reverse_vless_exits"] = []any{map[string]any{
		"id": "home", "enabled": true, "transport_ids": []any{"xhttp-reality"},
		"uuid_secret_ref": "reverse-vless-exits/home.uuid",
	}}
	for reference, value := range map[string]string{
		"transports/xhttp-reality/private":  privateKey,
		"transports/xhttp-reality/path":     "/reverse-xhttp",
		"transports/xhttp-reality/short-id": "0123456789abcdef",
		"reverse-vless-exits/home.uuid":     "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	body, err := server.buildReverseVLESSClientConfig(config, "home")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	stream := payload["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	settings := stream["xhttpSettings"].(map[string]any)
	if stream["network"] != "xhttp" || stream["method"] != nil || settings["mode"] != "auto" {
		t.Fatalf("XHTTP Reality stream = %#v", stream)
	}
	sockopt := stream["sockopt"].(map[string]any)
	if positiveInt(sockopt["tcpKeepAliveIdle"], 0) != 30 || positiveInt(sockopt["tcpKeepAliveInterval"], 0) != 10 || positiveInt(sockopt["tcpUserTimeout"], 0) != 60000 {
		t.Fatalf("XHTTP Reality sockopt = %#v", sockopt)
	}
	extra := settings["extra"].(map[string]any)
	if extra["uplinkDataPlacement"] != "auto" || extra["uplinkHTTPMethod"] != "POST" || extra["xPaddingBytes"] != "100-500" {
		t.Fatalf("XHTTP Reality export extras = %#v", extra)
	}
	if object, ok := extra["downloadSettings"].(map[string]any); !ok || object["address"] != "download.example.test" || object["port"] != float64(443) && object["port"] != 443 {
		t.Fatalf("XHTTP downloadSettings = %#v", extra["downloadSettings"])
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["fingerprint"] != "chrome" || reality["spiderX"] != "/spider" || reality["mldsa65Verify"] != "mldsa-verify" {
		t.Fatalf("REALITY client settings = %#v", reality)
	}
}

func TestReverseVLESSClientConfigFailsClosedWithoutSecret(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["transports"] = []any{map[string]any{
		"id": "xhttp-reality", "kind": "xhttp-reality", "enabled": true,
		"hostname": "reverse.example.test", "listen_port": 443,
		"path_secret_ref": "transports/xhttp-reality/missing",
	}}
	config["reverse_vless_exits"] = []any{map[string]any{
		"id": "home", "enabled": true, "transport_ids": []any{"xhttp-reality"},
		"uuid_secret_ref": "reverse-vless-exits/home.uuid",
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	if err := server.secrets.write("reverse-vless-exits/home.uuid", "2f1c08fc-3f43-4e95-8f57-f8bded750a1a", false); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/reverse-vless-exits/home/client-config", nil, nil, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing secret returned %d: %s", response.Code, response.Body.String())
	}
}

func TestReverseVLESSClientConfigRejectsNonRealityTransport(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["transports"] = []any{map[string]any{
		"id": "websocket", "kind": "ws", "enabled": true,
		"hostname": "reverse.example.test", "listen_port": 443,
		"path_secret_ref": "transports/websocket/path",
	}}
	config["reverse_vless_exits"] = []any{map[string]any{
		"id": "home", "enabled": true, "transport_ids": []any{"websocket"},
		"uuid_secret_ref": "reverse-vless-exits/home.uuid",
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	for reference, value := range map[string]string{
		"transports/websocket/path":     "/must-not-export",
		"reverse-vless-exits/home.uuid": "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/reverse-vless-exits/home/client-config", nil, nil, cookie)
	if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "must use Direct REALITY") {
		t.Fatalf("unsupported reverse transport returned %d: %s", response.Code, response.Body.String())
	}
}

func TestReverseExportSockoptKeepsOutboundAlignedWithRealityTransport(t *testing.T) {
	enabled := reverseExportSockopt(map[string]any{"kind": "reality"})
	if positiveInt(enabled["tcpKeepAliveIdle"], 0) != 30 || positiveInt(enabled["tcpKeepAliveInterval"], 0) != 10 || positiveInt(enabled["tcpUserTimeout"], 0) != 60000 {
		t.Fatalf("default Reality sockopt = %#v", enabled)
	}
	disabled := reverseExportSockopt(map[string]any{"kind": "reality-grpc", "tcp_keep_alive_enabled": false})
	if disabled["tcpKeepAliveIdle"] != -1 || disabled["tcpKeepAliveInterval"] != -1 {
		t.Fatalf("disabled Reality sockopt = %#v", disabled)
	}
	if disabled["tcpUserTimeout"] != 60000 {
		t.Fatalf("Keep-Alive must not disable the independent user timeout: %#v", disabled)
	}
	if sockopt := reverseExportSockopt(map[string]any{"kind": "grpc"}); len(sockopt) != 0 {
		t.Fatalf("Reverse gRPC unexpectedly inherited ordinary client-to-CDN sockopt: %#v", sockopt)
	}
	if sockopt := reverseExportSockopt(map[string]any{"kind": "ws"}); len(sockopt) != 0 {
		t.Fatalf("WebSocket unexpectedly inherited gRPC/Reality sockopt: %#v", sockopt)
	}
}

func TestTCPStabilityIndependentTimeout(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		for _, timeout := range []int{0, 60000, 120000} {
			sockopt := exportTCPStabilitySockopt(map[string]any{
				"tcp_keep_alive_enabled": enabled, "tcp_keep_alive_idle": 45,
				"tcp_keep_alive_interval": 20, "tcp_user_timeout": timeout,
			})
			idle, interval := 45, 20
			if !enabled {
				idle, interval = -1, -1
			}
			if sockopt["tcpKeepAliveIdle"] != idle || sockopt["tcpKeepAliveInterval"] != interval || sockopt["tcpUserTimeout"] != timeout {
				t.Fatalf("enabled=%v timeout=%d: %#v", enabled, timeout, sockopt)
			}
		}
	}
}

func TestRealityExportDerivesPublicKeyFromActivePrivateSecret(t *testing.T) {
	server := newTestServer(t)
	privateKey, expectedPublicKey, err := generateRealityKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for reference, value := range map[string]string{
		"transports/xhttp-reality/private": privateKey,
		"transports/xhttp-reality/short":   "0123456789abcdef",
		"transports/xhttp-reality/path":    "/portable-xhttp",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	transport := map[string]any{
		"id": "xhttp-reality", "kind": "xhttp-reality", "hostname": "vpn.example.test", "listen_port": 2446,
		"server_name": "cloudflare-dns.com", "fingerprint": "chrome", "public_key": "stale-public-key",
		"path_secret_ref": "transports/xhttp-reality/path", "vless_encryption_enabled": false,
		"secret_refs": map[string]any{
			"reality_private_key": "transports/xhttp-reality/private",
			"reality_short_id":    "transports/xhttp-reality/short",
		},
	}
	outbound, err := server.reverseExportOutbound(transport, "2f1c08fc-3f43-4e95-8f57-f8bded750a1a", "", 1, "chrome")
	if err != nil {
		t.Fatal(err)
	}
	reality := objectCopy(objectCopy(outbound["streamSettings"])["realitySettings"])
	if reality["password"] != expectedPublicKey || reality["password"] == transport["public_key"] {
		t.Fatalf("Reality export did not derive the active public key: %#v", reality)
	}
}

func containsAnyString(values []any, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
