package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestConvertXrayVLESSInboundWithRealityAndReverseUser(t *testing.T) {
	value := map[string]any{
		"type": "vless", "tag": "vless-reality", "listen": "0.0.0.0", "listen_port": 2443,
		"users": []any{
			map[string]any{"name": "reverse-vless-home", "uuid": "11111111-1111-1111-1111-111111111111", "flow": "xtls-rprx-vision"},
			map[string]any{"name": "alice", "uuid": "22222222-2222-2222-2222-222222222222"},
		},
		"transport": map[string]any{"type": "xhttp", "mode": "packet-up", "path": "/secret"},
		"tls":       map[string]any{"enabled": true, "reality": map[string]any{"enabled": true}},
		"sockopt":   map[string]any{"tcp_keep_alive_idle": 45, "tcp_keep_alive_interval": 30, "tcp_user_timeout": 60000},
	}
	reality := map[string]any{"target": "example.com:443", "privateKey": "secret", "shortIds": []string{"abcd"}}
	inbound, err := ConvertXrayInbound(value, XrayInboundOptions{
		ReverseTags: map[string]struct{}{"reverse-vless-home": {}},
		XHTTPExtra:  map[string]any{"xPaddingBytes": "100-1000"}, RealitySettings: reality,
	})
	if err != nil {
		t.Fatal(err)
	}
	settings := objectValue(inbound["settings"])
	users := objectSlice(settings["users"])
	if !reflect.DeepEqual(users[0]["reverse"], map[string]any{"tag": "reverse-vless-home"}) {
		t.Fatalf("reverse user was not linked: %#v", users[0])
	}
	if users[0]["flow"] != "xtls-rprx-vision" || settings["decryption"] != "none" {
		t.Fatalf("VLESS settings changed: %#v", settings)
	}
	stream := objectValue(inbound["streamSettings"])
	if stream["method"] != "xhttp" || stream["security"] != "reality" || !reflect.DeepEqual(stream["realitySettings"], reality) {
		t.Fatalf("XHTTP Reality stream changed: %#v", stream)
	}
	if !reflect.DeepEqual(stream["sockopt"], map[string]any{"tcpKeepAliveIdle": 45, "tcpKeepAliveInterval": 30, "tcpUserTimeout": 60000}) {
		t.Fatalf("keepalive settings changed: %#v", stream["sockopt"])
	}
}

func TestConvertXrayStreamTransportsAndTLSGuard(t *testing.T) {
	stream, err := ConvertXrayStream(map[string]any{
		"transport": map[string]any{
			"type": "grpc", "service_name": "grpc-service", "authority": "edge.example",
			"multi_mode": true, "idle_timeout": 30,
		},
		"tls": map[string]any{"enabled": true, "server_name": "edge.example", "alpn": []any{"h2"},
			"pinned_peer_cert_sha256":  "ea1f9d54f3955fa404e7fd3135319e93b4b7d2c719bdfd249aed20f470de131c",
			"verify_peer_cert_by_name": "edge.example", "utls": map[string]any{"fingerprint": "edge"}},
	}, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	grpc := objectValue(stream["grpcSettings"])
	if stream["method"] != "grpc" || grpc["serviceName"] != "grpc-service" || grpc["multiMode"] != true || grpc["idle_timeout"] != 30 {
		t.Fatalf("gRPC conversion changed: %#v", stream)
	}
	if !reflect.DeepEqual(stream["tlsSettings"], map[string]any{
		"serverName": "edge.example", "alpn": []string{"h2"}, "fingerprint": "edge",
		"pinnedPeerCertSha256": "ea1f9d54f3955fa404e7fd3135319e93b4b7d2c719bdfd249aed20f470de131c",
		"verifyPeerCertByName": "edge.example",
	}) {
		t.Fatalf("TLS conversion changed: %#v", stream["tlsSettings"])
	}
	_, err = ConvertXrayStream(map[string]any{"tls": map[string]any{"enabled": true, "insecure": true}}, false, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "allowInsecure") {
		t.Fatalf("insecure TLS was accepted: %v", err)
	}
	_, err = ConvertXrayStream(map[string]any{"transport": map[string]any{"type": "unsupported"}}, true, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot represent") {
		t.Fatalf("unsupported transport was accepted: %v", err)
	}
}

func TestConvertXrayStreamUsesMethodForEveryTransport(t *testing.T) {
	for _, item := range []struct {
		kind    string
		network string
	}{
		{kind: "ws", network: "websocket"},
		{kind: "grpc", network: "grpc"},
		{kind: "httpupgrade", network: "httpupgrade"},
		{kind: "xhttp", network: "xhttp"},
	} {
		t.Run(item.kind, func(t *testing.T) {
			stream, err := ConvertXrayStream(map[string]any{
				"transport": map[string]any{"type": item.kind},
			}, true, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if stream["method"] != item.network {
				t.Fatalf("method = %#v, want %q", stream["method"], item.network)
			}
			if _, exists := stream["network"]; exists {
				t.Fatalf("obsolete network field leaked: %#v", stream)
			}
		})
	}
}

func TestConvertXrayStreamPromotesLegacyHTTPHostHeader(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade"} {
		t.Run(kind, func(t *testing.T) {
			stream, err := ConvertXrayStream(map[string]any{"transport": map[string]any{
				"type": kind, "headers": map[string]any{"Host": "edge.example", "X-Test": "kept"},
			}}, false, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			settingsKey := kind + "Settings"
			if kind == "ws" {
				settingsKey = "wsSettings"
			}
			settings := objectValue(stream[settingsKey])
			headers := objectValue(settings["headers"])
			if settings["host"] != "edge.example" || headers["Host"] != nil || headers["X-Test"] != "kept" {
				t.Fatalf("legacy host header was not normalized: %#v", settings)
			}
		})
	}
}

func TestConvertXrayHysteriaInboundOptions(t *testing.T) {
	inbound, err := ConvertXrayInbound(map[string]any{
		"type": "hysteria2", "tag": "hysteria2-direct", "listen_port": 443,
		"users": []any{map[string]any{"name": "alice", "password": "secret"}},
		"tls":   map[string]any{"certificate_path": "/cert.pem", "key_path": "/key.pem"},
		"obfs":  map[string]any{"type": "salamander", "password": "mask"},
	}, XrayInboundOptions{HysteriaSettings: map[string]any{
		"udp_idle_timeout": 75,
		"masquerade":       map[string]any{"type": "string", "content": "not found", "status_code": 404},
		"quic_params":      map[string]any{"congestion": "brutal", "brutal_up_mbps": 20, "disable_path_mtu_discovery": true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	stream := objectValue(inbound["streamSettings"])
	hysteria := objectValue(stream["hysteriaSettings"])
	if stream["method"] != "hysteria" || hysteria["version"] != 2 || hysteria["udpIdleTimeout"] != 75 || objectValue(hysteria["masquerade"])["statusCode"] != 404 {
		t.Fatalf("Hysteria settings changed: %#v", hysteria)
	}
	mask := objectValue(stream["finalmask"])
	if objectValue(mask["quicParams"])["brutalUp"] != "20mbps" {
		t.Fatalf("Hysteria QUIC settings changed: %#v", mask)
	}
}

func TestConvertXrayHysteriaWebsiteMasqueradeUsesOnlyLoopbackHelper(t *testing.T) {
	inbound, err := ConvertXrayInbound(map[string]any{
		"type": "hysteria2", "tag": "hysteria2-direct", "listen_port": 443,
		"tls": map[string]any{"certificate_path": "/cert.pem", "key_path": "/key.pem"},
	}, XrayInboundOptions{HysteriaSettings: map[string]any{
		"masquerade": map[string]any{"type": "website", "url": "https://example.com/private"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	hysteria := objectValue(objectValue(inbound["streamSettings"])["hysteriaSettings"])
	masquerade := objectValue(hysteria["masquerade"])
	if masquerade["type"] != "proxy" || masquerade["url"] != WebsiteMasqueradeProxyURL || masquerade["rewriteHost"] != true {
		t.Fatalf("website masquerade exposed target to Xray: %#v", masquerade)
	}
}

func TestConvertXrayHysteriaAPIMasqueradeUsesOnlyLoopbackHelper(t *testing.T) {
	inbound, err := ConvertXrayInbound(map[string]any{
		"type": "hysteria2", "tag": "hysteria2-direct", "listen_port": 443,
		"tls": map[string]any{"certificate_path": "/cert.pem", "key_path": "/key.pem"},
	}, XrayInboundOptions{HysteriaSettings: map[string]any{
		"masquerade": map[string]any{"type": "api"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	masquerade := objectValue(objectValue(objectValue(inbound["streamSettings"])["hysteriaSettings"])["masquerade"])
	if masquerade["type"] != "proxy" || masquerade["url"] != WebsiteMasqueradeProxyURL || masquerade["rewriteHost"] != true {
		t.Fatalf("API masquerade did not use the loopback cover: %#v", masquerade)
	}
}

func TestConvertXrayTunAndMixedInbounds(t *testing.T) {
	tun, err := ConvertXrayInbound(map[string]any{
		"type": "tun", "tag": "tun-routeros", "interface_name": "sb-tun0",
		"address": []any{"172.31.255.2/30"}, "mtu": 1400,
	}, XrayInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if tun["protocol"] != "tun" || !reflect.DeepEqual(objectValue(tun["settings"])["gateway"], []string{"172.31.255.2/30"}) {
		t.Fatalf("TUN conversion changed: %#v", tun)
	}
	mixed, err := ConvertXrayInbound(map[string]any{"type": "mixed", "tag": "subscription-update-vpn", "listen": "127.0.0.1", "listen_port": 19080}, XrayInboundOptions{})
	if err != nil || mixed["protocol"] != "http" || mixed["port"] != 19080 {
		t.Fatalf("mixed conversion changed: %#v, %v", mixed, err)
	}
}

func TestConvertXrayTransparentInboundUsesKernelTPROXY(t *testing.T) {
	inbound, err := ConvertXrayInbound(map[string]any{
		"type": "transparent", "tag": "tun-routeros", "listen_port": 12345,
	}, XrayInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	settings := objectValue(inbound["settings"])
	sockopt := objectValue(objectValue(inbound["streamSettings"])["sockopt"])
	if inbound["protocol"] != "dokodemo-door" || settings["followRedirect"] != true ||
		settings["network"] != "tcp,udp" || sockopt["tproxy"] != "tproxy" {
		t.Fatalf("transparent inbound changed: %#v", inbound)
	}
}
