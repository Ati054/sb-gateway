package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHappUsesMobileLinksUnlessFormatIsExplicit(t *testing.T) {
	for _, accept := range []string{"", "*/*", "application/json"} {
		if got := normalizeProfileFormat("auto", "Happ/3.8 iOS", accept); got != "links" {
			t.Fatalf("Happ auto selected standalone TUN: %s", got)
		}
		if got := normalizeProfileFormat("xray", "Happ/3.8 iOS", accept); got != "xray" {
			t.Fatalf("explicit format ignored: %s", got)
		}
	}
}

func TestRemoteUserSubscriptionFormatOverridesDetection(t *testing.T) {
	user := map[string]any{"subscription_format": "mihomo"}
	if got := profileFormatForUser(user, "", "Happ/3.8 iOS", "application/json"); got != "mihomo" {
		t.Fatalf("saved preference = %s", got)
	}
	if got := profileFormatForUser(user, "xray", "Happ/3.8 iOS", "application/json"); got != "xray" {
		t.Fatalf("explicit query = %s", got)
	}
	if got := profileFormatForUser(map[string]any{}, "sing-box", "Mozilla/5.0", "*/*"); got != "singbox" {
		t.Fatalf("sing-box alias = %s", got)
	}
}

func TestConfirmedArrayClientsKeepNodesAndFullProfileSettings(t *testing.T) {
	for _, userAgent := range []string{"Happ/3.8 iOS", "v2rayNG/1.10 Android", "V2Box/9.4 iOS"} {
		for _, field := range []string{"client_individual_routing", "client_auto_fallback", "client_adblock"} {
			user := map[string]any{field: true}
			if got := profileFormatForUser(user, "auto", userAgent, "application/json"); got != "array" {
				t.Fatalf("%s %s auto format = %s", userAgent, field, got)
			}
		}
	}
	for _, userAgent := range []string{"Happ/3.8 iOS", "v2rayNG/1.10 Android", "V2Box/9.4 iOS"} {
		if got := profileFormatForUser(map[string]any{}, "auto", userAgent, "application/json"); got != "links" {
			t.Fatalf("simple %s format = %s", userAgent, got)
		}
	}
}

func TestAutomaticFormatCompatibilityMatrix(t *testing.T) {
	fullProfile := map[string]any{"client_individual_routing": true}
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{name: "Happ iOS", userAgent: "Happ/4.12.0 iOS", want: "array"},
		{name: "Happ Android", userAgent: "Happ/4.12.0 Android", want: "array"},
		{name: "v2rayNG current", userAgent: "v2rayNG/1.10.27 Android", want: "array"},
		{name: "v2rayNG broken 1.9.10", userAgent: "v2rayNG/1.9.10 Android", want: "links"},
		{name: "v2rayNG broken 1.9.11", userAgent: "v2rayNG/1.9.11 Android", want: "links"},
		{name: "V2Box iOS", userAgent: "V2Box/1.5.7 iOS", want: "array"},
		{name: "Hiddify iOS", userAgent: "Hiddify/4.0.0 iOS", want: "singbox"},
		{name: "Hiddify legacy Windows", userAgent: "HiddifyNext/2.5.7 Windows", want: "singbox"},
		{name: "Karing Android", userAgent: "Karing/1.2 Android", want: "singbox"},
		{name: "Mihomo Linux", userAgent: "Mihomo/1.19 Linux", want: "mihomo"},
		{name: "Clash Verge Windows", userAgent: "Clash-Verge/2.4 Windows", want: "mihomo"},
		{name: "Stash iOS", userAgent: "Stash/2.7 iOS", want: "mihomo"},
		{name: "XrayCore Linux", userAgent: "Xray-core/26.9.8 Linux", want: "xray"},
		{name: "XrayCore Windows", userAgent: "Xray-core/26.9.8 Windows", want: "xray"},
		{name: "Shadowrocket iOS", userAgent: "Shadowrocket/2.2 iOS", want: "links"},
		{name: "native sing-box", userAgent: "sing-box/1.12", want: "singbox"},
		{name: "v2rayN Windows", userAgent: "v2rayN/7.15 Windows", want: "links"},
		{name: "browser", userAgent: "Mozilla/5.0", want: "links"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := profileFormatForUser(fullProfile, "auto", test.userAgent, "application/json"); got != test.want {
				t.Fatalf("format = %s, want %s", got, test.want)
			}
		})
	}
}

func TestGenericJSONAcceptDoesNotReplaceNodeList(t *testing.T) {
	for _, userAgent := range []string{"Happ/3.8 iOS", "Shadowrocket/2.2", "v2rayNG/1.10", "Mozilla/5.0"} {
		if got := normalizeProfileFormat("auto", userAgent, "application/json"); got != "links" {
			t.Fatalf("%s auto format = %s", userAgent, got)
		}
	}
	if got := normalizeProfileFormat("auto", "xray-core/26.9.8", "application/json"); got != "xray" {
		t.Fatalf("explicit Xray client auto format = %s", got)
	}
}

func TestClientNodeNamesOmitUniqueTechnicalIndexes(t *testing.T) {
	if got := clientNodeName("iphone", "hysteria2", 1); got != "iphone · Hysteria 2" {
		t.Fatalf("unique name = %q", got)
	}
	if got := clientNodeName("iphone", "hysteria2", 2); got != "iphone · Hysteria 2 · 2" {
		t.Fatalf("duplicate name = %q", got)
	}
}

func TestLinksRejectCustomHeadersInsteadOfSilentlyDroppingThem(t *testing.T) {
	server, token := configuredPublicSubscriptionServer(t)
	active, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	objects(active["transports"])[0]["client_http_headers"] = map[string]any{"X-Required": "test"}
	revision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"links", "xray", "singbox", "mihomo"} {
		response := performRequest(t, server, http.MethodGet, "/"+token+"?format="+format, nil, nil)
		want := http.StatusOK
		if format == "links" {
			want = http.StatusUnprocessableEntity
		}
		if response.Code != want {
			t.Fatalf("%s: %d %s", format, response.Code, response.Body.String())
		}
		if format != "links" && !strings.Contains(response.Body.String(), "X-Required") {
			t.Fatalf("header missing in %s", format)
		}
	}
}

func TestClientTransportExportMatrix(t *testing.T) {
	for _, kind := range []string{"ws", "grpc", "httpupgrade", "xhttp", "reality", "reality-grpc", "xhttp-reality", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			server := newTestServer(t)
			transport := map[string]any{
				"id": "test", "kind": kind, "enabled": true, "hostname": "edge.example.test", "listen_port": 443,
				"path_secret_ref": "test/path", "service_name_secret_ref": "test/service",
				"server_name": "mask.example.test", "public_key": "test-public-key",
				"secret_refs": map[string]any{"reality_short_id": "test/short"},
				"http_host":   "host.example.test", "early_data": 1024,
				"client_http_headers": map[string]any{"X-Test": "kept"},
				"headers":             map[string]any{"X-XHTTP": "kept"}, "no_grpc_header": true,
			}
			user := map[string]any{"id": "phone", "uuid_secret_ref": "test/uuid", "hysteria2_password_secret_ref": "test/password"}
			if kind == "hysteria2" {
				transport["xray_hysteria"] = map[string]any{
					"quic_params": map[string]any{
						"congestion": "brutal", "brutal_up_mbps": 120, "brutal_down_mbps": 240,
						"init_stream_receive_window": 4194304, "max_stream_receive_window": 8388608,
						"init_connection_receive_window": 8388608, "max_connection_receive_window": 16777216,
						"max_idle_timeout": 30, "keep_alive_period": 15, "max_incoming_streams": 1024,
						"disable_path_mtu_discovery": true, "brutal_disable_loss_compensation": true,
						"disable_gso": true, "disable_stateless_reset": true,
					},
					"masquerade": map[string]any{"type": "proxy", "url": "http://127.0.0.1:8080/", "x_forwarded": true},
				}
			}
			for ref, value := range map[string]string{
				"test/uuid": "2f1c08fc-3f43-4e95-8f57-f8bded750a1a", "test/path": "/client", "test/service": "client-grpc",
				"test/short": "0123456789abcdef", "test/password": "test-hysteria-password",
			} {
				if err := server.secrets.write(ref, value, false); err != nil {
					t.Fatal(err)
				}
			}
			nodes, err := server.buildClientProfileNodes(map[string]any{"transports": []any{transport}}, user)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("nodes=%d err=%v", len(nodes), err)
			}
			node := nodes[0]
			uri, err := url.Parse(node.link)
			if err != nil || uri.Host != "edge.example.test:443" {
				t.Fatalf("endpoint: %v", err)
			}
			proxy, err := mihomoClientProxy(node)
			if err != nil {
				t.Fatal(err)
			}
			if proxy["server"] != "edge.example.test" || positiveInt(proxy["port"], 0) != 443 {
				t.Fatalf("wrong endpoint: %#v", proxy)
			}
			singBox, err := singBoxClientOutbound(node)
			if err != nil {
				t.Fatal(err)
			}
			if singBox["tag"] != node.name {
				t.Fatalf("sing-box node name lost: %#v", singBox)
			}
			settings := objectCopy(node.xray["settings"])
			if settings["reverse"] != nil {
				t.Fatal("mobile client received reverse bridge settings")
			}
			if kind == "hysteria2" {
				if uri.Scheme != "hysteria2" || proxy["type"] != "hysteria2" || proxy["password"] != "test-hysteria-password" {
					t.Fatal("Hysteria credentials/type lost")
				}
				quic := objectCopy(objectCopy(node.xray["streamSettings"])["finalmask"])
				quic = objectCopy(quic["quicParams"])
				for key, want := range map[string]any{
					"congestion": "brutal", "brutalUp": "120mbps", "brutalDown": "240mbps",
					"initStreamReceiveWindow": 4194304, "maxStreamReceiveWindow": 8388608,
					"initConnectionReceiveWindow": 8388608, "maxConnectionReceiveWindow": 16777216,
					"maxIdleTimeout": 30, "keepAlivePeriod": 15, "disablePathMTUDiscovery": true,
				} {
					if got := quic[key]; got != want {
						t.Fatalf("Hysteria client QUIC %s=%#v, want %#v: %#v", key, got, want, quic)
					}
				}
				for _, clientBody := range []any{node.xray, proxy, node.link} {
					body, marshalErr := json.Marshal(clientBody)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					for _, serverOnly := range []string{
						"brutal_disable_loss_compensation", "disable_gso", "disable_stateless_reset", "max_incoming_streams", "x_forwarded",
						"brutalDisableLossCompensation", "disableGSO", "disableStatelessReset", "maxIncomingStreams", "xForwarded",
					} {
						if strings.Contains(string(body), serverOnly) {
							t.Fatalf("client export inherited server-only %s: %s", serverOnly, body)
						}
					}
				}
				return
			}
			if uri.Scheme != "vless" || proxy["uuid"] != uri.User.Username() || settings["id"] != uri.User.Username() {
				t.Fatalf("VLESS credentials diverged: %#v", settings)
			}
			if strings.Contains(kind, "reality") {
				if uri.Query().Get("security") != "reality" || objectCopy(proxy["reality-opts"])["public-key"] != "test-public-key" {
					t.Fatal("REALITY security lost")
				}
			} else if uri.Query().Get("security") != "tls" || proxy["tls"] != true {
				t.Fatal("TLS lost")
			}
			if kind == "ws" || kind == "httpupgrade" {
				options := objectCopy(proxy["ws-opts"])
				if proxy["network"] != "ws" || objectCopy(options["headers"])["X-Test"] != "kept" || options["path"] != "/client?ed=1024" {
					t.Fatalf("WS options lost: %#v", options)
				}
				if (options["v2ray-http-upgrade"] == true) != (kind == "httpupgrade") {
					t.Fatal("HTTPUpgrade mapped to another protocol")
				}
			}
			if strings.Contains(kind, "xhttp") {
				options := objectCopy(proxy["xhttp-opts"])
				if objectCopy(options["headers"])["X-XHTTP"] != "kept" || options["no-grpc-header"] != true {
					t.Fatalf("XHTTP options lost: %#v", options)
				}
			}
		})
	}
}

func TestMihomoRejectsUntranslatedDownloadWithoutBreakingOtherFormats(t *testing.T) {
	server, token := configuredPublicSubscriptionServer(t)
	active, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	transport := objects(active["transports"])[0]
	transport["kind"] = "xhttp"
	transport["download_settings"] = map[string]any{"address": "download.example.test", "port": 443, "network": "xhttp", "security": "tls"}
	revision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"links", "xray", "singbox", "mihomo"} {
		response := performRequest(t, server, http.MethodGet, "/"+token+"?format="+format, nil, nil)
		want := http.StatusOK
		if format == "mihomo" {
			want = http.StatusUnprocessableEntity
		}
		if response.Code != want {
			t.Fatalf("%s: status=%d body=%s", format, response.Code, response.Body.String())
		}
	}
	_, err = mihomoClientProxy(clientProfileNode{xray: map[string]any{"streamSettings": map[string]any{"xhttpSettings": map[string]any{"extra": map[string]any{"downloadSettings": map[string]any{"address": "download.example.test"}}}}}})
	if !errors.Is(err, errClientProfileUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestClientEncryptedDNSMappingPreservesProviderAndDirection(t *testing.T) {
	for _, provider := range []string{"cloudflare", "google", "quad9", "yandex"} {
		for _, protocol := range []string{"doh", "dot"} {
			config := map[string]any{"dns": map[string]any{"vpn_resolver": map[string]any{"provider": provider, "protocol": protocol}}}
			resolver := clientResolverURL(config, "vpn_resolver", clientRouteProxy)
			for _, target := range []string{clientRouteDirect, clientRouteProxy} {
				plan := clientProfileRoutePlan{Individual: true, DefaultTarget: target, ExceptionTarget: map[string]string{clientRouteDirect: clientRouteProxy, clientRouteProxy: clientRouteDirect}[target], DirectDNS: "https://77.88.8.8/dns-query", ProxyDNS: resolver, Match: clientRouteMatch{Domains: []string{"example.test"}}}
				dns := buildXrayClientDNS(plan)
				body, _ := json.Marshal(dns)
				if strings.Contains(string(body), "tls://") {
					t.Fatalf("invalid Xray DNS: %s", body)
				}
				for _, item := range dns["servers"].([]any) {
					server := objectCopy(item)
					want := xrayClientResolverURL(clientDNSForTarget(plan, target))
					if server["tag"] == "client-dns-exception" {
						want = xrayClientResolverURL(clientDNSForTarget(plan, plan.ExceptionTarget))
					}
					if server["address"] != want {
						t.Fatalf("DNS direction/provider lost: %#v", server)
					}
				}
				mihomo, _ := json.Marshal(buildMihomoClientDNS(plan))
				if !strings.Contains(string(mihomo), resolver) {
					t.Fatalf("Mihomo DNS protocol changed: %s", mihomo)
				}
				singBox, _ := json.Marshal(buildSingBoxClientDNS(plan))
				if !strings.Contains(string(singBox), resolver) {
					t.Fatalf("sing-box DNS protocol changed: %s", singBox)
				}
			}
		}
	}
}

func TestSingBoxRealityPreservesQQFingerprint(t *testing.T) {
	node := clientProfileNode{name: "Reality", xray: map[string]any{
		"protocol": "vless",
		"settings": map[string]any{"address": "edge.example.test", "port": 443, "id": "2f1c08fc-3f43-4e95-8f57-f8bded750a1a", "flow": "xtls-rprx-vision"},
		"streamSettings": map[string]any{
			"network": "tcp", "security": "reality",
			"realitySettings": map[string]any{"serverName": "www.qq.com", "fingerprint": "qq", "password": "public-key", "shortId": "0123456789abcdef"},
		},
	}}
	outbound, err := singBoxClientOutbound(node)
	if err != nil {
		t.Fatal(err)
	}
	tls := objectCopy(outbound["tls"])
	if tls["server_name"] != "www.qq.com" || objectCopy(tls["utls"])["fingerprint"] != "qq" || objectCopy(tls["reality"])["public_key"] != "public-key" {
		t.Fatalf("REALITY values changed: %#v", tls)
	}
}

func TestSingBoxHysteriaPreservesObfsAndPinnedCertificate(t *testing.T) {
	node := clientProfileNode{name: "Hysteria 2", certificate: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", xray: map[string]any{
		"protocol": "hysteria",
		"settings": map[string]any{"address": "hy.example.test", "port": 443},
		"streamSettings": map[string]any{
			"hysteriaSettings": map[string]any{"auth": "secret"},
			"tlsSettings":      map[string]any{"serverName": "hy.example.test", "pinnedPeerCertSha256": "deadbeef"},
			"finalmask": map[string]any{"udp": []any{map[string]any{
				"type": "salamander", "settings": map[string]any{"password": "obfs-secret"},
			}}},
		},
	}}
	outbound, err := singBoxClientOutbound(node)
	if err != nil {
		t.Fatal(err)
	}
	if outbound["type"] != "hysteria2" || outbound["password"] != "secret" || objectCopy(outbound["obfs"])["password"] != "obfs-secret" {
		t.Fatalf("Hysteria 2 values changed: %#v", outbound)
	}
	certificates := anySlice(objectCopy(outbound["tls"])["certificate"])
	if len(certificates) != 1 || certificates[0] != node.certificate {
		t.Fatalf("Hysteria 2 certificate pin changed: %#v", outbound["tls"])
	}
}
