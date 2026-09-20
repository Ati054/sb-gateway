package controlplane

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestGRPCTLSPinExportUsesOneLeafPinAcrossClients(t *testing.T) {
	server, _ := configuredPublicSubscriptionServer(t)
	config, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	certificate, privateKey := testTLSKeypair(t)
	config["tls_profiles"] = []any{map[string]any{
		"id": "direct-private", "enabled": true,
		"certificate_secret_ref": "tls/direct/certificate.pem",
		"private_key_secret_ref": "tls/direct/private-key.pem",
	}}
	config["transports"] = []any{map[string]any{
		"id": "grpc-tls-pin", "kind": "grpc-tls", "enabled": true,
		"hostname": "edge.example.test", "listen_port": 2445,
		"tls_profile_id": "direct-private", "tls_server_name": "gateway.example.test",
		"service_name_secret_ref": "transports/grpc-tls-pin/service",
	}}
	user := objects(config["remote_users"])[0]
	user["client_fingerprint"] = "firefox"
	for reference, value := range map[string]string{
		"tls/direct/certificate.pem":      certificate,
		"tls/direct/private-key.pem":      privateKey,
		"transports/grpc-tls-pin/service": "private-grpc",
	} {
		if err := server.secrets.write(reference, value, true); err != nil {
			t.Fatal(err)
		}
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate gRPC TLS Pin config: %v", err)
	}
	nodes, err := server.buildClientProfileNodes(config, user)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("gRPC TLS Pin nodes = %d, err = %v", len(nodes), err)
	}
	block, _ := pem.Decode([]byte(certificate))
	wantDigest := sha256.Sum256(block.Bytes)
	wantPin := hex.EncodeToString(wantDigest[:])
	wantURIpin := colonSeparatedFingerprint(wantDigest[:])
	link, err := url.Parse(nodes[0].link)
	if err != nil {
		t.Fatal(err)
	}
	query := link.Query()
	if query.Get("type") != "grpc" || query.Get("security") != "tls" || query.Get("serviceName") != "private-grpc" || query.Get("sni") != "gateway.example.test" || query.Get("alpn") != "h2" || query.Get("pcs") != wantURIpin || query.Get("fp") != "firefox" {
		t.Fatalf("gRPC TLS Pin URI = %s", nodes[0].link)
	}
	stream := objectCopy(nodes[0].xray["streamSettings"])
	xrayTLS := objectCopy(stream["tlsSettings"])
	if xrayTLS["pinnedPeerCertSha256"] != wantPin || !reflect.DeepEqual(xrayTLS["alpn"], []any{"h2"}) {
		t.Fatalf("Xray TLS pin = %#v", stream)
	}
	if objectCopy(stream["sockopt"])["tcpUserTimeout"] != 60000 {
		t.Fatalf("Xray gRPC TCP stability = %#v", stream["sockopt"])
	}
	if nodes[0].mihomo["fingerprint"] != wantPin || nodes[0].mihomo["client-fingerprint"] != "firefox" || !reflect.DeepEqual(nodes[0].mihomo["alpn"], []string{"h2"}) {
		t.Fatalf("Mihomo TLS pin = %#v", nodes[0].mihomo)
	}
	singBox, err := singBoxClientOutbound(nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	tls := objectCopy(singBox["tls"])
	certificates := stringValues(tls["certificate"])
	if len(certificates) != 1 || strings.TrimSpace(certificates[0]) != strings.TrimSpace(certificate) || objectCopy(tls["utls"])["fingerprint"] != "firefox" {
		t.Fatalf("sing-box TLS trust = %#v", tls)
	}
}

func TestPublicSubscriptionServesLinksXraySingBoxAndMihomoFromActiveGeneration(t *testing.T) {
	server, token := configuredPublicSubscriptionServer(t)

	linksResponse := performRequest(t, server, http.MethodGet, "/"+token+"?format=links", nil, nil)
	if linksResponse.Code != http.StatusOK || linksResponse.Header().Get("X-SB-Profile-Format") != "links" {
		t.Fatalf("links response: %d %s", linksResponse.Code, linksResponse.Body.String())
	}
	if cacheControl := linksResponse.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "no-store") || !strings.Contains(cacheControl, "no-cache") {
		t.Fatalf("subscription cache policy = %q", cacheControl)
	}
	if linksResponse.Header().Get("Pragma") != "no-cache" || linksResponse.Header().Get("Expires") != "0" {
		t.Fatalf("legacy subscription cache policy = %#v", linksResponse.Header())
	}
	vary := linksResponse.Header().Values("Vary")
	if len(vary) != 1 || vary[0] != "User-Agent, Accept" {
		t.Fatalf("subscription negotiation vary = %#v", vary)
	}
	decoded, err := base64.StdEncoding.DecodeString(linksResponse.Body.String())
	if err != nil || !strings.Contains(string(decoded), "vless://") || !strings.Contains(string(decoded), "path=%2Fclient") {
		t.Fatalf("invalid links subscription: %q (%v)", decoded, err)
	}
	if title := linksResponse.Header().Get("profile-title"); title != "base64:"+base64.StdEncoding.EncodeToString([]byte("Home Gateway")) {
		t.Fatalf("profile title = %q", title)
	}

	xrayResponse := performRequest(t, server, http.MethodGet, "/"+token, nil, map[string]string{"User-Agent": "xray-core/26.9.8", "Accept": "application/json"})
	if xrayResponse.Code != http.StatusOK || xrayResponse.Header().Get("X-SB-Profile-Format") != "xray" {
		t.Fatalf("xray response: %d %s", xrayResponse.Code, xrayResponse.Body.String())
	}
	var xray map[string]any
	if err := json.Unmarshal(xrayResponse.Body.Bytes(), &xray); err != nil {
		t.Fatal(err)
	}
	outbound := xray["outbounds"].([]any)[0].(map[string]any)
	settings := outbound["settings"].(map[string]any)
	if outbound["protocol"] != "vless" || settings["address"] != "edge.example.test" || settings["reverse"] != nil {
		t.Fatalf("invalid client outbound: %#v", outbound)
	}
	wsSettings := outbound["streamSettings"].(map[string]any)["wsSettings"].(map[string]any)
	if wsSettings["host"] != "edge.example.test" || objectCopy(wsSettings["headers"])["Host"] != nil {
		t.Fatalf("Xray WebSocket host uses an obsolete header location: %#v", wsSettings)
	}

	singBoxResponse := performRequest(t, server, http.MethodGet, "/"+token, nil, map[string]string{"User-Agent": "Hiddify/4.0.0 iOS", "Accept": "application/json"})
	if singBoxResponse.Code != http.StatusOK || singBoxResponse.Header().Get("X-SB-Profile-Format") != "singbox" || !strings.HasPrefix(singBoxResponse.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("sing-box response: %d %s", singBoxResponse.Code, singBoxResponse.Body.String())
	}
	var singBox map[string]any
	if err := json.Unmarshal(singBoxResponse.Body.Bytes(), &singBox); err != nil {
		t.Fatal(err)
	}
	singBoxOutbound := singBox["outbounds"].([]any)[1].(map[string]any)
	if singBoxOutbound["type"] != "vless" || singBoxOutbound["server"] != "edge.example.test" {
		t.Fatalf("invalid sing-box outbound: %#v", singBoxOutbound)
	}

	mihomoResponse := performRequest(t, server, http.MethodGet, "/"+token, nil, map[string]string{"User-Agent": "Mihomo/1.19"})
	if mihomoResponse.Code != http.StatusOK || mihomoResponse.Header().Get("X-SB-Profile-Format") != "mihomo" {
		t.Fatalf("mihomo response: %d %s", mihomoResponse.Code, mihomoResponse.Body.String())
	}
	mihomo := mihomoResponse.Body.String()
	if !strings.Contains(mihomo, `"type": "vless"`) || !strings.Contains(mihomo, `"packet-encoding": "xudp"`) || !strings.Contains(mihomo, `"stack": "mixed"`) || !strings.Contains(mihomo, `"MATCH,SB Gateway"`) || !strings.Contains(mihomo, `"auto-route": true`) {
		t.Fatalf("invalid Mihomo profile:\n%s", mihomo)
	}
}

func TestPublicSubscriptionHonorsUserFormatAndBuildsClientJSONArray(t *testing.T) {
	server, token := configuredPublicSubscriptionServer(t)
	active, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	user := objects(active["remote_users"])[0]
	user["subscription_format"] = "mihomo"
	revision, err := server.repository.stageGeneration(active)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate Mihomo preference: %v", err)
	}
	response := performRequest(t, server, http.MethodGet, "/"+token, nil, map[string]string{"User-Agent": "Happ/3.8 iOS"})
	if response.Code != http.StatusOK || response.Header().Get("X-SB-Profile-Format") != "mihomo" {
		t.Fatalf("saved format: %d %s", response.Code, response.Body.String())
	}

	user["subscription_format"] = "auto"
	user["client_auto_fallback"] = true
	transport := cloneJSONObject(objects(active["transports"])[0])
	transport["id"] = "grpc"
	transport["kind"] = "grpc"
	transport["service_name_secret_ref"] = "transports/grpc/service"
	active["transports"] = []any{objects(active["transports"])[0], transport}
	if err := server.secrets.write("transports/grpc/service", "client-grpc", false); err != nil {
		t.Fatal(err)
	}
	revision, err = server.repository.stageGeneration(active)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate Happ auto profile: %v", err)
	}
	active, err = server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := server.buildClientProfileNodes(active, objects(active["remote_users"])[0])
	if err != nil {
		t.Fatalf("build Happ nodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("Happ nodes = %d; transports = %#v", len(nodes), active["transports"])
	}
	if _, err := server.buildPublicProfileForRequest(token, "", "Happ/3.8 iOS", "application/json"); err != nil {
		t.Fatalf("build Happ JSON array: %v", err)
	}
	response = performRequest(t, server, http.MethodGet, "/"+token, nil, map[string]string{"User-Agent": "Happ/3.8 iOS", "Accept": "application/json"})
	if response.Code != http.StatusOK || response.Header().Get("X-SB-Profile-Format") != "array" {
		t.Fatalf("Happ JSON array: %d %s", response.Code, response.Body.String())
	}
	var profiles []map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &profiles); err != nil {
		t.Fatalf("Happ JSON array: %v", err)
	}
	if len(profiles) != 3 || profiles[0]["remarks"] != "phone · Автоматический выбор" || profiles[1]["remarks"] != "phone · WebSocket" || profiles[2]["remarks"] != "phone · gRPC" {
		t.Fatalf("Happ profiles = %#v", profiles)
	}
	if strings.Contains(response.Body.String(), "geosite:") {
		t.Fatalf("Happ JSON array depends on an external geosite.dat:\n%s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "sb-client-tun0") {
		t.Fatalf("Happ JSON array pins a Linux-only TUN interface name:\n%s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"protocol": "tun"`) || strings.Contains(response.Body.String(), `"tun-in"`) {
		t.Fatalf("Happ JSON array contains a raw TUN inbound instead of app-managed proxies:\n%s", response.Body.String())
	}
	for _, profile := range profiles {
		inbounds := profile["inbounds"].([]any)
		if len(inbounds) != 2 || inbounds[0].(map[string]any)["protocol"] != "socks" || inbounds[1].(map[string]any)["protocol"] != "http" {
			t.Fatalf("Happ app-managed inbounds = %#v", inbounds)
		}
		dns := profile["dns"].(map[string]any)
		if !reflect.DeepEqual(dns["servers"], []any{"8.8.8.8", "1.1.1.1"}) {
			t.Fatalf("Happ DNS must be a portable resolver list: %#v", dns)
		}
		encoded, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "client-dns") {
			t.Fatalf("Happ profile retained standalone DNS routing: %#v", profile)
		}
		if strings.Contains(string(encoded), `"method"`) {
			t.Fatalf("Happ profile retained the incompatible stream method spelling: %#v", profile)
		}
	}
	grpcStream := objectCopy(profiles[2]["outbounds"].([]any)[0].(map[string]any)["streamSettings"])
	if grpcStream["network"] != "grpc" {
		t.Fatalf("Happ gRPC stream network = %#v", grpcStream)
	}
	for _, profile := range profiles[1:] {
		outbounds := profile["outbounds"].([]any)
		if outbounds[0].(map[string]any)["tag"] != "client-node-1" {
			t.Fatalf("individual profile target = %#v", outbounds[0])
		}
	}
}

func TestPublicSubscriptionAppliesPerUserHappTunnelSettings(t *testing.T) {
	server, token := configuredPublicSubscriptionServer(t)
	active, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	exposure := active["public_exposure"].(map[string]any)
	exposure["subscription"].(map[string]any)["happ_provider_id"] = "provider-123"
	user := objects(active["remote_users"])[0]
	user["happ_include_all_networks"] = true
	user["happ_exclude_local_networks"] = false
	user["happ_exclude_apns"] = true
	revision, err := server.repository.stageGeneration(active)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate Happ preferences: %v", err)
	}

	response := performRequest(t, server, http.MethodGet, "/"+token, nil, map[string]string{"User-Agent": "Happ/4.12.0 iOS"})
	if response.Code != http.StatusOK || response.Header().Get("X-SB-Profile-Format") != "links" {
		t.Fatalf("Happ subscription: %d %s", response.Code, response.Body.String())
	}
	for name, want := range map[string]string{
		"providerid": "provider-123", "include-all-networks-enable": "true",
		"exclude-local-networks-enable": "false", "exclude-apns-enable": "true",
	} {
		if got := response.Header().Get(name); got != want {
			t.Fatalf("Happ header %s = %q, want %q", name, got, want)
		}
	}

	delete(user, "happ_include_all_networks")
	delete(user, "happ_exclude_local_networks")
	delete(user, "happ_exclude_apns")
	revision, err = server.repository.stageGeneration(active)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate Happ defaults: %v", err)
	}
	response = performRequest(t, server, http.MethodGet, "/"+token, nil, map[string]string{"User-Agent": "Happ/4.12.0 iOS"})
	for _, name := range []string{"include-all-networks-enable", "exclude-local-networks-enable", "exclude-apns-enable"} {
		if got := response.Header().Get(name); got != "true" {
			t.Fatalf("default Happ header %s = %q, want true", name, got)
		}
	}
}

func TestPublicSubscriptionFailsClosedAndRotationRevokesOldToken(t *testing.T) {
	server, token := configuredPublicSubscriptionServer(t)
	cookie, csrf := loginSession(t, server)

	unknown := performRequest(t, server, http.MethodGet, "/"+strings.Repeat("z", 43), nil, nil)
	if unknown.Code != http.StatusNotFound || unknown.Body.Len() != 0 || unknown.Header().Get("X-Robots-Tag") == "" {
		t.Fatalf("unknown token leaked details: %d %q %#v", unknown.Code, unknown.Body.String(), unknown.Header())
	}
	unsupported := performRequest(t, server, http.MethodGet, "/"+token+"?format=unsupported", nil, nil)
	if unsupported.Code != http.StatusNotFound {
		t.Fatalf("unsupported format returned %d", unsupported.Code)
	}

	rotated := performRequest(t, server, http.MethodPost, apiPrefix+"/remote-users/phone/subscription-link/rotate", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotation failed: %d %s", rotated.Code, rotated.Body.String())
	}
	newURL := decodeResponse(t, rotated)["url"].(string)
	newToken := newURL[strings.LastIndex(newURL, "/")+1:]
	if newToken == token {
		t.Fatal("rotation retained old token")
	}
	oldResponse := performRequest(t, server, http.MethodGet, "/"+token, nil, nil)
	newResponse := performRequest(t, server, http.MethodGet, "/"+newToken, nil, nil)
	if oldResponse.Code != http.StatusNotFound || newResponse.Code != http.StatusOK {
		t.Fatalf("revocation result old=%d new=%d", oldResponse.Code, newResponse.Code)
	}
}

func TestPublicSubscriptionReturnsNotFoundWhenPublicationIsDisabled(t *testing.T) {
	server, token := configuredPublicSubscriptionServer(t)
	active, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	active["ingress"].(map[string]any)["subscription_endpoint_enabled"] = false
	revision, err := server.repository.stageGeneration(active)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("disable active publication: %v", err)
	}
	if _, err := server.buildPublicProfile(token, "links"); !errors.Is(err, errSubscriptionPublicationClosed) {
		t.Fatalf("disabled profile failure = %v", err)
	}
	response := performRequest(t, server, http.MethodGet, "/"+token, nil, nil)
	if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
		t.Fatalf("disabled publication leaked public response: %d %q", response.Code, response.Body.String())
	}
}

func TestPublicSubscriptionBuildsRealityAndHysteriaNodes(t *testing.T) {
	server := newTestServer(t)
	_, _ = bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["remote_users"] = []any{map[string]any{
		"id": "travel", "enabled": true, "uuid_secret_ref": "remote-users/travel.uuid",
		"hysteria2_password_secret_ref": "remote-users/travel.hy2", "subscription_path_secret_ref": "remote-users/travel.subscription-path",
		"client_tun_address": "172.30.1.2/30", "client_fingerprint": "ios",
	}}
	config["transports"] = []any{
		map[string]any{
			"id": "reality", "kind": "reality", "enabled": true, "hostname": "direct.example.test", "listen_port": 2443,
			"server_name": "www.example.com", "public_key": "public-reality-key", "fingerprint": "chrome",
			"secret_refs": map[string]any{"reality_short_id": "transports/reality/short-id"},
		},
		map[string]any{
			"id": "hy2", "kind": "hysteria2", "enabled": true, "hostname": "hy2.example.test", "listen_port": 8443,
			"tls_server_name": "hy2.example.test", "obfs_enabled": true,
			"xray_hysteria": map[string]any{
				"quic_params": map[string]any{"keep_alive_period": 15},
				"udp_hop": map[string]any{
					"enabled": true, "port_start": 20000, "port_end": 20100,
					"interval_min": 15, "interval_max": 45, "excluded_ports": "20053",
				},
			},
			"secret_refs": map[string]any{"hysteria2_obfs_password": "transports/hy2/obfs"},
		},
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate config: %v", err)
	}
	token := strings.Repeat("r", 43)
	for reference, value := range map[string]string{
		"remote-users/travel.uuid":              "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
		"remote-users/travel.hy2":               "strong-hysteria-password",
		"remote-users/travel.subscription-path": token,
		"transports/reality/short-id":           "0123456789abcdef",
		"transports/hy2/obfs":                   "obfuscation-password",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	response := performRequest(t, server, http.MethodGet, "/"+token+"?format=links", nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("profile failed: %d %s", response.Code, response.Body.String())
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Body.String())
	if err != nil {
		t.Fatal(err)
	}
	links := string(decoded)
	if !strings.Contains(links, "security=reality") || strings.Count(links, "fp=ios") != 2 || !strings.Contains(links, "flow=xtls-rprx-vision") || !strings.Contains(links, "hysteria2://") || !strings.Contains(links, "obfs=salamander") || !strings.Contains(links, "mport=20000-20052%2C20054-20100") {
		t.Fatalf("transport links missing:\n%s", links)
	}
	nodes, err := server.buildClientProfileNodes(config, config["remote_users"].([]any)[0].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	hysteriaStream := nodes[1].xray["streamSettings"].(map[string]any)
	if objectCopy(objectCopy(nodes[0].xray["streamSettings"])["realitySettings"])["fingerprint"] != "ios" || objectCopy(hysteriaStream["tlsSettings"])["fingerprint"] != "ios" {
		t.Fatalf("per-user fingerprint did not reach REALITY and Hysteria: %#v %#v", nodes[0].xray, nodes[1].xray)
	}
	quicParams := hysteriaStream["finalmask"].(map[string]any)["quicParams"].(map[string]any)
	if quicParams["keepAlivePeriod"] != 15 {
		t.Fatalf("Hysteria client QUIC keepalive = %#v", quicParams)
	}
	if strings.Contains(nodes[1].link, "keepalive") || nodes[1].mihomo["keep-alive"] != nil {
		t.Fatalf("Xray-only QUIC keepalive leaked into unsupported formats: %s %#v", nodes[1].link, nodes[1].mihomo)
	}
	udpMasks := hysteriaStream["finalmask"].(map[string]any)["udp"].([]any)
	if first := udpMasks[0].(map[string]any); first["type"] != "udphop" || first["settings"].(map[string]any)["mode"] != "intervalRemote" || first["settings"].(map[string]any)["remotePorts"] != "20000-20052,20054-20100" {
		t.Fatalf("Xray UDP hopping mask is not outermost: %#v", udpMasks)
	}
	if second := udpMasks[1].(map[string]any); second["type"] != "salamander" {
		t.Fatalf("Salamander mask ordering changed: %#v", udpMasks)
	}
	parsedLink, err := url.Parse(nodes[1].link)
	if err != nil || parsedLink.Query().Get("mport") != "20000-20052,20054-20100" {
		t.Fatalf("Hysteria URI UDP hopping export changed: %v %#v", err, parsedLink)
	}
	if nodes[1].mihomo["ports"] != "20000-20052,20054-20100" || nodes[1].mihomo["hop-interval"] != "15-45" {
		t.Fatalf("Mihomo UDP hopping export changed: %#v", nodes[1].mihomo)
	}
	singBox, err := singBoxHysteriaOutbound(nodes[1])
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(singBox["server_ports"]) != "[20000:20052 20054:20100]" || singBox["hop_interval"] != "15s" || singBox["hop_interval_max"] != "45s" || singBox["server_port"] != nil {
		t.Fatalf("sing-box UDP hopping export changed: %#v", singBox)
	}
	if objectCopy(objectCopy(singBox["tls"])["utls"])["fingerprint"] != "ios" {
		t.Fatalf("per-user Hysteria fingerprint did not reach sing-box: %#v", singBox)
	}
}

func TestPublicSubscriptionAppliesClientOnlyTransportSettings(t *testing.T) {
	server := newTestServer(t)
	config := map[string]any{"transports": []any{
		map[string]any{
			"id": "grpc", "kind": "grpc", "enabled": true, "hostname": "grpc.example.test", "listen_port": 443,
			"service_name_secret_ref": "transports/grpc/service", "grpc_authority": "authority.example.test",
			"grpc_user_agent": "sb-client", "grpc_multi_mode": true, "grpc_idle_timeout": 45,
			"grpc_health_check_timeout": 20, "grpc_permit_without_stream": true, "grpc_initial_windows_size": 1048576,
			"tcp_keep_alive_idle": 30, "tcp_keep_alive_interval": 10, "tcp_user_timeout": 60000,
		},
		map[string]any{
			"id": "xhttp-reality", "kind": "xhttp-reality", "enabled": true, "hostname": "xhttp.example.test", "listen_port": 2446,
			"server_name": "www.example.com", "public_key": "public-key", "fingerprint": "firefox", "spider_x": "/spider",
			"tcp_keep_alive_idle": 30, "tcp_keep_alive_interval": 10, "tcp_user_timeout": 60000,
			"reality_mldsa65_enabled": true, "mldsa65_verify": "mldsa-verify", "path_secret_ref": "transports/xhttp/path",
			"secret_refs": map[string]any{"reality_short_id": "transports/xhttp/short-id"},
			"mode":        "auto", "x_padding_bytes": "100-500", "xmux_max_connections": "3",
			"download_settings": map[string]any{"address": "download.example.test", "port": 443},
		},
	}}
	user := map[string]any{"id": "phone", "uuid_secret_ref": "remote-users/phone.uuid", "client_fingerprint": "ios"}
	for reference, value := range map[string]string{
		"remote-users/phone.uuid":   "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
		"transports/grpc/service":   "grpc-service",
		"transports/xhttp/path":     "/xhttp-client",
		"transports/xhttp/short-id": "0123456789abcdef",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}

	nodes, err := server.buildClientProfileNodes(config, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("client nodes = %#v", nodes)
	}
	grpcStream := nodes[0].xray["streamSettings"].(map[string]any)
	if objectCopy(grpcStream["tlsSettings"])["fingerprint"] != "ios" || !strings.Contains(nodes[0].link, "fp=ios") {
		t.Fatalf("per-user fingerprint did not reach ordinary TLS: %#v %s", grpcStream, nodes[0].link)
	}
	grpc := grpcStream["grpcSettings"].(map[string]any)
	if grpc["serviceName"] != "grpc-service" || grpc["authority"] != "authority.example.test" || grpc["user_agent"] != "sb-client" ||
		grpc["multiMode"] != true || grpc["idle_timeout"] != 45 || grpc["health_check_timeout"] != 20 ||
		grpc["permit_without_stream"] != true || grpc["initial_windows_size"] != 1048576 {
		t.Fatalf("generated gRPC client settings = %#v", grpc)
	}
	grpcMihomo := nodes[0].mihomo["grpc-opts"].(map[string]any)
	if grpcMihomo["grpc-service-name"] != "grpc-service" || grpcMihomo["grpc-user-agent"] != "sb-client" {
		t.Fatalf("generated Mihomo gRPC client settings = %#v", grpcMihomo)
	}
	if strings.Contains(nodes[0].link, "userAgent=authority.example.test") || !strings.Contains(nodes[0].link, "userAgent=sb-client") {
		t.Fatalf("gRPC share link confused authority with User-Agent: %s", nodes[0].link)
	}
	grpcSockopt := grpcStream["sockopt"].(map[string]any)
	if grpcSockopt["tcpKeepAliveIdle"] != 30 || grpcSockopt["tcpKeepAliveInterval"] != 10 || grpcSockopt["tcpUserTimeout"] != 60000 {
		t.Fatalf("generated gRPC CDN client sockopt = %#v", grpcSockopt)
	}
	for _, transport := range objects(config["transports"]) {
		transport["tcp_keep_alive_enabled"] = false
		transport["tcp_user_timeout"] = 0
	}
	disabledNodes, err := server.buildClientProfileNodes(config, user)
	if err != nil {
		t.Fatal(err)
	}
	for index, node := range disabledNodes {
		options := node.xray["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
		if options["tcpKeepAliveIdle"] != -1 || options["tcpKeepAliveInterval"] != -1 || options["tcpUserTimeout"] != 0 {
			t.Fatalf("disabled client socket options: %#v", options)
		}
		if node.link != nodes[index].link {
			t.Fatal("Xray-only socket options changed a share link")
		}
		if _, exists := node.mihomo["sockopt"]; exists {
			t.Fatal("Xray socket options leaked into Mihomo")
		}
	}
	xhttpStream := nodes[1].xray["streamSettings"].(map[string]any)
	sockopt := xhttpStream["sockopt"].(map[string]any)
	if sockopt["tcpKeepAliveIdle"] != 30 || sockopt["tcpKeepAliveInterval"] != 10 || sockopt["tcpUserTimeout"] != 60000 {
		t.Fatalf("generated XHTTP client sockopt = %#v", sockopt)
	}
	extra := xhttpStream["xhttpSettings"].(map[string]any)["extra"].(map[string]any)
	if extra["xPaddingBytes"] != "100-500" || extra["xmux"].(map[string]any)["maxConnections"] != "3" {
		t.Fatalf("generated XHTTP client settings = %#v", extra)
	}
	download := extra["downloadSettings"].(map[string]any)
	if download["address"] != "download.example.test" || download["port"] != 443 {
		t.Fatalf("generated XHTTP downloadSettings = %#v", download)
	}
	reality := xhttpStream["realitySettings"].(map[string]any)
	if reality["fingerprint"] != "ios" || reality["spiderX"] != "/spider" || reality["mldsa65Verify"] != "mldsa-verify" {
		t.Fatalf("generated REALITY client settings = %#v", reality)
	}
}

func TestFullClientProfilesApplyEveryClientPolicyControl(t *testing.T) {
	config := map[string]any{
		"dns": map[string]any{
			"direct_resolver": map[string]any{"provider": "yandex", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "dot"},
			"internal_server": "192.168.3.1", "internal_zones": []any{"home.arpa"},
		},
		"networks": []any{map[string]any{
			"id": "home", "kind": "internal", "enabled": true, "cidrs": []any{"192.168.3.0/24"},
		}},
		"routeros":      map[string]any{"router_addresses": []any{"192.168.3.1/32"}},
		"system":        map[string]any{"networking": map[string]any{"routeros_gateway": "172.19.0.1"}},
		"service_packs": []any{},
		"policies": []any{map[string]any{
			"id": "europe", "enabled": true, "traffic_mode": "vless_with_wan_exceptions",
			"domain_strategy": "AsIs", "torrent_direct": false,
			"direct_services": []any{"ru-marketplaces", "ru-telecom", "binance"}, "direct_domains": []any{"manual.example"},
		}},
	}
	user := map[string]any{
		"id": "phone", "policy_id": "europe", "role": "trusted-limited",
		"client_tun_address": "172.30.0.2/30", "client_individual_routing": true,
		"client_auto_fallback": true, "client_adblock": true,
		"allowed_cidrs": []any{"192.168.3.0/24"}, "allowed_ports": []any{float64(443)},
	}
	nodes := []clientProfileNode{
		{name: "one", xray: map[string]any{"tag": "client-node-1", "protocol": "vless"}, mihomo: map[string]any{"name": "one", "server": "one.example.test"}},
		{name: "two", xray: map[string]any{"tag": "client-node-2", "protocol": "vless"}, mihomo: map[string]any{"name": "two", "server": "two.example.test"}},
	}

	body, err := buildCombinedXrayProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	dns := profile["dns"].(map[string]any)
	if dns["useSystemHosts"] != false {
		t.Fatalf("system hosts remained enabled: %#v", dns)
	}
	servers := dns["servers"].([]any)
	if !jsonObjectSliceContains(servers, "tag", "client-dns-exception", "address", "https://77.88.8.8/dns-query") ||
		!jsonObjectSliceContains(servers, "tag", "client-dns-default", "address", "https://1.1.1.1/dns-query") {
		t.Fatalf("directional DNS controls were not rendered: %#v", servers)
	}
	tunSettings := profile["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
	if _, pinned := tunSettings["name"]; pinned {
		t.Fatalf("portable Xray profile pins a platform-specific TUN name: %#v", tunSettings)
	}
	routing := profile["routing"].(map[string]any)
	if routing["domainStrategy"] != "AsIs" {
		t.Fatalf("domain strategy did not reach profile: %#v", routing)
	}
	rules := routing["rules"].([]any)
	marketplace := xrayRuleWithDomain(rules, "domain:ozon.ru")
	if marketplace == nil || marketplace["outboundTag"] != "client-direct" || strings.Contains(string(body), "geosite:") {
		t.Fatalf("portable service route is missing or still depends on geosite.dat: %#v", rules)
	}
	if xrayRuleWithDomain(rules, "domain:manual.example") == nil {
		t.Fatalf("service fallback or pinpoint domains are missing: %#v", rules)
	}
	for _, domain := range []string{"domain:sibset.ru", "domain:211.ru", "domain:sibseti.ru", "domain:lk.sibseti.ru", "domain:binance.com", "domain:binance.vision", "domain:token.awswaf.com"} {
		if rule := xrayRuleWithDomain(rules, domain); rule == nil || rule["outboundTag"] != "client-direct" {
			t.Fatalf("release-pinned service domain %q is missing from the portable client route: %#v", domain, rules)
		}
	}
	if !xrayRuleTargets(rules, "client-dns-exception", "client-direct", "") ||
		!xrayRuleTargets(rules, "client-dns-default", "", "client-proxy") {
		t.Fatalf("DNS direction does not follow route sheet: %#v", rules)
	}
	if !xrayLANRuleExists(rules, "192.168.3.0/24", "443", "client-proxy") {
		t.Fatalf("LAN CIDR/port did not reach profile: %#v", rules)
	}
	for _, rawRule := range rules {
		rule, _ := rawRule.(map[string]any)
		if rule["outboundTag"] != "client-direct" {
			continue
		}
		for _, value := range stringsOf(rule["ip"]) {
			if netip.MustParsePrefix(value).Contains(netip.MustParseAddr("192.168.3.1")) {
				t.Fatalf("remote LAN still overlaps a direct Xray route: %#v", rule)
			}
		}
	}
	outbounds := profile["outbounds"].([]any)
	dnsOutbound := outbounds[len(outbounds)-3].(map[string]any)["settings"].(map[string]any)
	directOutbound := outbounds[len(outbounds)-2].(map[string]any)
	directSockopt := directOutbound["streamSettings"].(map[string]any)["sockopt"].(map[string]any)
	if directOutbound["settings"].(map[string]any)["domainStrategy"] != nil || directSockopt["domainStrategy"] != "UseIP" {
		t.Fatalf("client direct DNS strategy uses an obsolete location: %#v", directOutbound)
	}
	if first := dnsOutbound["rules"].([]any)[0].(map[string]any); first["action"] != "return" || first["rCode"] != float64(3) {
		t.Fatalf("adblock did not become a DNS rejection: %#v", dnsOutbound)
	}

	yaml, err := buildMihomoProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	text := string(yaml)
	for _, wanted := range []string{
		`"DOMAIN-SUFFIX,manual.example,DIRECT"`,
		`"DOMAIN-SUFFIX,ozon.ru,DIRECT"`,
		`"DOMAIN-SUFFIX,doubleclick.net,REJECT"`,
		`"AND,((IP-CIDR,192.168.3.0/24),(DST-PORT,443)),SB Gateway"`,
		`"MATCH,SB Gateway"`,
	} {
		if !strings.Contains(text, wanted) {
			t.Fatalf("Mihomo setting %q is missing:\n%s", wanted, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "geosite") {
		t.Fatalf("Mihomo client profile depends on a server-side geosite catalog:\n%s", text)
	}
	if strings.Contains(text, `"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"`) {
		t.Fatalf("remote LAN still overlaps a direct Mihomo route:\n%s", text)
	}

	singBoxBody, err := buildSingBoxProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	var singBox map[string]any
	if err := json.Unmarshal(singBoxBody, &singBox); err != nil {
		t.Fatal(err)
	}
	singOutbounds := singBox["outbounds"].([]any)
	if first := singOutbounds[0].(map[string]any); first["type"] != "selector" || first["default"] != singBoxAutoTag {
		t.Fatalf("automatic selector is not first/default: %#v", singOutbounds)
	}
	tun := singBox["inbounds"].([]any)[0].(map[string]any)
	if _, pinned := tun["interface_name"]; pinned {
		t.Fatalf("sing-box profile pins a platform-specific TUN name: %#v", tun)
	}
	if _, forced := tun["stack"]; forced {
		t.Fatalf("automatic sing-box profile overrides the core-selected TUN stack: %#v", tun)
	}
	routeJSON, _ := json.Marshal(singBox["route"])
	if !strings.Contains(string(routeJSON), "192.168.3.0/24") || !strings.Contains(string(routeJSON), "manual.example") || strings.Contains(strings.ToLower(string(routeJSON)), "geosite") {
		t.Fatalf("sing-box routing policy is incomplete: %s", routeJSON)
	}
	if strings.Contains(string(routeJSON), `"ip_cidr":["192.168.0.0/16"]`) {
		t.Fatalf("remote LAN still overlaps a direct sing-box route: %s", routeJSON)
	}
}

func TestFullClientProfilesHonorManualTUNStack(t *testing.T) {
	config := map[string]any{
		"dns": map[string]any{}, "networks": []any{}, "routeros": map[string]any{},
		"system": map[string]any{"networking": map[string]any{}}, "service_packs": []any{},
		"policies": []any{map[string]any{"id": "main", "enabled": true}},
	}
	user := map[string]any{
		"id": "phone", "policy_id": "main", "role": "internet-only",
		"client_tun_address": "172.30.0.2/30", "client_tun_stack": "gvisor",
	}
	nodes := []clientProfileNode{{name: "one", xray: map[string]any{"tag": "client-node-1", "protocol": "vless"}, mihomo: map[string]any{"name": "one", "type": "vless"}}}

	singBody, err := buildSingBoxProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	var sing map[string]any
	if err := json.Unmarshal(singBody, &sing); err != nil {
		t.Fatal(err)
	}
	if stack := sing["inbounds"].([]any)[0].(map[string]any)["stack"]; stack != "gvisor" {
		t.Fatalf("sing-box manual TUN stack = %#v", stack)
	}

	mihomo, err := buildMihomoProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mihomo), `"stack": "gvisor"`) {
		t.Fatalf("Mihomo manual TUN stack is missing:\n%s", mihomo)
	}
}

func TestIndividualClientRoutingIsSymmetricAndCanBeDisabled(t *testing.T) {
	config := map[string]any{
		"dns": map[string]any{}, "networks": []any{}, "routeros": map[string]any{},
		"system": map[string]any{"networking": map[string]any{}}, "service_packs": []any{},
		"policies": []any{map[string]any{
			"id": "main", "enabled": true, "traffic_mode": "wan_with_vless_exceptions",
			"service_routes": map[string]any{"claude": "main", "torrent": "main"}, "torrent_direct": true,
		}},
	}
	user := map[string]any{
		"id": "phone", "policy_id": "main", "role": "internet-only",
		"client_tun_address": "172.30.0.2/30", "client_individual_routing": true,
	}
	nodes := []clientProfileNode{{name: "one", xray: map[string]any{"tag": "client-node-1", "protocol": "vless"}, mihomo: map[string]any{"name": "one", "server": "203.0.113.10"}}}
	body, err := buildCombinedXrayProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(body, &profile); err != nil {
		t.Fatal(err)
	}
	rules := profile["routing"].(map[string]any)["rules"].([]any)
	claude := xrayRuleWithDomain(rules, "domain:claude.ai")
	if claude == nil || claude["outboundTag"] != "client-node-1" {
		t.Fatalf("WAN+VLESS exception did not select proxy: %#v", rules)
	}
	if strings.Contains(string(body), "bittorrent") {
		t.Fatalf("torrent_direct was emitted as a proxy exception:\n%s", body)
	}
	last := rules[len(rules)-1].(map[string]any)
	if last["outboundTag"] != "client-direct" {
		t.Fatalf("WAN+VLESS default is not direct: %#v", last)
	}
	config["policies"].([]any)[0].(map[string]any)["torrent_direct"] = false
	body, err = buildCombinedXrayProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "bittorrent") {
		t.Fatalf("disabled torrent_direct did not preserve the explicit proxy exception:\n%s", body)
	}

	user["client_individual_routing"] = false
	body, err = buildCombinedXrayProfile(config, user, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "claude.ai") || strings.Contains(string(body), "geosite:claude") {
		t.Fatalf("disabled individual routing still emitted policy rules:\n%s", body)
	}
}

func TestXrayClientDomainMatchersNormalizeAndDeduplicate(t *testing.T) {
	matchers := xrayClientDomainMatchers(clientRouteMatch{Domains: []string{
		"Example.COM", " example.com ", "*.example.com", ".api.example.com", "api.example.com",
	}})
	want := []string{"domain:api.example.com", "domain:example.com"}
	if !reflect.DeepEqual(matchers, want) {
		t.Fatalf("unexpected portable domain matchers: got %#v, want %#v", matchers, want)
	}
}

func jsonObjectSliceContains(values []any, key, expected, secondKey, secondExpected string) bool {
	for _, raw := range values {
		value, _ := raw.(map[string]any)
		if value[key] == expected && value[secondKey] == secondExpected {
			return true
		}
	}
	return false
}

func xrayRuleWithDomain(values []any, wanted string) map[string]any {
	for _, raw := range values {
		rule, _ := raw.(map[string]any)
		domains, _ := rule["domain"].([]any)
		for _, domain := range domains {
			if domain == wanted {
				return rule
			}
		}
	}
	return nil
}

func xrayRuleTargets(values []any, inbound, outbound, balancer string) bool {
	for _, raw := range values {
		rule, _ := raw.(map[string]any)
		if !reflect.DeepEqual(rule["inboundTag"], []any{inbound}) {
			continue
		}
		if (outbound == "" || rule["outboundTag"] == outbound) && (balancer == "" || rule["balancerTag"] == balancer) {
			return true
		}
	}
	return false
}

func xrayLANRuleExists(values []any, cidr, port, balancer string) bool {
	for _, raw := range values {
		rule, _ := raw.(map[string]any)
		if rule["port"] == port && rule["balancerTag"] == balancer && reflect.DeepEqual(rule["ip"], []any{cidr}) {
			return true
		}
	}
	return false
}

func configuredPublicSubscriptionServer(t *testing.T) (*Server, string) {
	t.Helper()
	server := newTestServer(t)
	_, _ = bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["public_exposure"] = map[string]any{"subscription": map[string]any{"display_name": "Home Gateway"}}
	config["ingress"].(map[string]any)["subscription_hostname"] = "subscribe.example.test"
	config["ingress"].(map[string]any)["subscription_endpoint_mode"] = "direct"
	config["remote_users"] = []any{map[string]any{
		"id": "phone", "enabled": true, "uuid_secret_ref": "remote-users/phone.uuid",
		"subscription_path_secret_ref": "remote-users/phone.subscription-path", "client_tun_address": "172.30.0.2/30",
	}}
	config["transports"] = []any{map[string]any{
		"id": "ws", "kind": "ws", "enabled": true, "hostname": "edge.example.test", "listen_port": 443,
		"tls_server_name": "edge.example.test", "path_secret_ref": "transports/ws/path",
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil || server.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate config: %v", err)
	}
	token := strings.Repeat("a", 43)
	for reference, value := range map[string]string{
		"remote-users/phone.uuid":              "2f1c08fc-3f43-4e95-8f57-f8bded750a1a",
		"remote-users/phone.subscription-path": token,
		"transports/ws/path":                   "/client",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	return server, token
}

func loginSession(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "panel-password-123",
	}, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	return response.Result().Cookies()[0], body["csrf_token"].(string)
}
