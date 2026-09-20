package controlplane

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const defaultClientFingerprint = "chrome"

type clientProfileNode struct {
	name         string
	link         string
	xray         map[string]any
	mihomo       map[string]any
	certificate  string
	xrayFilename string
	linkFilename string
}

type clientProfileDocument struct {
	content                []byte
	mediaType              string
	format                 string
	title                  string
	capturesRemoteNetworks bool
	happProviderID         string
	happIncludeAllNetworks bool
	happExcludeLocal       bool
	happExcludeAPNs        bool
}

var (
	errClientProfileUnsupported      = errors.New("selected settings are unsupported by this profile format")
	errSubscriptionPublicationClosed = errors.New("subscription publication is disabled")
)

func (server *Server) publicRemoteSubscription(response http.ResponseWriter, request *http.Request) {
	// One public URL can intentionally negotiate different documents by client.
	// It also includes live RouterOS routes, so an intermediary must never reuse
	// an older response or one produced for another User-Agent/Accept pair.
	response.Header().Set("Cache-Control", "private, no-store, no-cache, must-revalidate, max-age=0")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("Expires", "0")
	response.Header().Set("Vary", "User-Agent, Accept")
	response.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	token := request.PathValue("token")
	if !subscriptionTokenPattern.MatchString(token) {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	document, err := server.buildPublicProfileForRequest(
		token,
		request.URL.Query().Get("format"),
		request.Header.Get("User-Agent"),
		request.Header.Get("Accept"),
	)
	if err != nil {
		if errors.Is(err, errClientProfileUnsupported) {
			http.Error(response, errClientProfileUnsupported.Error(), http.StatusUnprocessableEntity)
			return
		}
		response.WriteHeader(http.StatusNotFound)
		return
	}
	response.Header().Set("Content-Type", document.mediaType)
	response.Header().Set("X-SB-Profile-Format", document.format)
	response.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte(document.title)))
	setHappManagedTunnelHeaders(response.Header(), request.Header.Get("User-Agent"), document)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(document.content)
}

func setHappManagedTunnelHeaders(header http.Header, userAgent string, document *clientProfileDocument) {
	if document == nil || !strings.Contains(strings.ToLower(userAgent), "happ") || document.happProviderID == "" {
		return
	}
	header.Set("providerid", document.happProviderID)
	header.Set("include-all-networks-enable", strconv.FormatBool(document.happIncludeAllNetworks))
	header.Set("exclude-local-networks-enable", strconv.FormatBool(document.happExcludeLocal))
	header.Set("exclude-apns-enable", strconv.FormatBool(document.happExcludeAPNs))
	if document.format != "array" || !document.capturesRemoteNetworks {
		return
	}
	// Happ owns the NetworkExtension tunnel around the embedded Xray core. Clear
	// stale explicit private-network exclusions so remote RFC1918 destinations
	// reach the JSON routing rules. The separate NetworkExtension local-network
	// preference is deliberately controlled per remote user above.
	header.Set("exclude-routes-set", "127.0.0.0/8, ::1/128")
	header.Set("xray-tun-enable", "true")
}

func normalizeProfileFormat(format, userAgent, accept string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	aliases := map[string]string{"base64": "links", "v2ray": "links", "clash": "mihomo", "clash-meta": "mihomo", "meta": "mihomo", "sing-box": "singbox", "json": "xray", "json-array": "array"}
	if alias := aliases[format]; alias != "" {
		format = alias
	}
	if format == "" || format == "auto" {
		userAgent = strings.ToLower(userAgent)
		accept = strings.ToLower(accept)
		switch {
		case strings.Contains(userAgent, "happ"):
			// Happ owns the mobile VPN/TUN. A generic JSON Accept header must
			// not replace its tunnel with our standalone Xray TUN configuration.
			format = "links"
		case containsAny(userAgent, "hiddify", "sing-box", "singbox", "karing"):
			format = "singbox"
		case containsAny(userAgent, "mihomo", "clash", "stash"):
			format = "mihomo"
		case strings.Contains(userAgent, "xray-core"):
			format = "xray"
		default:
			format = "links"
		}
	}
	return format
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func (server *Server) buildPublicProfile(token, format string) (*clientProfileDocument, error) {
	return server.buildPublicProfileForRequest(token, format, "", "")
}

func (server *Server) buildPublicProfileForRequest(token, requestedFormat, userAgent, accept string) (*clientProfileDocument, error) {
	active, err := server.repository.loadActive()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("active configuration is unavailable")
		}
		return nil, err
	}
	if !runtimeconfig.SubscriptionEndpointEnabled(active) {
		return nil, errSubscriptionPublicationClosed
	}
	active = server.withRouterOSLiveNetworks(active)
	user, err := server.remoteUserForSubscription(active, token)
	if err != nil {
		return nil, err
	}
	format := profileFormatForUser(user, requestedFormat, userAgent, accept)
	if format != "links" && format != "array" && format != "xray" && format != "mihomo" && format != "singbox" {
		return nil, errors.New("unsupported profile format")
	}
	nodes, err := server.buildClientProfileNodes(active, user)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, errors.New("client profile is unavailable")
	}
	title := "SB Gateway"
	happProviderID := ""
	if exposure, ok := active["public_exposure"].(map[string]any); ok {
		if subscription, ok := exposure["subscription"].(map[string]any); ok {
			title = stringDefault(subscription["display_name"], title)
			happProviderID = strings.TrimSpace(text(subscription["happ_provider_id"]))
		}
	}
	allowedLAN, _, err := clientAllowedLAN(active, user)
	if err != nil {
		return nil, err
	}
	newDocument := func(content []byte, mediaType, format string) *clientProfileDocument {
		return &clientProfileDocument{
			content: content, mediaType: mediaType, format: format, title: title,
			capturesRemoteNetworks: len(allowedLAN) != 0, happProviderID: happProviderID,
			happIncludeAllNetworks: boolDefault(user, "happ_include_all_networks", true),
			happExcludeLocal:       boolDefault(user, "happ_exclude_local_networks", true),
			happExcludeAPNs:        boolDefault(user, "happ_exclude_apns", true),
		}
	}
	switch format {
	case "links":
		links := make([]string, len(nodes))
		for index := range nodes {
			stream := objectCopy(nodes[index].xray["streamSettings"])
			for _, key := range []string{"wsSettings", "httpupgradeSettings"} {
				for header := range stringMap(objectCopy(stream[key])["headers"]) {
					if !strings.EqualFold(header, "Host") {
						return nil, errClientProfileUnsupported
					}
				}
			}
			links[index] = nodes[index].link
		}
		body := []byte(strings.Join(links, "\n") + "\n")
		return newDocument([]byte(base64.StdEncoding.EncodeToString(body)), "text/plain; charset=utf-8", format), nil
	case "xray":
		body, buildErr := buildCombinedXrayProfile(active, user, nodes)
		return newDocument(body, "application/json; charset=utf-8", format), buildErr
	case "array":
		body, buildErr := buildClientJSONProfileArray(active, user, nodes)
		return newDocument(body, "application/json; charset=utf-8", format), buildErr
	case "singbox":
		body, buildErr := buildSingBoxProfile(active, user, nodes)
		return newDocument(body, "application/json; charset=utf-8", format), buildErr
	default:
		body, buildErr := buildMihomoProfile(active, user, nodes)
		return newDocument(body, "application/yaml; charset=utf-8", format), buildErr
	}
}

func profileFormatForUser(user map[string]any, requestedFormat, userAgent, accept string) string {
	requested := strings.ToLower(strings.TrimSpace(requestedFormat))
	if requested != "" && requested != "auto" {
		return normalizeProfileFormat(requested, userAgent, accept)
	}
	preferred := strings.ToLower(strings.TrimSpace(text(user["subscription_format"])))
	if preferred != "" && preferred != "auto" {
		return normalizeProfileFormat(preferred, "", "")
	}
	detected := normalizeProfileFormat("auto", userAgent, accept)
	arrayClient := supportsManagedXrayJSONArray(userAgent)
	if detected == "links" && arrayClient && userRequiresFullProfile(user) {
		return "array"
	}
	return detected
}

func supportsManagedXrayJSONArray(userAgent string) bool {
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))
	if containsAny(userAgent, "happ", "v2box") {
		return true
	}
	if !strings.Contains(userAgent, "v2rayng") {
		return false
	}
	// v2rayNG 1.9.10 and 1.9.11 regressed subscriptions containing multiple
	// JSON configurations. Keep those exact releases on the portable URI list;
	// an administrator can still force ?format=array after upgrading the app.
	return !containsAny(userAgent, "v2rayng/1.9.10", "v2rayng/1.9.11")
}

func userRequiresFullProfile(user map[string]any) bool {
	return boolDefault(user, "client_individual_routing", false) ||
		boolDefault(user, "client_auto_fallback", false) ||
		boolDefault(user, "client_adblock", false)
}

func (server *Server) remoteUserForSubscription(config map[string]any, token string) (map[string]any, error) {
	for _, user := range objects(config["remote_users"]) {
		if !boolDefault(user, "enabled", true) || text(user["id"]) == "" {
			continue
		}
		reference := stringDefault(user["subscription_path_secret_ref"], "remote-users/"+text(user["id"])+".subscription-path")
		candidate, err := server.secrets.read(reference, false)
		if err != nil {
			continue
		}
		if subscriptionTokenPattern.MatchString(candidate) && hmac.Equal([]byte(candidate), []byte(token)) {
			return user, nil
		}
	}
	return nil, errors.New("subscription token was not found")
}

func (server *Server) buildClientProfileNodes(config, user map[string]any) ([]clientProfileNode, error) {
	uuid, err := server.secrets.read(text(user["uuid_secret_ref"]), true)
	if err != nil || !uuidValuePattern.MatchString(uuid) {
		return nil, errors.New("remote user UUID is unavailable")
	}
	excluded := map[string]bool{}
	for _, id := range stringsOf(user["excluded_transports"]) {
		excluded[id] = true
	}
	nodes := make([]clientProfileNode, 0)
	kindCounts := map[string]int{}
	for _, transport := range objects(config["transports"]) {
		if !boolDefault(transport, "enabled", true) || excluded[text(transport["id"])] {
			continue
		}
		kind := text(transport["kind"])
		transport, err = server.resolveConnectionTransport(config, transport)
		if err != nil {
			return nil, err
		}
		if kind == "hysteria2" {
			kindCounts[kind]++
			node, buildErr := server.buildHysteriaClientNode(config, user, transport, len(nodes)+1, kindCounts[kind])
			if buildErr != nil {
				return nil, buildErr
			}
			nodes = append(nodes, node)
			continue
		}
		if kind != "ws" && kind != "grpc" && kind != "grpc-tls" && kind != "httpupgrade" && kind != "xhttp" && kind != "reality" && kind != "reality-grpc" && kind != "xhttp-reality" {
			continue
		}
		for _, expanded := range reverseExportTransports(transport) {
			kindCounts[kind]++
			node, buildErr := server.buildVLESSClientNode(config, user, expanded, uuid, len(nodes)+1, kindCounts[kind])
			if buildErr != nil {
				return nil, buildErr
			}
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

func clientFingerprint(user map[string]any) string {
	return stringDefault(user["client_fingerprint"], defaultClientFingerprint)
}

func (server *Server) buildVLESSClientNode(config, user, transport map[string]any, uuid string, index, occurrence int) (clientProfileNode, error) {
	hostname, port := text(transport["hostname"]), positiveInt(transport["listen_port"], 443)
	if !validReverseExportHostname(hostname) || port < 1 || port > 65535 {
		return clientProfileNode{}, errors.New("transport public endpoint is invalid")
	}
	name := clientNodeName(text(user["id"]), text(transport["kind"]), occurrence)
	fingerprint := clientFingerprint(user)
	outbound, err := server.reverseExportOutbound(transport, strings.ToLower(uuid), "", index, fingerprint)
	if err != nil {
		return clientProfileNode{}, err
	}
	outbound["tag"] = fmt.Sprintf("client-node-%d", index)
	settings, _ := outbound["settings"].(map[string]any)
	delete(settings, "reverse")
	query := url.Values{}
	query.Set("encryption", stringDefault(settings["encryption"], "none"))
	if flow := text(settings["flow"]); flow != "" {
		query.Set("flow", flow)
	}
	stream, _ := outbound["streamSettings"].(map[string]any)
	pinnedCertificate := ""
	if kind := text(transport["kind"]); kind == "grpc" || kind == "grpc-tls" {
		stream["sockopt"] = exportTCPStabilitySockopt(transport)
	}
	security := stringDefault(stream["security"], "tls")
	query.Set("security", security)
	if security == "reality" {
		reality := objectCopy(stream["realitySettings"])
		query.Set("sni", text(reality["serverName"]))
		query.Set("fp", stringDefault(reality["fingerprint"], "chrome"))
		query.Set("pbk", text(reality["password"]))
		query.Set("sid", text(reality["shortId"]))
		setQuery(query, "spx", text(reality["spiderX"]))
		setQuery(query, "pqv", text(reality["mldsa65Verify"]))
	} else {
		tls := objectCopy(stream["tlsSettings"])
		query.Set("sni", stringDefault(tls["serverName"], hostname))
		query.Set("fp", fingerprint)
		if text(transport["kind"]) == "grpc-tls" {
			certificate, certErr := server.tlsProfileCertificate(config, transport)
			if certErr != nil {
				return clientProfileNode{}, certErr
			}
			block, _ := pem.Decode([]byte(certificate))
			if block == nil || block.Type != "CERTIFICATE" {
				return clientProfileNode{}, errors.New("gRPC TLS certificate is invalid")
			}
			if _, certErr = x509.ParseCertificate(block.Bytes); certErr != nil {
				return clientProfileNode{}, errors.New("gRPC TLS certificate is invalid")
			}
			digest := sha256.Sum256(block.Bytes)
			pin := hex.EncodeToString(digest[:])
			query.Set("pcs", colonSeparatedFingerprint(digest[:]))
			query.Set("alpn", "h2")
			tls["pinnedPeerCertSha256"] = pin
			tls["alpn"] = []any{"h2"}
			stream["tlsSettings"] = tls
			outbound["streamSettings"] = stream
			pinnedCertificate = certificate
		}
	}
	switch exportedStreamNetwork(stream) {
	case "websocket":
		ws := objectCopy(stream["wsSettings"])
		query.Set("type", "ws")
		query.Set("path", stringDefault(ws["path"], "/"))
		query.Set("host", stringDefault(ws["host"], hostname))
	case "grpc":
		grpc := objectCopy(stream["grpcSettings"])
		query.Set("type", "grpc")
		query.Set("serviceName", text(grpc["serviceName"]))
		setQuery(query, "authority", text(grpc["authority"]))
		setQuery(query, "userAgent", text(grpc["user_agent"]))
		if grpc["multiMode"] == true {
			query.Set("multiMode", "true")
		}
	case "httpupgrade":
		httpUpgrade := objectCopy(stream["httpupgradeSettings"])
		query.Set("type", "httpupgrade")
		query.Set("path", stringDefault(httpUpgrade["path"], "/"))
		query.Set("host", stringDefault(httpUpgrade["host"], hostname))
	case "xhttp":
		xhttp := objectCopy(stream["xhttpSettings"])
		query.Set("type", "xhttp")
		query.Set("mode", stringDefault(xhttp["mode"], "packet-up"))
		query.Set("path", stringDefault(xhttp["path"], "/"))
		query.Set("host", stringDefault(xhttp["host"], hostname))
		if extra := objectCopy(xhttp["extra"]); len(extra) != 0 {
			encoded, _ := json.Marshal(extra)
			query.Set("extra", string(encoded))
		}
	default:
		query.Set("type", "tcp")
	}
	link := profileURI("vless", uuid, hostname, port, query, name)
	xrayFilename, linkFilename := profileNodeFilenames(text(transport["kind"]), occurrence)
	return clientProfileNode{name: name, link: link, xray: outbound, mihomo: mihomoVLESSProxy(name, hostname, port, uuid, query), certificate: pinnedCertificate, xrayFilename: xrayFilename, linkFilename: linkFilename}, nil
}

func exportedStreamNetwork(stream map[string]any) string {
	if method := text(stream["method"]); method != "" {
		return method
	}
	return text(stream["network"])
}

func colonSeparatedFingerprint(value []byte) string {
	parts := make([]string, len(value))
	for index, item := range value {
		parts[index] = fmt.Sprintf("%02X", item)
	}
	return strings.Join(parts, ":")
}

func (server *Server) buildHysteriaClientNode(config, user, transport map[string]any, index, occurrence int) (clientProfileNode, error) {
	hostname, port := text(transport["hostname"]), positiveInt(transport["listen_port"], 443)
	if !validReverseExportHostname(hostname) || port < 1 || port > 65535 {
		return clientProfileNode{}, errors.New("Hysteria 2 public endpoint is invalid")
	}
	password, err := server.secrets.read(text(user["hysteria2_password_secret_ref"]), true)
	if err != nil || password == "" {
		return clientProfileNode{}, errors.New("Hysteria 2 password is unavailable")
	}
	name := clientNodeName(text(user["id"]), "hysteria2", occurrence)
	serverName := stringDefault(transport["tls_server_name"], hostname)
	fingerprint := clientFingerprint(user)
	query := url.Values{"sni": []string{serverName}, "fp": []string{fingerprint}}
	tlsSettings := map[string]any{"serverName": serverName, "fingerprint": fingerprint}
	pinnedCertificate := ""
	if transport["tls_pin_certificate"] == true {
		certificate, certErr := server.hysteriaCertificate(config, transport)
		if certErr != nil {
			return clientProfileNode{}, certErr
		}
		block, _ := pem.Decode([]byte(certificate))
		if block == nil || block.Type != "CERTIFICATE" {
			return clientProfileNode{}, errors.New("Hysteria 2 certificate is invalid")
		}
		if _, certErr = x509.ParseCertificate(block.Bytes); certErr != nil {
			return clientProfileNode{}, errors.New("Hysteria 2 certificate is invalid")
		}
		fingerprint := sha256.Sum256(block.Bytes)
		query.Set("pinSHA256", strings.ToUpper(hex.EncodeToString(fingerprint[:])))
		tlsSettings["pinnedPeerCertSha256"] = hex.EncodeToString(fingerprint[:])
		pinnedCertificate = certificate
	}
	hysteriaSettings := map[string]any{"version": 2, "auth": password}
	stream := map[string]any{"method": "hysteria", "security": "tls", "hysteriaSettings": hysteriaSettings, "tlsSettings": tlsSettings}
	finalMask := map[string]any{}
	if quic := clientHysteriaQUICParams(nestedObject(transport, "xray_hysteria", "quic_params")); len(quic) != 0 {
		finalMask["quicParams"] = quic
	}
	udpMasks := make([]any, 0, 2)
	udpHop, hopErr := runtimeconfig.ParseHysteriaUDPHop(transport)
	if hopErr != nil {
		return clientProfileNode{}, fmt.Errorf("Hysteria 2 UDP hopping settings are invalid: %w", hopErr)
	}
	if udpHop.Enabled {
		ports, interval := udpHop.PortList("-"), fmt.Sprintf("%d-%d", udpHop.IntervalMin, udpHop.IntervalMax)
		query.Set("mport", ports)
		udpMasks = append(udpMasks, map[string]any{"type": "udphop", "settings": map[string]any{
			"mode": "intervalRemote", "interval": interval, "remotePorts": ports,
		}})
	}
	if transport["obfs_enabled"] == true {
		obfs, obfsErr := server.transportMapSecret(transport, "hysteria2_obfs_password")
		if obfsErr != nil {
			return clientProfileNode{}, obfsErr
		}
		query.Set("obfs", "salamander")
		query.Set("obfs-password", obfs)
		udpMasks = append(udpMasks, map[string]any{"type": "salamander", "settings": map[string]any{"password": obfs}})
	}
	if len(udpMasks) != 0 {
		finalMask["udp"] = udpMasks
	}
	if len(finalMask) > 0 {
		stream["finalmask"] = finalMask
	}
	outbound := map[string]any{"tag": fmt.Sprintf("client-node-%d", index), "protocol": "hysteria", "settings": map[string]any{"version": 2, "address": hostname, "port": port}, "streamSettings": stream}
	link := profileURI("hysteria2", password, hostname, port, query, name)
	mihomo := map[string]any{"name": name, "type": "hysteria2", "server": hostname, "port": port, "password": password, "sni": serverName, "udp": true}
	if query.Get("obfs") != "" {
		mihomo["obfs"] = "salamander"
		mihomo["obfs-password"] = query.Get("obfs-password")
	}
	if query.Get("mport") != "" {
		mihomo["ports"] = query.Get("mport")
		mihomo["hop-interval"] = fmt.Sprintf("%d-%d", udpHop.IntervalMin, udpHop.IntervalMax)
	}
	if query.Get("pinSHA256") != "" {
		mihomo["fingerprint"] = strings.ToLower(query.Get("pinSHA256"))
	}
	xrayFilename, linkFilename := profileNodeFilenames("hysteria2", occurrence)
	return clientProfileNode{name: name, link: link, xray: outbound, mihomo: mihomo, certificate: pinnedCertificate, xrayFilename: xrayFilename, linkFilename: linkFilename}, nil
}

func clientHysteriaQUICParams(raw map[string]any) map[string]any {
	quic := make(map[string]any)
	congestion := strings.ToLower(strings.TrimSpace(text(raw["congestion"])))
	if congestion != "" {
		quic["congestion"] = congestion
	}
	if congestion == "brutal" {
		for source, target := range map[string]string{"brutal_up_mbps": "brutalUp", "brutal_down_mbps": "brutalDown"} {
			if value := positiveInt(raw[source], 0); value > 0 {
				quic[target] = fmt.Sprintf("%dmbps", value)
			}
		}
	}
	for _, field := range []struct{ source, target string }{
		{"init_stream_receive_window", "initStreamReceiveWindow"},
		{"max_stream_receive_window", "maxStreamReceiveWindow"},
		{"init_connection_receive_window", "initConnectionReceiveWindow"},
		{"max_connection_receive_window", "maxConnectionReceiveWindow"},
		{"max_idle_timeout", "maxIdleTimeout"},
		{"keep_alive_period", "keepAlivePeriod"},
	} {
		if value := positiveInt(raw[field.source], 0); value > 0 {
			quic[field.target] = value
		}
	}
	if raw["disable_path_mtu_discovery"] == true {
		quic["disablePathMTUDiscovery"] = true
	}
	return quic
}

func (server *Server) tlsProfileCertificate(config, transport map[string]any) (string, error) {
	profileID := text(transport["tls_profile_id"])
	for _, profile := range objects(config["tls_profiles"]) {
		if text(profile["id"]) == profileID && boolDefault(profile, "enabled", true) {
			return server.secrets.read(text(profile["certificate_secret_ref"]), true)
		}
	}
	return "", errors.New("TLS profile certificate is unavailable")
}

func (server *Server) hysteriaCertificate(config, transport map[string]any) (string, error) {
	if text(transport["tls_profile_id"]) != "" {
		return server.tlsProfileCertificate(config, transport)
	}
	return server.transportMapSecret(transport, "hysteria2_tls_certificate")
}

func buildCombinedXrayProfile(config, user map[string]any, nodes []clientProfileNode) ([]byte, error) {
	tunIPv4 := text(user["client_tun_address"])
	prefix, err := netip.ParsePrefix(tunIPv4)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return nil, errors.New("client TUN address is invalid")
	}
	digest := sha256.Sum256([]byte(prefix.String()))
	groups := make([]string, 4)
	for index := range groups {
		groups[index] = hex.EncodeToString(digest[index*2 : index*2+2])
	}
	tunIPv6 := "fd53:4247:5700:" + strings.Join(groups, ":") + ":1/126"
	plan, err := buildClientProfileRoutePlan(config, user, nodes)
	if err != nil {
		return nil, err
	}
	outbounds := make([]any, 0, len(nodes)+3)
	for _, node := range nodes {
		outbounds = append(outbounds, node.xray)
	}
	outbounds = append(outbounds,
		map[string]any{"tag": "client-dns", "protocol": "dns", "settings": buildXrayClientDNSOutbound(plan)},
		map[string]any{
			"tag": "client-direct", "protocol": "freedom", "settings": map[string]any{},
			"streamSettings": map[string]any{"sockopt": map[string]any{"domainStrategy": "UseIP"}},
		},
		map[string]any{"tag": "client-block", "protocol": "blackhole", "settings": map[string]any{}},
	)
	proxyTarget := "client-node-1"
	routing := map[string]any{"domainStrategy": plan.DomainStrategy, "domainMatcher": "hybrid"}
	useBalancer := boolDefault(user, "client_auto_fallback", false) && len(nodes) > 1
	if useBalancer {
		proxyTarget = "client-proxy"
		routing["balancers"] = []any{map[string]any{"tag": proxyTarget, "selector": []any{"client-node-"}, "fallbackTag": "client-node-1", "strategy": map[string]any{"type": "leastPing"}}}
	}
	rules := []any{map[string]any{"type": "field", "inboundTag": []any{"tun-in"}, "port": "53", "network": "tcp,udp", "outboundTag": "client-dns"}}
	rules = appendXrayClientDNSRoutes(rules, plan, proxyTarget, useBalancer)
	if len(plan.AdblockDomains) != 0 {
		rules = append(rules, map[string]any{
			"type": "field", "inboundTag": []any{"tun-in"},
			"domain": xrayClientPlainDomainMatchers(plan.AdblockDomains), "outboundTag": "client-block",
		})
	}
	if len(plan.NodeDomains) != 0 {
		rules = append(rules, map[string]any{
			"type": "field", "inboundTag": []any{"tun-in"},
			"domain": xrayClientPlainDomainMatchers(plan.NodeDomains), "outboundTag": "client-direct",
		})
	}
	if len(plan.AllowedLANCIDRs) != 0 {
		rule := map[string]any{"type": "field", "inboundTag": []any{"tun-in"}, "ip": plan.AllowedLANCIDRs}
		if len(plan.AllowedLANPorts) != 0 {
			ports := make([]string, len(plan.AllowedLANPorts))
			for index, port := range plan.AllowedLANPorts {
				ports[index] = strconv.Itoa(port)
			}
			rule["port"] = strings.Join(ports, ",")
		}
		rules = append(rules, xrayClientTarget(rule, clientRouteProxy, proxyTarget, useBalancer))
	}
	if directPrivate := clientDirectPrivateCIDRs(plan.AllowedLANCIDRs); len(directPrivate) != 0 {
		rules = append(rules, map[string]any{
			"type": "field", "inboundTag": []any{"tun-in"}, "ip": directPrivate, "outboundTag": "client-direct",
		})
	}
	if plan.Individual {
		rules = appendXrayClientMatchRules(rules, plan.Match, plan.ExceptionTarget, proxyTarget, useBalancer)
	}
	rules = append(rules, xrayClientTarget(map[string]any{
		"type": "field", "inboundTag": []any{"tun-in"}, "network": "tcp,udp",
	}, plan.DefaultTarget, proxyTarget, useBalancer))
	routing["rules"] = rules
	result := map[string]any{
		"log": map[string]any{"loglevel": "warning", "dnsLog": false},
		"dns": buildXrayClientDNS(plan),
		// Do not pin a platform-specific interface name in a portable client
		// profile. Xray selects a valid name for the OS where it actually runs.
		"inbounds":  []any{map[string]any{"tag": "tun-in", "protocol": "tun", "settings": map[string]any{"mtu": 1400, "gateway": []any{prefix.String(), tunIPv6}, "dns": []any{"198.18.0.2"}, "autoSystemRoutingTable": []any{"0.0.0.0/1", "128.0.0.0/1", "::/0"}, "autoOutboundsInterface": "auto"}, "sniffing": map[string]any{"enabled": true, "destOverride": []any{"http", "tls", "quic"}, "routeOnly": true}}},
		"outbounds": outbounds, "routing": routing,
	}
	if useBalancer {
		result["observatory"] = map[string]any{"subjectSelector": []any{"client-node-"}, "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "30s", "enableConcurrency": true}
	}
	body, err := json.MarshalIndent(result, "", "  ")
	return append(body, '\n'), err
}

func buildClientJSONProfileArray(config, user map[string]any, nodes []clientProfileNode) ([]byte, error) {
	profiles := make([]any, 0, len(nodes)+1)
	if boolDefault(user, "client_auto_fallback", false) && len(nodes) > 1 {
		body, err := buildCombinedXrayProfile(config, user, nodes)
		if err != nil {
			return nil, err
		}
		var profile map[string]any
		if err := json.Unmarshal(body, &profile); err != nil {
			return nil, err
		}
		adaptXrayProfileForManagedClient(profile)
		profile["remarks"] = fmt.Sprintf("%s · Автоматический выбор", text(user["id"]))
		profiles = append(profiles, profile)
	}
	individualUser := cloneJSONObject(user)
	individualUser["client_auto_fallback"] = false
	for _, node := range nodes {
		individualNode := node
		individualNode.xray = cloneJSONObject(node.xray)
		individualNode.xray["tag"] = "client-node-1"
		body, err := buildCombinedXrayProfile(config, individualUser, []clientProfileNode{individualNode})
		if err != nil {
			return nil, err
		}
		var profile map[string]any
		if err := json.Unmarshal(body, &profile); err != nil {
			return nil, err
		}
		adaptXrayProfileForManagedClient(profile)
		profile["remarks"] = node.name
		profiles = append(profiles, profile)
	}
	body, err := json.MarshalIndent(profiles, "", "  ")
	return append(body, '\n'), err
}

func adaptXrayProfileForManagedClient(profile map[string]any) {
	// Happ and similar applications own the system tunnel and its DNS path. Keep
	// the embedded Xray core on the same portable resolver shape used by common
	// provider profiles; domain policy belongs only to routing.rules here.
	profile["dns"] = map[string]any{
		"queryStrategy": "UseIP",
		"servers":       []any{"8.8.8.8", "1.1.1.1"},
	}
	sniffing := map[string]any{
		"enabled": true, "destOverride": []any{"http", "tls", "quic"}, "routeOnly": true,
	}
	profile["inbounds"] = []any{
		map[string]any{
			"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true}, "sniffing": cloneJSONObject(sniffing),
		},
		map[string]any{
			"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http",
			"settings": map[string]any{"allowTransparent": false}, "sniffing": cloneJSONObject(sniffing),
		},
	}
	rawOutbounds, _ := profile["outbounds"].([]any)
	outbounds := make([]any, 0, len(rawOutbounds))
	for _, rawOutbound := range rawOutbounds {
		outbound, ok := rawOutbound.(map[string]any)
		if ok && text(outbound["tag"]) == "client-dns" {
			continue
		}
		if ok {
			// Happ and other embedded-core clients still consume the established
			// Xray streamSettings.network spelling. Current Xray accepts it too;
			// the newer method spelling silently degrades to TCP in older cores.
			stream := objectCopy(outbound["streamSettings"])
			if method := text(stream["method"]); method != "" {
				stream["network"] = method
				delete(stream, "method")
			}
		}
		outbounds = append(outbounds, rawOutbound)
	}
	profile["outbounds"] = outbounds

	routing, _ := profile["routing"].(map[string]any)
	rawRules, _ := routing["rules"].([]any)
	rules := make([]any, 0, len(rawRules))
	for _, rawRule := range rawRules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			rules = append(rules, rawRule)
			continue
		}
		usesTUN, usesManagedDNS := false, false
		for _, tag := range stringsOf(rule["inboundTag"]) {
			if tag == "tun-in" {
				usesTUN = true
			}
			if strings.HasPrefix(tag, "client-dns-") {
				usesManagedDNS = true
			}
		}
		if usesManagedDNS || text(rule["outboundTag"]) == "client-dns" {
			continue
		}
		if !usesTUN {
			rules = append(rules, rule)
			continue
		}
		adapted := cloneJSONObject(rule)
		adapted["inboundTag"] = []any{"socks", "http"}
		rules = append(rules, adapted)
	}
	routing["rules"] = rules
}

func buildMihomoProfile(config, user map[string]any, nodes []clientProfileNode) ([]byte, error) {
	plan, err := buildClientProfileRoutePlan(config, user, nodes)
	if err != nil {
		return nil, err
	}
	proxies := make([]any, len(nodes))
	names := make([]any, len(nodes))
	for index, node := range nodes {
		proxy, proxyErr := mihomoClientProxy(node)
		if proxyErr != nil {
			return nil, proxyErr
		}
		proxies[index], names[index] = proxy, node.name
	}
	group := map[string]any{"name": "SB Gateway", "type": "select", "proxies": names}
	if boolDefault(user, "client_auto_fallback", false) && len(nodes) > 1 {
		group["type"] = "fallback"
		group["url"] = "https://www.gstatic.com/generate_204"
		group["interval"] = 300
		group["lazy"] = true
	}
	tunStack := clientTUNStack(user)
	if tunStack == "auto" {
		// Mihomo does not expose sing-box's build-sensitive automatic choice.
		// Its documented compatibility default for generated profiles is mixed.
		tunStack = "mixed"
	}
	payload := map[string]any{
		"mode": "rule", "mixed-port": 7890, "allow-lan": false, "ipv6": true, "unified-delay": true, "tcp-concurrent": true,
		"tun":     map[string]any{"enable": true, "stack": tunStack, "auto-route": true, "strict-route": true, "dns-hijack": []any{"any:53", "tcp://any:53"}},
		"dns":     buildMihomoClientDNS(plan),
		"proxies": proxies, "proxy-groups": []any{group}, "rules": buildMihomoClientRules(plan),
	}
	var builder strings.Builder
	writeYAML(&builder, payload, 0)
	return []byte(builder.String()), nil
}

func mihomoVLESSProxy(name, hostname string, port int, uuid string, query url.Values) map[string]any {
	proxy := map[string]any{"name": name, "type": "vless", "server": hostname, "port": port, "uuid": uuid, "udp": true, "packet-encoding": "xudp", "tls": query.Get("security") == "tls" || query.Get("security") == "reality", "servername": stringDefault(query.Get("sni"), hostname), "network": stringDefault(query.Get("type"), "tcp")}
	setMapString(proxy, "encryption", query.Get("encryption"), "none")
	setMapString(proxy, "flow", query.Get("flow"), "")
	setMapString(proxy, "client-fingerprint", query.Get("fp"), "")
	setMapString(proxy, "fingerprint", strings.ReplaceAll(strings.ToLower(query.Get("pcs")), ":", ""), "")
	if alpn := strings.TrimSpace(query.Get("alpn")); alpn != "" {
		proxy["alpn"] = strings.Split(alpn, ",")
	}
	if query.Get("security") == "reality" {
		proxy["reality-opts"] = map[string]any{"public-key": query.Get("pbk"), "short-id": query.Get("sid")}
	}
	switch query.Get("type") {
	case "ws", "httpupgrade":
		proxy["ws-opts"] = map[string]any{"path": stringDefault(query.Get("path"), "/"), "headers": map[string]any{"Host": stringDefault(query.Get("host"), hostname)}}
		if query.Get("type") == "httpupgrade" {
			proxy["network"] = "ws"
			proxy["ws-opts"].(map[string]any)["v2ray-http-upgrade"] = true
		}
	case "grpc":
		grpc := map[string]any{"grpc-service-name": query.Get("serviceName")}
		if userAgent := query.Get("userAgent"); userAgent != "" {
			grpc["grpc-user-agent"] = userAgent
		}
		proxy["grpc-opts"] = grpc
	case "xhttp":
		xhttp := map[string]any{"path": stringDefault(query.Get("path"), "/"), "host": stringDefault(query.Get("host"), hostname), "mode": stringDefault(query.Get("mode"), "packet-up")}
		if extra := query.Get("extra"); extra != "" {
			var decoded map[string]any
			if json.Unmarshal([]byte(extra), &decoded) == nil {
				fieldMap := map[string]string{
					"headers": "headers", "noGRPCHeader": "no-grpc-header",
					"xPaddingBytes": "x-padding-bytes", "xPaddingObfsMode": "x-padding-obfs-mode", "xPaddingKey": "x-padding-key",
					"xPaddingHeader": "x-padding-header", "xPaddingPlacement": "x-padding-placement", "xPaddingMethod": "x-padding-method",
					"uplinkHTTPMethod": "uplink-http-method", "sessionPlacement": "session-placement", "sessionKey": "session-key",
					"sessionTable": "session-table", "sessionLength": "session-length", "sessionIDPlacement": "session-placement",
					"sessionIDKey": "session-key", "sessionIDTable": "session-table", "sessionIDLength": "session-length",
					"seqPlacement": "seq-placement", "seqKey": "seq-key", "uplinkDataPlacement": "uplink-data-placement",
					"uplinkDataKey": "uplink-data-key", "uplinkChunkSize": "uplink-chunk-size", "scMaxEachPostBytes": "sc-max-each-post-bytes",
					"scMinPostsIntervalMs": "sc-min-posts-interval-ms",
				}
				for source, target := range fieldMap {
					if value, exists := decoded[source]; exists {
						xhttp[target] = value
					}
				}
				reuse := objectCopy(decoded["xmux"])
				if len(reuse) == 0 {
					reuse = objectCopy(decoded["reuseSettings"])
				}
				if len(reuse) != 0 {
					normalized := map[string]any{}
					for key, value := range reuse {
						normalized[camelToKebab(key)] = value
					}
					xhttp["reuse-settings"] = normalized
				}
			}
		}
		proxy["xhttp-opts"] = xhttp
	}
	return proxy
}

// Full profiles can carry headers that have no portable VLESS URI equivalent.
// Never quietly discard a separate XHTTP download connection: its stream and
// TLS inheritance differ between cores. The original Xray export remains usable.
func mihomoClientProxy(node clientProfileNode) (map[string]any, error) {
	proxy := cloneJSONObject(node.mihomo)
	stream := objectCopy(node.xray["streamSettings"])
	if len(objectCopy(objectCopy(objectCopy(stream["xhttpSettings"])["extra"])["downloadSettings"])) != 0 {
		return nil, errClientProfileUnsupported
	}
	settings := objectCopy(stream["wsSettings"])
	if exportedStreamNetwork(stream) == "httpupgrade" {
		settings = objectCopy(stream["httpupgradeSettings"])
	}
	if options, ok := proxy["ws-opts"].(map[string]any); ok {
		headers := stringMap(settings["headers"])
		headers["Host"] = stringDefault(settings["host"], text(objectCopy(options["headers"])["Host"]))
		options["headers"] = headers
	}
	return proxy, nil
}

func profileURI(scheme, credential, hostname string, port int, query url.Values, label string) string {
	return (&url.URL{Scheme: scheme, User: url.User(credential), Host: net.JoinHostPort(hostname, strconv.Itoa(port)), RawQuery: query.Encode(), Fragment: label}).String()
}

func clientNodeName(userID, kind string, occurrence int) string {
	label := map[string]string{"ws": "WebSocket", "grpc": "gRPC", "grpc-tls": "gRPC + TLS Pin", "httpupgrade": "HTTPUpgrade", "xhttp": "XHTTP", "reality": "Reality + Vision", "reality-grpc": "gRPC + Reality", "xhttp-reality": "XHTTP + Reality", "hysteria2": "Hysteria 2"}[kind]
	if label == "" {
		label = kind
	}
	if occurrence > 1 {
		return fmt.Sprintf("%s · %s · %d", userID, label, occurrence)
	}
	return fmt.Sprintf("%s · %s", userID, label)
}

func profileNodeFilenames(kind string, occurrence int) (string, string) {
	files := transportExportFiles[kind]
	if len(files) != 2 {
		return fmt.Sprintf("xray-node-%d.json", occurrence), fmt.Sprintf("share-node-%d.txt", occurrence)
	}
	if occurrence <= 1 {
		return files[0], files[1]
	}
	suffix := "-" + strconv.Itoa(occurrence)
	return strings.TrimSuffix(files[0], ".json") + suffix + ".json", strings.TrimSuffix(files[1], ".txt") + suffix + ".txt"
}

func setQuery(query url.Values, key, value string) {
	if value != "" {
		query.Set(key, value)
	}
}
func setMapString(target map[string]any, key, value, omitted string) {
	if value != "" && value != omitted {
		target[key] = value
	}
}

func camelToKebab(value string) string {
	var builder strings.Builder
	for index, char := range value {
		if index > 0 && char >= 'A' && char <= 'Z' {
			builder.WriteByte('-')
			char += 'a' - 'A'
		}
		builder.WriteRune(char)
	}
	return builder.String()
}
func objectCopy(value any) map[string]any {
	if object, ok := value.(map[string]any); ok {
		return object
	}
	return map[string]any{}
}

func writeYAML(builder *strings.Builder, value any, indent int) {
	padding := strings.Repeat(" ", indent)
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			builder.WriteString(padding)
			builder.WriteString(yamlString(key))
			builder.WriteString(":")
			if yamlComposite(typed[key]) {
				builder.WriteByte('\n')
				writeYAML(builder, typed[key], indent+2)
			} else {
				builder.WriteByte(' ')
				builder.WriteString(yamlScalar(typed[key]))
				builder.WriteByte('\n')
			}
		}
	case []any:
		for _, item := range typed {
			builder.WriteString(padding)
			builder.WriteString("-")
			if yamlComposite(item) {
				builder.WriteByte('\n')
				writeYAML(builder, item, indent+2)
			} else {
				builder.WriteByte(' ')
				builder.WriteString(yamlScalar(item))
				builder.WriteByte('\n')
			}
		}
	}
}

func yamlComposite(value any) bool {
	switch value.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}
func yamlString(value string) string { encoded, _ := json.Marshal(value); return string(encoded) }
func yamlScalar(value any) string {
	switch typed := value.(type) {
	case string:
		return yamlString(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	case nil:
		return "null"
	default:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	}
}
