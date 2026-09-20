package controlplane

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

var reverseExportHostnamePattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)

var reversePrivateReservedCIDRs = []any{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8",
}

func (server *Server) reverseVLESSClientConfig(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireSession(response, request)
	if !ok {
		return
	}
	exitID := request.PathValue("exit")
	if !entityIDPattern.MatchString(exitID) {
		server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "Enabled Reverse VLESS exit was not found.")
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	body, err := server.buildReverseVLESSClientConfig(config, exitID)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "reverse_vless_export_failed", err.Error())
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "reverse_vless_exits.client_config", "ok", map[string]any{"id": exitID})
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Content-Disposition", `attachment; filename="xray-reverse-`+exitID+`.json"`)
	response.Header().Set("X-SB-Gateway-Reverse-Xray-Version", "26.7.28")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
}

func (server *Server) buildReverseVLESSClientConfig(config map[string]any, exitID string) ([]byte, error) {
	var reverse map[string]any
	for _, raw := range collectionArray(config["reverse_vless_exits"]) {
		item, ok := raw.(map[string]any)
		if ok && item["id"] == exitID && item["enabled"] != false {
			reverse = item
			break
		}
	}
	if reverse == nil {
		return nil, errors.New("enabled Reverse VLESS exit was not found")
	}
	uuidRef, _ := reverse["uuid_secret_ref"].(string)
	uuid, err := server.secrets.read(uuidRef, true)
	if err != nil || !uuidValuePattern.MatchString(uuid) {
		return nil, errors.New("Reverse VLESS UUID is unavailable or invalid")
	}
	transportIDs := stringArray(reverse["transport_ids"])
	if len(transportIDs) == 0 {
		if legacy, _ := reverse["transport_id"].(string); legacy != "" {
			transportIDs = []string{legacy}
		}
	}
	if len(transportIDs) == 0 {
		return nil, errors.New("Reverse VLESS has no selected transport")
	}
	byID := make(map[string]map[string]any)
	for _, raw := range collectionArray(config["transports"]) {
		item, ok := raw.(map[string]any)
		id, _ := item["id"].(string)
		if ok && id != "" && item["enabled"] != false {
			byID[id] = item
		}
	}
	reverseTag := "reverse-in-" + exitID
	outbounds := make([]any, 0, len(transportIDs)+2)
	for _, transportID := range transportIDs {
		transport := byID[transportID]
		if transport == nil {
			return nil, fmt.Errorf("Reverse VLESS transport %q is unavailable", transportID)
		}
		transport, err = server.resolveConnectionTransport(config, transport)
		if err != nil {
			return nil, err
		}
		kind, _ := transport["kind"].(string)
		if !reverseTransportKinds[kind] {
			return nil, fmt.Errorf("Reverse VLESS transport %q must use Direct REALITY, gRPC + REALITY, or XHTTP + REALITY", transportID)
		}
		expanded := reverseExportTransports(transport)
		if len(expanded) == 0 {
			return nil, fmt.Errorf("Reverse VLESS transport %q has no enabled public endpoint", transportID)
		}
		for _, endpoint := range expanded {
			outbound, buildErr := server.reverseExportOutbound(endpoint, strings.ToLower(uuid), reverseTag, len(outbounds)+1, defaultClientFingerprint)
			if buildErr != nil {
				return nil, fmt.Errorf("transport %q: %w", transportID, buildErr)
			}
			outbounds = append(outbounds, outbound)
		}
	}
	outbounds = append(outbounds,
		map[string]any{
			"tag": "reverse-direct", "protocol": "freedom",
			"settings": map[string]any{
				"finalRules": []any{
					map[string]any{"action": "block", "network": "tcp,udp", "ip": reversePrivateReservedCIDRs},
					map[string]any{"action": "allow", "network": "tcp,udp"},
				},
			},
			"streamSettings": map[string]any{"sockopt": map[string]any{"domainStrategy": "AsIs"}},
		},
		map[string]any{"tag": "block", "protocol": "blackhole", "settings": map[string]any{}},
	)
	result := map[string]any{
		"log":       map[string]any{"loglevel": "warning", "dnsLog": false},
		"outbounds": outbounds,
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch", "domainMatcher": "hybrid",
			"rules": []any{map[string]any{
				"type": "field", "inboundTag": []any{reverseTag}, "network": "tcp,udp", "outboundTag": "reverse-direct",
			}},
		},
	}
	body, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func (server *Server) reverseExportOutbound(transport map[string]any, uuid, reverseTag string, index int, fingerprint string) (map[string]any, error) {
	kind, _ := transport["kind"].(string)
	hostname, _ := transport["hostname"].(string)
	if !validReverseExportHostname(hostname) {
		return nil, errors.New("public hostname is invalid")
	}
	port := positiveInt(transport["listen_port"], 443)
	if port < 1 || port > 65535 {
		return nil, errors.New("public port is invalid")
	}
	encryption := "none"
	if transport["vless_encryption_enabled"] == true {
		value, err := server.transportMapSecret(transport, "vless_encryption")
		if err != nil {
			return nil, err
		}
		encryption = value
	}
	settings := map[string]any{
		"address": hostname, "port": port, "id": uuid, "encryption": encryption,
		"reverse": map[string]any{
			"tag":      reverseTag,
			"sniffing": map[string]any{"enabled": true, "destOverride": []any{"http", "tls", "quic"}, "routeOnly": true},
		},
	}
	stream := map[string]any{}
	if sockopt := reverseExportSockopt(transport); len(sockopt) > 0 {
		stream["sockopt"] = sockopt
	}
	flow := ""
	switch kind {
	case "ws":
		path, err := server.transportSecret(transport, "path_secret_ref")
		if err != nil {
			return nil, err
		}
		host := stringDefault(transport["http_host"], hostname)
		headers := xrayHTTPHeadersWithoutHost(transport["client_http_headers"])
		stream["network"] = "websocket"
		wsSettings := map[string]any{
			"path": earlyDataPath(path, transport["early_data"]), "host": host,
			"heartbeatPeriod": positiveInt(transport["ws_heartbeat_period"], 0),
		}
		if len(headers) != 0 {
			wsSettings["headers"] = headers
		}
		stream["wsSettings"] = wsSettings
	case "grpc", "reality-grpc", "grpc-tls":
		serviceName, err := server.transportSecret(transport, "service_name_secret_ref")
		if err != nil {
			return nil, err
		}
		stream["network"] = "grpc"
		stream["grpcSettings"] = grpcExportSettings(transport, serviceName)
	case "httpupgrade":
		path, err := server.transportSecret(transport, "path_secret_ref")
		if err != nil {
			return nil, err
		}
		stream["network"] = "httpupgrade"
		httpUpgradeSettings := map[string]any{
			"path": earlyDataPath(path, transport["early_data"]),
			"host": stringDefault(transport["http_host"], hostname),
		}
		if headers := xrayHTTPHeadersWithoutHost(transport["client_http_headers"]); len(headers) != 0 {
			httpUpgradeSettings["headers"] = headers
		}
		stream["httpupgradeSettings"] = httpUpgradeSettings
	case "xhttp", "xhttp-reality":
		path, err := server.transportSecret(transport, "path_secret_ref")
		if err != nil {
			return nil, err
		}
		stream["network"] = "xhttp"
		defaultMode := "packet-up"
		if kind == "xhttp-reality" {
			defaultMode = "auto"
		}
		stream["xhttpSettings"] = map[string]any{
			"mode": stringDefault(transport["mode"], defaultMode), "host": stringDefault(transport["http_host"], hostname),
			"path": path, "extra": xhttpExportExtra(transport),
		}
		if encryption != "none" {
			flow = "xtls-rprx-vision"
		}
	case "reality":
		stream["network"] = "tcp"
		flow = "xtls-rprx-vision"
	default:
		return nil, fmt.Errorf("unsupported kind %q", kind)
	}
	if kind == "reality" || kind == "reality-grpc" || kind == "xhttp-reality" {
		shortID, err := server.transportMapSecret(transport, "reality_short_id")
		if err != nil {
			return nil, err
		}
		serverName, _ := transport["server_name"].(string)
		publicKey, keyErr := server.realityClientPublicKey(transport)
		if serverName == "" || keyErr != nil {
			return nil, errors.New("REALITY public parameters are incomplete")
		}
		reality := map[string]any{
			"serverName": serverName, "fingerprint": stringDefault(fingerprint, defaultClientFingerprint),
			"password": publicKey, "shortId": shortID,
		}
		if spider := stringDefault(transport["spider_x"], ""); spider != "" {
			reality["spiderX"] = spider
		}
		if transport["reality_mldsa65_enabled"] == true {
			verify, _ := transport["mldsa65_verify"].(string)
			if verify == "" {
				return nil, errors.New("REALITY ML-DSA-65 verifier is missing")
			}
			reality["mldsa65Verify"] = verify
		}
		stream["security"] = "reality"
		stream["realitySettings"] = reality
	} else {
		stream["security"] = "tls"
		stream["tlsSettings"] = map[string]any{
			"serverName":  stringDefault(transport["tls_server_name"], hostname),
			"fingerprint": stringDefault(fingerprint, defaultClientFingerprint),
		}
	}
	if flow != "" {
		settings["flow"] = flow
	}
	return map[string]any{
		"tag": fmt.Sprintf("sb-gateway-reverse-server-%d", index), "protocol": "vless",
		"settings": settings, "streamSettings": stream,
	}, nil
}

func xrayHTTPHeadersWithoutHost(value any) map[string]any {
	headers := stringMap(value)
	for key := range headers {
		if strings.EqualFold(key, "host") {
			delete(headers, key)
		}
	}
	return headers
}

func (server *Server) realityClientPublicKey(transport map[string]any) (string, error) {
	reference := text(objectCopy(transport["secret_refs"])["reality_private_key"])
	if reference == "" {
		// Legacy imported transports may only contain the already-derived public
		// key. Preserve their export path, while every native transport with an
		// active private-secret reference is derived below and cannot drift.
		if publicKey := text(transport["public_key"]); publicKey != "" {
			return publicKey, nil
		}
		return "", errors.New("REALITY public key is unavailable")
	}
	privateValue, err := server.secrets.read(reference, true)
	if err != nil || privateValue == "" {
		return "", errors.New("REALITY private key is unavailable")
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateValue)
	if err != nil {
		return "", errors.New("REALITY private key is invalid")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return "", errors.New("REALITY private key is invalid")
	}
	return base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), nil
}

func reverseExportSockopt(transport map[string]any) map[string]any {
	kind := stringDefault(transport["kind"], "")
	if kind != "reality" && kind != "reality-grpc" && kind != "xhttp-reality" {
		return nil
	}
	return exportTCPStabilitySockopt(transport)
}

func exportTCPStabilitySockopt(transport map[string]any) map[string]any {
	sockopt := map[string]any{
		"tcpKeepAliveIdle":     positiveInt(transport["tcp_keep_alive_idle"], 30),
		"tcpKeepAliveInterval": positiveInt(transport["tcp_keep_alive_interval"], 10),
		"tcpUserTimeout":       positiveInt(transport["tcp_user_timeout"], 60000),
	}
	if transport["tcp_keep_alive_enabled"] == false {
		// Xray enables 45-second Keep-Alive defaults for outbounds. Negative
		// values disable only Keep-Alive; TCP_USER_TIMEOUT is independent.
		sockopt["tcpKeepAliveIdle"], sockopt["tcpKeepAliveInterval"] = -1, -1
	}
	return sockopt
}

func reverseExportTransports(transport map[string]any) []map[string]any {
	kind, _ := transport["kind"].(string)
	if kind != "ws" && kind != "grpc" && kind != "httpupgrade" && kind != "xhttp" {
		return []map[string]any{cloneJSONObject(transport)}
	}
	configured, configuredOK := transport["cdn_deployments"].([]any)
	if !configuredOK || len(configured) == 0 {
		return []map[string]any{cloneJSONObject(transport)}
	}
	result := make([]map[string]any, 0, len(configured))
	for _, raw := range configured {
		deployment, ok := raw.(map[string]any)
		if !ok || deployment["enabled"] == false {
			continue
		}
		expanded := cloneJSONObject(transport)
		for _, field := range []string{"hostname", "listen_port", "tls_server_name", "http_host", "grpc_authority"} {
			if value, exists := deployment[field]; exists {
				expanded[field] = cloneJSONValue(value)
			}
		}
		result = append(result, expanded)
	}
	return result
}

func (server *Server) transportSecret(transport map[string]any, field string) (string, error) {
	reference, _ := transport[field].(string)
	if reference == "" {
		return "", fmt.Errorf("transport secret reference %s is missing", field)
	}
	value, err := server.secrets.read(reference, true)
	if err != nil {
		return "", fmt.Errorf("transport secret %s is unavailable", field)
	}
	return value, nil
}

func (server *Server) transportMapSecret(transport map[string]any, field string) (string, error) {
	refs, _ := transport["secret_refs"].(map[string]any)
	reference, _ := refs[field].(string)
	if reference == "" {
		return "", fmt.Errorf("transport secret reference %s is missing", field)
	}
	value, err := server.secrets.read(reference, true)
	if err != nil {
		return "", fmt.Errorf("transport secret %s is unavailable", field)
	}
	return value, nil
}

func grpcExportSettings(transport map[string]any, serviceName string) map[string]any {
	result := map[string]any{"serviceName": serviceName}
	for target, source := range map[string]string{"authority": "grpc_authority", "user_agent": "grpc_user_agent"} {
		if value := stringDefault(transport[source], ""); value != "" {
			result[target] = value
		}
	}
	for target, source := range map[string]string{
		"idle_timeout": "grpc_idle_timeout", "health_check_timeout": "grpc_health_check_timeout", "initial_windows_size": "grpc_initial_windows_size",
	} {
		if value := positiveInt(transport[source], 0); value > 0 {
			result[target] = value
		}
	}
	if transport["grpc_multi_mode"] == true {
		result["multiMode"] = true
	}
	if transport["grpc_permit_without_stream"] == true {
		result["permit_without_stream"] = true
	}
	return result
}

func xhttpExportExtra(transport map[string]any) map[string]any {
	result := map[string]any{}
	defaultMode := "packet-up"
	if stringDefault(transport["kind"], "") == "xhttp-reality" {
		defaultMode = "auto"
	}
	mode := strings.ToLower(strings.TrimSpace(stringDefault(transport["mode"], defaultMode)))
	if headers := stringMap(transport["headers"]); len(headers) > 0 {
		result["headers"] = headers
	}
	for source, target := range map[string]string{
		"x_padding_bytes": "xPaddingBytes", "x_padding_obfs_mode": "xPaddingObfsMode", "x_padding_key": "xPaddingKey",
		"x_padding_header": "xPaddingHeader", "x_padding_placement": "xPaddingPlacement", "x_padding_method": "xPaddingMethod",
		"uplink_http_method": "uplinkHTTPMethod", "session_id_placement": "sessionIDPlacement", "session_id_key": "sessionIDKey",
		"session_id_table": "sessionIDTable", "session_id_length": "sessionIDLength", "seq_placement": "seqPlacement", "seq_key": "seqKey",
		"uplink_data_placement": "uplinkDataPlacement", "uplink_data_key": "uplinkDataKey", "uplink_chunk_size": "uplinkChunkSize",
		"no_grpc_header": "noGRPCHeader", "no_sse_header": "noSSEHeader", "sc_max_each_post_bytes": "scMaxEachPostBytes",
		"sc_min_posts_interval_ms": "scMinPostsIntervalMs", "sc_max_buffered_posts": "scMaxBufferedPosts",
		"sc_stream_up_server_secs": "scStreamUpServerSecs", "server_max_header_bytes": "serverMaxHeaderBytes",
	} {
		if value, exists := transport[source]; exists && value != nil && value != "" {
			if mode != "packet-up" && source == "uplink_data_placement" {
				placement := strings.ToLower(strings.TrimSpace(stringDefault(value, "")))
				if placement == "header" || placement == "cookie" {
					value = "auto"
				}
			}
			if mode != "packet-up" && source == "uplink_http_method" && strings.EqualFold(strings.TrimSpace(stringDefault(value, "")), "GET") {
				value = "POST"
			}
			result[target] = cloneJSONValue(value)
		}
	}
	xmux := map[string]any{}
	for source, target := range map[string]string{
		"xmux_max_concurrency": "maxConcurrency", "xmux_max_connections": "maxConnections", "xmux_c_max_reuse_times": "cMaxReuseTimes",
		"xmux_h_max_request_times": "hMaxRequestTimes", "xmux_h_max_reusable_secs": "hMaxReusableSecs", "xmux_h_keep_alive_period": "hKeepAlivePeriod",
	} {
		if value, exists := transport[source]; exists && value != nil && value != "" {
			xmux[target] = cloneJSONValue(value)
		}
	}
	if len(xmux) > 0 {
		result["xmux"] = xmux
	}
	if download, ok := transport["download_settings"].(map[string]any); ok && len(download) > 0 {
		result["downloadSettings"] = cloneJSONObject(download)
	}
	return result
}

func validReverseExportHostname(value string) bool {
	return value != "" && len(value) <= 253 && (net.ParseIP(value) != nil || reverseExportHostnamePattern.MatchString(value))
}

func earlyDataPath(path string, raw any) string {
	value := positiveInt(raw, 0)
	if value <= 0 {
		return path
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	return fmt.Sprintf("%s%sed=%d", path, separator, value)
}

func positiveInt(value any, fallback int) int {
	integer, ok := jsonInt(value)
	if !ok {
		return fallback
	}
	return int(integer)
}

func stringMap(value any) map[string]any {
	result := map[string]any{}
	values, _ := value.(map[string]any)
	for key, raw := range values {
		text, ok := raw.(string)
		if key != "" && ok && text != "" {
			result[key] = text
		}
	}
	return result
}

func stringArray(value any) []string {
	values, _ := value.([]any)
	result := make([]string, 0, len(values))
	for _, raw := range values {
		if text, ok := raw.(string); ok && text != "" {
			result = append(result, text)
		}
	}
	return result
}

func collectionArray(value any) []any {
	values, _ := value.([]any)
	return values
}
