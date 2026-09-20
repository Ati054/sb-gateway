package runtimeconfig

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// WebsiteMasqueradeProxyURL is handled only by the loopback website helper.
// The configured public target never reaches Xray's generic proxy transport.
const WebsiteMasqueradeProxyURL = "http://127.0.0.1:18081/"

type XrayInboundOptions struct {
	ReverseTags      map[string]struct{}
	XHTTPExtra       map[string]any
	RealitySettings  map[string]any
	VLESSDecryption  string
	HysteriaSettings map[string]any
}

func ConvertXrayInbound(value map[string]any, options XrayInboundOptions) (map[string]any, error) {
	kind := textValue(value["type"])
	tag := textValue(value["tag"])
	listen := textValue(value["listen"])
	if listen == "" {
		listen = "0.0.0.0"
	}
	sniffing := map[string]any{
		"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true,
	}
	switch kind {
	case "tun":
		mtu, err := integerDefault(value["mtu"], 1400)
		if err != nil {
			return nil, fmt.Errorf("inbound %q mtu: %w", tag, err)
		}
		return map[string]any{
			"tag": tag, "protocol": "tun",
			"settings": map[string]any{
				"name": textDefault(value["interface_name"], "sb-tun0"), "mtu": mtu,
				"gateway": nonEmptyStrings(value["address"]),
			},
			"sniffing": sniffing,
		}, nil
	case "transparent":
		port, err := requiredInteger(value["listen_port"])
		if err != nil {
			return nil, fmt.Errorf("inbound %q listen_port: %w", tag, err)
		}
		return map[string]any{
			"tag": tag, "listen": "0.0.0.0", "port": port, "protocol": "dokodemo-door",
			"settings": map[string]any{
				"network": "tcp,udp", "followRedirect": true, "userLevel": 0,
			},
			"streamSettings": map[string]any{
				"sockopt": map[string]any{"tproxy": "tproxy"},
			},
			"sniffing": sniffing,
		}, nil
	case "mixed":
		port, err := requiredInteger(value["listen_port"])
		if err != nil {
			return nil, fmt.Errorf("inbound %q listen_port: %w", tag, err)
		}
		return map[string]any{
			"tag": tag, "listen": listen, "port": port, "protocol": "http",
			"settings": map[string]any{"allowTransparent": false}, "sniffing": sniffing,
		}, nil
	case "vless":
		port, err := requiredInteger(value["listen_port"])
		if err != nil {
			return nil, fmt.Errorf("inbound %q listen_port: %w", tag, err)
		}
		users := make([]map[string]any, 0)
		for _, raw := range objectSlice(value["users"]) {
			email := textValue(raw["name"])
			user := map[string]any{"id": textValue(raw["uuid"]), "email": email, "level": 0}
			if _, ok := options.ReverseTags[email]; ok {
				user["reverse"] = map[string]any{"tag": email}
			}
			if flow := textValue(raw["flow"]); flow != "" {
				user["flow"] = flow
			}
			users = append(users, user)
		}
		decryption := options.VLESSDecryption
		if decryption == "" {
			decryption = "none"
		}
		inbound := map[string]any{
			"tag": tag, "listen": listen, "port": port, "protocol": "vless",
			"settings": map[string]any{"users": users, "decryption": decryption}, "sniffing": sniffing,
		}
		stream, err := ConvertXrayStream(value, true, options.XHTTPExtra, options.RealitySettings)
		if err != nil {
			return nil, err
		}
		if len(stream) != 0 {
			inbound["streamSettings"] = stream
		}
		return inbound, nil
	case "hysteria2":
		port, err := requiredInteger(value["listen_port"])
		if err != nil {
			return nil, fmt.Errorf("inbound %q listen_port: %w", tag, err)
		}
		hysteria, quic, err := xrayHysteriaOptions(options.HysteriaSettings)
		if err != nil {
			return nil, err
		}
		hysteria["version"] = 2
		users := make([]map[string]any, 0)
		for _, raw := range objectSlice(value["users"]) {
			users = append(users, map[string]any{
				"auth": textValue(raw["password"]), "email": textValue(raw["name"]), "level": 0,
			})
		}
		tls := objectValue(value["tls"])
		stream := map[string]any{
			"method": "hysteria", "security": "tls", "hysteriaSettings": hysteria,
			"tlsSettings": map[string]any{"certificates": []any{map[string]any{
				"certificateFile": textValue(tls["certificate_path"]), "keyFile": textValue(tls["key_path"]),
			}}},
		}
		if obfs := objectValue(value["obfs"]); textValue(obfs["type"]) == "salamander" {
			stream["finalmask"] = salamanderMask(textValue(obfs["password"]))
		}
		if len(quic) != 0 {
			mask := objectValue(stream["finalmask"])
			if mask == nil {
				mask = make(map[string]any)
				stream["finalmask"] = mask
			}
			mask["quicParams"] = quic
		}
		return map[string]any{
			"tag": tag, "listen": listen, "port": port, "protocol": "hysteria",
			"settings":       map[string]any{"version": 2, "users": users},
			"streamSettings": stream, "sniffing": sniffing,
		}, nil
	default:
		return nil, fmt.Errorf("enabled inbound %q has unsupported type %q", tag, kind)
	}
}

func ConvertXrayStream(value map[string]any, inbound bool, xhttpExtra, realitySettings map[string]any) (map[string]any, error) {
	stream := make(map[string]any)
	transport := objectValue(value["transport"])
	switch kind := textValue(transport["type"]); kind {
	case "ws":
		settings := map[string]any{"path": textDefault(transport["path"], "/")}
		if !inbound {
			host, headers := xrayHTTPTransportHostAndHeaders(transport)
			if host != "" {
				settings["host"] = host
			}
			if len(headers) != 0 {
				settings["headers"] = headers
			}
			heartbeat, err := integerDefault(transport["heartbeat_period"], 0)
			if err != nil {
				return nil, err
			}
			settings["heartbeatPeriod"] = heartbeat
		}
		stream["method"], stream["wsSettings"] = "websocket", settings
	case "grpc":
		settings := map[string]any{"serviceName": textValue(transport["service_name"])}
		if !inbound {
			for _, field := range []string{"authority", "user_agent"} {
				if value := textValue(transport[field]); value != "" {
					settings[field] = value
				}
			}
			for _, field := range []string{"idle_timeout", "health_check_timeout", "initial_windows_size"} {
				value, err := integerDefault(transport[field], 0)
				if err != nil {
					return nil, err
				}
				if value > 0 {
					settings[field] = value
				}
			}
			if transport["multi_mode"] == true {
				settings["multiMode"] = true
			}
			if transport["permit_without_stream"] == true {
				settings["permit_without_stream"] = true
			}
		}
		stream["method"], stream["grpcSettings"] = "grpc", settings
	case "httpupgrade":
		settings := map[string]any{"path": textDefault(transport["path"], "/")}
		if !inbound {
			host, headers := xrayHTTPTransportHostAndHeaders(transport)
			if host != "" {
				settings["host"] = host
			}
			if len(headers) != 0 {
				settings["headers"] = headers
			}
		} else if host := textValue(transport["host"]); host != "" {
			settings["host"] = host
		}
		stream["method"], stream["httpupgradeSettings"] = "httpupgrade", settings
	case "xhttp":
		stream["method"] = "xhttp"
		stream["xhttpSettings"] = map[string]any{
			"mode": textDefault(transport["mode"], "auto"), "host": textValue(transport["host"]),
			"path": textDefault(transport["path"], "/"), "extra": cloneMap(xhttpExtra),
		}
	case "", "tcp":
	default:
		return nil, fmt.Errorf("Xray candidate cannot represent transport %q", kind)
	}

	if sockopt := objectValue(value["sockopt"]); len(sockopt) != 0 {
		idle, err := integerDefault(sockopt["tcp_keep_alive_idle"], 0)
		if err != nil {
			return nil, err
		}
		interval, err := integerDefault(sockopt["tcp_keep_alive_interval"], 0)
		if err != nil {
			return nil, err
		}
		userTimeout, err := integerDefault(sockopt["tcp_user_timeout"], 0)
		if err != nil {
			return nil, err
		}
		if idle > 0 || interval > 0 || userTimeout > 0 {
			stream["sockopt"] = map[string]any{
				"tcpKeepAliveIdle": idle, "tcpKeepAliveInterval": interval, "tcpUserTimeout": userTimeout,
			}
		}
		if inbound && sockopt["accept_proxy_protocol"] == true {
			settings := objectValue(stream["sockopt"])
			if settings == nil {
				settings = map[string]any{}
			}
			settings["acceptProxyProtocol"] = true
			stream["sockopt"] = settings
		}
	}
	tls := objectValue(value["tls"])
	if tls["enabled"] != true {
		return stream, nil
	}
	reality := objectValue(tls["reality"])
	if reality["enabled"] == true {
		stream["security"] = "reality"
		if inbound {
			if realitySettings != nil {
				stream["realitySettings"] = cloneMap(realitySettings)
				return stream, nil
			}
			handshake := objectValue(reality["handshake"])
			port, err := integerDefault(handshake["server_port"], 443)
			if err != nil {
				return nil, err
			}
			shortIDs := stringOrSlice(reality["short_id"])
			stream["realitySettings"] = map[string]any{
				"show": false, "target": fmt.Sprintf("%s:%d", textValue(handshake["server"]), port), "xver": 0,
				"serverNames": []string{textValue(tls["server_name"])}, "privateKey": textValue(reality["private_key"]),
				"shortIds": shortIDs,
			}
		} else {
			fingerprint := "chrome"
			if utls := objectValue(tls["utls"]); textValue(utls["fingerprint"]) != "" {
				fingerprint = textValue(utls["fingerprint"])
			}
			stream["realitySettings"] = map[string]any{
				"serverName": textValue(tls["server_name"]), "fingerprint": fingerprint,
				"password": textValue(reality["public_key"]), "shortId": textValue(reality["short_id"]),
			}
		}
		return stream, nil
	}
	stream["security"] = "tls"
	settings := map[string]any{"serverName": textValue(tls["server_name"])}
	if inbound {
		if _, exists := tls["alpn"]; exists {
			settings["alpn"] = stringSlice(tls["alpn"])
		}
		certificatePath := textValue(tls["certificate_path"])
		keyPath := textValue(tls["key_path"])
		if certificatePath != "" || keyPath != "" {
			if certificatePath == "" || keyPath == "" {
				return nil, errors.New("Xray inbound TLS requires certificate and private key paths together")
			}
			settings["certificates"] = []any{map[string]any{
				"certificateFile": certificatePath,
				"keyFile":         keyPath,
			}}
		}
	} else {
		var err error
		settings, err = xrayClientTLSSettings(tls)
		if err != nil {
			return nil, err
		}
	}
	stream["tlsSettings"] = settings
	return stream, nil
}

func xrayHTTPTransportHostAndHeaders(transport map[string]any) (string, map[string]any) {
	host := textValue(transport["host"])
	headers := clonedObject(transport["headers"])
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !strings.EqualFold(key, "host") {
			continue
		}
		if host == "" {
			host = textValue(headers[key])
		}
		delete(headers, key)
	}
	return host, headers
}

func xrayClientTLSSettings(tls map[string]any) (map[string]any, error) {
	if tls["insecure"] == true {
		return nil, errors.New("Xray outbound TLS cannot use allowInsecure; provide a trusted certificate or an explicit certificate pin")
	}
	settings := map[string]any{"serverName": textValue(tls["server_name"])}
	if pin := textValue(tls["pinned_peer_cert_sha256"]); pin != "" {
		settings["pinnedPeerCertSha256"] = pin
	}
	if verifyName := textValue(tls["verify_peer_cert_by_name"]); verifyName != "" {
		settings["verifyPeerCertByName"] = verifyName
	}
	if fingerprint := textValue(objectValue(tls["utls"])["fingerprint"]); fingerprint != "" {
		settings["fingerprint"] = fingerprint
	}
	if _, exists := tls["alpn"]; exists {
		settings["alpn"] = stringSlice(tls["alpn"])
	}
	return settings, nil
}

func xrayHysteriaOptions(settings map[string]any) (map[string]any, map[string]any, error) {
	idle, err := integerDefault(settings["udp_idle_timeout"], 60)
	if err != nil {
		return nil, nil, err
	}
	hysteria := map[string]any{"udpIdleTimeout": idle}
	masquerade := objectValue(settings["masquerade"])
	switch textValue(masquerade["type"]) {
	case "api":
		hysteria["masquerade"] = map[string]any{
			"type": "proxy", "url": WebsiteMasqueradeProxyURL,
			"rewriteHost": true, "insecure": false,
		}
	case "string":
		status, statusErr := integerDefault(masquerade["status_code"], 200)
		if statusErr != nil {
			return nil, nil, statusErr
		}
		hysteria["masquerade"] = map[string]any{
			"type": "string", "content": textValue(masquerade["content"]),
			"headers": stringMap(masquerade["headers"]), "statusCode": status,
		}
	case "proxy":
		proxy := map[string]any{
			"type": "proxy", "url": textValue(masquerade["url"]),
			"rewriteHost": masquerade["rewrite_host"] == true, "insecure": false,
		}
		if masquerade["x_forwarded"] == true {
			proxy["xForwarded"] = true
		}
		hysteria["masquerade"] = proxy
	case "website":
		hysteria["masquerade"] = map[string]any{
			"type": "proxy", "url": WebsiteMasqueradeProxyURL,
			"rewriteHost": true, "insecure": false,
		}
	}
	quic := make(map[string]any)
	rawQUIC := objectValue(settings["quic_params"])
	congestion := textValue(rawQUIC["congestion"])
	if congestion != "" {
		quic["congestion"] = congestion
	}
	if congestion == "brutal" {
		for source, target := range map[string]string{"brutal_up_mbps": "brutalUp", "brutal_down_mbps": "brutalDown"} {
			value, valueErr := integerDefault(rawQUIC[source], 0)
			if valueErr != nil {
				return nil, nil, valueErr
			}
			if value != 0 {
				quic[target] = fmt.Sprintf("%dmbps", value)
			}
		}
		if rawQUIC["brutal_disable_loss_compensation"] == true {
			quic["brutalDisableLossCompensation"] = true
		}
	}
	integerFields := []struct{ source, target string }{
		{"init_stream_receive_window", "initStreamReceiveWindow"},
		{"max_stream_receive_window", "maxStreamReceiveWindow"},
		{"init_connection_receive_window", "initConnectionReceiveWindow"},
		{"max_connection_receive_window", "maxConnectionReceiveWindow"},
		{"max_idle_timeout", "maxIdleTimeout"},
		{"keep_alive_period", "keepAlivePeriod"},
		{"max_incoming_streams", "maxIncomingStreams"},
	}
	for _, field := range integerFields {
		value, valueErr := integerDefault(rawQUIC[field.source], 0)
		if valueErr != nil {
			return nil, nil, valueErr
		}
		if value != 0 {
			quic[field.target] = value
		}
	}
	if rawQUIC["disable_path_mtu_discovery"] == true {
		quic["disablePathMTUDiscovery"] = true
	}
	if rawQUIC["disable_gso"] == true {
		quic["disableGSO"] = true
	}
	if rawQUIC["disable_stateless_reset"] == true {
		quic["disableStatelessReset"] = true
	}
	return hysteria, quic, nil
}

func salamanderMask(password string) map[string]any {
	return map[string]any{"udp": []any{map[string]any{
		"type": "salamander", "settings": map[string]any{"password": password},
	}}}
}

func objectSlice(value any) []map[string]any {
	if values, ok := value.([]map[string]any); ok {
		return append([]map[string]any(nil), values...)
	}
	raw, _ := value.([]any)
	result := make([]map[string]any, 0, len(raw))
	for _, value := range raw {
		if object := objectValue(value); object != nil {
			result = append(result, object)
		}
	}
	return result
}

func nonEmptyStrings(value any) []string {
	values := stringSlice(value)
	result := values[:0]
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func textDefault(value any, fallback string) string {
	if result := textValue(value); result != "" {
		return result
	}
	return fallback
}

func requiredInteger(value any) (int, error) {
	if value == nil {
		return 0, errors.New("is required")
	}
	return integerDefault(value, 0)
}

func clonedObject(value any) map[string]any {
	return cloneMap(objectValue(value))
}

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func stringOrSlice(value any) []string {
	if text, ok := value.(string); ok {
		return []string{text}
	}
	return stringSlice(value)
}
