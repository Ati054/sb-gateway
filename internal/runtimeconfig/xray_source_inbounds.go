package runtimeconfig

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type SecretPathResolver func(reference string) (string, error)

type XrayInboundSourceArtifacts struct {
	Inbounds []map[string]any
	Options  XrayCandidateOptions
}

var (
	ingressPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_./~-]{1,255}$`)
	grpcNamePattern    = regexp.MustCompile(`^[A-Za-z0-9_.~-]{1,128}$`)
	uuidPattern        = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type xrayHealthProbeLane struct {
	Tag  string
	Port int
}

var xrayHealthProbeLanes = []xrayHealthProbeLane{
	{"outbound-health-probe", 19082},
	{"outbound-health-background", 19083},
	{"outbound-health-background-2", 19084},
	{"outbound-health-background-3", 19085},
}

func xrayHealthProbeLanesForConfig(config map[string]any) []xrayHealthProbeLane {
	backgrounds := 3
	monitor := objectValue(objectValue(config["system"])["routing_monitor"])
	if batch, ok := numericInt(monitor["probe_batch_size"]); ok && batch > backgrounds {
		backgrounds = min(batch, 10)
	} else if len(monitor) == 0 {
		for _, policy := range objectSlice(config["policies"]) {
			if batch, ok := numericInt(policy["probe_batch_size"]); ok && batch > backgrounds {
				backgrounds = min(batch, 10)
			}
		}
	}
	lanes := append([]xrayHealthProbeLane(nil), xrayHealthProbeLanes...)
	for index := 4; index <= backgrounds; index++ {
		lanes = append(lanes, xrayHealthProbeLane{
			Tag: fmt.Sprintf("outbound-health-background-%d", index), Port: 19082 + index,
		})
	}
	return lanes
}

func BuildXrayInboundSource(config map[string]any, readSecret SecretReader, secretPath SecretPathResolver) (XrayInboundSourceArtifacts, error) {
	if readSecret == nil || secretPath == nil {
		return XrayInboundSourceArtifacts{}, errors.New("Xray inbound source requires secret and path resolvers")
	}
	transports := enabledObjects(config["transports"])
	byKind := make(map[string]map[string]any, len(transports))
	for _, transport := range transports {
		if kind := textValue(transport["kind"]); kind != "" {
			byKind[kind] = transport
		}
	}
	transportSecret := func(transport map[string]any, field string) (string, error) {
		if transport == nil {
			return "", nil
		}
		reference := textValue(transport[field])
		if reference == "" {
			return "", fmt.Errorf("enabled transport %q is missing %s", textValue(transport["id"]), field)
		}
		value, err := readSecret(reference)
		if err != nil || value == "" {
			if err == nil {
				err = errors.New("secret is empty")
			}
			return "", fmt.Errorf("transport secret %s: %w", field, err)
		}
		return value, nil
	}
	paths := map[string]string{}
	for kind, field := range map[string]string{
		"ws": "path_secret_ref", "httpupgrade": "path_secret_ref", "xhttp": "path_secret_ref", "xhttp-reality": "path_secret_ref",
	} {
		value, err := transportSecret(byKind[kind], field)
		if err != nil {
			return XrayInboundSourceArtifacts{}, err
		}
		if value != "" && !ingressPathPattern.MatchString(value) {
			return XrayInboundSourceArtifacts{}, fmt.Errorf("transport %q ingress path has invalid format", kind)
		}
		paths[kind] = value
	}
	grpcNames := map[string]string{}
	for kind := range map[string]struct{}{"grpc": {}, "reality-grpc": {}, "grpc-tls": {}} {
		value, err := transportSecret(byKind[kind], "service_name_secret_ref")
		if err != nil {
			return XrayInboundSourceArtifacts{}, err
		}
		if value != "" && !grpcNamePattern.MatchString(value) {
			return XrayInboundSourceArtifacts{}, fmt.Errorf("transport %q gRPC service name has invalid format", kind)
		}
		grpcNames[kind] = value
	}

	users := make([]map[string]any, 0)
	hysteriaUsers := make(map[string]map[string]any)
	for _, user := range enabledObjects(config["remote_users"]) {
		id := textValue(user["id"])
		reference := textValue(user["uuid_secret_ref"])
		if reference == "" {
			return XrayInboundSourceArtifacts{}, fmt.Errorf("enabled remote user %q has no UUID secret reference", id)
		}
		uuid, err := readSecret(reference)
		if err != nil || !uuidPattern.MatchString(uuid) {
			return XrayInboundSourceArtifacts{}, fmt.Errorf("remote user %q UUID secret is invalid", id)
		}
		users = append(users, map[string]any{"name": id, "uuid": strings.ToLower(uuid)})
		if hysteriaRef := textValue(user["hysteria2_password_secret_ref"]); hysteriaRef != "" {
			password, readErr := readSecret(hysteriaRef)
			if readErr != nil || password == "" {
				return XrayInboundSourceArtifacts{}, fmt.Errorf("remote user %q Hysteria 2 secret is unavailable", id)
			}
			hysteriaUsers[id] = map[string]any{"name": id, "password": password}
		}
	}
	reverseByTransport := make(map[string][]map[string]any)
	for _, reverse := range enabledObjects(config["reverse_vless_exits"]) {
		id := textValue(reverse["id"])
		reference := textValue(reverse["uuid_secret_ref"])
		if reference == "" {
			return XrayInboundSourceArtifacts{}, fmt.Errorf("enabled reverse VLESS exit %q has no UUID secret reference", id)
		}
		uuid, err := readSecret(reference)
		if err != nil || !uuidPattern.MatchString(uuid) {
			return XrayInboundSourceArtifacts{}, fmt.Errorf("reverse VLESS exit %q UUID secret is invalid", id)
		}
		for _, transportID := range stringSlice(reverse["transport_ids"]) {
			reverseByTransport[transportID] = append(reverseByTransport[transportID], map[string]any{
				"name": "reverse-vless-" + id, "uuid": strings.ToLower(uuid),
			})
		}
	}

	networking := objectValue(objectValue(config["system"])["networking"])
	remoteIPv6Mode := textDefault(networking["remote_ipv6_mode"], "proxy_only")
	if remoteIPv6Mode != "proxy_only" && remoteIPv6Mode != "disabled" {
		return XrayInboundSourceArtifacts{}, errors.New("system.networking.remote_ipv6_mode must be proxy_only or disabled")
	}
	inbounds := []map[string]any{
		{
			"type": "transparent", "tag": "tun-routeros", "listen_port": 12345,
		},
		{"type": "mixed", "tag": "subscription-update-vpn", "listen": "127.0.0.1", "listen_port": 19080},
		{"type": "mixed", "tag": "subscription-update-direct", "listen": "127.0.0.1", "listen_port": 19081},
	}
	for _, lane := range xrayHealthProbeLanesForConfig(config) {
		inbounds = append(inbounds, map[string]any{"type": "mixed", "tag": lane.Tag, "listen": "127.0.0.1", "listen_port": lane.Port})
	}
	selectedUsers := func(transportID string, vision bool) []map[string]any {
		selected := make([]map[string]any, 0, len(users)+len(reverseByTransport[transportID]))
		appendUser := func(user map[string]any) {
			copy := cloneJSONMap(user)
			if vision {
				copy["flow"] = "xtls-rprx-vision"
			}
			selected = append(selected, copy)
		}
		for _, user := range users {
			appendUser(user)
		}
		for _, user := range reverseByTransport[transportID] {
			appendUser(user)
		}
		return selected
	}
	directSockopt := func(transport map[string]any) (map[string]any, error) {
		idle, err := integerDefault(transport["tcp_keep_alive_idle"], 30)
		if err != nil {
			return nil, fmt.Errorf("transport %q tcp_keep_alive_idle: %w", textValue(transport["id"]), err)
		}
		interval, err := integerDefault(transport["tcp_keep_alive_interval"], 10)
		if err != nil {
			return nil, fmt.Errorf("transport %q tcp_keep_alive_interval: %w", textValue(transport["id"]), err)
		}
		userTimeout, err := integerDefault(transport["tcp_user_timeout"], 60000)
		if err != nil {
			return nil, fmt.Errorf("transport %q tcp_user_timeout: %w", textValue(transport["id"]), err)
		}
		if transport["tcp_keep_alive_enabled"] == false {
			// Inbound Keep-Alive defaults to off; keep its timeout independent.
			idle, interval = 0, 0
		}
		return map[string]any{
			"tcp_keep_alive_idle": idle, "tcp_keep_alive_interval": interval, "tcp_user_timeout": userTimeout,
		}, nil
	}
	if transport := byKind["ws"]; transport != nil {
		inbounds = append(inbounds, vlessSourceInbound("vless-ws", "127.0.0.1", 11001, selectedUsers(textValue(transport["id"]), false), map[string]any{"type": "ws", "path": paths["ws"]}, nil, nil))
	}
	if transport := byKind["grpc"]; transport != nil {
		inbounds = append(inbounds, vlessSourceInbound("vless-grpc", "127.0.0.1", 11002, selectedUsers(textValue(transport["id"]), false), map[string]any{"type": "grpc", "service_name": grpcNames["grpc"]}, nil, nil))
	}
	if transport := byKind["grpc-tls"]; transport != nil {
		certPath, keyPath, pathErr := transportTLSPaths(config, transport, secretPath)
		if pathErr != nil {
			return XrayInboundSourceArtifacts{}, pathErr
		}
		port, portErr := integerDefault(transport["listen_port"], 2445)
		if portErr != nil {
			return XrayInboundSourceArtifacts{}, portErr
		}
		sockopt, sockoptErr := directSockopt(transport)
		if sockoptErr != nil {
			return XrayInboundSourceArtifacts{}, sockoptErr
		}
		inbounds = append(inbounds, vlessSourceInbound(
			"vless-grpc-tls-pin", "0.0.0.0", port,
			selectedUsers(textValue(transport["id"]), false),
			map[string]any{"type": "grpc", "service_name": grpcNames["grpc-tls"]},
			map[string]any{
				"enabled": true, "server_name": textValue(transport["tls_server_name"]),
				"alpn": []any{"h2"}, "certificate_path": certPath, "key_path": keyPath,
			},
			sockopt,
		))
	}
	if transport := byKind["httpupgrade"]; transport != nil {
		inbounds = append(inbounds, vlessSourceInbound("vless-httpupgrade", "127.0.0.1", 11003, selectedUsers(textValue(transport["id"]), false), map[string]any{"type": "httpupgrade", "path": paths["httpupgrade"]}, nil, nil))
	}
	if transport := byKind["xhttp"]; transport != nil {
		inbounds = append(inbounds, vlessSourceInbound("vless-xhttp", "127.0.0.1", 11004, selectedUsers(textValue(transport["id"]), transport["vless_encryption_enabled"] == true), map[string]any{
			"type": "xhttp", "mode": textDefault(transport["mode"], "packet-up"), "host": textValue(transport["hostname"]), "path": paths["xhttp"],
			"x_padding_bytes": textDefault(transport["x_padding_bytes"], "100-1000"),
		}, nil, nil))
	}
	realityKinds := []struct {
		kind, tag string
		port      int
		transport map[string]any
	}{
		{"xhttp-reality", "vless-xhttp-reality", 2446, map[string]any{"type": "xhttp", "mode": "auto", "path": paths["xhttp-reality"]}},
		{"reality", "vless-reality", 2443, nil},
		{"reality-grpc", "vless-reality-grpc", 2444, map[string]any{"type": "grpc", "service_name": grpcNames["reality-grpc"]}},
	}
	for _, definition := range realityKinds {
		transport := byKind[definition.kind]
		if transport == nil {
			continue
		}
		port, portErr := integerDefault(transport["listen_port"], definition.port)
		if portErr != nil {
			return XrayInboundSourceArtifacts{}, portErr
		}
		transportSettings := cloneJSONMap(definition.transport)
		if definition.kind == "xhttp-reality" {
			// Xray's auto mode accepts every XHTTP mode on the server and lets a
			// REALITY client choose stream-one. Keeping the listener permissive also
			// lets existing packet-up bridge clients reconnect during migration.
			transportSettings["mode"] = textDefault(transport["mode"], "auto")
			transportSettings["x_padding_bytes"] = textDefault(transport["x_padding_bytes"], "100-1000")
		}
		tls, tlsErr := realitySourceTLS(transport, readSecret)
		if tlsErr != nil {
			return XrayInboundSourceArtifacts{}, tlsErr
		}
		vision := definition.kind == "reality" || (definition.kind == "xhttp-reality" && transport["vless_encryption_enabled"] == true)
		sockopt, sockoptErr := directSockopt(transport)
		if sockoptErr != nil {
			return XrayInboundSourceArtifacts{}, sockoptErr
		}
		listen := "0.0.0.0"
		if Shared443(config) && port == 443 {
			listen, port = "127.0.0.1", RealityBackendPort(definition.kind)
			if sockopt == nil {
				sockopt = map[string]any{}
			}
			sockopt["accept_proxy_protocol"] = true
		}
		inbounds = append(inbounds, vlessSourceInbound(definition.tag, listen, port, selectedUsers(textValue(transport["id"]), vision), transportSettings, tls, sockopt))
	}
	if transport := byKind["hysteria2"]; transport != nil {
		certPath, keyPath, pathErr := transportTLSPaths(config, transport, secretPath)
		if pathErr != nil {
			return XrayInboundSourceArtifacts{}, pathErr
		}
		port, portErr := integerDefault(transport["listen_port"], 443)
		if portErr != nil {
			return XrayInboundSourceArtifacts{}, portErr
		}
		hyUsers := make([]map[string]any, 0)
		for _, user := range users {
			if value := hysteriaUsers[textValue(user["name"])]; value != nil {
				hyUsers = append(hyUsers, cloneJSONMap(value))
			}
		}
		inbound := map[string]any{
			"type": "hysteria2", "tag": "hysteria2-direct", "listen": "0.0.0.0", "listen_port": port,
			"users": hyUsers, "tls": map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath},
		}
		if transport["obfs_enabled"] == true {
			reference := textValue(objectValue(transport["secret_refs"])["hysteria2_obfs_password"])
			password, readErr := readSecret(reference)
			if reference == "" || readErr != nil || password == "" {
				return XrayInboundSourceArtifacts{}, errors.New("Hysteria 2 obfuscation is not provisioned")
			}
			inbound["obfs"] = map[string]any{"type": "salamander", "password": password}
		}
		inbounds = append(inbounds, inbound)
	}
	options, err := xrayCandidateOptionsFromTransports(byKind, readSecret)
	if err != nil {
		return XrayInboundSourceArtifacts{}, err
	}
	return XrayInboundSourceArtifacts{Inbounds: inbounds, Options: options}, nil
}

func vlessSourceInbound(tag, listen string, port int, users []map[string]any, transport, tls, sockopt map[string]any) map[string]any {
	result := map[string]any{"type": "vless", "tag": tag, "listen": listen, "listen_port": port, "users": users}
	if len(transport) != 0 {
		result["transport"] = transport
	}
	if len(tls) != 0 {
		result["tls"] = tls
	}
	if len(sockopt) != 0 {
		result["sockopt"] = sockopt
	}
	return result
}

func realitySourceTLS(transport map[string]any, readSecret SecretReader) (map[string]any, error) {
	refs := objectValue(transport["secret_refs"])
	privateRef := textValue(refs["reality_private_key"])
	shortRef := textValue(refs["reality_short_id"])
	if privateRef == "" || shortRef == "" {
		return nil, fmt.Errorf("transport %q Reality keys are not provisioned", textValue(transport["id"]))
	}
	privateKey, privateErr := readSecret(privateRef)
	shortID, shortErr := readSecret(shortRef)
	if privateErr != nil || shortErr != nil || privateKey == "" || shortID == "" {
		return nil, fmt.Errorf("transport %q Reality keys are unavailable", textValue(transport["id"]))
	}
	host, port, err := realityHandshakeTarget(transport)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"enabled": true, "server_name": textValue(transport["server_name"]),
		"reality": map[string]any{
			"enabled": true, "handshake": map[string]any{"server": host, "server_port": port},
			"private_key": privateKey, "short_id": []string{shortID},
		},
	}, nil
}

func realityHandshakeTarget(transport map[string]any) (string, int, error) {
	if textValue(transport["cover_mode"]) == "api" {
		return "127.0.0.1", RealityCoverPort, nil
	}
	port, err := integerDefault(transport["handshake_port"], 443)
	return textValue(transport["handshake_server"]), port, err
}

func transportTLSPaths(config, transport map[string]any, secretPath SecretPathResolver) (string, string, error) {
	profileID := textValue(transport["tls_profile_id"])
	for _, profile := range enabledObjects(config["tls_profiles"]) {
		if textValue(profile["id"]) != profileID {
			continue
		}
		certRef := textValue(profile["certificate_secret_ref"])
		keyRef := textValue(profile["private_key_secret_ref"])
		if certRef == "" || keyRef == "" {
			break
		}
		certPath, err := secretPath(certRef)
		if err != nil {
			return "", "", err
		}
		keyPath, err := secretPath(keyRef)
		return certPath, keyPath, err
	}
	return "", "", fmt.Errorf("transport %q has no active TLS profile", textValue(transport["id"]))
}

func xrayCandidateOptionsFromTransports(byKind map[string]map[string]any, readSecret SecretReader) (XrayCandidateOptions, error) {
	options := XrayCandidateOptions{
		XHTTPExtraByTag: make(map[string]map[string]any), RealitySettingsByTag: make(map[string]map[string]any),
		VLESSDecryptionByTag: make(map[string]string), HysteriaSettingsByTag: make(map[string]map[string]any),
	}
	for kind, tag := range map[string]string{"xhttp": "vless-xhttp", "xhttp-reality": "vless-xhttp-reality"} {
		transport := byKind[kind]
		if transport == nil {
			continue
		}
		options.XHTTPExtraByTag[tag] = xhttpExtra(transport)
		if transport["vless_encryption_enabled"] == true {
			reference := textValue(objectValue(transport["secret_refs"])["vless_decryption"])
			value, err := readSecret(reference)
			if reference == "" || err != nil || value == "" {
				return XrayCandidateOptions{}, errors.New("VLESS Encryption decryption key is not provisioned")
			}
			options.VLESSDecryptionByTag[tag] = value
		}
	}
	for kind, tag := range map[string]string{"reality": "vless-reality", "reality-grpc": "vless-reality-grpc", "xhttp-reality": "vless-xhttp-reality"} {
		transport := byKind[kind]
		if transport == nil {
			continue
		}
		settings, err := realityRuntimeSettings(transport, readSecret)
		if err != nil {
			return XrayCandidateOptions{}, err
		}
		options.RealitySettingsByTag[tag] = settings
	}
	if hysteria := byKind["hysteria2"]; hysteria != nil {
		if settings := objectValue(hysteria["xray_hysteria"]); len(settings) != 0 {
			options.HysteriaSettingsByTag["hysteria2-direct"] = cloneJSONMap(settings)
		}
	}
	return options, nil
}

func realityRuntimeSettings(transport map[string]any, readSecret SecretReader) (map[string]any, error) {
	refs := objectValue(transport["secret_refs"])
	privateKey, err := readSecret(textValue(refs["reality_private_key"]))
	if err != nil || privateKey == "" {
		return nil, fmt.Errorf("transport %q Reality private key is unavailable", textValue(transport["id"]))
	}
	shortID, err := readSecret(textValue(refs["reality_short_id"]))
	if err != nil || shortID == "" {
		return nil, fmt.Errorf("transport %q Reality short ID is unavailable", textValue(transport["id"]))
	}
	host, port, err := realityHandshakeTarget(transport)
	if err != nil {
		return nil, err
	}
	serverNames := []string{textValue(transport["server_name"])}
	for _, value := range stringSlice(transport["server_names"]) {
		value = strings.TrimSpace(value)
		if value != "" && !containsText(serverNames, value) {
			serverNames = append(serverNames, value)
		}
	}
	settings := map[string]any{
		"show":   boolDefault(transport["reality_show"], false),
		"target": net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(port)),
		"xver":   0, "serverNames": serverNames, "privateKey": privateKey, "shortIds": []string{shortID},
	}
	if xver, valueErr := integerDefault(transport["xver"], 0); valueErr == nil {
		settings["xver"] = xver
	}
	for source, target := range map[string]string{"min_client_ver": "minClientVer", "max_client_ver": "maxClientVer", "max_time_diff": "maxTimeDiff"} {
		if value := transport[source]; value != nil && value != "" {
			settings[target] = value
		}
	}
	for direction, target := range map[string]string{"upload": "limitFallbackUpload", "download": "limitFallbackDownload"} {
		limit := make(map[string]any, 3)
		hasLimit := false
		for source, output := range map[string]string{"after_bytes": "afterBytes", "bytes_per_sec": "bytesPerSec", "burst_bytes_per_sec": "burstBytesPerSec"} {
			value, valueErr := integerDefault(transport["reality_fallback_"+direction+"_"+source], 0)
			if valueErr != nil {
				return nil, fmt.Errorf("transport %q Reality fallback %s %s: %w", textValue(transport["id"]), direction, source, valueErr)
			}
			limit[output] = value
			hasLimit = hasLimit || value != 0
		}
		if hasLimit {
			settings[target] = limit
		}
	}
	if transport["reality_mldsa65_enabled"] == true {
		reference := textValue(refs["reality_mldsa65_seed"])
		seed, readErr := readSecret(reference)
		if reference == "" || readErr != nil || seed == "" {
			return nil, errors.New("Reality ML-DSA-65 seed is not provisioned")
		}
		settings["mldsa65Seed"] = seed
	}
	return settings, nil
}

func xhttpExtra(transport map[string]any) map[string]any {
	result := make(map[string]any)
	defaultMode := "packet-up"
	if textValue(transport["kind"]) == "xhttp-reality" {
		defaultMode = "auto"
	}
	mode := strings.ToLower(strings.TrimSpace(textDefault(transport["mode"], defaultMode)))
	if headers := stringMap(transport["headers"]); len(headers) != 0 {
		normalized := make(map[string]string)
		for key, value := range headers {
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			if key != "" && value != "" {
				normalized[key] = value
			}
		}
		if len(normalized) != 0 {
			result["headers"] = normalized
		}
	}
	scalars := map[string]string{
		"x_padding_bytes": "xPaddingBytes", "x_padding_obfs_mode": "xPaddingObfsMode", "x_padding_key": "xPaddingKey",
		"x_padding_header": "xPaddingHeader", "x_padding_placement": "xPaddingPlacement", "x_padding_method": "xPaddingMethod",
		"uplink_http_method": "uplinkHTTPMethod", "session_id_placement": "sessionIDPlacement", "session_id_key": "sessionIDKey",
		"session_id_table": "sessionIDTable", "session_id_length": "sessionIDLength", "seq_placement": "seqPlacement", "seq_key": "seqKey",
		"uplink_data_placement": "uplinkDataPlacement", "uplink_data_key": "uplinkDataKey", "uplink_chunk_size": "uplinkChunkSize",
		"no_grpc_header": "noGRPCHeader", "no_sse_header": "noSSEHeader", "sc_max_each_post_bytes": "scMaxEachPostBytes",
		"sc_min_posts_interval_ms": "scMinPostsIntervalMs", "sc_max_buffered_posts": "scMaxBufferedPosts",
		"sc_stream_up_server_secs": "scStreamUpServerSecs", "server_max_header_bytes": "serverMaxHeaderBytes",
	}
	for source, target := range scalars {
		if value := transport[source]; value != nil && value != "" {
			if mode != "packet-up" && source == "uplink_data_placement" {
				placement := strings.ToLower(strings.TrimSpace(textValue(value)))
				if placement == "header" || placement == "cookie" {
					value = "auto"
				}
			}
			if mode != "packet-up" && source == "uplink_http_method" && strings.EqualFold(strings.TrimSpace(textValue(value)), "GET") {
				value = "POST"
			}
			result[target] = value
		}
	}
	xmux := make(map[string]any)
	for source, target := range map[string]string{
		"xmux_max_concurrency": "maxConcurrency", "xmux_max_connections": "maxConnections", "xmux_c_max_reuse_times": "cMaxReuseTimes",
		"xmux_h_max_request_times": "hMaxRequestTimes", "xmux_h_max_reusable_secs": "hMaxReusableSecs", "xmux_h_keep_alive_period": "hKeepAlivePeriod",
	} {
		if value := transport[source]; value != nil && value != "" {
			xmux[target] = value
		}
	}
	if len(xmux) != 0 {
		result["xmux"] = xmux
	}
	return result
}
