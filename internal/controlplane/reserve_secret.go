package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	reserveUUIDPattern    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	xhttpPaddingPattern   = regexp.MustCompile(`^([1-9][0-9]{0,5})(?:-([1-9][0-9]{0,5}))?$`)
	reserveCountryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
)

func (server *Server) prepareSubscriptionReserve(item map[string]any, entityID string, create bool, pending []pendingEntitySecret) ([]pendingEntitySecret, error) {
	rawLink, supplied := item["link"]
	delete(item, "link")
	if !supplied {
		if create {
			return nil, errors.New("VLESS link is required when creating an independent reserve")
		}
		if _, ok := item["node"].(map[string]any); !ok {
			return nil, errors.New("independent reserve has no normalized VLESS node")
		}
		return pending, nil
	}
	link, ok := rawLink.(string)
	if !ok {
		return nil, errors.New("independent reserve must be one VLESS link")
	}
	node, uuid, err := parseReserveVLESSLink(strings.TrimSpace(link), entityID)
	if err != nil {
		return nil, err
	}
	reference := "subscription-reserves/" + entityID + ".uuid"
	pending = append(pending, pendingEntitySecret{reference: reference, value: uuid, overwrite: !create})
	node["uuid_secret_ref"] = reference
	item["node"] = node
	return pending, nil
}

func parseReserveVLESSLink(link, entityID string) (map[string]any, string, error) {
	return parseVLESSLink(link, entityID, false)
}

func parseProviderVLESSLink(link, entityID string) (map[string]any, string, error) {
	return parseVLESSLink(link, entityID, true)
}

func parseVLESSLink(link, entityID string, providerLink bool) (map[string]any, string, error) {
	parsed, err := url.Parse(link)
	if err != nil || strings.ToLower(parsed.Scheme) != "vless" || parsed.User == nil {
		return nil, "", errors.New("independent reserve must be one valid VLESS link")
	}
	uuid := strings.ToLower(parsed.User.Username())
	if _, hasPassword := parsed.User.Password(); hasPassword || !reserveUUIDPattern.MatchString(uuid) {
		return nil, "", errors.New("VLESS reserve UUID is invalid")
	}
	hostname := parsed.Hostname()
	port, portErr := strconv.Atoi(parsed.Port())
	if portErr != nil || port < 1 || port > 65535 || !validReserveHost(hostname) {
		return nil, "", errors.New("VLESS reserve server or port is invalid")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, "", errors.New("VLESS reserve query is invalid")
	}
	one := func(name, fallback string) string {
		if values, exists := query[name]; exists && len(values) > 0 {
			return values[0]
		}
		return fallback
	}
	security := strings.ToLower(one("security", "none"))
	if security != "none" && security != "tls" && security != "reality" {
		return nil, "", errors.New("VLESS reserve security mode is unsupported")
	}
	insecureTLS := queryFlag(one("allowInsecure", "")) || queryFlag(one("insecure", ""))
	pinnedPeerCert, err := normalizeCertificatePins(firstNonEmpty(one("pcs", ""), one("pinnedPeerCertSha256", "")))
	if err != nil {
		return nil, "", errors.New("VLESS TLS certificate pin is invalid")
	}
	verifyPeerName, err := normalizeVerifyPeerNames(firstNonEmpty(one("vcn", ""), one("verifyPeerCertByName", "")))
	if err != nil {
		return nil, "", errors.New("VLESS TLS verification name is invalid")
	}
	if insecureTLS && (!providerLink || pinnedPeerCert == "") {
		return nil, "", errors.New("insecure TLS VLESS reserves are rejected")
	}
	transportType := strings.ToLower(one("type", "tcp"))
	if transportType != "tcp" && transportType != "ws" && transportType != "grpc" && transportType != "httpupgrade" && transportType != "xhttp" {
		return nil, "", errors.New("VLESS reserve transport is unsupported")
	}
	label := parsed.Fragment
	if label == "" {
		label = entityID
	}
	locationDigest := sha256.Sum256([]byte(strings.ToLower(hostname) + ":" + strconv.Itoa(port)))
	idDigest := sha256.Sum256([]byte(entityID))
	node := map[string]any{
		"id":      "sub-reserve-" + hex.EncodeToString(idDigest[:])[:16],
		"enabled": true, "protocol": "vless", "server": hostname, "server_port": port,
		"country": "", "city": one("city", ""), "city_source": "provider",
		"location_key": hex.EncodeToString(locationDigest[:])[:16], "label": label,
		"subscription_reserve_id": entityID, "subscription_id": "independent-reserve",
	}
	if country := strings.ToUpper(one("country", "")); reserveCountryPattern.MatchString(country) {
		node["country"] = country
	}
	if flow := one("flow", ""); flow != "" {
		node["flow"] = flow
	}
	if security == "tls" || security == "reality" {
		tlsSettings := map[string]any{"enabled": true, "server_name": one("sni", hostname)}
		if security == "tls" && pinnedPeerCert != "" {
			tlsSettings["pinned_peer_cert_sha256"] = pinnedPeerCert
		}
		if security == "tls" && verifyPeerName != "" {
			tlsSettings["verify_peer_cert_by_name"] = verifyPeerName
		}
		if fingerprint := one("fp", ""); fingerprint != "" {
			tlsSettings["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
		}
		if alpn := commaSeparatedValues(one("alpn", "")); len(alpn) != 0 {
			tlsSettings["alpn"] = alpn
		}
		if security == "reality" {
			publicKey := one("pbk", "")
			if publicKey == "" {
				return nil, "", errors.New("Reality VLESS reserve has no public key")
			}
			tlsSettings["reality"] = map[string]any{"enabled": true, "public_key": publicKey, "short_id": one("sid", "")}
		}
		node["tls"] = tlsSettings
	}
	transport, err := reserveTransport(transportType, hostname, query)
	if err != nil {
		return nil, "", err
	}
	if transport != nil {
		node["transport"] = transport
	}
	return node, uuid, nil
}

func normalizeCertificatePins(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	values := strings.Split(value, ",")
	if len(values) > 16 {
		return "", errors.New("too many certificate pins")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
		decoded, err := hex.DecodeString(normalized)
		if err != nil || len(decoded) != sha256.Size {
			return "", errors.New("invalid SHA-256 certificate pin")
		}
		result = append(result, normalized)
	}
	return strings.Join(result, ","), nil
}

func normalizeVerifyPeerNames(value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	values := strings.Split(value, ",")
	if len(values) > 16 {
		return "", errors.New("too many TLS verification names")
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		base := strings.TrimPrefix(name, "*.")
		if name == "" || (!validReserveHost(name) && (base == name || !validReserveHost(base))) {
			return "", errors.New("invalid TLS verification name")
		}
		result = append(result, name)
	}
	return strings.Join(result, ","), nil
}

func commaSeparatedValues(value string) []any {
	result := make([]any, 0, 4)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func queryFlag(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func reserveTransport(kind, hostname string, query url.Values) (map[string]any, error) {
	one := func(name, fallback string) string {
		if values, exists := query[name]; exists && len(values) > 0 {
			return values[0]
		}
		return fallback
	}
	switch kind {
	case "tcp":
		return nil, nil
	case "ws":
		result := map[string]any{"type": "ws", "path": one("path", "/")}
		if host := one("host", ""); host != "" {
			result["headers"] = map[string]any{"Host": host}
		}
		return result, nil
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": firstNonEmpty(one("serviceName", ""), one("service_name", ""))}, nil
	case "httpupgrade":
		result := map[string]any{"type": "httpupgrade", "path": one("path", "/")}
		if host := one("host", ""); host != "" {
			result["host"] = host
		}
		return result, nil
	case "xhttp":
		mode := one("mode", "auto")
		if mode != "auto" && mode != "packet-up" && mode != "stream-up" && mode != "stream-one" {
			return nil, errors.New("VLESS XHTTP reserve mode is invalid")
		}
		padding := firstNonEmpty(one("x_padding_bytes", ""), one("xPaddingBytes", ""), "100-1000")
		if rawExtra := one("extra", ""); rawExtra != "" {
			extra := map[string]any{}
			if json.Unmarshal([]byte(rawExtra), &extra) != nil {
				return nil, errors.New("VLESS XHTTP reserve extra options are invalid")
			}
			if value, exists := extra["xPaddingBytes"]; exists {
				padding = fmt.Sprint(value)
			}
		}
		match := xhttpPaddingPattern.FindStringSubmatch(padding)
		if len(match) == 0 {
			return nil, errors.New("VLESS XHTTP reserve padding range is invalid")
		}
		if match[2] != "" {
			minimum, _ := strconv.Atoi(match[1])
			maximum, _ := strconv.Atoi(match[2])
			if minimum > maximum {
				return nil, errors.New("VLESS XHTTP reserve padding range is invalid")
			}
		}
		return map[string]any{
			"type": "xhttp", "mode": mode, "path": one("path", "/"),
			"host": one("host", hostname), "x_padding_bytes": padding,
		}, nil
	default:
		return nil, errors.New("VLESS reserve transport is unsupported")
	}
}

func validReserveHost(value string) bool {
	if value == "" || strings.ContainsAny(value, "\r\n/\\") {
		return false
	}
	return net.ParseIP(value) != nil || validReverseExportHostname(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
