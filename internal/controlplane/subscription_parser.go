package controlplane

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var subscriptionSlugPattern = regexp.MustCompile(`[^a-z0-9]+`)

type subscriptionParseError struct {
	code    string
	message string
}

func (failure *subscriptionParseError) Error() string { return failure.message }

func parseProxySubscription(body []byte, maxNodes int) ([]map[string]any, error) {
	if maxNodes < 1 {
		return nil, &subscriptionParseError{code: "invalid_limit", message: "Subscription node limit is invalid."}
	}
	text := strings.TrimSpace(string(body))
	if text == "" || !utf8.ValidString(text) {
		return nil, &subscriptionParseError{code: "invalid_content", message: "Subscription content is empty or not UTF-8."}
	}
	if !containsProxyScheme(text) {
		compact := strings.Map(func(value rune) rune {
			if value == ' ' || value == '\t' || value == '\r' || value == '\n' {
				return -1
			}
			return value
		}, text)
		decoded, err := decodeSubscriptionBase64(compact)
		if err != nil || !utf8.Valid(decoded) {
			return nil, &subscriptionParseError{code: "invalid_content", message: "Subscription is neither supported proxy links nor valid base64 text."}
		}
		text = string(decoded)
	}
	links := make([]string, 0, min(maxNodes, 64))
	for _, line := range strings.FieldsFunc(strings.ReplaceAll(text, "\r", "\n"), func(value rune) bool { return value == '\n' }) {
		link := strings.TrimSpace(line)
		lower := strings.ToLower(link)
		if strings.HasPrefix(lower, "vless://") || strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://") {
			links = append(links, link)
			if len(links) > maxNodes {
				return nil, &subscriptionParseError{code: "too_many_nodes", message: "Subscription contains too many nodes."}
			}
		}
	}
	if len(links) == 0 {
		return nil, &subscriptionParseError{code: "unsupported_nodes", message: "Subscription contains no supported VLESS or Hysteria 2 nodes."}
	}
	result := make([]map[string]any, 0, len(links))
	var firstError error
	for index, link := range links {
		var node map[string]any
		var err error
		if strings.HasPrefix(strings.ToLower(link), "vless://") {
			node, err = parseSubscriptionVLESSLink(link, index+1)
		} else {
			node, err = parseSubscriptionHysteria2Link(link, index+1)
		}
		if err != nil {
			if firstError == nil {
				firstError = err
			}
			continue
		}
		result = append(result, node)
	}
	if len(result) == 0 {
		if firstError != nil {
			return nil, firstError
		}
		return nil, &subscriptionParseError{code: "unsupported_nodes", message: "Subscription contains no valid proxy nodes."}
	}
	deduplicateSubscriptionNodeIDs(result)
	return result, nil
}

func containsProxyScheme(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "vless://") || strings.Contains(lower, "hysteria2://") || strings.Contains(lower, "hy2://")
}

func decodeSubscriptionBase64(value string) ([]byte, error) {
	encodings := []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64 subscription")
}

func parseSubscriptionVLESSLink(link string, index int) (map[string]any, error) {
	node, uuid, err := parseProviderVLESSLink(link, "node")
	if err != nil {
		return nil, &subscriptionParseError{code: "invalid_node", message: err.Error()}
	}
	delete(node, "subscription_reserve_id")
	delete(node, "subscription_id")
	node["_uuid"] = uuid
	decorateSubscriptionNode(node, link, index)
	return node, nil
}

func parseSubscriptionHysteria2Link(link string, index int) (map[string]any, error) {
	parsed, err := url.Parse(link)
	if err != nil || parsed.User == nil {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Subscription contains an invalid Hysteria 2 link."}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "hysteria2" && scheme != "hy2" {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 link has an invalid scheme."}
	}
	hostname := parsed.Hostname()
	port, portErr := strconv.Atoi(parsed.Port())
	if portErr != nil || port < 1 || port > 65535 || !validReserveHost(hostname) {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 link is missing a valid server or port."}
	}
	password := parsed.User.Username()
	if suffix, exists := parsed.User.Password(); exists {
		password += ":" + suffix
	}
	if password == "" || strings.ContainsAny(password, "\r\n") {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 link has no authentication password."}
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 query is invalid."}
	}
	one := func(name, fallback string) string {
		if values := query[name]; len(values) > 0 {
			return values[0]
		}
		return fallback
	}
	insecureTLS := queryFlag(one("insecure", "")) || queryFlag(one("allowInsecure", ""))
	pinnedPeerCert, pinErr := normalizeCertificatePins(firstNonEmpty(one("pinSHA256", ""), one("pcs", ""), one("pinnedPeerCertSha256", "")))
	if pinErr != nil {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 TLS certificate pin is invalid."}
	}
	if insecureTLS && pinnedPeerCert == "" {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 legacy insecure TLS requires a certificate pin."}
	}
	verifyPeerName, verifyErr := normalizeVerifyPeerNames(firstNonEmpty(one("vcn", ""), one("verifyPeerCertByName", "")))
	if verifyErr != nil {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 TLS verification name is invalid."}
	}
	serverName := one("sni", hostname)
	if !validReserveHost(serverName) {
		return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 TLS server name is invalid."}
	}
	label := parsed.Fragment
	if label == "" {
		label = hostname
	}
	locationDigest := sha256.Sum256([]byte(strings.ToLower(hostname) + ":" + strconv.Itoa(port)))
	node := map[string]any{
		"enabled": true, "protocol": "hysteria2", "server": hostname, "server_port": port,
		"_password": password, "tls": map[string]any{"enabled": true, "server_name": serverName},
		"country": "", "city": label, "city_source": "label", "label": label,
		"location_key": hex.EncodeToString(locationDigest[:])[:16],
	}
	if pinnedPeerCert != "" {
		node["tls"].(map[string]any)["pinned_peer_cert_sha256"] = pinnedPeerCert
	}
	if verifyPeerName != "" {
		node["tls"].(map[string]any)["verify_peer_cert_by_name"] = verifyPeerName
	}
	if fingerprint := one("fp", ""); fingerprint != "" {
		node["tls"].(map[string]any)["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if alpn := commaSeparatedValues(one("alpn", "")); len(alpn) != 0 {
		node["tls"].(map[string]any)["alpn"] = alpn
	}
	if country := strings.ToUpper(one("country", "")); reserveCountryPattern.MatchString(country) {
		node["country"] = country
	} else if inferred := countryFromLabel(label); inferred != "" {
		node["country"] = inferred
	}
	if city := cleanSubscriptionLocation(one("city", "")); city != "" {
		node["city"], node["city_source"] = city, "explicit"
	}
	for queryName, fieldName := range map[string]string{"upmbps": "up_mbps", "downmbps": "down_mbps"} {
		if raw := one(queryName, ""); raw != "" {
			value, parseErr := strconv.Atoi(raw)
			if parseErr != nil || value < 1 {
				return nil, &subscriptionParseError{code: "invalid_node", message: "Hysteria 2 bandwidth parameter is invalid."}
			}
			node[fieldName] = value
		}
	}
	if obfs := one("obfs", ""); obfs != "" {
		obfsPassword := one("obfs-password", "")
		if obfs != "salamander" || obfsPassword == "" {
			return nil, &subscriptionParseError{code: "invalid_node", message: "Only provisioned salamander Hysteria 2 obfuscation is supported."}
		}
		node["obfs"] = map[string]any{"type": "salamander"}
		node["_obfs_password"] = obfsPassword
	}
	setSubscriptionNodeID(node, index)
	return node, nil
}

func decorateSubscriptionNode(node map[string]any, link string, index int) {
	parsed, _ := url.Parse(link)
	query, _ := url.ParseQuery(parsed.RawQuery)
	label, _ := node["label"].(string)
	if parsed.Fragment == "" {
		label = parsed.Hostname()
		node["label"] = label
	}
	if country, _ := node["country"].(string); country == "" {
		node["country"] = countryFromLabel(label)
	}
	if city := cleanSubscriptionLocation(query.Get("city")); city != "" {
		node["city"], node["city_source"] = city, "explicit"
	} else if cleanSubscriptionLocation(label) != "" {
		node["city"], node["city_source"] = label, "label"
	} else {
		node["city"], node["city_source"] = "", "unknown"
	}
	setSubscriptionNodeID(node, index)
}

func setSubscriptionNodeID(node map[string]any, _ int) {
	label := fmt.Sprint(node["label"])
	slug := strings.Trim(subscriptionSlugPattern.ReplaceAllString(strings.ToLower(label), "-"), "-")
	if len(slug) > 48 {
		slug = strings.TrimRight(slug[:48], "-")
	}
	if slug == "" {
		slug = "node"
	}
	node["id"] = slug + "-" + stableSubscriptionIdentity(node)[:10]
}

// Identity follows a provider endpoint/transport, not its position in the feed.
// Credential rotation updates that connection; display labels distinguish
// multiple logical nodes sharing the same provider endpoint and transport.
func stableSubscriptionIdentity(node map[string]any) string {
	identity := cloneJSONObject(node)
	for key := range identity {
		if strings.HasPrefix(key, "_") || strings.HasSuffix(key, "_secret_ref") {
			delete(identity, key)
		}
	}
	for _, key := range []string{"id", "enabled", "subscription_id", "subscription_display_name", "selection_identity", "selection_key", "legacy_selection_key", "stable_identity", "country", "city", "city_source"} {
		delete(identity, key)
	}
	body, _ := canonicalJSON(identity)
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])[:24]
}

// Endpoint identity deliberately excludes display metadata and credentials.
// It lets a provider rename a unique endpoint or rotate its credentials without
// discarding the node ID and its accumulated runtime history.
func subscriptionEndpointIdentity(node map[string]any) string {
	identity := cloneJSONObject(node)
	for key := range identity {
		if strings.HasPrefix(key, "_") || strings.HasSuffix(key, "_secret_ref") {
			delete(identity, key)
		}
	}
	for _, key := range []string{"id", "label", "enabled", "subscription_id", "subscription_display_name", "selection_identity", "selection_key", "legacy_selection_key", "stable_identity", "credential_identity", "country", "city", "city_source"} {
		delete(identity, key)
	}
	body, _ := canonicalJSON(identity)
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// Only an unambiguous same-name, same-protocol entry from the SAME provider may
// carry an explicit selection across an endpoint change. Duplicate names do not.
func subscriptionLogicalIdentity(node map[string]any) string {
	body, _ := canonicalJSON([]string{subscriptionText(node["label"]), subscriptionNodeProtocol(node), subscriptionTransport(node)})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func countryFromLabel(label string) string {
	runes := []rune(label)
	for index := 0; index+1 < len(runes); index++ {
		if runes[index] >= 0x1F1E6 && runes[index] <= 0x1F1FF && runes[index+1] >= 0x1F1E6 && runes[index+1] <= 0x1F1FF {
			return string([]rune{'A' + runes[index] - 0x1F1E6, 'A' + runes[index+1] - 0x1F1E6})
		}
	}
	upper := strings.ToUpper(label)
	for index := 0; index+1 < len(upper); index++ {
		beforeOK := index == 0 || upper[index-1] < 'A' || upper[index-1] > 'Z'
		after := index + 2
		afterOK := after == len(upper) || upper[after] < 'A' || upper[after] > 'Z'
		if beforeOK && afterOK && upper[index] >= 'A' && upper[index] <= 'Z' && upper[index+1] >= 'A' && upper[index+1] <= 'Z' {
			return upper[index : index+2]
		}
	}
	return ""
}

func cleanSubscriptionLocation(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.IndexFunc(value, func(character rune) bool { return character < 32 }) >= 0 {
		return ""
	}
	return value
}

func deduplicateSubscriptionNodeIDs(nodes []map[string]any) {
	counts := map[string]int{}
	for _, node := range nodes {
		counts[stableSubscriptionIdentity(node)]++
	}
	for _, node := range nodes {
		if counts[stableSubscriptionIdentity(node)] > 1 {
			// Different accounts on an otherwise identical endpoint are distinct.
			// A digest distinguishes them without exposing credentials or depending
			// on feed order. Rotation of ambiguous duplicate accounts is not guessed.
			body, _ := canonicalJSON([]any{node["_uuid"], node["_password"], node["_obfs_password"]})
			digest := sha256.Sum256(body)
			node["credential_identity"] = hex.EncodeToString(digest[:])[:24]
			setSubscriptionNodeID(node, 0)
		}
	}
	used := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		base := fmt.Sprint(node["id"])
		candidate := base
		for suffix := 2; ; suffix++ {
			if _, exists := used[candidate]; !exists {
				break
			}
			candidate = base + "-" + strconv.Itoa(suffix)
		}
		node["id"] = candidate
		used[candidate] = struct{}{}
	}
}
