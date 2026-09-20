package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	singBoxProxyTag  = "SB Gateway"
	singBoxAutoTag   = "Автоматический выбор"
	singBoxDirectTag = "direct"
)

// buildSingBoxProfile renders a native sing-box document for Hiddify, Karing
// and standalone sing-box clients.  It is deliberately separate from Mihomo:
// JSON-looking Accept headers and the overlapping protocol set do not make the
// two configuration schemas interchangeable.
func buildSingBoxProfile(config, user map[string]any, nodes []clientProfileNode) ([]byte, error) {
	plan, err := buildClientProfileRoutePlan(config, user, nodes)
	if err != nil {
		return nil, err
	}
	tunIPv4 := strings.TrimSpace(text(user["client_tun_address"]))
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

	outbounds := make([]any, 0, len(nodes)+3)
	names := make([]any, 0, len(nodes)+1)
	useURLTest := boolDefault(user, "client_auto_fallback", false) && len(nodes) > 1
	if useURLTest {
		names = append(names, singBoxAutoTag)
	}
	for _, node := range nodes {
		names = append(names, node.name)
	}
	selector := map[string]any{"type": "selector", "tag": singBoxProxyTag, "outbounds": names}
	if useURLTest {
		selector["default"] = singBoxAutoTag
	}
	outbounds = append(outbounds, selector)
	if useURLTest {
		leafNames := make([]any, len(nodes))
		for index, node := range nodes {
			leafNames[index] = node.name
		}
		outbounds = append(outbounds, map[string]any{
			"type": "urltest", "tag": singBoxAutoTag, "outbounds": leafNames,
			"url": "https://www.gstatic.com/generate_204", "interval": "5m", "tolerance": 50,
		})
	}
	for _, node := range nodes {
		outbound, buildErr := singBoxClientOutbound(node)
		if buildErr != nil {
			return nil, buildErr
		}
		outbounds = append(outbounds, outbound)
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": singBoxDirectTag})

	payload := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": buildSingBoxClientDNS(plan),
		"inbounds": []any{map[string]any{
			"type": "tun", "tag": "tun-in", "address": []any{prefix.String(), tunIPv6},
			"mtu": 1400, "auto_route": true, "strict_route": true,
		}},
		"outbounds": outbounds,
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules":                 buildSingBoxClientRules(plan),
			"final":                 singBoxTarget(plan.DefaultTarget),
		},
	}
	if stack := clientTUNStack(user); stack != "auto" {
		payload["inbounds"].([]any)[0].(map[string]any)["stack"] = stack
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	return append(body, '\n'), err
}

func clientTUNStack(user map[string]any) string {
	switch strings.ToLower(strings.TrimSpace(text(user["client_tun_stack"]))) {
	case "system", "mixed", "gvisor":
		return strings.ToLower(strings.TrimSpace(text(user["client_tun_stack"])))
	default:
		return "auto"
	}
}

func singBoxClientOutbound(node clientProfileNode) (map[string]any, error) {
	protocol := strings.ToLower(text(node.xray["protocol"]))
	if protocol == "hysteria" {
		return singBoxHysteriaOutbound(node)
	}
	if protocol != "vless" {
		return nil, fmt.Errorf("unsupported sing-box client protocol %q", protocol)
	}
	settings := objectCopy(node.xray["settings"])
	stream := objectCopy(node.xray["streamSettings"])
	network := exportedStreamNetwork(stream)
	if network == "xhttp" {
		return map[string]any{
			"type": "xray", "tag": node.name, "domain_resolver": "dns-direct",
			"xray_outbound_raw": standardXrayClientOutbound(node.xray),
		}, nil
	}
	outbound := map[string]any{
		"type": "vless", "tag": node.name,
		"server": text(settings["address"]), "server_port": positiveInt(settings["port"], 443),
		"uuid": text(settings["id"]), "packet_encoding": "xudp", "domain_resolver": "dns-direct",
	}
	setMapString(outbound, "flow", text(settings["flow"]), "")
	security := strings.ToLower(text(stream["security"]))
	if security == "tls" || security == "reality" {
		tls := map[string]any{"enabled": true}
		if security == "reality" {
			reality := objectCopy(stream["realitySettings"])
			tls["server_name"] = text(reality["serverName"])
			if fingerprint := text(reality["fingerprint"]); fingerprint != "" {
				// Fingerprints are protocol values. In particular, never rewrite
				// the intentionally selected qq fingerprint.
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
			}
			tls["reality"] = map[string]any{
				"enabled": true, "public_key": text(reality["password"]), "short_id": text(reality["shortId"]),
			}
		} else {
			legacyTLS := objectCopy(stream["tlsSettings"])
			tls["server_name"] = text(legacyTLS["serverName"])
			if fingerprint := text(legacyTLS["fingerprint"]); fingerprint != "" {
				tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
			}
			if alpn := anySlice(legacyTLS["alpn"]); len(alpn) != 0 {
				tls["alpn"] = alpn
			}
			if node.certificate != "" {
				tls["certificate"] = []any{node.certificate}
			}
		}
		outbound["tls"] = tls
	}
	if transport := singBoxV2RayTransport(network, stream); len(transport) != 0 {
		outbound["transport"] = transport
	}
	return outbound, nil
}

func singBoxV2RayTransport(network string, stream map[string]any) map[string]any {
	switch network {
	case "websocket", "ws":
		settings := objectCopy(stream["wsSettings"])
		path := stringDefault(settings["path"], "/")
		transport := map[string]any{"type": "ws", "path": path}
		headers := objectCopy(settings["headers"])
		if host := text(settings["host"]); host != "" {
			headers["Host"] = host
		}
		if len(headers) != 0 {
			transport["headers"] = headers
		}
		if parsed, err := url.Parse(path); err == nil {
			if earlyData, parseErr := strconv.Atoi(parsed.Query().Get("ed")); parseErr == nil && earlyData > 0 {
				parsedQuery := parsed.Query()
				parsedQuery.Del("ed")
				parsed.RawQuery = parsedQuery.Encode()
				transport["path"] = parsed.String()
				transport["max_early_data"] = earlyData
				transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
			}
		}
		return transport
	case "grpc":
		settings := objectCopy(stream["grpcSettings"])
		transport := map[string]any{"type": "grpc", "service_name": text(settings["serviceName"])}
		if seconds := positiveInt(settings["idle_timeout"], 0); seconds > 0 {
			transport["idle_timeout"] = strconv.Itoa(seconds) + "s"
		}
		if seconds := positiveInt(settings["health_check_timeout"], 0); seconds > 0 {
			transport["ping_timeout"] = strconv.Itoa(seconds) + "s"
		}
		if settings["permit_without_stream"] == true {
			transport["permit_without_stream"] = true
		}
		return transport
	case "httpupgrade":
		settings := objectCopy(stream["httpupgradeSettings"])
		transport := map[string]any{"type": "httpupgrade", "path": stringDefault(settings["path"], "/")}
		headers := objectCopy(settings["headers"])
		if host := text(settings["host"]); host != "" {
			headers["Host"] = host
		}
		if len(headers) != 0 {
			transport["headers"] = headers
		}
		return transport
	default:
		return nil
	}
}

func singBoxHysteriaOutbound(node clientProfileNode) (map[string]any, error) {
	settings := objectCopy(node.xray["settings"])
	stream := objectCopy(node.xray["streamSettings"])
	legacyTLS := objectCopy(stream["tlsSettings"])
	hysteria := objectCopy(stream["hysteriaSettings"])
	tls := map[string]any{"enabled": true, "server_name": text(legacyTLS["serverName"])}
	if fingerprint := text(legacyTLS["fingerprint"]); fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fingerprint}
	}
	if node.certificate != "" {
		// sing-box trusts the exact selected certificate. This is equivalent to
		// the Xray DER pin without confusing it with sing-box's SPKI hash field.
		tls["certificate"] = []any{node.certificate}
	}
	outbound := map[string]any{
		"type": "hysteria2", "tag": node.name,
		"server": text(settings["address"]), "server_port": positiveInt(settings["port"], 443),
		"password": text(hysteria["auth"]), "domain_resolver": "dns-direct",
		"tls": tls,
	}
	finalMask := objectCopy(stream["finalmask"])
	udp := anySlice(finalMask["udp"])
	for _, rawEntry := range udp {
		entry := objectCopy(rawEntry)
		switch text(entry["type"]) {
		case "udphop":
			settings := objectCopy(entry["settings"])
			ports := text(settings["remotePorts"])
			parts := strings.SplitN(text(settings["interval"]), "-", 2)
			if ports != "" && len(parts) == 2 {
				serverPorts := make([]any, 0)
				for _, portRange := range strings.Split(ports, ",") {
					serverPorts = append(serverPorts, strings.ReplaceAll(portRange, "-", ":"))
				}
				outbound["server_ports"] = serverPorts
				outbound["hop_interval"] = parts[0] + "s"
				outbound["hop_interval_max"] = parts[1] + "s"
				delete(outbound, "server_port")
			}
		case "salamander":
			password := text(objectCopy(entry["settings"])["password"])
			if password != "" {
				outbound["obfs"] = map[string]any{"type": "salamander", "password": password}
			}
		}
	}
	return outbound, nil
}

func standardXrayClientOutbound(raw map[string]any) map[string]any {
	outbound := cloneJSONObject(raw)
	settings := objectCopy(outbound["settings"])
	if text(outbound["protocol"]) == "vless" && settings["vnext"] == nil {
		user := map[string]any{
			"id": text(settings["id"]), "encryption": stringDefault(settings["encryption"], "none"), "level": 0,
		}
		setMapString(user, "flow", text(settings["flow"]), "")
		outbound["settings"] = map[string]any{"vnext": []any{map[string]any{
			"address": text(settings["address"]), "port": positiveInt(settings["port"], 443), "users": []any{user},
		}}}
	}
	stream := objectCopy(outbound["streamSettings"])
	if method := text(stream["method"]); method != "" {
		stream["network"] = method
		delete(stream, "method")
	}
	return outbound
}

func buildSingBoxClientDNS(plan clientProfileRoutePlan) map[string]any {
	servers := []any{
		singBoxDNSServer("dns-direct", plan.DirectDNS, singBoxDirectTag),
		singBoxDNSServer("dns-proxy", plan.ProxyDNS, singBoxProxyTag),
	}
	rules := make([]any, 0, 1)
	if plan.InternalDNSServer != "" && len(plan.InternalZones) != 0 {
		servers = append(servers, map[string]any{
			"tag": "dns-internal", "address": "udp://" + net.JoinHostPort(plan.InternalDNSServer, "53"), "detour": singBoxProxyTag,
		})
		rules = append(rules, map[string]any{"domain_suffix": plan.InternalZones, "server": "dns-internal"})
	}
	// Service domains live only in route.rules. Duplicating the same catalog in
	// DNS rules needlessly inflates mobile profiles. Node resolution is pinned
	// to dns-direct on each outbound; only private DNS zones need a DNS rule.
	return map[string]any{
		"servers": servers, "rules": rules,
		"final": singBoxDNSTag(plan.DefaultTarget), "strategy": "prefer_ipv4",
	}
}

func singBoxDNSServer(tag, address, detour string) map[string]any {
	return map[string]any{"tag": tag, "address": address, "detour": detour}
}

func singBoxDNSTag(target string) string {
	if target == clientRouteDirect {
		return "dns-direct"
	}
	return "dns-proxy"
}

func buildSingBoxClientRules(plan clientProfileRoutePlan) []any {
	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	}
	seenDomains := make(map[string]bool)
	if domains := uniqueSingBoxRuleDomains(plan.NodeDomains, seenDomains); len(domains) != 0 {
		rules = append(rules, singBoxRouteRule(map[string]any{"domain": domains}, clientRouteDirect))
	}
	if domains := uniqueSingBoxRuleDomains(plan.AdblockDomains, seenDomains); len(domains) != 0 {
		rules = append(rules, map[string]any{"domain_suffix": domains, "action": "reject"})
	}
	if len(plan.AllowedLANCIDRs) != 0 {
		match := map[string]any{"ip_cidr": plan.AllowedLANCIDRs}
		if len(plan.AllowedLANPorts) != 0 {
			match["port"] = plan.AllowedLANPorts
		}
		rules = append(rules, singBoxRouteRule(match, clientRouteProxy))
	}
	if directPrivate := clientDirectPrivateCIDRs(plan.AllowedLANCIDRs); len(directPrivate) != 0 {
		rules = append(rules, singBoxRouteRule(map[string]any{"ip_cidr": directPrivate}, clientRouteDirect))
	}
	if plan.Individual {
		match := plan.Match
		match.Domains = uniqueSingBoxRuleDomains(match.Domains, seenDomains)
		rules = appendSingBoxClientMatchRules(rules, match, plan.ExceptionTarget)
	}
	return rules
}

func appendSingBoxClientMatchRules(rules []any, match clientRouteMatch, target string) []any {
	if len(match.Domains) != 0 {
		rules = append(rules, singBoxRouteRule(map[string]any{"domain_suffix": match.Domains}, target))
	}
	if len(match.IPCIDRs) != 0 {
		rules = append(rules, singBoxRouteRule(map[string]any{"ip_cidr": match.IPCIDRs}, target))
	}
	if len(match.Protocols) != 0 {
		rules = append(rules, singBoxRouteRule(map[string]any{"protocol": match.Protocols}, target))
	}
	for _, entry := range []struct {
		network string
		ports   []string
	}{{"tcp", match.TCPPorts}, {"udp", match.UDPPorts}} {
		network, ports := entry.network, entry.ports
		exact := make([]int, 0, len(ports))
		ranges := make([]string, 0, len(ports))
		for _, value := range ports {
			if port, err := strconv.Atoi(value); err == nil {
				exact = append(exact, port)
			} else {
				ranges = append(ranges, value)
			}
		}
		if len(exact) != 0 {
			rules = append(rules, singBoxRouteRule(map[string]any{"network": network, "port": exact}, target))
		}
		if len(ranges) != 0 {
			rules = append(rules, singBoxRouteRule(map[string]any{"network": network, "port_range": ranges}, target))
		}
	}
	return rules
}

func uniqueSingBoxRuleDomains(values []string, seen map[string]bool) []string {
	result := make([]string, 0, len(values))
	for _, value := range normalizedClientDomains(values) {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func singBoxRouteRule(match map[string]any, target string) map[string]any {
	rule := cloneJSONObject(match)
	rule["action"] = "route"
	rule["outbound"] = singBoxTarget(target)
	return rule
}

func singBoxTarget(target string) string {
	if target == clientRouteDirect {
		return singBoxDirectTag
	}
	return singBoxProxyTag
}
