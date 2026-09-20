package controlplane

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

const (
	clientRouteDirect = "direct"
	clientRouteProxy  = "proxy"
)

var (
	clientCatalogOnce sync.Once
	clientCatalogBase map[string]rulesets.ServicePack
	clientCatalogErr  error
)

var conservativeClientAdblock = []string{
	"adnxs.com",
	"adsrvr.org",
	"app-measurement.com",
	"criteo.com",
	"criteo.net",
	"doubleclick.net",
	"google-analytics.com",
	"googleadservices.com",
	"googlesyndication.com",
	"scorecardresearch.com",
}

var clientPrivateCIDRs = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

type clientRouteMatch struct {
	Domains   []string
	IPCIDRs   []string
	Protocols []string
	TCPPorts  []string
	UDPPorts  []string
}

type clientProfileRoutePlan struct {
	Individual        bool
	ExceptionTarget   string
	DefaultTarget     string
	DomainStrategy    string
	Match             clientRouteMatch
	AllowedLANCIDRs   []string
	AllowedLANPorts   []int
	InternalZones     []string
	InternalDNSServer string
	AdblockDomains    []string
	NodeDomains       []string
	DirectDNS         string
	ProxyDNS          string
}

func buildClientProfileRoutePlan(config, user map[string]any, nodes []clientProfileNode) (clientProfileRoutePlan, error) {
	plan := clientProfileRoutePlan{
		DefaultTarget:  clientRouteProxy,
		DomainStrategy: "IPIfNonMatch",
		DirectDNS:      clientResolverURL(config, "direct_resolver", clientRouteDirect),
		ProxyDNS:       clientResolverURL(config, "vpn_resolver", clientRouteProxy),
		NodeDomains:    clientNodeDomains(nodes),
	}
	if boolDefault(user, "client_adblock", false) {
		plan.AdblockDomains = append([]string(nil), conservativeClientAdblock...)
	}
	allowed, ports, err := clientAllowedLAN(config, user)
	if err != nil {
		return clientProfileRoutePlan{}, err
	}
	plan.AllowedLANCIDRs, plan.AllowedLANPorts = allowed, ports
	if text(user["role"]) == "trusted-full" {
		dns := objectCopy(config["dns"])
		plan.InternalDNSServer = strings.TrimSpace(text(dns["internal_server"]))
		plan.InternalZones = normalizedClientDomains(stringsOf(dns["internal_zones"]))
		if plan.InternalDNSServer != "" {
			if address, parseErr := netip.ParseAddr(plan.InternalDNSServer); parseErr != nil || !address.IsValid() {
				return clientProfileRoutePlan{}, errors.New("internal DNS server is invalid")
			}
		}
	}
	if !boolDefault(user, "client_individual_routing", false) {
		return plan, nil
	}

	policy := enabledClientPolicy(config, text(user["policy_id"]))
	if policy == nil {
		return clientProfileRoutePlan{}, errors.New("individual client routing requires an enabled policy")
	}
	catalog, err := clientServiceCatalog(config)
	if err != nil {
		return clientProfileRoutePlan{}, err
	}
	plan.Individual = true
	if strategy := text(policy["domain_strategy"]); strategy == "AsIs" || strategy == "IPIfNonMatch" || strategy == "IPOnDemand" {
		plan.DomainStrategy = strategy
	}
	mode := text(policy["traffic_mode"])
	services := make([]string, 0)
	switch mode {
	case "vless_with_wan_exceptions":
		plan.ExceptionTarget, plan.DefaultTarget = clientRouteDirect, clientRouteProxy
		services = append(services, stringsOf(policy["direct_services"])...)
		services = append(services, stringsOf(user["direct_services"])...)
		if boolDefault(policy, "torrent_direct", true) {
			for id, pack := range catalog {
				if pack.AlwaysDirect {
					services = append(services, id)
				}
			}
		}
	case "wan_with_vless_exceptions":
		plan.ExceptionTarget, plan.DefaultTarget = clientRouteProxy, clientRouteDirect
		excludeAlwaysDirect := boolDefault(policy, "torrent_direct", true)
		services = append(services, clientProxyServiceRoutes(policy["service_routes"], catalog, excludeAlwaysDirect)...)
		services = append(services, clientProxyServiceRoutes(user["service_routes"], catalog, excludeAlwaysDirect)...)
	default:
		return clientProfileRoutePlan{}, fmt.Errorf("unsupported client traffic mode %q", mode)
	}

	match, err := buildClientRouteMatch(services, catalog)
	if err != nil {
		return clientProfileRoutePlan{}, err
	}
	match.Domains = sortedClientStrings(append(match.Domains,
		normalizedClientDomains(append(stringsOf(policy["direct_domains"]), stringsOf(user["direct_domains"])...))...,
	))
	plan.Match = match
	return plan, nil
}

func clientServiceCatalog(config map[string]any) (map[string]rulesets.ServicePack, error) {
	clientCatalogOnce.Do(func() {
		packs, err := rulesets.Catalog()
		if err != nil {
			clientCatalogErr = err
			return
		}
		clientCatalogBase = make(map[string]rulesets.ServicePack, len(packs))
		for _, pack := range packs {
			clientCatalogBase[pack.ID] = pack
		}
	})
	if clientCatalogErr != nil {
		return nil, clientCatalogErr
	}
	result := make(map[string]rulesets.ServicePack, len(clientCatalogBase))
	for id, pack := range clientCatalogBase {
		result[id] = pack
	}
	for _, item := range objects(config["service_packs"]) {
		if !boolDefault(item, "enabled", true) {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(text(item["id"])))
		upstream := strings.ToLower(strings.TrimSpace(stringDefault(item["upstream_name"], id)))
		pack, err := rulesets.CustomPack(upstream, text(item["name"]))
		if err != nil || id == "" || id != upstream {
			continue
		}
		pack.ID = id
		pack.FallbackDomains = normalizedClientDomains(stringsOf(item["fallback_domains"]))
		pack.IncludedPackIDs = normalizedClientIDs(stringsOf(item["included_pack_ids"]))
		result[id] = pack
	}
	return result, nil
}

func buildClientRouteMatch(serviceIDs []string, catalog map[string]rulesets.ServicePack) (clientRouteMatch, error) {
	match := clientRouteMatch{}
	seenPacks := make(map[string]bool)
	var visit func(string) error
	visit = func(raw string) error {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" || seenPacks[id] {
			return nil
		}
		pack, ok := catalog[id]
		if !ok {
			return fmt.Errorf("client route references unknown service %q", id)
		}
		seenPacks[id] = true
		match.Domains = append(match.Domains, normalizedClientDomains(pack.FallbackDomains)...)
		match.IPCIDRs = append(match.IPCIDRs, pack.IPCIDRs...)
		match.Protocols = append(match.Protocols, pack.SniffedProtocols...)
		for _, port := range pack.TCPPorts {
			match.TCPPorts = append(match.TCPPorts, strconv.Itoa(port))
		}
		match.TCPPorts = append(match.TCPPorts, pack.TCPPortRanges...)
		for _, port := range pack.UDPPorts {
			match.UDPPorts = append(match.UDPPorts, strconv.Itoa(port))
		}
		match.UDPPorts = append(match.UDPPorts, pack.UDPPortRanges...)
		for _, dependency := range pack.IncludedPackIDs {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		return nil
	}
	for _, id := range normalizedClientIDs(serviceIDs) {
		if err := visit(id); err != nil {
			return clientRouteMatch{}, err
		}
	}
	match.Domains = sortedClientStrings(match.Domains)
	match.IPCIDRs = sortedClientCIDRs(match.IPCIDRs)
	match.Protocols = sortedClientStrings(match.Protocols)
	match.TCPPorts = sortedClientPorts(match.TCPPorts)
	match.UDPPorts = sortedClientPorts(match.UDPPorts)
	return match, nil
}

func enabledClientPolicy(config map[string]any, id string) map[string]any {
	for _, policy := range objects(config["policies"]) {
		if text(policy["id"]) == id && boolDefault(policy, "enabled", true) {
			return policy
		}
	}
	return nil
}

func clientProxyServiceRoutes(value any, catalog map[string]rulesets.ServicePack, excludeAlwaysDirect bool) []string {
	routes, _ := value.(map[string]any)
	result := make([]string, 0, len(routes))
	for service, rawTarget := range routes {
		if pack, exists := catalog[strings.ToLower(strings.TrimSpace(service))]; excludeAlwaysDirect && exists && pack.AlwaysDirect {
			continue
		}
		target := strings.ToLower(strings.TrimSpace(fmt.Sprint(rawTarget)))
		if target != "" && target != "direct" && target != "direct-wan" && target != "block" {
			result = append(result, service)
		}
	}
	return result
}

func clientAllowedLAN(config, user map[string]any) ([]string, []int, error) {
	role := text(user["role"])
	values := make([]string, 0)
	switch role {
	case "trusted-full":
		if live, available := config["routeros_live_networks"]; available {
			values = append(values, stringsOf(live)...)
		} else {
			for _, network := range objects(config["networks"]) {
				kind := stringDefault(network["kind"], "internal")
				if boolDefault(network, "enabled", true) && (kind == "internal" || kind == "management") {
					values = append(values, stringsOf(network["cidrs"])...)
				}
			}
		}
	case "trusted-limited":
		values = append(values, stringsOf(user["allowed_cidrs"])...)
		wanted := make(map[string]bool)
		for _, id := range stringsOf(user["allowed_network_ids"]) {
			wanted[id] = true
		}
		for _, network := range objects(config["networks"]) {
			if wanted[text(network["id"])] && boolDefault(network, "enabled", true) {
				values = append(values, stringsOf(network["cidrs"])...)
			}
		}
	}
	cidrs := sortedClientCIDRs(values)
	ports := make([]int, 0)
	if role == "trusted-limited" {
		for _, raw := range anySlice(user["allowed_ports"]) {
			port, ok := jsonInteger(raw)
			if !ok || port < 1 || port > 65535 {
				return nil, nil, errors.New("client LAN port is invalid")
			}
			ports = append(ports, port)
		}
		sort.Ints(ports)
		ports = uniqueClientInts(ports)
	}
	return cidrs, ports, nil
}

func clientResolverURL(config map[string]any, field, target string) string {
	dns := objectCopy(config["dns"])
	resolver := objectCopy(dns[field])
	provider := strings.ToLower(stringDefault(resolver["provider"], map[string]string{clientRouteDirect: "yandex", clientRouteProxy: "cloudflare"}[target]))
	protocol := strings.ToLower(stringDefault(resolver["protocol"], "doh"))
	ip := map[string]string{
		"cloudflare": "1.1.1.1", "google": "8.8.8.8", "quad9": "9.9.9.9", "yandex": "77.88.8.8",
	}[provider]
	if ip == "" {
		ip = "1.1.1.1"
	}
	if protocol == "dot" {
		return "tls://" + ip + ":853"
	}
	return "https://" + ip + "/dns-query"
}

func clientNodeDomains(nodes []clientProfileNode) []string {
	result := make([]string, 0, len(nodes))
	for _, node := range nodes {
		host := strings.ToLower(strings.TrimSpace(fmt.Sprint(node.mihomo["server"])))
		if _, err := netip.ParseAddr(host); err != nil && host != "" {
			result = append(result, host)
		}
	}
	return sortedClientStrings(result)
}

func normalizedClientIDs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			result = append(result, value)
		}
	}
	return sortedClientStrings(result)
}

func normalizedClientDomains(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.TrimPrefix(value, "*.")
		value = strings.TrimPrefix(value, ".")
		if value != "" && !strings.ContainsAny(value, "/:?#@ ") {
			result = append(result, value)
		}
	}
	return sortedClientStrings(result)
}

func sortedClientCIDRs(values []string) []string {
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]bool, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			if address, addressErr := netip.ParseAddr(strings.TrimSpace(value)); addressErr == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
			} else {
				continue
			}
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}
	sort.Slice(prefixes, func(left, right int) bool {
		if prefixes[left].Addr().BitLen() != prefixes[right].Addr().BitLen() {
			return prefixes[left].Addr().BitLen() < prefixes[right].Addr().BitLen()
		}
		if prefixes[left].Bits() != prefixes[right].Bits() {
			return prefixes[left].Bits() < prefixes[right].Bits()
		}
		return prefixes[left].Addr().Less(prefixes[right].Addr())
	})
	compact := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		covered := false
		for _, parent := range compact {
			if parent.Addr().BitLen() == prefix.Addr().BitLen() && parent.Contains(prefix.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			compact = append(compact, prefix)
		}
	}
	result := make([]string, 0, len(compact))
	for _, prefix := range compact {
		result = append(result, prefix.String())
	}
	return sortedClientStrings(result)
}

// clientDirectPrivateCIDRs returns the private ranges that may still bypass the
// gateway. Remote LAN ranges are removed from the broad defaults so a client
// never has to rely on rule order to distinguish, for example,
// 192.168.88.0/24 from 192.168.0.0/16.
func clientDirectPrivateCIDRs(remoteLAN []string) []string {
	cuts := make([]netip.Prefix, 0, len(remoteLAN))
	for _, value := range remoteLAN {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err == nil {
			cuts = append(cuts, prefix.Masked())
		}
	}
	remaining := make([]netip.Prefix, 0, len(clientPrivateCIDRs))
	for _, value := range clientPrivateCIDRs {
		base, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		parts := []netip.Prefix{base.Masked()}
		for _, cut := range cuts {
			next := make([]netip.Prefix, 0, len(parts)+1)
			for _, part := range parts {
				next = append(next, subtractClientPrefix(part, cut)...)
			}
			parts = next
		}
		remaining = append(remaining, parts...)
	}
	values := make([]string, 0, len(remaining))
	for _, prefix := range remaining {
		values = append(values, prefix.String())
	}
	return sortedClientStrings(values)
}

func subtractClientPrefix(base, cut netip.Prefix) []netip.Prefix {
	base, cut = base.Masked(), cut.Masked()
	if base.Addr().BitLen() != cut.Addr().BitLen() || !base.Contains(cut.Addr()) {
		return []netip.Prefix{base}
	}
	if cut.Bits() <= base.Bits() {
		return nil
	}
	left, right := splitClientPrefix(base)
	result := subtractClientPrefix(left, cut)
	return append(result, subtractClientPrefix(right, cut)...)
}

func splitClientPrefix(prefix netip.Prefix) (netip.Prefix, netip.Prefix) {
	prefix = prefix.Masked()
	leftAddress := prefix.Addr()
	bit := prefix.Bits()
	if leftAddress.Is4() {
		rightBytes := leftAddress.As4()
		rightBytes[bit/8] |= byte(1 << (7 - bit%8))
		bits := bit + 1
		return netip.PrefixFrom(leftAddress, bits), netip.PrefixFrom(netip.AddrFrom4(rightBytes), bits)
	}
	rightBytes := leftAddress.As16()
	rightBytes[bit/8] |= byte(1 << (7 - bit%8))
	bits := bit + 1
	return netip.PrefixFrom(leftAddress, bits), netip.PrefixFrom(netip.AddrFrom16(rightBytes), bits)
}

func sortedClientPorts(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ReplaceAll(value, ":", "-"))
		if value != "" {
			result = append(result, value)
		}
	}
	return sortedClientStrings(result)
}

func sortedClientStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func uniqueClientInts(values []int) []int {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func xrayClientDomainMatchers(match clientRouteMatch) []string {
	// Public client profiles must be self-contained. Server-side geosite sets
	// are not guaranteed to exist in Happ, v2rayNG, V2Box, or another Xray
	// client, and a missing tag prevents the entire client core from starting.
	// Service packs carry a conservative built-in domain fallback; use that
	// portable subset here. Server-side catalog identifiers never reach clients.
	domains := normalizedClientDomains(match.Domains)
	result := make([]string, 0, len(domains))
	for _, domain := range domains {
		result = append(result, "domain:"+domain)
	}
	return result
}

func xrayClientPlainDomainMatchers(domains []string) []string {
	domains = normalizedClientDomains(domains)
	result := make([]string, 0, len(domains))
	for _, domain := range domains {
		result = append(result, "domain:"+domain)
	}
	return result
}

func xrayClientTarget(rule map[string]any, target, proxyTarget string, useBalancer bool) map[string]any {
	if target == clientRouteDirect {
		rule["outboundTag"] = "client-direct"
	} else if useBalancer {
		rule["balancerTag"] = proxyTarget
	} else {
		rule["outboundTag"] = proxyTarget
	}
	return rule
}

func appendXrayClientMatchRules(rules []any, match clientRouteMatch, target, proxyTarget string, useBalancer bool) []any {
	base := func() map[string]any {
		return map[string]any{"type": "field", "inboundTag": []any{"tun-in"}}
	}
	if domains := xrayClientDomainMatchers(match); len(domains) != 0 {
		rule := base()
		rule["domain"] = domains
		rules = append(rules, xrayClientTarget(rule, target, proxyTarget, useBalancer))
	}
	if len(match.IPCIDRs) != 0 {
		rule := base()
		rule["ip"] = match.IPCIDRs
		rules = append(rules, xrayClientTarget(rule, target, proxyTarget, useBalancer))
	}
	if len(match.Protocols) != 0 {
		rule := base()
		rule["protocol"] = match.Protocols
		rules = append(rules, xrayClientTarget(rule, target, proxyTarget, useBalancer))
	}
	for network, ports := range map[string][]string{"tcp": match.TCPPorts, "udp": match.UDPPorts} {
		if len(ports) == 0 {
			continue
		}
		rule := base()
		rule["network"], rule["port"] = network, strings.Join(ports, ",")
		rules = append(rules, xrayClientTarget(rule, target, proxyTarget, useBalancer))
	}
	return rules
}

func buildXrayClientDNS(plan clientProfileRoutePlan) map[string]any {
	servers := make([]any, 0, 4)
	if len(plan.NodeDomains) != 0 {
		domains := make([]string, 0, len(plan.NodeDomains))
		for _, domain := range plan.NodeDomains {
			domains = append(domains, "full:"+domain)
		}
		servers = append(servers, map[string]any{
			"address": "https+local://1.1.1.1/dns-query", "domains": domains,
			"skipFallback": true, "finalQuery": true,
		})
	}
	if plan.InternalDNSServer != "" && len(plan.InternalZones) != 0 {
		servers = append(servers, map[string]any{
			"address": plan.InternalDNSServer, "domains": xrayClientPlainDomainMatchers(plan.InternalZones),
			"skipFallback": true, "finalQuery": true, "tag": "client-dns-internal",
		})
	}
	if plan.Individual {
		if domains := xrayClientDomainMatchers(plan.Match); len(domains) != 0 {
			servers = append(servers, map[string]any{
				"address": xrayClientResolverURL(clientDNSForTarget(plan, plan.ExceptionTarget)), "domains": domains,
				"skipFallback": true, "finalQuery": true, "tag": "client-dns-exception",
			})
		}
	}
	servers = append(servers, map[string]any{
		"address":    xrayClientResolverURL(clientDNSForTarget(plan, plan.DefaultTarget)),
		"finalQuery": true, "tag": "client-dns-default",
	})
	return map[string]any{
		"servers": servers, "queryStrategy": "UseIP", "disableCache": false,
		"disableFallbackIfMatch": true, "enableParallelQuery": false, "useSystemHosts": false,
	}
}

// Xray's built-in resolver has no DoT transport. Keep the selected provider and
// routing tag, using its encrypted DoH endpoint instead of an invalid tls:// URL.
func xrayClientResolverURL(resolver string) string {
	if strings.HasPrefix(resolver, "tls://") {
		host, _, err := net.SplitHostPort(strings.TrimPrefix(resolver, "tls://"))
		if err == nil {
			return "https://" + host + "/dns-query"
		}
	}
	return resolver
}

func buildXrayClientDNSOutbound(plan clientProfileRoutePlan) map[string]any {
	rules := make([]any, 0, 2)
	if len(plan.AdblockDomains) != 0 {
		rules = append(rules, map[string]any{
			"action": "return", "rCode": 3, "domain": xrayClientPlainDomainMatchers(plan.AdblockDomains),
		})
	}
	rules = append(rules, map[string]any{"action": "hijack"})
	return map[string]any{"rules": rules}
}

func appendXrayClientDNSRoutes(rules []any, plan clientProfileRoutePlan, proxyTarget string, useBalancer bool) []any {
	if plan.InternalDNSServer != "" && len(plan.InternalZones) != 0 {
		rules = append(rules, xrayClientTarget(map[string]any{
			"type": "field", "inboundTag": []any{"client-dns-internal"},
		}, clientRouteProxy, proxyTarget, useBalancer))
	}
	if plan.Individual && len(xrayClientDomainMatchers(plan.Match)) != 0 {
		rules = append(rules, xrayClientTarget(map[string]any{
			"type": "field", "inboundTag": []any{"client-dns-exception"},
		}, plan.ExceptionTarget, proxyTarget, useBalancer))
	}
	rules = append(rules, xrayClientTarget(map[string]any{
		"type": "field", "inboundTag": []any{"client-dns-default"},
	}, plan.DefaultTarget, proxyTarget, useBalancer))
	return rules
}

func clientDNSForTarget(plan clientProfileRoutePlan, target string) string {
	if target == clientRouteDirect {
		return plan.DirectDNS
	}
	return plan.ProxyDNS
}

func appendMihomoClientMatchRules(rules []any, match clientRouteMatch, target string) []any {
	// Keep exported client profiles self-contained. The managed geosite catalog
	// belongs to the gateway and may be absent or incompatible on the client.
	for _, domain := range match.Domains {
		rules = append(rules, "DOMAIN-SUFFIX,"+domain+","+target)
	}
	for _, cidr := range match.IPCIDRs {
		kind := "IP-CIDR"
		if strings.Contains(cidr, ":") {
			kind = "IP-CIDR6"
		}
		rules = append(rules, kind+","+cidr+","+target+",no-resolve")
	}
	for network, ports := range map[string][]string{"TCP": match.TCPPorts, "UDP": match.UDPPorts} {
		for _, port := range ports {
			rules = append(rules, "AND,((NETWORK,"+network+"),(DST-PORT,"+port+")),"+target)
		}
	}
	return rules
}

func buildMihomoClientRules(plan clientProfileRoutePlan) []any {
	rules := make([]any, 0, 32)
	for _, domain := range plan.AdblockDomains {
		rules = append(rules, "DOMAIN-SUFFIX,"+domain+",REJECT")
	}
	for _, domain := range plan.NodeDomains {
		rules = append(rules, "DOMAIN,"+domain+",DIRECT")
	}
	for _, cidr := range plan.AllowedLANCIDRs {
		kind := "IP-CIDR"
		if strings.Contains(cidr, ":") {
			kind = "IP-CIDR6"
		}
		if len(plan.AllowedLANPorts) == 0 {
			rules = append(rules, kind+","+cidr+",SB Gateway,no-resolve")
			continue
		}
		for _, port := range plan.AllowedLANPorts {
			rules = append(rules, "AND,(("+kind+","+cidr+"),(DST-PORT,"+strconv.Itoa(port)+")),SB Gateway")
		}
	}
	for _, cidr := range clientDirectPrivateCIDRs(plan.AllowedLANCIDRs) {
		kind := "IP-CIDR"
		if strings.Contains(cidr, ":") {
			kind = "IP-CIDR6"
		}
		rules = append(rules, kind+","+cidr+",DIRECT,no-resolve")
	}
	if plan.Individual {
		rules = appendMihomoClientMatchRules(rules, plan.Match, mihomoTarget(plan.ExceptionTarget))
	}
	rules = append(rules, "MATCH,"+mihomoTarget(plan.DefaultTarget))
	return rules
}

func buildMihomoClientDNS(plan clientProfileRoutePlan) map[string]any {
	defaultTarget := mihomoTarget(plan.DefaultTarget)
	dns := map[string]any{
		"enable": true, "listen": "0.0.0.0:1053", "ipv6": true,
		"enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
		"fake-ip-filter": []any{"*.lan", "*.local"},
		"respect-rules":  true, "use-system-hosts": false,
		"default-nameserver":              []any{"https://1.1.1.1/dns-query"},
		"proxy-server-nameserver":         []any{plan.DirectDNS + "#DIRECT"},
		"direct-nameserver":               []any{plan.DirectDNS + "#DIRECT"},
		"direct-nameserver-follow-policy": true,
		"nameserver":                      []any{clientDNSForTarget(plan, plan.DefaultTarget) + "#" + defaultTarget},
	}
	policy := make(map[string]any)
	for _, domain := range plan.NodeDomains {
		policy["="+domain] = "https://1.1.1.1/dns-query#DIRECT"
	}
	if plan.InternalDNSServer != "" && len(plan.InternalZones) != 0 {
		endpoint := "udp://" + net.JoinHostPort(plan.InternalDNSServer, "53") + "#SB Gateway"
		for _, domain := range plan.InternalZones {
			policy["+."+domain] = endpoint
		}
	}
	if plan.Individual {
		target := mihomoTarget(plan.ExceptionTarget)
		resolver := clientDNSForTarget(plan, plan.ExceptionTarget) + "#" + target
		for _, domain := range plan.Match.Domains {
			policy["+."+domain] = resolver
		}
	}
	if len(policy) != 0 {
		dns["nameserver-policy"] = policy
	}
	return dns
}

func mihomoTarget(target string) string {
	if target == clientRouteDirect {
		return "DIRECT"
	}
	return "SB Gateway"
}
