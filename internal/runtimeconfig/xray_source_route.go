package runtimeconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

var xrayPrivateDestinations = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

var localTransparentInbounds = []string{"tun-routeros"}

// BuildXrayRouteSource builds ordered schema-v1 routing rules. It operates on
// the already-built outbound source so invalid references fail closed without
// keeping a second candidate graph in memory.
func BuildXrayRouteSource(config map[string]any, nodes, outbounds []map[string]any) (map[string]any, error) {
	available := make(map[string]struct{}, len(outbounds))
	for _, outbound := range outbounds {
		if tag := textValue(outbound["tag"]); tag != "" {
			available[tag] = struct{}{}
		}
	}
	rules := []map[string]any{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
		{"inbound": append([]string{"subscription-update-direct", "subscription-update-vpn"}, healthProbeLaneTags(config)...), "ip_cidr": append([]string(nil), xrayPrivateDestinations...), "action": "reject"},
		{"inbound": []string{"subscription-update-direct"}, "action": "route", "outbound": "direct-wan"},
		{"inbound": []string{"subscription-update-vpn"}, "action": "route", "outbound": "subscription-update-egress"},
	}
	for _, lane := range xrayHealthProbeLanesForConfig(config) {
		if _, exists := available[lane.Tag]; exists {
			rules = append(rules, map[string]any{"inbound": []string{lane.Tag}, "action": "route", "outbound": lane.Tag})
		}
	}
	managedInbounds := []string{
		"tun-routeros", "vless-ws", "vless-grpc", "vless-httpupgrade", "vless-xhttp",
		"vless-reality", "vless-reality-grpc", "vless-grpc-tls-pin", "hysteria2-direct",
	}
	remoteInbounds := append([]string(nil), managedInbounds[1:]...)
	for _, transport := range enabledObjects(config["transports"]) {
		if textValue(transport["kind"]) == "xhttp-reality" {
			managedInbounds = append(managedInbounds, "vless-xhttp-reality")
			remoteInbounds = append(remoteInbounds, "vless-xhttp-reality")
			break
		}
	}
	dns := objectValue(config["dns"])
	if boolDefault(dns["hijack_managed_clients"], true) {
		rules = append(rules, map[string]any{
			"inbound": managedInbounds, "network": []string{"tcp", "udp"}, "port": 53, "action": "hijack-dns",
		})
	}
	if boolDefault(dns["strict_dns"], true) {
		rules = append(rules, map[string]any{
			"inbound": managedInbounds, "network": "tcp", "port": 853, "action": "reject",
		})
	}
	if loopRule := xrayNodeLoopRule(nodes); loopRule != nil {
		rules = append(rules, loopRule)
	}

	internalNetworks := enabledInternalCIDRs(config)
	trustedFullNetworks := sortedUniqueStrings(append(append([]string(nil), internalNetworks...), trustedFullIPv4Destinations...))
	managementTargets, err := xrayManagementTargets(config)
	if err != nil {
		return nil, err
	}
	networksByID := make(map[string][]string)
	for _, network := range enabledObjects(config["networks"]) {
		networksByID[textValue(network["id"])] = stringSlice(network["cidrs"])
	}
	remoteUsers := enabledObjects(config["remote_users"])
	policies := enabledObjectsByID(config["policies"])
	for _, user := range remoteUsers {
		userID := textValue(user["id"])
		switch textDefault(user["role"], "limited") {
		case "trusted-full":
			for _, targets := range [][]string{trustedFullNetworks, managementTargets} {
				if len(targets) != 0 {
					rules = append(rules, map[string]any{
						"inbound": remoteInbounds, "auth_user": []string{userID}, "ip_cidr": targets,
						"action": "route", "outbound": "direct-wan",
					})
				}
			}
		case "trusted-limited":
			allowed := append([]string(nil), stringSlice(user["allowed_cidrs"])...)
			for _, networkID := range stringSlice(user["allowed_network_ids"]) {
				allowed = append(allowed, networksByID[networkID]...)
			}
			allowed = sortedUniqueStrings(allowed)
			if len(allowed) != 0 {
				rule := map[string]any{
					"inbound": remoteInbounds, "auth_user": []string{userID}, "ip_cidr": allowed,
					"action": "route", "outbound": "direct-wan",
				}
				ports, portErr := integerSlice(user["allowed_ports"])
				if portErr != nil {
					return nil, fmt.Errorf("remote user %q allowed ports: %w", userID, portErr)
				}
				if len(ports) != 0 {
					rule["port"] = ports
				}
				rules = append(rules, rule)
			}
		}
	}
	if len(managementTargets) != 0 && !boolDefault(objectValue(config["security"])["allow_router_management"], false) {
		rules = append(rules, map[string]any{"inbound": remoteInbounds, "ip_cidr": managementTargets, "action": "reject"})
	}
	if len(trustedFullNetworks) != 0 {
		rules = append(rules, map[string]any{
			"inbound": remoteInbounds, "ip_cidr": trustedFullNetworks, "action": "route", "outbound": "block",
		})
	}

	catalog, err := loadPolicyDNSCatalog()
	if err != nil {
		return nil, err
	}
	referencedServices := make(map[string]struct{})
	forceServiceTCP := boolDefault(dns["force_tcp_for_proxy_services"], false)
	appendServiceRoute := func(identity map[string]any, serviceIDs []string, outbound string) {
		tags := make([]string, 0, len(serviceIDs))
		for _, serviceID := range serviceIDs {
			referencedServices[serviceID] = struct{}{}
			tags = append(tags, "service-"+serviceID)
		}
		match := cloneJSONMap(identity)
		match["rule_set"] = tags
		if forceServiceTCP {
			reject := cloneJSONMap(match)
			reject["network"], reject["port"], reject["action"] = "udp", 443, "reject"
			rules = append(rules, reject)
		}
		route := cloneJSONMap(match)
		route["action"], route["outbound"] = "route", outbound
		rules = append(rules, route)
	}
	appendService := func(identity map[string]any, serviceID, outbound string) error {
		canonical, serviceErr := canonicalServiceID(serviceID)
		if serviceErr != nil {
			return serviceErr
		}
		if protocols := serviceSniffedProtocols(canonical, catalog); len(protocols) != 0 {
			rule := cloneJSONMap(identity)
			rule["protocol"], rule["action"], rule["outbound"] = protocols, "route", outbound
			rules = append(rules, rule)
		}
		appendServiceRoute(identity, serviceRuleSetIDs(canonical, catalog.byID), outbound)
		return nil
	}
	appendEntityRoutes := func(entity, policy map[string]any, identity map[string]any, remote bool) error {
		policyID := textValue(policy["id"])
		trafficMode := textValue(policy["traffic_mode"])
		if textValue(policy["mode"]) == "priority" {
			for _, serviceID := range candidateServiceIDs(policy) {
				selector := policyServiceSelectorTag(policyID, serviceID)
				if _, ok := available[selector]; ok {
					if routeErr := appendService(identity, serviceID, selector); routeErr != nil {
						return routeErr
					}
				}
			}
		}
		directServiceIDs, serviceErr := directServices(entity, policy, catalog)
		if serviceErr != nil {
			return serviceErr
		}
		for _, serviceID := range directServiceIDs {
			if routeErr := appendService(identity, serviceID, "direct-wan"); routeErr != nil {
				return routeErr
			}
		}
		if domains := directDomains(entity, policy); len(domains) != 0 {
			outbound := "direct-wan"
			if trafficMode == "wan_with_vless_exceptions" {
				outbound = selectableOrBlock(policyID, available)
			}
			rule := cloneJSONMap(identity)
			rule["domain_suffix"], rule["action"], rule["outbound"] = domains, "route", outbound
			rules = append(rules, rule)
		}
		serviceRoutes := make(map[string]string)
		for name, outbound := range stringMap(policy["service_routes"]) {
			serviceRoutes[name] = outbound
		}
		for name, outbound := range stringMap(entity["service_routes"]) {
			serviceRoutes[name] = outbound
		}
		names := make([]string, 0, len(serviceRoutes))
		for name := range serviceRoutes {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			canonical, canonicalErr := canonicalServiceID(name)
			if canonicalErr != nil {
				return canonicalErr
			}
			if pack, ok := catalog.byID[canonical]; ok && pack.AlwaysDirect && boolDefault(policy["torrent_direct"], true) {
				continue
			}
			outbound := serviceRoutes[name]
			if _, ok := available[outbound]; !ok || outbound == "direct-wan" {
				outbound = "block"
			}
			if routeErr := appendService(identity, canonical, outbound); routeErr != nil {
				return routeErr
			}
		}
		if remote {
			outbound := "direct-wan"
			if policy == nil || trafficMode != "wan_with_vless_exceptions" {
				outbound = selectableOrBlock(policyID, available)
			}
			rule := cloneJSONMap(identity)
			rule["action"], rule["outbound"] = "route", outbound
			rules = append(rules, rule)
			return nil
		}
		final := textValue(entity["final"])
		if final == "" {
			if trafficMode == "vless_with_wan_exceptions" {
				final = policyID
			} else {
				final = textValue(policy["final"])
			}
		}
		if final == "" || final == "direct" || final == "direct-wan" {
			return nil
		}
		rule := cloneJSONMap(identity)
		rule["action"], rule["outbound"] = "route", selectableOrBlock(final, available)
		rules = append(rules, rule)
		return nil
	}

	remoteIPv6Mode := textDefault(objectValue(objectValue(config["system"])["networking"])["remote_ipv6_mode"], "proxy_only")
	if remoteIPv6Mode != "proxy_only" && remoteIPv6Mode != "disabled" {
		return nil, errors.New("system.networking.remote_ipv6_mode must be proxy_only or disabled")
	}
	for _, user := range remoteUsers {
		userID := textValue(user["id"])
		policyID := textValue(user["policy_id"])
		policy := policies[policyID]
		ipv6 := map[string]any{"inbound": remoteInbounds, "auth_user": []string{userID}, "ip_version": 6}
		if remoteIPv6Mode == "proxy_only" && selectableNonDirect(policyID, available) {
			ipv6["action"], ipv6["outbound"] = "route", policyID
		} else {
			ipv6["action"], ipv6["method"] = "reject", "default"
		}
		rules = append(rules, ipv6)
		identity := map[string]any{"inbound": remoteInbounds, "auth_user": []string{userID}}
		if routeErr := appendEntityRoutes(user, policy, identity, true); routeErr != nil {
			return nil, fmt.Errorf("remote user %q routing: %w", userID, routeErr)
		}
	}
	if len(internalNetworks) != 0 {
		rules = append(rules, map[string]any{
			"inbound": localTransparentInbounds, "ip_cidr": internalNetworks, "action": "route", "outbound": "direct-wan",
		})
	}
	for _, client := range enabledLocalClientsSpecificFirst(config["local_clients"]) {
		clientID := textValue(client["id"])
		identity := map[string]any{"inbound": localTransparentInbounds, "source_ip_cidr": stringSlice(client["source_cidrs"])}
		if routeErr := appendEntityRoutes(client, policies[textValue(client["policy_id"])], identity, false); routeErr != nil {
			return nil, fmt.Errorf("local client %q routing: %w", clientID, routeErr)
		}
	}
	rules = append(rules,
		map[string]any{"inbound": localTransparentInbounds, "action": "route", "outbound": "direct-wan"},
		map[string]any{"inbound": remoteInbounds, "action": "route", "outbound": "block"},
	)
	serviceIDs := make([]string, 0, len(referencedServices))
	for serviceID := range referencedServices {
		serviceIDs = append(serviceIDs, serviceID)
	}
	sort.Strings(serviceIDs)
	ruleSets := make([]map[string]any, 0, len(serviceIDs))
	for _, serviceID := range serviceIDs {
		ruleSets = append(ruleSets, map[string]any{
			"type": "local", "tag": "service-" + serviceID, "format": "binary", "path": "/config/rulesets/" + serviceID + ".srs",
		})
	}
	return map[string]any{"rules": rules, "rule_set": ruleSets}, nil
}

func healthProbeLaneTags(config map[string]any) []string {
	lanes := xrayHealthProbeLanesForConfig(config)
	tags := make([]string, 0, len(lanes))
	for _, lane := range lanes {
		tags = append(tags, lane.Tag)
	}
	return tags
}

func enabledInternalCIDRs(config map[string]any) []string {
	result := make([]string, 0)
	for _, network := range enabledObjects(config["networks"]) {
		kind := textDefault(network["kind"], "internal")
		if kind == "internal" || kind == "management" {
			result = append(result, stringSlice(network["cidrs"])...)
		}
	}
	return result
}

func xrayNodeLoopRule(nodes []map[string]any) map[string]any {
	domains := make([]string, 0)
	addresses := make([]string, 0)
	for _, node := range nodes {
		server := textValue(node["server"])
		if server == "" {
			continue
		}
		if address, err := netip.ParseAddr(server); err == nil {
			addresses = append(addresses, netip.PrefixFrom(address, address.BitLen()).String())
		} else {
			domains = append(domains, server)
		}
	}
	domains, addresses = sortedUniqueStrings(domains), sortedUniqueStrings(addresses)
	if len(domains) == 0 && len(addresses) == 0 {
		return nil
	}
	rule := map[string]any{"inbound": localTransparentInbounds, "action": "route", "outbound": "direct-wan"}
	if len(domains) != 0 {
		rule["domain"] = domains
	}
	if len(addresses) != 0 {
		rule["ip_cidr"] = addresses
	}
	return rule
}

func xrayManagementTargets(config map[string]any) ([]string, error) {
	values := []string{"127.0.0.0/8", "::1/128"}
	values = append(values, stringSlice(objectValue(config["routeros"])["router_addresses"])...)
	networking := objectValue(objectValue(config["system"])["networking"])
	if gateway := textValue(networking["routeros_gateway"]); gateway != "" {
		address, err := netip.ParseAddr(gateway)
		if err != nil {
			return nil, errors.New("system.networking.routeros_gateway is invalid")
		}
		values = append(values, netip.PrefixFrom(address, address.BitLen()).String())
	}
	for _, field := range []string{"container_address", "tun_address"} {
		value := textValue(networking[field])
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("system.networking.%s is invalid", field)
		}
		values = append(values, netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()).String())
	}
	return sortedUniqueStrings(values), nil
}

func sortedUniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func selectableOrBlock(value string, available map[string]struct{}) string {
	if selectableNonDirect(value, available) {
		return value
	}
	return "block"
}

func serviceSniffedProtocols(serviceID string, catalog policyDNSCatalog) []string {
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, dependencyID := range serviceRuleSetIDs(serviceID, catalog.byID) {
		for _, protocol := range catalog.byID[dependencyID].SniffedProtocols {
			if _, exists := seen[protocol]; exists {
				continue
			}
			seen[protocol] = struct{}{}
			result = append(result, protocol)
		}
	}
	return result
}

func integerSlice(value any) ([]int, error) {
	raw, _ := value.([]any)
	if raw == nil {
		if typed, ok := value.([]int); ok {
			return append([]int(nil), typed...), nil
		}
		return nil, nil
	}
	result := make([]int, 0, len(raw))
	for _, item := range raw {
		port, err := requiredInteger(item)
		if err != nil {
			return nil, err
		}
		if port < 1 || port > 65535 {
			return nil, errors.New("port must be between 1 and 65535")
		}
		result = append(result, port)
	}
	return result, nil
}
