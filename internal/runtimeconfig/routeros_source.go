package runtimeconfig

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
)

type RouterOSWireGuardExit struct {
	ID            string
	Tag           string
	Interface     string
	SourceAddress string
	RoutingTable  string
}

type RouterOSPublicIngress struct {
	Key                string
	Protocol           string
	PublicPort         int
	PublicPortEnd      int
	TargetPort         int
	DestinationAddress string
	SourceAddressList  string
	GuardForeignUDP    bool
}

type RouterOSPublicSourceList struct {
	Name    string
	Comment string
	CIDRs   []string
}

type RouterOSConnectionGuard struct {
	Enabled           bool
	NewConnectionRate int
	Burst             int
	QuarantineSeconds int
}

type RouterOSRenderModel struct {
	Managed4, Managed6                        []string
	FailClosed4, FailClosed6                  []string
	Internal4, Internal6                      []string
	ContainerAllowed4, ManagementSources4     []string
	BypassEndpoints4, ManagementIngress       []string
	ContainerIP, ContainerNetwork, TunNetwork string
	RouterOSGateway, BridgeName, VethName     string
	RoutingTable                              string
	RESTPort, SSHPort                         int
	PanelPort                                 int
	DNSServers, DNSDoHURL                     string
	WatchdogInterval, WatchdogFailure         int
	WatchdogRecovery, WatchdogCooldownTicks   int
	IPv6Mode                                  string
	WireGuardExits                            []RouterOSWireGuardExit
	PublicIngress                             []RouterOSPublicIngress
	PublicSourceLists                         []RouterOSPublicSourceList
	PublicTrusted4                            []string
	ConnectionGuard                           RouterOSConnectionGuard
}

var routerOSNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:+@ -]{0,62}$`)
var routerOSWireGuardIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// RouterOSEndpointBypass returns the endpoint-only RouterOS model, without secrets.
func RouterOSEndpointBypass(config map[string]any, nodes []map[string]any) ([]string, error) {
	augmented, err := augmentRuntimeNodes(config, nodes)
	if err != nil {
		return nil, err
	}
	model, err := BuildRouterOSRenderModel(config, augmented)
	return model.BypassEndpoints4, err
}

// UpdateRouterOSEndpointSource records only the address-list update that was
// actually performed. Unrelated renderer changes must remain visible to the
// next explicit Apply, not block subscription refresh or be marked as applied.
func UpdateRouterOSEndpointSource(committed string, previous, desired []string) (string, error) {
	for _, values := range [][]string{previous, desired} {
		for _, value := range values {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 32 {
				return "", errors.New("invalid subscription endpoint source address")
			}
		}
	}
	block := func(values []string) string {
		return strings.Join(renderRouterOSAddressList("Bypass", "SB_BYPASS_ENDPOINTS", "SB-GATEWAY loop bypass", values), "\n") + "\n"
	}
	old := block(previous)
	if strings.Count(committed, old) != 1 || strings.Count(committed, ":local wantedBypass ") != 1 {
		return "", errors.New("committed subscription endpoint block missing or inconsistent")
	}
	return strings.Replace(committed, old, block(desired), 1), nil
}

// BuildRouterOSRenderModel normalizes the current schema into the small model
// consumed by the RSC renderer. It performs no RouterOS request and carries no
// secrets.
func BuildRouterOSRenderModel(config map[string]any, nodes []map[string]any) (RouterOSRenderModel, error) {
	model := RouterOSRenderModel{}
	policies := enabledObjectsByID(config["policies"])
	managed := make([]string, 0)
	failClosed := make([]string, 0)
	for _, client := range enabledObjects(config["local_clients"]) {
		sources := stringSlice(client["source_cidrs"])
		managed = append(managed, sources...)
		outage := textValue(client["container_outage"])
		if outage == "" {
			outage = textValue(policies[textValue(client["policy_id"])]["container_outage"])
		}
		if outage == "lan_only" {
			failClosed = append(failClosed, sources...)
		}
	}
	networkValues := make(map[string][]string)
	internal := make([]string, 0)
	for _, network := range enabledObjects(config["networks"]) {
		kind := textDefault(network["kind"], "internal")
		if kind != "internal" && kind != "management" {
			continue
		}
		cidrs := stringSlice(network["cidrs"])
		networkValues[textValue(network["id"])] = cidrs
		internal = append(internal, cidrs...)
	}
	containerAllowed := make([]string, 0)
	for _, user := range enabledObjects(config["remote_users"]) {
		switch textValue(user["role"]) {
		case "trusted-full":
			containerAllowed = append(containerAllowed, internal...)
			containerAllowed = append(containerAllowed, trustedFullIPv4Destinations...)
		case "trusted-limited":
			containerAllowed = append(containerAllowed, stringSlice(user["allowed_cidrs"])...)
			for _, networkID := range stringSlice(user["allowed_network_ids"]) {
				containerAllowed = append(containerAllowed, networkValues[networkID]...)
			}
		}
	}
	system := objectValue(config["system"])
	networking := objectValue(system["networking"])
	management := objectValue(system["management"])
	if management["routeros_panel_port"] != nil {
		port, err := integerDefault(management["routeros_panel_port"], 0)
		if err != nil || port < 1024 || port > 65535 || port == 9443 || port == 18081 {
			return RouterOSRenderModel{}, errors.New("system.management.routeros_panel_port must be an integer from 1024 to 65535, except internal ports 9443 and 18081")
		}
		model.PanelPort = port
	}
	model.ManagementIngress = sortedUniqueStrings(stringSlice(management["allowed_ingress_interfaces"]))
	if len(model.ManagementIngress) == 0 {
		return RouterOSRenderModel{}, errors.New("system.management.allowed_ingress_interfaces must select at least one RouterOS interface")
	}
	for _, name := range model.ManagementIngress {
		if !routerOSNamePattern.MatchString(name) {
			return RouterOSRenderModel{}, fmt.Errorf("unsafe RouterOS management ingress interface %q", name)
		}
	}
	managementSources := stringSlice(management["allowed_source_cidrs"])
	bypass := make([]string, 0)
	for _, node := range nodes {
		address, err := netip.ParseAddr(textValue(node["server"]))
		if err == nil {
			bypass = append(bypass, netip.PrefixFrom(address, address.BitLen()).String())
		}
	}
	var err error
	model.Managed4, model.Managed6, err = splitRouterOSCIDRs(managed)
	if err != nil {
		return RouterOSRenderModel{}, fmt.Errorf("managed clients: %w", err)
	}
	model.FailClosed4, model.FailClosed6, err = splitRouterOSCIDRs(failClosed)
	if err != nil {
		return RouterOSRenderModel{}, fmt.Errorf("fail-closed clients: %w", err)
	}
	model.Internal4, model.Internal6, err = splitRouterOSCIDRs(internal)
	if err != nil {
		return RouterOSRenderModel{}, fmt.Errorf("internal networks: %w", err)
	}
	model.ContainerAllowed4, _, err = splitRouterOSCIDRs(containerAllowed)
	if err != nil {
		return RouterOSRenderModel{}, fmt.Errorf("container allowlist: %w", err)
	}
	model.ManagementSources4, _, err = splitRouterOSCIDRs(managementSources)
	if err != nil {
		return RouterOSRenderModel{}, fmt.Errorf("management sources: %w", err)
	}
	model.BypassEndpoints4, _, err = splitRouterOSCIDRs(bypass)
	if err != nil {
		return RouterOSRenderModel{}, fmt.Errorf("bypass endpoints: %w", err)
	}

	container, err := netip.ParsePrefix(textValue(networking["container_address"]))
	if err != nil || !container.Addr().Is4() {
		return RouterOSRenderModel{}, errors.New("system.networking.container_address must be a valid IPv4 interface")
	}
	model.ContainerIP, model.ContainerNetwork = container.Addr().String(), container.Masked().String()
	tun, err := netip.ParsePrefix(textValue(networking["tun_address"]))
	if err != nil || !tun.Addr().Is4() {
		return RouterOSRenderModel{}, errors.New("system.networking.tun_address must be a valid IPv4 interface")
	}
	model.TunNetwork = tun.Masked().String()
	gateway, err := netip.ParseAddr(textValue(networking["routeros_gateway"]))
	if err != nil || !gateway.Is4() {
		return RouterOSRenderModel{}, errors.New("system.networking.routeros_gateway must be a valid IPv4 address")
	}
	model.RouterOSGateway = gateway.String()
	model.BridgeName = textValue(networking["bridge_name"])
	model.VethName = textValue(networking["veth_name"])
	model.RoutingTable = textDefault(networking["routing_table"], "to-sb-gateway")
	for field, value := range map[string]string{"bridge_name": model.BridgeName, "veth_name": model.VethName, "routing_table": model.RoutingTable} {
		if !routerOSNamePattern.MatchString(value) {
			return RouterOSRenderModel{}, fmt.Errorf("system.networking.%s must be an actual safe RouterOS name", field)
		}
	}
	model.IPv6Mode = textDefault(networking["ipv6_mode"], "block_managed")
	if model.IPv6Mode != "block_managed" && model.IPv6Mode != "disabled" {
		return RouterOSRenderModel{}, errors.New("system.networking.ipv6_mode must be block_managed or disabled")
	}
	model.WireGuardExits, err = routerOSWireGuardExits(networking)
	if err != nil {
		return RouterOSRenderModel{}, err
	}
	if len(model.WireGuardExits) > 0 {
		wireGuardPool := netip.MustParsePrefix("198.18.0.0/15")
		occupied := append(append([]string{}, internal...), model.ContainerNetwork, model.TunNetwork)
		for _, raw := range occupied {
			prefix, parseErr := netip.ParsePrefix(raw)
			if parseErr == nil && prefix.Addr().Is4() && prefixesOverlap(prefix.Masked(), wireGuardPool) {
				return RouterOSRenderModel{}, errors.New("WireGuard source pool 198.18.0.0/15 overlaps a configured network")
			}
		}
	}
	model.PublicIngress, model.PublicSourceLists, model.PublicTrusted4, err = routerOSPublicIngress(config)
	if err != nil {
		return RouterOSRenderModel{}, err
	}
	for _, ingress := range model.PublicIngress {
		if model.PanelPort != 0 && ingress.Protocol == "tcp" && ingress.PublicPort == model.PanelPort {
			return RouterOSRenderModel{}, errors.New("routeros_panel_port conflicts with a public TCP ingress port")
		}
	}
	model.ConnectionGuard, err = routerOSConnectionGuard(config)
	if err != nil {
		return RouterOSRenderModel{}, err
	}

	routerOS := objectValue(config["routeros"])
	baseURL := textValue(routerOS["base_url"])
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Hostname() == "" || parsedURL.Port() == "" || parsedURL.User != nil || (parsedURL.Path != "" && parsedURL.Path != "/") || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return RouterOSRenderModel{}, errors.New("routeros.base_url must be an HTTPS origin with an explicit www-ssl port")
	}
	model.RESTPort, err = requiredPort(parsedURL.Port())
	if err != nil {
		return RouterOSRenderModel{}, errors.New("routeros.base_url has an invalid port")
	}
	model.SSHPort, err = integerDefault(routerOS["ssh_port"], 22)
	if err != nil || model.SSHPort < 1 || model.SSHPort > 65535 {
		return RouterOSRenderModel{}, errors.New("routeros.ssh_port must be between 1 and 65535")
	}
	dns := objectValue(config["dns"])
	directResolver := objectValue(dns["direct_resolver"])
	provider := textDefault(directResolver["provider"], "yandex")
	if provider == "routeros" {
		provider = "yandex"
	}
	servers, ok := routerOSPublicDNSServers[provider]
	if !ok {
		return RouterOSRenderModel{}, fmt.Errorf("dns.direct_resolver.provider %q is unsupported by RouterOS", provider)
	}
	model.DNSServers = strings.Join(servers, ",")
	protocol := textDefault(directResolver["protocol"], "doh")
	if protocol != "doh" && protocol != "udp" && protocol != "tcp" {
		return RouterOSRenderModel{}, fmt.Errorf("dns.direct_resolver.protocol %q is unsupported by RouterOS", protocol)
	}
	if protocol == "doh" {
		model.DNSDoHURL = routerOSPublicDNSDoHURLs[provider]
	}

	watchdog := objectValue(config["watchdog"])
	model.WatchdogInterval, err = integerDefault(watchdog["interval_seconds"], 5)
	if err != nil || model.WatchdogInterval < 1 {
		return RouterOSRenderModel{}, errors.New("watchdog.interval_seconds must be positive")
	}
	model.WatchdogFailure, err = integerDefault(watchdog["failure_threshold"], 3)
	if err != nil || model.WatchdogFailure < 1 {
		return RouterOSRenderModel{}, errors.New("watchdog.failure_threshold must be positive")
	}
	model.WatchdogRecovery, err = integerDefault(watchdog["recovery_threshold"], 3)
	if err != nil || model.WatchdogRecovery < 1 {
		return RouterOSRenderModel{}, errors.New("watchdog.recovery_threshold must be positive")
	}
	cooldown, err := integerDefault(watchdog["recovery_cooldown_seconds"], 0)
	if err != nil || cooldown < 0 {
		return RouterOSRenderModel{}, errors.New("watchdog.recovery_cooldown_seconds must be non-negative")
	}
	model.WatchdogCooldownTicks = (cooldown + model.WatchdogInterval - 1) / model.WatchdogInterval
	return model, nil
}

func routerOSConnectionGuard(config map[string]any) (RouterOSConnectionGuard, error) {
	guard := objectValue(objectValue(config["public_exposure"])["connection_guard"])
	result := RouterOSConnectionGuard{Enabled: boolDefault(guard["enabled"], true)}
	var err error
	result.NewConnectionRate, err = integerDefault(guard["new_connection_rate"], 40)
	if err != nil || result.NewConnectionRate < 5 || result.NewConnectionRate > 1000 {
		return RouterOSConnectionGuard{}, errors.New("public_exposure.connection_guard.new_connection_rate must be between 5 and 1000")
	}
	result.Burst, err = integerDefault(guard["burst"], 80)
	if err != nil || result.Burst < 10 || result.Burst > 5000 {
		return RouterOSConnectionGuard{}, errors.New("public_exposure.connection_guard.burst must be between 10 and 5000")
	}
	result.QuarantineSeconds, err = integerDefault(guard["quarantine_seconds"], 600)
	if err != nil || result.QuarantineSeconds < 60 || result.QuarantineSeconds > 86400 {
		return RouterOSConnectionGuard{}, errors.New("public_exposure.connection_guard.quarantine_seconds must be between 60 and 86400")
	}
	return result, nil
}

type routerOSPublicIngressCandidate struct {
	identity, protocol, destination, sourceList string
	publicPort, publicPortEnd, targetPort       int
	guardForeignUDP                             bool
}

// RequiredCDNFeeds shares the exact public listener selection used by Apply,
// including a separate subscription endpoint and disabled deployments.
func RequiredCDNFeeds(config map[string]any) ([]string, error) {
	ingress, _, _, err := routerOSPublicIngress(config)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	shared := SharedOriginPorts(config)
	for _, p := range OriginPolicies(config) {
		if shared[p.Port] && p.Mode == "auto-cidr" && p.Provider == "cloudflare" {
			seen["cloudflare"] = true
		}
	}
	for _, entry := range ingress {
		id := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(entry.SourceAddressList, "SB_CDN_"), "_V4"))
		if p, ok := cdnfeed.Lookup(id); ok {
			seen[p.ID] = true
		}
	}
	result := make([]string, 0, len(seen))
	for id := range seen {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

func routerOSPublicIngress(config map[string]any) ([]RouterOSPublicIngress, []RouterOSPublicSourceList, []string, error) {
	candidates := make([]routerOSPublicIngressCandidate, 0)
	sourceLists := make(map[string]RouterOSPublicSourceList)
	trusted := make([]string, 0)
	addRange := func(identity, protocol string, publicPort, publicPortEnd, targetPort int, destination, protection, provider string, cidrs []string) error {
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("public ingress %q has unsupported protocol %q", identity, protocol)
		}
		if publicPort < 1 || publicPort > 65535 || publicPortEnd < publicPort || publicPortEnd > 65535 || targetPort < 1 || targetPort > 65535 {
			return fmt.Errorf("public ingress %q has an invalid port", identity)
		}
		destination = strings.TrimSpace(destination)
		if destination != "" {
			address, parseErr := netip.ParseAddr(destination)
			if parseErr != nil || !address.Is4() {
				return fmt.Errorf("public ingress %q wan_destination_address must be an IPv4 address", identity)
			}
			destination = address.String()
		}
		sourceList := ""
		switch protection {
		case "", "none", "secret-header":
		case "auto-cidr":
			if !cdnfeed.Supports(provider) {
				return fmt.Errorf("public ingress %q has no official origin CIDR adapter for %q", identity, provider)
			}
			sourceList = cdnfeed.ListName(provider)
		case "manual-cidr":
			normalized, ipv6, splitErr := splitRouterOSCIDRs(cidrs)
			if splitErr != nil || len(normalized) == 0 || len(ipv6) != 0 {
				return fmt.Errorf("public ingress %q manual origin CIDRs must contain IPv4 networks", identity)
			}
			digest := sha256.Sum256([]byte(strings.Join(normalized, "\x00")))
			suffix := hex.EncodeToString(digest[:])[:12]
			sourceList = "SB_PUBLIC_" + strings.ToUpper(suffix)
			sourceLists[sourceList] = RouterOSPublicSourceList{
				Name: sourceList, Comment: "SB-GATEWAY public source " + suffix, CIDRs: normalized,
			}
			trusted = append(trusted, normalized...)
		default:
			return fmt.Errorf("public ingress %q has unsupported origin protection %q", identity, protection)
		}
		candidates = append(candidates, routerOSPublicIngressCandidate{
			identity: identity, protocol: protocol, publicPort: publicPort, publicPortEnd: publicPortEnd, targetPort: targetPort,
			destination: destination, sourceList: sourceList,
			guardForeignUDP: protocol == "udp" && (publicPort != targetPort || publicPortEnd != publicPort),
		})
		return nil
	}
	add := func(identity, protocol string, publicPort, targetPort int, destination, protection, provider string, cidrs []string) error {
		return addRange(identity, protocol, publicPort, publicPort, targetPort, destination, protection, provider, cidrs)
	}

	for _, transport := range enabledObjects(config["transports"]) {
		id, kind := textValue(transport["id"]), textValue(transport["kind"])
		switch kind {
		case "ws", "grpc", "httpupgrade", "xhttp":
			deployments, ok := transport["cdn_deployments"].([]any)
			if !ok {
				return nil, nil, nil, fmt.Errorf("transport %q requires current cdn_deployments", id)
			}
			for _, raw := range deployments {
				deployment := objectValue(raw)
				if deployment == nil || deployment["enabled"] == false {
					continue
				}
				port, portErr := requiredInteger(deployment["origin_port"])
				if portErr != nil {
					return nil, nil, nil, fmt.Errorf("CDN deployment %q origin_port: %w", textValue(deployment["id"]), portErr)
				}
				provider := textDefault(deployment["cdn_provider"], textDefault(transport["cdn_provider"], "cloudflare"))
				protection := textDefault(deployment["origin_protection_mode"], "")
				if protection == "" {
					if strings.EqualFold(provider, "cloudflare") {
						protection = "auto-cidr"
					} else if len(stringSlice(deployment["origin_allowed_cidrs"])) != 0 {
						protection = "manual-cidr"
					} else {
						protection = "secret-header"
					}
				}
				if err := add("transport:"+id+":"+textValue(deployment["id"]), "tcp", port, port, "", protection, provider, stringSlice(deployment["origin_allowed_cidrs"])); err != nil {
					return nil, nil, nil, err
				}
			}
		case "reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2":
			port, portErr := requiredInteger(transport["listen_port"])
			if portErr != nil {
				return nil, nil, nil, fmt.Errorf("transport %q listen_port: %w", id, portErr)
			}
			protocol := "tcp"
			if kind == "hysteria2" {
				protocol = "udp"
				hop, hopErr := ParseHysteriaUDPHop(transport)
				if hopErr != nil {
					return nil, nil, nil, fmt.Errorf("transport %q: %w", id, hopErr)
				}
				if hop.Enabled {
					for _, portRange := range hop.Ranges {
						if err := addRange("transport:"+id, protocol, portRange.Start, portRange.End, port, textValue(transport["wan_destination_address"]), "none", "", nil); err != nil {
							return nil, nil, nil, err
						}
					}
					continue
				}
			}
			if err := add("transport:"+id, protocol, port, port, textValue(transport["wan_destination_address"]), "none", "", nil); err != nil {
				return nil, nil, nil, err
			}
		}
	}

	ingress := objectValue(config["ingress"])
	if statusHost := strings.TrimSpace(textValue(ingress["status_hostname"])); statusHost != "" {
		port, portErr := integerDefault(ingress["status_listen_port"], 443)
		if portErr != nil {
			return nil, nil, nil, portErr
		}
		protection := "none"
		if boolDefault(ingress["require_cloudflare_source_ranges"], true) {
			protection = "auto-cidr"
		}
		if err := add("status", "tcp", port, port, "", protection, "cloudflare", nil); err != nil {
			return nil, nil, nil, err
		}
	}
	mode := textDefault(ingress["subscription_endpoint_mode"], "separate")
	if host := strings.TrimSpace(textValue(ingress["subscription_hostname"])); SubscriptionEndpointEnabled(config) && host != "" && (mode == "separate" || mode == "direct" || mode == "direct-and-cdn") {
		port, portErr := integerDefault(ingress["subscription_listen_port"], 443)
		if portErr != nil {
			return nil, nil, nil, portErr
		}
		protection, provider := "none", ""
		if mode == "separate" {
			provider = textDefault(ingress["subscription_cdn_provider"], "cloudflare")
			protection = textDefault(ingress["subscription_origin_protection_mode"], "auto-cidr")
		}
		if err := add("subscription:"+mode, "tcp", port, port, "", protection, provider, stringSlice(ingress["subscription_origin_allowed_cidrs"])); err != nil {
			return nil, nil, nil, err
		}
	}

	// Rules form a union at the socket; Nginx enforces each virtual host's
	// source boundary. An open Reality/direct endpoint does not bypass that check.
	if err := ValidateSharedIngress(config); err != nil {
		return nil, nil, nil, err
	}
	shared := SharedOriginPorts(config)
	for index := range candidates {
		if shared[candidates[index].publicPort] && candidates[index].sourceList == "SB_CLOUDFLARE_V4" {
			candidates[index].sourceList = "SB_CDN_CLOUDFLARE_V4"
		}
	}
	unique := make(map[string]routerOSPublicIngressCandidate)
	for _, candidate := range candidates {
		key := strings.Join([]string{candidate.protocol, strconv.Itoa(candidate.publicPort), strconv.Itoa(candidate.publicPortEnd), strconv.Itoa(candidate.targetPort), candidate.destination, candidate.sourceList}, "\x00")
		if existing, ok := unique[key]; ok {
			existing.identity += "+" + candidate.identity
			unique[key] = existing
		} else {
			unique[key] = candidate
		}
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]RouterOSPublicIngress, 0, len(keys))
	for _, canonical := range keys {
		candidate := unique[canonical]
		digest := sha256.Sum256([]byte(canonical))
		result = append(result, RouterOSPublicIngress{
			Key: hex.EncodeToString(digest[:])[:16], Protocol: candidate.protocol,
			PublicPort: candidate.publicPort, PublicPortEnd: candidate.publicPortEnd, TargetPort: candidate.targetPort,
			DestinationAddress: candidate.destination, SourceAddressList: candidate.sourceList,
			GuardForeignUDP: candidate.guardForeignUDP,
		})
	}
	listNames := make([]string, 0, len(sourceLists))
	for name := range sourceLists {
		listNames = append(listNames, name)
	}
	sort.Strings(listNames)
	lists := make([]RouterOSPublicSourceList, 0, len(listNames))
	for _, name := range listNames {
		lists = append(lists, sourceLists[name])
	}
	return result, lists, sortedUniqueStrings(trusted), nil
}

var routerOSPublicDNSServers = map[string][]string{
	"cloudflare": {"1.1.1.1", "1.0.0.1"},
	"google":     {"8.8.8.8", "8.8.4.4"},
	"yandex":     {"77.88.8.8", "77.88.8.1"},
	"quad9":      {"9.9.9.9", "149.112.112.112"},
}

var routerOSPublicDNSDoHURLs = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/dns-query",
	"yandex":     "https://common.dot.dns.yandex.net/dns-query",
	"quad9":      "https://dns.quad9.net/dns-query",
}

func routerOSWireGuardExits(networking map[string]any) ([]RouterOSWireGuardExit, error) {
	if networking["wireguard_egress_enabled"] != true {
		return nil, nil
	}
	base := binary.BigEndian.Uint32(netip.MustParseAddr("198.18.0.0").AsSlice())
	const poolSize = uint32(1<<17) - 2
	result := make([]RouterOSWireGuardExit, 0)
	seenIDs, seenSources := make(map[string]struct{}), make(map[string]struct{})
	for _, item := range enabledObjects(networking["wireguard_egress_exits"]) {
		id := strings.ToLower(textValue(item["id"]))
		if !routerOSWireGuardIDPattern.MatchString(id) {
			return nil, fmt.Errorf("WireGuard egress id %q is invalid", id)
		}
		if _, exists := seenIDs[id]; exists {
			return nil, fmt.Errorf("duplicate WireGuard egress id %q", id)
		}
		seenIDs[id] = struct{}{}
		name := textValue(item["interface"])
		if !routerOSNamePattern.MatchString(name) {
			return nil, fmt.Errorf("WireGuard egress %q has an unsafe interface name", id)
		}
		digest := sha256.Sum256([]byte(id))
		offset := uint32(1) + binary.BigEndian.Uint32(digest[:4])%poolSize
		bytes := make([]byte, 4)
		binary.BigEndian.PutUint32(bytes, base+offset)
		source, ok := netip.AddrFromSlice(bytes)
		if !ok {
			return nil, errors.New("could not allocate WireGuard source identity")
		}
		if _, exists := seenSources[source.String()]; exists {
			return nil, errors.New("WireGuard source identity collision")
		}
		seenSources[source.String()] = struct{}{}
		result = append(result, RouterOSWireGuardExit{
			ID: id, Tag: "wg-egress-" + id, Interface: name, SourceAddress: source.String(),
			RoutingTable: "sb-wg-" + hex.EncodeToString(digest[:])[:12],
		})
	}
	return result, nil
}

func splitRouterOSCIDRs(values []string) ([]string, []string, error) {
	v4, v6 := make([]string, 0), make([]string, 0)
	seen := make(map[string]struct{})
	for _, raw := range values {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		value := prefix.Masked().String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		if prefix.Addr().Is4() {
			v4 = append(v4, value)
		} else {
			v6 = append(v6, value)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6, nil
}

func requiredPort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("invalid port")
	}
	return port, nil
}

func uniqueInts(values []int) []int {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}
