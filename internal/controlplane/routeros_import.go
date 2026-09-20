package controlplane

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var routerOSVersionPattern = regexp.MustCompile(`(?im)^#\s*(?:.*?\bRouterOS\s+)?(7\.\d+(?:\.\d+)?(?:[A-Za-z]+\d*)?)\b`)

type routerOSExportCommand struct {
	section    string
	properties map[string]string
}

type routerOSImportFacts struct {
	version            string
	channel            string
	interfaces         map[string]bool
	networks           map[string]bool
	routerAddresses    map[string]bool
	managementIngress  map[string]bool
	managementNetworks map[string]bool
	managedTopology    map[string]any
	warnings           []map[string]any
	warningCodes       []string
	managedLines       int
	fingerprint        string
}

func (server *Server) importRouterOSExport(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	exportText, ok := body["export_text"].(string)
	if !ok {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "missing_export", "Provide JSON field export_text with a UTF-8 RouterOS export.")
		return
	}
	facts, err := parseRouterOSExport(exportText)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "unsafe_routeros_export", err.Error())
		return
	}

	server.configMu.Lock()
	defer server.configMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	router := objectAt(config, "routeros")
	if facts.version != "" {
		router["detected_version"] = facts.version
	}
	if facts.channel != "" {
		router["channel"] = facts.channel
	}
	router["router_addresses"] = sortedStringsAny(facts.routerAddresses)

	existing := configuredNetworkPrefixes(config)
	previousStatuses := reviewedNetworkStatuses(router)
	inventory := make([]any, 0, len(facts.networks))
	suggestions := make([]any, 0, len(facts.networks))
	for _, cidr := range sortedStrings(facts.networks) {
		candidate, _ := netip.ParsePrefix(cidr)
		status := previousStatuses[cidr]
		if prefixCovered(candidate, existing) {
			status = "accepted"
		} else if status != "accepted" && status != "ignored" {
			status = "pending"
		}
		inventory = append(inventory, map[string]any{"cidr": cidr, "status": status})
		if status == "pending" {
			suggestions = append(suggestions, cidr)
		}
	}
	topology := suggestRouterOSTopology(facts.networks, facts.interfaces, facts.managedTopology)
	router["import_review"] = map[string]any{
		"source_fingerprint":             facts.fingerprint,
		"imported_at":                    server.now().UTC().Format("2006-01-02T15:04:05.999999Z"),
		"networks":                       inventory,
		"management_ingress_suggestions": sortedStringsAny(facts.managementIngress),
		"management_network_suggestions": sortedStringsAny(facts.managementNetworks),
		"posture_warnings":               stringAnySlice(facts.warningCodes),
		"topology_suggestions":           topology,
	}
	config["routeros"] = router
	objectAt(config, "system")["deployment_ready"] = false
	validation := validateCurrentConfig(config)
	if !validation.Valid {
		server.writeValidationError(response, request, validation)
		return
	}
	revision, err := server.repository.saveDraft(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.rememberValidation(validation)
	sourceName := strings.TrimSpace(text(body["source_name"]))
	if len(sourceName) > 255 {
		sourceName = sourceName[:255]
	}
	server.audit(request, text(payload["sub"]), "routeros.import", "ok", map[string]any{
		"source_name": sourceName, "source_fingerprint": facts.fingerprint,
		"network_suggestions": len(suggestions), "posture_warnings": facts.warningCodes,
	})
	warnings := make([]any, 0, len(facts.warningCodes)+1)
	if len(suggestions) != 0 {
		warnings = append(warnings, "Classify every imported RouterOS network before Apply.")
	}
	for _, code := range facts.warningCodes {
		warnings = append(warnings, code)
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"ok": true, "discovered": facts.document(), "sanitized": true,
		"warnings": warnings, "network_suggestions": suggestions, "network_inventory": inventory,
		"management_ingress_suggestions": sortedStringsAny(facts.managementIngress),
		"management_network_suggestions": sortedStringsAny(facts.managementNetworks),
		"topology_suggestions":           topology, "draft_revision": revision,
	})
}

func parseRouterOSExport(value string) (*routerOSImportFacts, error) {
	if len([]byte(value)) > maxRequestBytes {
		return nil, fmt.Errorf("RouterOS export exceeds the 2 MiB import limit")
	}
	commands := routerOSExportCommands(value)
	if strings.Contains(strings.ToLower(value), "show-sensitive=yes") || routerOSExportContainsSecrets(commands) {
		return nil, fmt.Errorf("export contains secrets; create it with plain /export and without show-sensitive")
	}
	facts := &routerOSImportFacts{
		interfaces: map[string]bool{}, networks: map[string]bool{}, routerAddresses: map[string]bool{},
		managementIngress: map[string]bool{}, managementNetworks: map[string]bool{}, managedTopology: map[string]any{},
		fingerprint: fmt.Sprintf("%x", sha256.Sum256([]byte(value))),
	}
	warningSet := map[string]bool{}
	addWarning := func(code, message string) {
		if warningSet[code] {
			return
		}
		warningSet[code] = true
		facts.warningCodes = append(facts.warningCodes, code)
		facts.warnings = append(facts.warnings, map[string]any{"code": code, "message": message})
	}
	interfaceNetworks := map[string]map[string]bool{}
	wanInterfaces := map[string]bool{}
	for _, command := range commands {
		section, properties := command.section, command.properties
		owned := exportProjectOwned(properties)
		if owned {
			switch section {
			case "/interface bridge":
				setString(facts.managedTopology, "bridge_name", properties["name"])
			case "/interface veth":
				setString(facts.managedTopology, "veth_name", properties["name"])
				setString(facts.managedTopology, "container_address", properties["address"])
				setString(facts.managedTopology, "routeros_gateway", properties["gateway"])
			case "/ip address":
				if prefix, ok := parsePrefixOrAddress(properties["address"]); ok {
					facts.managedTopology["routeros_address"] = prefix.String()
					facts.managedTopology["routeros_gateway"] = prefix.Addr().String()
					facts.managedTopology["container_dns"] = prefix.Addr().String()
				}
			case "/container envs":
				if properties["key"] == "SB_TUN_ADDRESS" {
					setString(facts.managedTopology, "tun_address", properties["value"])
				}
			}
		}
		for _, key := range []string{"interface", "bridge"} {
			name := properties[key]
			if resolvedInterfaceName(name) {
				facts.interfaces[name] = true
			} else if strings.HasPrefix(name, "*") {
				addWarning("unresolved_interface_reference", "The export contains an unresolved RouterOS *interface reference.")
			}
		}
		if sectionDefinesInterface(section) {
			for _, key := range []string{"name", "default-name"} {
				if resolvedInterfaceName(properties[key]) {
					facts.interfaces[properties[key]] = true
				}
			}
		}
		if section == "/interface list member" && !exportDisabled(properties) {
			name := properties["interface"]
			if strings.EqualFold(properties["list"], "LAN") && resolvedInterfaceName(name) {
				facts.managementIngress[name] = true
			}
			if strings.EqualFold(properties["list"], "WAN") && resolvedInterfaceName(name) {
				wanInterfaces[name] = true
			}
		}
		if section == "/ip dhcp-client" && !exportDisabled(properties) && resolvedInterfaceName(properties["interface"]) {
			wanInterfaces[properties["interface"]] = true
		}
		switch section {
		case "/ip address", "/ipv6 address":
			addExportAddressFacts(properties, facts, interfaceNetworks, !owned)
		case "/ip route", "/ipv6 route":
			if !exportDisabled(properties) && !owned {
				addNetworkTokens(facts.networks, properties["dst-address"])
			}
		case "/ip dhcp-server network", "/ipv6 pool":
			if !exportDisabled(properties) && !owned {
				addNetworkTokens(facts.networks, properties["address"])
			}
		case "/interface wireguard peers":
			if !exportDisabled(properties) && !owned {
				if containsDefaultNetwork(properties["allowed-address"]) {
					addWarning("wireguard_default_allowed_address", "An enabled WireGuard peer permits a default route (0/0).")
				}
				addNetworkTokens(facts.networks, properties["allowed-address"])
			}
		case "/ppp secret", "/ppp profile":
			addRouterAddress(facts.routerAddresses, properties["local-address"])
			addNetworkTokens(facts.networks, properties["local-address"])
			addNetworkTokens(facts.networks, properties["remote-address"])
		case "/system package update":
			facts.channel = properties["channel"]
		case "/ip socks":
			if exportTruthy(properties["enabled"]) {
				addWarning("socks_configured", "RouterOS SOCKS is enabled; verify that it is strictly scoped or disable it.")
			}
		case "/interface sstp-server server":
			if exportTruthy(properties["enabled"]) && (properties["port"] == "" || properties["port"] == "443") {
				addWarning("sstp_tcp_443_enabled", "The SSTP server is enabled on TCP 443 and may conflict with public ingress.")
			}
		}
	}
	for _, command := range commands {
		properties := command.properties
		if command.section != "/ip firewall filter" || !strings.EqualFold(properties["action"], "drop") || !exportDisabled(properties) {
			continue
		}
		chain, list, iface, comment := strings.ToLower(properties["chain"]), strings.ToLower(properties["in-interface-list"]), properties["in-interface"], strings.ToLower(properties["comment"])
		if chain == "input" && (list == "wan" || list == "!lan" || wanInterfaces[iface] || strings.Contains(comment, "not coming from lan") || strings.Contains(comment, "not from lan")) {
			addWarning("disabled_wan_input_drop", "A firewall input drop rule protecting WAN/non-LAN traffic is disabled.")
		}
		natState := strings.ToLower(properties["connection-nat-state"])
		if chain == "forward" && ((list == "wan" && (natState == "!dstnat" || strings.Contains(comment, "not dstnat") || strings.Contains(comment, "not dstnated"))) || (wanInterfaces[iface] && natState == "!dstnat")) {
			addWarning("disabled_wan_forward_drop", "A forward drop rule for non-dstnat WAN traffic is disabled.")
		}
	}
	if match := routerOSVersionPattern.FindStringSubmatch(value); len(match) == 2 {
		facts.version = match[1]
	}
	for name := range facts.managementIngress {
		for network := range interfaceNetworks[name] {
			facts.managementNetworks[network] = true
		}
	}
	facts.managedLines = strings.Count(value, "SB-GATEWAY")
	return facts, nil
}

func (facts *routerOSImportFacts) document() map[string]any {
	return map[string]any{
		"sanitized": true, "detected_version": nullableString(facts.version), "channel": nullableString(facts.channel), "architecture": nil,
		"interfaces": sortedStringsAny(facts.interfaces), "networks": sortedStringsAny(facts.networks), "router_addresses": sortedStringsAny(facts.routerAddresses),
		"management_ingress_suggestions": sortedStringsAny(facts.managementIngress), "management_network_suggestions": sortedStringsAny(facts.managementNetworks),
		"managed_topology": facts.managedTopology, "warnings": facts.warnings, "posture_warnings": facts.warnings, "managed_lines": facts.managedLines,
		"capabilities": map[string]any{}, "source_fingerprint": facts.fingerprint,
	}
}

func routerOSExportCommands(value string) []routerOSExportCommand {
	commands := make([]routerOSExportCommand, 0)
	section := ""
	parts := make([]string, 0, 2)
	flush := func() {
		if section != "" && len(parts) != 0 {
			commands = append(commands, routerOSExportCommand{section: section, properties: routerOSProperties(strings.Join(parts, " "))})
		}
		parts = parts[:0]
	}
	verbs := map[string]bool{"add": true, "set": true, "remove": true, "enable": true, "disable": true, "unset": true}
	for _, raw := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "/ ") {
			flush()
			tokens := strings.Fields(line)
			commandAt := -1
			for index := 1; index < len(tokens); index++ {
				if verbs[strings.ToLower(tokens[index])] {
					commandAt = index
					break
				}
			}
			if commandAt < 0 {
				section = strings.ToLower(line)
			} else {
				section = strings.ToLower(strings.Join(tokens[:commandAt], " "))
				parts = append(parts, strings.Join(tokens[commandAt:], " "))
				flush()
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		continued := strings.HasSuffix(line, "\\")
		if continued {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))
		}
		parts = append(parts, line)
		if !continued {
			flush()
		}
	}
	flush()
	return commands
}

func routerOSProperties(command string) map[string]string {
	result := map[string]string{}
	for index := 0; index < len(command); {
		for index < len(command) && unicode.IsSpace(rune(command[index])) {
			index++
		}
		start := index
		for index < len(command) && propertyKeyByte(command[index]) {
			index++
		}
		if start == index {
			index++
			continue
		}
		key := strings.ToLower(command[start:index])
		afterKey := index
		for index < len(command) && unicode.IsSpace(rune(command[index])) {
			index++
		}
		if index >= len(command) || command[index] != '=' {
			index = afterKey
			continue
		}
		index++
		for index < len(command) && unicode.IsSpace(rune(command[index])) {
			index++
		}
		var builder strings.Builder
		if index < len(command) && command[index] == '"' {
			index++
			for index < len(command) {
				if command[index] == '"' {
					index++
					break
				}
				if command[index] == '\\' && index+1 < len(command) {
					index++
				}
				builder.WriteByte(command[index])
				index++
			}
		} else {
			start = index
			for index < len(command) && !unicode.IsSpace(rune(command[index])) {
				index++
			}
			builder.WriteString(command[start:index])
		}
		result[key] = builder.String()
	}
	return result
}

func propertyKeyByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("_.-", rune(value))
}

func routerOSExportContainsSecrets(commands []routerOSExportCommand) bool {
	redacted := map[string]bool{"": true, "***": true, "*****": true, "<redacted>": true, "[redacted]": true, "(unknown)": true}
	for _, command := range commands {
		for key, value := range command.properties {
			secret := key == "private-key" || key == "preshared-key" || key == "secret" || key == "token" || key == "password" || strings.HasSuffix(key, "-password")
			normalized := strings.TrimSpace(value)
			if !secret || redacted[strings.ToLower(normalized)] || normalized != "" && strings.Trim(normalized, "*") == "" {
				continue
			}
			return true
		}
	}
	return false
}

func resolvedInterfaceName(value string) bool {
	if value == "" || len(value) > 63 || strings.HasPrefix(value, "*") || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z') || (value[0] >= '0' && value[0] <= '9')) {
		return false
	}
	for _, char := range value[1:] {
		if !(unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune("_.:+@ -", char)) {
			return false
		}
	}
	return true
}

func sectionDefinesInterface(section string) bool {
	if !strings.HasPrefix(section, "/interface ") {
		return false
	}
	excluded := map[string]bool{"/interface bridge port": true, "/interface bridge vlan": true, "/interface list": true, "/interface list member": true, "/interface ovpn-server server": true, "/interface sstp-server server": true, "/interface wireguard peers": true}
	return !excluded[section]
}

func exportTruthy(value string) bool {
	return strings.EqualFold(value, "yes") || strings.EqualFold(value, "true")
}
func exportDisabled(properties map[string]string) bool { return exportTruthy(properties["disabled"]) }
func exportProjectOwned(properties map[string]string) bool {
	return strings.HasPrefix(strings.TrimSpace(properties["comment"]), "SB-GATEWAY")
}
func setString(target map[string]any, key, value string) {
	if value != "" {
		target[key] = value
	}
}

func parsePrefixOrAddress(value string) (netip.Prefix, bool) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, true
	}
	if address, err := netip.ParseAddr(value); err == nil {
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return netip.PrefixFrom(address, bits), true
	}
	return netip.Prefix{}, false
}

func importUsablePrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	return prefix.IsValid() && prefix.Bits() != 0 && !address.IsUnspecified() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsMulticast()
}

func addNetworkTokens(target map[string]bool, value string) {
	for _, token := range strings.Split(value, ",") {
		if prefix, ok := parsePrefixOrAddress(token); ok {
			prefix = prefix.Masked()
			if importUsablePrefix(prefix) {
				target[prefix.String()] = true
			}
		}
	}
}

func containsDefaultNetwork(value string) bool {
	for _, token := range strings.Split(value, ",") {
		if prefix, ok := parsePrefixOrAddress(token); ok && prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

func addRouterAddress(target map[string]bool, value string) {
	if prefix, ok := parsePrefixOrAddress(value); ok {
		address := prefix.Addr()
		if !address.IsUnspecified() && !address.IsLoopback() && !address.IsMulticast() {
			bits := 128
			if address.Is4() {
				bits = 32
			}
			target[netip.PrefixFrom(address, bits).String()] = true
		}
	}
}

func addExportAddressFacts(properties map[string]string, facts *routerOSImportFacts, byInterface map[string]map[string]bool, includeNetworks bool) {
	prefix, ok := parsePrefixOrAddress(properties["address"])
	if !ok {
		return
	}
	addRouterAddress(facts.routerAddresses, properties["address"])
	if includeNetworks && importUsablePrefix(prefix.Masked()) {
		network := prefix.Masked().String()
		facts.networks[network] = true
		if name := properties["interface"]; resolvedInterfaceName(name) {
			if byInterface[name] == nil {
				byInterface[name] = map[string]bool{}
			}
			byInterface[name][network] = true
		}
	}
	if !includeNetworks || properties["network"] == "" {
		return
	}
	if strings.Contains(properties["network"], "/") {
		addNetworkTokens(facts.networks, properties["network"])
		return
	}
	peer, err := netip.ParseAddr(properties["network"])
	if err != nil {
		return
	}
	if prefix.Bits() < addressBits(prefix.Addr()) && peer == prefix.Masked().Addr() {
		return
	}
	addNetworkTokens(facts.networks, peer.String())
}

func addressBits(address netip.Addr) int {
	if address.Is4() {
		return 32
	}
	return 128
}

func sortedStrings(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
func sortedStringsAny(values map[string]bool) []any { return stringAnySlice(sortedStrings(values)) }

func configuredNetworkPrefixes(config map[string]any) []netip.Prefix {
	result := []netip.Prefix{}
	for _, raw := range anySlice(config["networks"]) {
		network, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, cidr := range anySlice(network["cidrs"]) {
			if prefix, ok := parsePrefixOrAddress(text(cidr)); ok {
				result = append(result, prefix.Masked())
			}
		}
	}
	return result
}

func reviewedNetworkStatuses(router map[string]any) map[string]string {
	result := map[string]string{}
	review, _ := router["import_review"].(map[string]any)
	for _, raw := range anySlice(review["networks"]) {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		status := text(item["status"])
		if status == "accepted" || status == "ignored" {
			result[text(item["cidr"])] = status
		}
	}
	return result
}

func prefixCovered(candidate netip.Prefix, existing []netip.Prefix) bool {
	for _, configured := range existing {
		if configured.Addr().BitLen() == candidate.Addr().BitLen() && configured.Contains(candidate.Addr()) && configured.Bits() <= candidate.Bits() {
			return true
		}
	}
	return false
}

func suggestRouterOSTopology(networks, interfaces map[string]bool, managed map[string]any) map[string]any {
	required := []string{"bridge_name", "veth_name", "routeros_gateway", "container_address"}
	complete := true
	for _, key := range required {
		if text(managed[key]) == "" {
			complete = false
		}
	}
	if complete {
		result := map[string]any{}
		for key, value := range managed {
			if text(value) != "" {
				result[key] = value
			}
		}
		if text(result["container_dns"]) == "" {
			result["container_dns"] = result["routeros_gateway"]
		}
		result["requires_live_confirmation"] = true
		result["source"] = "existing_project_export"
		return result
	}
	occupied := make([]netip.Prefix, 0, len(networks))
	for value := range networks {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			occupied = append(occupied, prefix.Masked())
		}
	}
	candidates := make([]netip.Prefix, 0, 2)
	for _, poolText := range []string{"172.31.252.0/22", "10.255.252.0/22", "192.168.252.0/22"} {
		pool := netip.MustParsePrefix(poolText)
		base := binary.BigEndian.Uint32(pool.Addr().AsSlice())
		for offset := uint32(1020); ; offset -= 4 {
			bytes := [4]byte{}
			binary.BigEndian.PutUint32(bytes[:], base+offset)
			candidate := netip.PrefixFrom(netip.AddrFrom4(bytes), 30)
			collision := false
			for _, current := range occupied {
				if prefixesOverlap(candidate, current) {
					collision = true
					break
				}
			}
			if !collision {
				candidates = append(candidates, candidate)
				occupied = append(occupied, candidate)
			}
			if len(candidates) == 2 || offset == 0 {
				break
			}
		}
		if len(candidates) == 2 {
			break
		}
	}
	if len(candidates) != 2 {
		return map[string]any{}
	}
	availableName := func(base string) string {
		if !interfaces[base] {
			return base
		}
		for suffix := 2; suffix < 100; suffix++ {
			candidate := fmt.Sprintf("%s-%d", base, suffix)
			if !interfaces[candidate] {
				return candidate
			}
		}
		return ""
	}
	bridge, veth := availableName("bridge-sb"), availableName("veth-sb")
	if bridge == "" || veth == "" {
		return map[string]any{}
	}
	containerRouter, container := candidates[0].Addr().Next(), candidates[0].Addr().Next().Next()
	tun := candidates[1].Addr().Next()
	return map[string]any{"bridge_name": bridge, "veth_name": veth, "routeros_gateway": containerRouter.String(), "routeros_address": fmt.Sprintf("%s/30", containerRouter), "container_address": fmt.Sprintf("%s/30", container), "container_dns": containerRouter.String(), "tun_address": fmt.Sprintf("%s/30", tun), "requires_live_confirmation": true, "source": "offline_nonoverlap_candidate"}
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Addr().BitLen() == right.Addr().BitLen() && (left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func anySlice(value any) []any {
	if values, ok := value.([]any); ok {
		return values
	}
	return nil
}
