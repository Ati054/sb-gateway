package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type routerOSDiscoveryFunc func(context.Context, map[string]any) (map[string]any, error)

type routerOSInventoryQuery struct {
	name string
	path string
}

const routerOSContainerInventoryPath = "/rest/container?.proplist=.id,name,comment,interface,root-dir,healthy,healthcheck-status,memory-current,memory-high,memory-max,cpu-usage,restart-count,start-on-boot,restart-policy,tag,remote-image,status"

var routerOSInventoryQueries = []routerOSInventoryQuery{
	{"update", "/rest/system/package/update"},
	{"containers", routerOSContainerInventoryPath},
	{"ipv6_settings", "/rest/ipv6/settings"},
	{"interface_members", "/rest/interface/list/member?.proplist=list,interface,disabled,comment"},
	{"dhcp_clients", "/rest/ip/dhcp-client?.proplist=interface,disabled,status,comment"},
	{"ipv4_addresses", "/rest/ip/address?.proplist=address,network,interface,disabled,invalid,dynamic,comment"},
	{"ipv6_addresses", "/rest/ipv6/address?.proplist=address,interface,disabled,invalid,dynamic,comment"},
	{"ipv4_routes", "/rest/ip/route?.proplist=dst-address,gateway,immediate-gw,routing-table,disabled,dynamic,active,comment"},
	{"ipv6_routes", "/rest/ipv6/route?.proplist=dst-address,gateway,immediate-gw,routing-table,disabled,dynamic,active,comment"},
	{"dhcp_leases", "/rest/ip/dhcp-server/lease?.proplist=.id,address,mac-address,host-name,server,dynamic,disabled,comment"},
	{"wireguard_interfaces", "/rest/interface/wireguard?.proplist=.id,name,disabled,comment"},
	{"wireguard_peers", "/rest/interface/wireguard/peers?.proplist=.id,name,allowed-address,interface,disabled,comment,last-handshake,rx,tx"},
	{"ppp_secrets", "/rest/ppp/secret?.proplist=.id,name,remote-address,service,profile,disabled,comment"},
}

func (server *Server) routerOSDiscover(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	if !routerOSCredentialsConfigured(config, server.secrets) {
		server.writeErrorResponse(response, request, http.StatusConflict, "routeros_not_configured", "RouterOS HTTPS REST connection is not configured.")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	discovery, err := server.discoverRouterOS(ctx, config)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusBadGateway, "routeros_unavailable", "RouterOS discovery is unavailable.")
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{"routeros": redactValue(discovery, "", false)})
}

func (server *Server) routerOSContainerStatus(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	if !routerOSCredentialsConfigured(config, server.secrets) {
		server.writeErrorResponse(response, request, http.StatusConflict, "routeros_not_configured", "RouterOS HTTPS REST connection is not configured.")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	container, err := server.discoverRouterOSContainer(ctx, config)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusBadGateway, "routeros_unavailable", "RouterOS container status is unavailable.")
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{"container": redactValue(container, "", false)})
}

func (server *Server) fetchRouterOSContainer(ctx context.Context, config map[string]any) (map[string]any, error) {
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		return nil, err
	}
	defer stack.REST.CloseIdleConnections()
	rows, err := stack.REST.List(ctx, routerOSContainerInventoryPath)
	if err != nil {
		return nil, errors.New("RouterOS container inventory is unavailable")
	}
	managed, rollback := managedContainers(rows)
	return containerSummary(managed, rollback, true), nil
}

func (server *Server) fetchRouterOSDiscovery(ctx context.Context, config map[string]any) (map[string]any, error) {
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		return nil, err
	}
	defer stack.REST.CloseIdleConnections()
	resources, err := stack.REST.List(ctx, "/rest/system/resource")
	if err != nil || len(resources) == 0 {
		return nil, errors.New("RouterOS resource inventory is unavailable")
	}
	inventory := map[string][]map[string]any{"resources": resources}
	complete := make(map[string]bool, len(routerOSInventoryQueries))
	tasks := make(chan routerOSInventoryQuery)
	var wait sync.WaitGroup
	var mu sync.Mutex
	workers := 4
	if len(routerOSInventoryQueries) < workers {
		workers = len(routerOSInventoryQueries)
	}
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for query := range tasks {
				rows, queryErr := stack.REST.List(ctx, query.path)
				mu.Lock()
				if queryErr == nil {
					inventory[query.name] = rows
					complete[query.name] = true
				} else {
					inventory[query.name] = []map[string]any{}
					complete[query.name] = false
				}
				mu.Unlock()
			}
		}()
	}
	for _, query := range routerOSInventoryQueries {
		select {
		case tasks <- query:
		case <-ctx.Done():
			close(tasks)
			wait.Wait()
			return nil, ctx.Err()
		}
	}
	close(tasks)
	wait.Wait()
	return buildRouterOSDiscovery(inventory, complete), nil
}

func buildRouterOSDiscovery(inventory map[string][]map[string]any, complete map[string]bool) map[string]any {
	resource := firstRow(inventory["resources"])
	rawVersion := strings.TrimSpace(text(resource["version"]))
	version := strings.Fields(rawVersion)
	detectedVersion := ""
	if len(version) != 0 {
		detectedVersion = version[0]
	}
	update := firstRow(inventory["update"])
	addresses := append(append([]map[string]any{}, inventory["ipv4_addresses"]...), inventory["ipv6_addresses"]...)
	routes := append(append([]map[string]any{}, inventory["ipv4_routes"]...), inventory["ipv6_routes"]...)
	wanInterfaces := map[string]bool{}
	lanInterfaces := map[string]bool{}
	wireGuardInterfaces := map[string]bool{}
	for _, row := range inventory["wireguard_interfaces"] {
		if name := text(row["name"]); name != "" {
			wireGuardInterfaces[name] = true
		}
	}
	for _, row := range inventory["interface_members"] {
		if restBool(row["disabled"]) {
			continue
		}
		switch {
		case strings.EqualFold(text(row["list"]), "wan"):
			wanInterfaces[text(row["interface"])] = true
		case strings.EqualFold(text(row["list"]), "lan"):
			lanInterfaces[text(row["interface"])] = true
		case strings.EqualFold(text(row["list"]), "wireguard"):
			wireGuardInterfaces[text(row["interface"])] = true
		}
	}
	for _, row := range inventory["dhcp_clients"] {
		if !restBool(row["disabled"]) {
			wanInterfaces[text(row["interface"])] = true
		}
	}
	networkSet, routerAddressSet, lanSourceSet := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, row := range addresses {
		if restBool(row["disabled"]) || restBool(row["invalid"]) || projectOwned(row) {
			continue
		}
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(text(row["address"]))); err == nil {
			interfaceName := text(row["interface"])
			routerAddressSet[prefix.String()] = true
			if usablePrefix(prefix.Masked()) && !wanInterfaces[interfaceName] {
				networkSet[prefix.Masked().String()] = true
			}
			if prefix.Addr().Is4() && prefix.Bits() < 32 && usablePrefix(prefix.Masked()) && lanInterfaces[interfaceName] && !wanInterfaces[interfaceName] && !wireGuardInterfaces[interfaceName] {
				lanSourceSet[prefix.Masked().String()] = true
			}
		}
	}
	access := make([]any, 0)
	for _, row := range routes {
		if restBool(row["disabled"]) || projectOwned(row) || text(row["routing-table"]) != "" && text(row["routing-table"]) != "main" {
			continue
		}
		prefix, err := netip.ParsePrefix(strings.TrimSpace(text(row["dst-address"])))
		if err != nil || !usablePrefix(prefix.Masked()) {
			continue
		}
		gateway := firstNonempty(text(row["immediate-gw"]), text(row["gateway"]))
		if routeUsesInterface(gateway, wanInterfaces) || restBool(row["dynamic"]) && !internalPrefix(prefix) {
			continue
		}
		networkSet[prefix.Masked().String()] = true
		if !restBoolFalse(row, "active") {
			continue
		}
		access = append(access, map[string]any{"cidr": prefix.Masked().String(), "source_type": "route", "comment": text(row["comment"])})
	}
	lan := staticLANClients(inventory["dhcp_leases"])
	wireguard := wireGuardClients(inventory["wireguard_interfaces"], inventory["wireguard_peers"])
	wireguardEgress := wireGuardEgressCandidates(inventory["wireguard_interfaces"], inventory["wireguard_peers"], inventory["ipv4_routes"])
	ppp := pppClients(inventory["ppp_secrets"])
	containers := inventory["containers"]
	managed, rollback := managedContainers(containers)
	ipv6Settings := firstRow(inventory["ipv6_settings"])
	ipv6AddressCount, ipv6Defaults := 0, 0
	for _, row := range inventory["ipv6_addresses"] {
		if !restBool(row["disabled"]) {
			ipv6AddressCount++
		}
	}
	for _, row := range inventory["ipv6_routes"] {
		if text(row["dst-address"]) == "::/0" && !restBool(row["disabled"]) && restBoolFalse(row, "active") {
			ipv6Defaults++
		}
	}
	sort.Slice(access, func(left, right int) bool {
		return text(access[left].(map[string]any)["cidr"]) < text(access[right].(map[string]any)["cidr"])
	})
	return map[string]any{
		"detected_version": detectedVersion, "channel": nullableText(update["channel"]),
		"architecture":  nullableText(firstNonempty(text(resource["architecture-name"]), text(resource["architecture"]))),
		"release_label": nullableText(rawVersion), "networks": sortedBoolKeys(networkSet), "router_addresses": sortedBoolKeys(routerAddressSet),
		"lan_source_cidrs": lanSourceCIDRs(lanSourceSet), "lan_source_inventory_complete": complete["interface_members"] && complete["ipv4_addresses"] && complete["wireguard_interfaces"],
		"client_sources":                   map[string]any{"lan": lan, "wireguard": wireguard, "ppp-vpn": ppp},
		"client_source_inventory_complete": map[string]any{"lan": complete["dhcp_leases"], "wireguard": complete["wireguard_interfaces"] && complete["wireguard_peers"], "ppp-vpn": complete["ppp_secrets"]},
		"access_destinations":              access, "access_destination_inventory_complete": complete["ipv4_routes"] && complete["ipv6_routes"],
		"container":                           containerSummary(managed, rollback, complete["containers"]),
		"ipv6":                                map[string]any{"settings_available": len(ipv6Settings) != 0, "disabled": optionalRestBool(ipv6Settings["disable-ipv6"]), "address_count": ipv6AddressCount, "active_default_route_count": ipv6Defaults, "inventory_complete": complete["ipv6_addresses"] && complete["ipv6_routes"]},
		"wireguard_egress_inventory_complete": complete["wireguard_interfaces"] && complete["wireguard_peers"] && complete["ipv4_routes"],
		"wireguard_egress_candidates":         wireguardEgress,
	}
}

func lanSourceCIDRs(values map[string]bool) []any {
	items := sortedBoolKeys(values)
	result := make([]any, len(items))
	for index := range items {
		result[index] = items[index]
	}
	return result
}

func staticLANClients(rows []map[string]any) []any {
	result := make([]any, 0)
	for _, row := range rows {
		if restBool(row["dynamic"]) || restBool(row["disabled"]) || projectOwned(row) {
			continue
		}
		cidr := hostCIDR(text(row["address"]))
		if cidr == "" {
			continue
		}
		result = append(result, map[string]any{"id": "dhcp:" + firstNonempty(text(row["server"]), "static") + ":" + cidr, "cidr": cidr, "address": strings.Split(cidr, "/")[0], "hostname": text(row["host-name"]), "mac_address": text(row["mac-address"]), "server": text(row["server"]), "comment": text(row["comment"]), "label": firstNonempty(text(row["comment"]), text(row["host-name"]), text(row["mac-address"]), cidr)})
	}
	return result
}

func wireGuardClients(interfaces, peers []map[string]any) []any {
	enabled := map[string]bool{}
	for _, row := range interfaces {
		if !restBool(row["disabled"]) && !projectOwned(row) {
			enabled[text(row["name"])] = true
		}
	}
	result := make([]any, 0)
	for index, row := range peers {
		name := text(row["interface"])
		if !enabled[name] || restBool(row["disabled"]) || projectOwned(row) {
			continue
		}
		cidrs := make([]string, 0)
		for _, token := range strings.Split(text(row["allowed-address"]), ",") {
			if prefix, err := netip.ParsePrefix(strings.TrimSpace(token)); err == nil && prefix.Addr().Is4() && prefix.Bits() != 0 && usablePrefix(prefix) {
				cidrs = append(cidrs, prefix.Masked().String())
			}
		}
		if len(cidrs) == 0 {
			continue
		}
		sort.Strings(cidrs)
		ref := firstNonempty(text(row[".id"]), fmt.Sprintf("%s:%d", name, index))
		result = append(result, map[string]any{"id": "wireguard-peer:" + ref, "peer_ref": ref, "cidr": cidrs[0], "source_cidrs": stringAnySlice(cidrs), "address": strings.Split(cidrs[0], "/")[0], "interface": name, "peer_name": text(row["name"]), "label": firstNonempty(text(row["name"]), name), "comment": text(row["comment"]), "disabled": false, "valid": true, "validation_message": ""})
	}
	return result
}

func wireGuardEgressCandidates(interfaces, peers, routes []map[string]any) []any {
	interfaceRows := make(map[string]map[string]any)
	interfaceNames := make([]string, 0)
	for _, row := range interfaces {
		name := strings.TrimSpace(text(row["name"]))
		if name == "" {
			continue
		}
		if _, exists := interfaceRows[name]; !exists {
			interfaceNames = append(interfaceNames, name)
		}
		interfaceRows[name] = row
	}
	sort.Strings(interfaceNames)

	peersByInterface := make(map[string][]map[string]any)
	for _, row := range peers {
		if projectOwned(row) {
			continue
		}
		name := text(row["interface"])
		if _, exists := interfaceRows[name]; exists {
			peersByInterface[name] = append(peersByInterface[name], row)
		}
	}

	routesByInterface := make(map[string][]map[string]any)
	for _, row := range routes {
		if restBool(row["disabled"]) || projectOwned(row) || text(row["dst-address"]) != "0.0.0.0/0" {
			continue
		}
		if name := wireGuardRouteInterface(row, interfaceNames); name != "" {
			routesByInterface[name] = append(routesByInterface[name], row)
		}
	}

	result := make([]any, 0, len(interfaceNames))
	for _, name := range interfaceNames {
		row := interfaceRows[name]
		allPeers := peersByInterface[name]
		enabledPeers := make([]map[string]any, 0, len(allPeers))
		defaultPeers := make([]map[string]any, 0, len(allPeers))
		for _, peer := range allPeers {
			if restBool(peer["disabled"]) {
				continue
			}
			enabledPeers = append(enabledPeers, peer)
			if peerHasIPv4Default(peer) {
				defaultPeers = append(defaultPeers, peer)
			}
		}

		routeTables, activeRouteTables := map[string]bool{}, map[string]bool{}
		for _, route := range routesByInterface[name] {
			table := firstNonempty(text(route["routing-table"]), "main")
			routeTables[table] = true
			if restBoolFalse(route, "active") {
				activeRouteTables[table] = true
			}
		}

		disabled := restBool(row["disabled"])
		peerIsUnambiguous := len(enabledPeers) == 1 || len(defaultPeers) == 1
		eligible := !disabled && peerIsUnambiguous
		reason := "ready"
		switch {
		case disabled:
			reason = "interface_disabled"
		case len(allPeers) == 0:
			reason = "no_peer"
		case len(enabledPeers) == 0:
			reason = "no_enabled_peer"
		case !peerIsUnambiguous:
			reason = "ambiguous_peers"
		case len(defaultPeers) == 0:
			reason = "will_prepare"
		}

		result = append(result, map[string]any{
			"interface":                   name,
			"label":                       firstNonempty(text(row["comment"]), name),
			"comment":                     text(row["comment"]),
			"disabled":                    disabled,
			"peer_count":                  len(allPeers),
			"enabled_peer_count":          len(enabledPeers),
			"default_peer_count":          len(defaultPeers),
			"default_route_tables":        stringAnySlice(sortedBoolKeysAsStrings(routeTables)),
			"active_default_route_tables": stringAnySlice(sortedBoolKeysAsStrings(activeRouteTables)),
			"eligible":                    eligible,
			"reason":                      reason,
		})
	}
	return result
}

func peerHasIPv4Default(row map[string]any) bool {
	for _, token := range strings.Split(text(row["allowed-address"]), ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(token))
		if err == nil && prefix.Addr().Is4() && prefix.Bits() == 0 {
			return true
		}
	}
	return false
}

func wireGuardRouteInterface(row map[string]any, interfaceNames []string) string {
	values := []string{text(row["immediate-gw"]), text(row["gateway"])}
	for _, value := range values {
		for _, name := range interfaceNames {
			if value == name || strings.HasSuffix(value, "%"+name) || strings.HasPrefix(value, name+"@") {
				return name
			}
		}
	}
	return ""
}

func sortedBoolKeysAsStrings(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func pppClients(rows []map[string]any) []any {
	result := make([]any, 0)
	for _, row := range rows {
		if restBool(row["disabled"]) || projectOwned(row) {
			continue
		}
		cidr := hostCIDR(text(row["remote-address"]))
		if cidr == "" {
			continue
		}
		service := firstNonempty(strings.ToLower(text(row["service"])), "any")
		result = append(result, map[string]any{"id": "ppp:" + service + ":" + text(row["name"]) + ":" + cidr, "cidr": cidr, "address": strings.Split(cidr, "/")[0], "account": text(row["name"]), "service": service, "profile": text(row["profile"]), "comment": text(row["comment"])})
	}
	return result
}

func managedContainers(rows []map[string]any) (map[string]any, map[string]any) {
	var managed, rollback map[string]any
	for _, row := range rows {
		comment := text(row["comment"])
		if comment == "SB-GATEWAY container rollback" || comment == "SB-GATEWAY rollback container" {
			rollback = row
		} else if comment == "SB-GATEWAY container" || managed == nil && (strings.HasPrefix(comment, "SB-GATEWAY") || strings.HasPrefix(text(row["name"]), "sb-gateway")) {
			managed = row
		}
	}
	return managed, rollback
}

func containerSummary(row, rollback map[string]any, inventoryAvailable bool) map[string]any {
	healthy := optionalRestBool(row["healthy"])
	if healthy == nil {
		status := strings.ToLower(strings.TrimSpace(text(row["healthcheck-status"])))
		if status != "" {
			healthy = strings.HasPrefix(status, "good")
		}
	}
	return map[string]any{"inventory_available": inventoryAvailable, "present": row != nil, "name": nullableText(row["name"]), "root_dir": nullableText(row["root-dir"]), "interface": nullableText(row["interface"]), "healthy": healthy, "healthcheck_status": nullableText(row["healthcheck-status"]), "memory_current_bytes": row["memory-current"], "memory_high": row["memory-high"], "memory_max": row["memory-max"], "cpu_usage_percent": row["cpu-usage"], "restart_count": row["restart-count"], "start_on_boot": optionalRestBool(row["start-on-boot"]), "restart_policy": nullableText(row["restart-policy"]), "tag": nullableText(row["tag"]), "remote_image": nullableText(row["remote-image"]), "status": nullableText(row["status"]), "rollback_retained": rollback != nil, "rollback_root_dir": nullableText(rollback["root-dir"])}
}

func firstRow(rows []map[string]any) map[string]any {
	if len(rows) == 0 {
		return map[string]any{}
	}
	return rows[0]
}
func projectOwned(row map[string]any) bool {
	return strings.HasPrefix(strings.TrimSpace(text(row["comment"])), "SB-GATEWAY")
}
func restBool(value any) bool {
	return value == true || strings.EqualFold(text(value), "true") || text(value) == "yes"
}
func restBoolFalse(row map[string]any, key string) bool {
	value, exists := row[key]
	return !exists || restBool(value)
}
func optionalRestBool(value any) any {
	if value == nil || text(value) == "" {
		return nil
	}
	return restBool(value)
}
func nullableText(value any) any {
	if result := strings.TrimSpace(text(value)); result != "" {
		return result
	}
	return nil
}
func hostCIDR(value string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() {
		return ""
	}
	if address.Is4() {
		return address.String() + "/32"
	}
	return address.String() + "/128"
}
func usablePrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Bits() != 0 && !prefix.Addr().IsUnspecified() && !prefix.Addr().IsLoopback() && !prefix.Addr().IsMulticast()
}
func internalPrefix(prefix netip.Prefix) bool {
	address := prefix.Addr()
	return address.IsPrivate() || address.IsLinkLocalUnicast()
}
func routeUsesInterface(gateway string, interfaces map[string]bool) bool {
	for name := range interfaces {
		if gateway == name || strings.HasSuffix(gateway, "%"+name) || strings.HasSuffix(gateway, "@"+name) {
			return true
		}
	}
	return false
}
func sortedBoolKeys(values map[string]bool) []any {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return stringAnySlice(keys)
}
