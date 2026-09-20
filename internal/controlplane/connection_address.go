package controlplane

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// One small snapshot, shared by the panel and all client export formats.
type connectionAddressCache struct {
	mu      sync.Mutex
	key     string
	expires time.Time
	value   map[string]any
}

func directConnectionTransport(transport map[string]any) bool {
	switch text(transport["kind"]) {
	case "reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2":
		return true
	}
	return false
}

func automaticConnectionAddress(transport map[string]any) bool {
	return directConnectionTransport(transport) && text(transport["hostname_mode"]) == "auto"
}

func selectConnectionAddress(addresses, routes, members []map[string]any) map[string]any {
	wan, active := map[string]bool{}, map[string]bool{}
	for _, row := range members {
		if !restBool(row["disabled"]) && strings.EqualFold(text(row["list"]), "WAN") {
			wan[text(row["interface"])] = true
		}
	}
	for _, row := range routes {
		if text(row["dst-address"]) != "0.0.0.0/0" || restBool(row["disabled"]) || !restBool(row["active"]) ||
			(text(row["routing-table"]) != "" && text(row["routing-table"]) != "main") {
			continue
		}
		for _, gateway := range strings.Split(text(row["immediate-gw"]), ",") {
			gateway = strings.TrimSpace(gateway)
			iface := gateway
			if index := strings.LastIndex(gateway, "%"); index >= 0 {
				iface = gateway[index+1:]
			}
			if wan[iface] {
				active[iface] = true
			}
		}
	}
	candidates := map[string]string{}
	owned := map[string]string{}
	localAddresses := make([]any, 0)
	for _, row := range addresses {
		iface := text(row["interface"])
		if restBool(row["disabled"]) || restBool(row["invalid"]) {
			continue
		}
		prefix, err := netip.ParsePrefix(text(row["address"]))
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsLoopback() {
			continue
		}
		if !wan[iface] {
			localAddresses = append(localAddresses, map[string]any{"address": prefix.Addr().String(), "interface": iface})
			continue
		}
		owned[prefix.Addr().String()] = iface
		if active[iface] {
			candidates[prefix.Addr().String()] = iface
		}
	}
	keys := make([]string, 0, len(owned))
	for address := range owned {
		keys = append(keys, address)
	}
	sort.Strings(keys)
	wanAddresses := make([]any, 0, len(keys))
	for _, address := range keys {
		wanAddresses = append(wanAddresses, map[string]any{"address": address, "interface": owned[address]})
	}
	result := map[string]any{"state": "unavailable", "address": "", "interface": "", "inventory_ready": true, "wan_addresses": wanAddresses, "local_addresses": localAddresses}
	if len(candidates) == 1 {
		for address, iface := range candidates {
			result["state"], result["address"], result["interface"] = "ready", address, iface
		}
	}
	if len(candidates) > 1 {
		result["state"] = "ambiguous"
	}
	return result
}

// Client hostname and NAT destination coincide only for an exact local WAN IP.
// An external router's public IP or a domain must never become our dstnat match.
func (server *Server) prepareConnectionBinding(config, transport map[string]any) error {
	if !directConnectionTransport(transport) {
		return nil
	}
	switch text(transport["hostname_mode"]) {
	case "auto":
		transport["wan_destination_address"] = ""
	case "manual":
		host := strings.TrimSpace(text(transport["hostname"]))
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is4() {
			transport["wan_destination_address"] = ""
			return nil
		}
		snapshot := server.connectionAddress(config)
		if snapshot["inventory_ready"] != true {
			return errors.New("Не удалось определить WAN-адреса MikroTik. Проверьте связь с роутером и повторите сохранение.")
		}
		transport["wan_destination_address"] = ""
		for _, raw := range collectionArray(snapshot["wan_addresses"]) {
			row, _ := raw.(map[string]any)
			if text(row["address"]) == address.String() {
				transport["wan_destination_address"] = address.String()
				break
			}
		}
	}
	return nil
}

func (server *Server) connectionAddress(config map[string]any) map[string]any {
	cache := &server.connectionAddressCache
	cache.mu.Lock()
	defer cache.mu.Unlock()
	key, _ := revisionFor(objectAt(config, "routeros"))
	if cache.key == key && server.now().Before(cache.expires) {
		return cache.value
	}
	value := map[string]any{"state": "unavailable", "address": "", "interface": ""}
	stack, err := server.newRouterOSStack(config)
	if err == nil {
		defer stack.REST.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		addresses, addressErr := stack.REST.List(ctx, "/rest/ip/address?.proplist=address,interface,disabled,invalid")
		routes, routeErr := stack.REST.List(ctx, "/rest/ip/route?.proplist=dst-address,immediate-gw,routing-table,disabled,active")
		members, memberErr := stack.REST.List(ctx, "/rest/interface/list/member?.proplist=list,interface,disabled")
		if addressErr == nil && routeErr == nil && memberErr == nil {
			value = selectConnectionAddress(addresses, routes, members)
		}
	}
	cache.key, cache.value, cache.expires = key, value, server.now().Add(30*time.Second)
	return value
}

func (server *Server) resolveConnectionTransport(config, transport map[string]any) (map[string]any, error) {
	if !automaticConnectionAddress(transport) {
		return transport, nil
	}
	snapshot := server.connectionAddress(config)
	if snapshot["state"] != "ready" {
		return nil, errors.New("WAN address is unavailable or ambiguous; select a manual connection address")
	}
	resolved := make(map[string]any, len(transport))
	for key, value := range transport {
		resolved[key] = value
	}
	resolved["hostname"] = snapshot["address"]
	return resolved, nil
}
