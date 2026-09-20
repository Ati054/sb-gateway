package controlplane

import (
	"context"
	"net/netip"
	"time"
)

const routerOSLiveNetworkInterval = 30 * time.Second

// runRouterOSLiveNetworkScheduler keeps the client-side LAN inventory current
// without turning a read-only subscription request into a RouterOS operation.
// Only the last complete, successfully discovered snapshot is published.
func (server *Server) runRouterOSLiveNetworkScheduler(ctx context.Context) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		operation, cancel := context.WithTimeout(ctx, 25*time.Second)
		_ = server.refreshRouterOSLiveNetworks(operation)
		cancel()
		timer.Reset(routerOSLiveNetworkInterval)
	}
}

func (server *Server) refreshRouterOSLiveNetworks(ctx context.Context) error {
	active, err := server.repository.loadActive()
	if err != nil || !routerOSCredentialsConfigured(active, server.secrets) {
		return err
	}
	discovery, err := server.discoverRouterOS(ctx, active)
	if err != nil {
		return err
	}
	cidrs, complete := routerOSLiveNetworkCIDRs(active, discovery)
	if !complete {
		return nil
	}
	previous, err := server.repository.auxiliary("routeros-live-networks")
	if err != nil {
		return err
	}
	if previous["complete"] == true && equalJSON(previous["cidrs"], cidrs) {
		return nil
	}
	return server.repository.saveAuxiliary("routeros-live-networks", map[string]any{
		"cidrs": cidrs, "complete": true, "refreshed_at": server.now().UTC().Format(time.RFC3339Nano),
	})
}

func routerOSLiveNetworkCIDRs(config, discovery map[string]any) ([]any, bool) {
	if discovery["access_destination_inventory_complete"] != true {
		return nil, false
	}
	excluded := make([]netip.Prefix, 0, 2)
	networking := objectCopy(objectCopy(config["system"])["networking"])
	for _, field := range []string{"container_address", "tun_address"} {
		if prefix, err := netip.ParsePrefix(text(networking[field])); err == nil && prefix.Addr().Is4() {
			excluded = append(excluded, prefix.Masked())
		}
	}
	values := make([]string, 0)
	for _, raw := range anySlice(discovery["access_destinations"]) {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		prefix, err := netip.ParsePrefix(text(item["cidr"]))
		if err != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() {
			continue
		}
		prefix = prefix.Masked()
		skip := false
		for _, reserved := range excluded {
			if prefixesOverlap(prefix, reserved) {
				skip = true
				break
			}
		}
		if !skip {
			values = append(values, prefix.String())
		}
	}
	values = sortedClientCIDRs(values)
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result, true
}

func (server *Server) withRouterOSLiveNetworks(config map[string]any) map[string]any {
	state, err := server.repository.auxiliary("routeros-live-networks")
	if err != nil || state["complete"] != true {
		return config
	}
	result := cloneJSONObject(config)
	result["routeros_live_networks"] = cloneJSONValue(state["cidrs"])
	return result
}
