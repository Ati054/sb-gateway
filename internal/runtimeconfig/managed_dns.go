package runtimeconfig

import (
	"fmt"
	"net/netip"
)

const ManagedDNSPort = 1053
const managedDNSInbound = "routeros-client-dns"

// Reuse the compiler's ordered source identities. Authenticated-user and
// generic TPROXY DNS rules continue to be evaluated by Xray.
func managedDNSGoIngress(containerIP string, dnsRules []map[string]any, lanes []PolicyDNSLane) (*PolicyDNSManagedIngress, error) {
	address, err := netip.ParseAddr(containerIP)
	if err != nil || !validManagedDNSAddress(address) {
		return nil, fmt.Errorf("managed DNS requires an explicit unicast container address")
	}
	known := make(map[string]struct{}, len(lanes))
	for _, lane := range lanes {
		known[lane.ID] = struct{}{}
	}
	result := &PolicyDNSManagedIngress{
		Listeners: []PolicyDNSManagedListener{{Host: address.Unmap().String(), Port: ManagedDNSPort}},
		Rules:     make([]PolicyDNSManagedRule, 0),
	}
	for _, rule := range dnsRules {
		sources := stringSlice(rule["source"])
		if len(sources) == 0 || !containsText(stringSlice(rule["inboundTag"]), "tun-routeros") {
			continue
		}
		// Never erase a user/domain/other restriction from a source identity.
		for key := range rule {
			switch key {
			case "type", "inboundTag", "source", "network", "port", "outboundTag":
			default:
				return nil, fmt.Errorf("managed DNS source rule has unsupported condition %q", key)
			}
		}
		for _, key := range []string{"type", "network", "port", "outboundTag"} {
			if value, exists := rule[key]; exists {
				if _, ok := value.(string); !ok {
					return nil, fmt.Errorf("managed DNS source rule has a non-string %s", key)
				}
			}
		}
		if kind := textValue(rule["type"]); kind != "" && kind != "field" {
			return nil, fmt.Errorf("managed DNS requires field rules")
		}
		if network := textValue(rule["network"]); network != "" && network != "tcp,udp" && network != "udp,tcp" {
			return nil, fmt.Errorf("managed DNS source rule must apply to TCP and UDP")
		}
		if port := textValue(rule["port"]); port != "" && port != "53" {
			return nil, fmt.Errorf("managed DNS source rule has an unexpected destination port")
		}
		laneID := textValue(rule["outboundTag"])
		if _, ok := known[laneID]; !ok {
			return nil, fmt.Errorf("managed DNS source rule references an unknown lane")
		}
		prefixes := make([]string, 0, len(sources))
		switch values := rule["source"].(type) {
		case []string:
		case []any:
			if len(values) != len(sources) {
				return nil, fmt.Errorf("managed DNS source identity contains a non-string CIDR")
			}
		default:
			return nil, fmt.Errorf("managed DNS source identity is not a CIDR list")
		}
		for _, source := range sources {
			prefix, err := netip.ParsePrefix(source)
			if err != nil {
				ip, parseErr := netip.ParseAddr(source)
				if parseErr != nil || ip.Zone() != "" {
					return nil, fmt.Errorf("managed DNS has an invalid source CIDR")
				}
				prefix = netip.PrefixFrom(ip, ip.BitLen())
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, fmt.Errorf("managed DNS mapped source CIDR is ambiguous")
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			prefixes = append(prefixes, prefix.Masked().String())
		}
		result.Rules = append(result.Rules, PolicyDNSManagedRule{SourceCIDRs: prefixes, LaneID: laneID})
	}
	return result, nil
}

func validManagedDNSAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	return !address.IsUnspecified() && !address.IsMulticast() &&
		!(address.Is4() && address.As4() == [4]byte{255, 255, 255, 255})
}
