package runtimeconfig

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

var xrayPrivateReservedCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/3",
	"::/127",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

var xrayPrivateReservedPrefixes = parseStaticPrefixes(xrayPrivateReservedCIDRs)

type XrayOutboundSet struct {
	Outbounds  []map[string]any
	Balancers  []map[string]any
	Selectable map[string]struct{}
}

func ConvertXrayOutbounds(
	values []map[string]any,
	directBindAddress string,
	directPrivateAllowCIDRs []string,
	reverseTags map[string]struct{},
) (XrayOutboundSet, error) {
	result := XrayOutboundSet{Selectable: make(map[string]struct{})}
	selectors := make(map[string][]string)
	for _, value := range values {
		if textValue(value["type"]) != "selector" {
			continue
		}
		tag := textValue(value["tag"])
		if tag == "" {
			continue
		}
		members := make([]string, 0)
		for _, member := range stringSlice(value["outbounds"]) {
			if member != "block" {
				members = append(members, member)
			}
		}
		selectors[tag] = members
	}

	for _, value := range values {
		kind := textValue(value["type"])
		tag := textValue(value["tag"])
		if tag == "" {
			continue
		}
		if _, reverse := reverseTags[tag]; reverse {
			continue
		}
		switch kind {
		case "selector":
			members, err := flattenXraySelector(tag, selectors, nil)
			if err != nil {
				return XrayOutboundSet{}, err
			}
			if len(members) == 0 {
				continue
			}
			result.Balancers = append(result.Balancers, map[string]any{
				"tag": tag, "selector": members, "strategy": map[string]any{"type": "random"},
			})
			result.Selectable[tag] = struct{}{}
		case "direct":
			domainStrategy := "UseIP"
			settings := map[string]any{}
			if tag == "direct-wan" && len(directPrivateAllowCIDRs) != 0 {
				domainStrategy = "AsIs"
				settings["finalRules"] = []any{
					map[string]any{"action": "allow", "network": "tcp,udp", "ip": append([]string(nil), directPrivateAllowCIDRs...)},
					map[string]any{"action": "block", "network": "tcp,udp", "ip": append([]string(nil), xrayPrivateReservedCIDRs...)},
					map[string]any{"action": "allow", "network": "tcp,udp"},
				}
			}
			outbound := map[string]any{
				"tag": tag, "protocol": "freedom", "settings": settings,
				"streamSettings": map[string]any{
					"sockopt": map[string]any{"domainStrategy": domainStrategy},
				},
			}
			bind := textValue(value["inet4_bind_address"])
			if bind == "" && tag == "direct-wan" {
				bind = directBindAddress
			}
			if bind != "" {
				outbound["sendThrough"] = bind
			}
			result.Outbounds = append(result.Outbounds, outbound)
		case "block":
			result.Outbounds = append(result.Outbounds, map[string]any{
				"tag": tag, "protocol": "blackhole", "settings": map[string]any{},
			})
		case "vless":
			port, err := requiredInteger(value["server_port"])
			if err != nil {
				return XrayOutboundSet{}, fmt.Errorf("outbound %q server_port: %w", tag, err)
			}
			settings := map[string]any{
				"address": textValue(value["server"]), "port": port,
				"id": textValue(value["uuid"]), "encryption": textDefault(value["encryption"], "none"),
			}
			if flow := textValue(value["flow"]); flow != "" {
				settings["flow"] = flow
			}
			stream, err := ConvertXrayStream(value, false, nil, nil)
			if err != nil {
				return XrayOutboundSet{}, fmt.Errorf("outbound %q: %w", tag, err)
			}
			result.Outbounds = append(result.Outbounds, map[string]any{
				"tag": tag, "protocol": "vless", "settings": settings, "streamSettings": stream,
			})
		case "hysteria2":
			port, err := requiredInteger(value["server_port"])
			if err != nil {
				return XrayOutboundSet{}, fmt.Errorf("outbound %q server_port: %w", tag, err)
			}
			stream := map[string]any{
				"method": "hysteria", "security": "tls",
				"hysteriaSettings": map[string]any{
					"version": 2, "auth": textValue(value["password"]), "udpIdleTimeout": 60,
				},
			}
			tls := objectValue(value["tls"])
			if len(tls) != 0 {
				tlsSettings, tlsErr := xrayClientTLSSettings(tls)
				if tlsErr != nil {
					return XrayOutboundSet{}, fmt.Errorf("selected Hysteria 2 outbound %q: %w", tag, tlsErr)
				}
				stream["tlsSettings"] = tlsSettings
			}
			if obfs := objectValue(value["obfs"]); textValue(obfs["type"]) == "salamander" {
				stream["finalmask"] = salamanderMask(textValue(obfs["password"]))
			}
			result.Outbounds = append(result.Outbounds, map[string]any{
				"tag": tag, "protocol": "hysteria",
				"settings": map[string]any{
					"version": 2, "address": textValue(value["server"]), "port": port,
				},
				"streamSettings": stream,
			})
		default:
			return XrayOutboundSet{}, fmt.Errorf("selected outbound %q has unsupported type %q", tag, kind)
		}
	}
	return result, nil
}

func DirectPrivateAllowCIDRs(values any) ([]string, error) {
	allowed := make(map[string]netip.Prefix)
	for _, rule := range objectSlice(values) {
		if textValue(rule["action"]) != "route" || textValue(rule["outbound"]) != "direct-wan" || len(stringOrList(rule["auth_user"])) == 0 {
			continue
		}
		for _, raw := range stringSlice(rule["ip_cidr"]) {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid remote private target CIDR %q", raw)
			}
			prefix = prefix.Masked()
			address := prefix.Addr()
			if address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || !withinXrayReservedPrefix(prefix) {
				continue
			}
			allowed[prefix.String()] = prefix
		}
	}
	result := make([]string, 0, len(allowed))
	for value := range allowed {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool {
		leftPrefix := allowed[result[left]]
		rightPrefix := allowed[result[right]]
		if leftPrefix.Addr().Is4() != rightPrefix.Addr().Is4() {
			return leftPrefix.Addr().Is4()
		}
		return result[left] < result[right]
	})
	return result, nil
}

func flattenXraySelector(tag string, selectors map[string][]string, trail []string) ([]string, error) {
	for _, item := range trail {
		if item == tag {
			chain := append(append([]string(nil), trail...), tag)
			return nil, fmt.Errorf("selector cycle cannot be represented safely in Xray: %s", strings.Join(chain, " -> "))
		}
	}
	members, selector := selectors[tag]
	if !selector {
		return []string{tag}, nil
	}
	nextTrail := append(append([]string(nil), trail...), tag)
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, member := range members {
		leaves, err := flattenXraySelector(member, selectors, nextTrail)
		if err != nil {
			return nil, err
		}
		for _, leaf := range leaves {
			if _, exists := seen[leaf]; exists {
				continue
			}
			seen[leaf] = struct{}{}
			result = append(result, leaf)
		}
	}
	return result, nil
}

func withinXrayReservedPrefix(value netip.Prefix) bool {
	for _, reserved := range xrayPrivateReservedPrefixes {
		if reserved.Addr().BitLen() == value.Addr().BitLen() && reserved.Bits() <= value.Bits() && reserved.Contains(value.Addr()) {
			return true
		}
	}
	return false
}

func parseStaticPrefixes(values []string) []netip.Prefix {
	result := make([]netip.Prefix, len(values))
	for index, value := range values {
		result[index] = netip.MustParsePrefix(value)
	}
	return result
}
