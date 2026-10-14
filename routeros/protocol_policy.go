package routerosassets

import (
	"fmt"
	"strings"
)

// ProtocolPolicySource reconciles only owned forwarding and diversion rules.
// Related ICMP errors are independent of the optional WAN echo exception.
func ProtocolPolicySource(containerIP string, allowPing bool) string {
	var lines []string
	type rule struct{ table, chain, label, fields string }
	var rules []rule
	add := func(table, chain, label, fields string) {
		rules = append(rules, rule{table, chain, "SB-GATEWAY protocol " + label, fields})
	}
	for _, family := range []struct {
		table, chain, proto, managed, internal, multicast string
		errors, echo                                      []int
	}{
		{"/ip/firewall/filter", "sb-gateway-protocol-v4", "icmp", "SB_MANAGED_CLIENTS", "SB_INTERNAL_NETWORKS", "224.0.0.0/4", []int{3, 11, 12}, []int{8, 0}},
		{"/ipv6/firewall/filter", "sb-gateway-protocol-v6", "icmpv6", "SB_MANAGED_CLIENTS_V6", "SB_INTERNAL_NETWORKS_V6", "ff00::/8", []int{1, 2, 3, 4}, []int{128, 129}},
	} {
		lines = append(lines, fmt.Sprintf(`:foreach pr in=[%s/find where chain="%s"] do={ :if ([:pick [%s/get $pr comment] 0 20] != "SB-GATEWAY protocol ") do={ :error "SB-GATEWAY protocol chain contains an unowned rule" } }`, family.table, family.chain, family.table))
		for _, protocol := range []string{"tcp", "udp"} {
			add(family.table, family.chain, family.proto+" "+protocol, "action=return protocol="+protocol)
		}
		scopes := []string{`src-address-list="` + family.managed + `"`, `dst-address-list="` + family.managed + `"`}
		if family.proto == "icmp" {
			scopes = append(scopes, `src-address="`+containerIP+`"`, `dst-address="`+containerIP+`"`)
		}
		for scope, fields := range scopes {
			for _, kind := range family.errors {
				add(family.table, family.chain, fmt.Sprintf("%s related %d %d", family.proto, scope, kind), fmt.Sprintf(`action=accept protocol=%s icmp-options=%d:0-255 connection-state=related %s`, family.proto, kind, fields))
			}
		}
		add(family.table, family.chain, family.proto+" multicast", `action=return dst-address="`+family.multicast+`"`)
		if family.proto == "icmp" {
			add(family.table, family.chain, "icmp broadcast", `action=accept src-address-list="SB_MANAGED_CLIENTS" dst-address-type=broadcast`)
		}
		add(family.table, family.chain, family.proto+" internal", `action=return dst-address-list="`+family.internal+`"`)
		add(family.table, family.chain, family.proto+" unmanaged", `action=return src-address-list="!`+family.managed+`"`)
		action := "drop"
		if allowPing {
			action = "accept"
		}
		for _, kind := range family.echo {
			add(family.table, family.chain, fmt.Sprintf("%s echo %d", family.proto, kind), fmt.Sprintf("action=%s protocol=%s icmp-options=%d:0-255", action, family.proto, kind))
		}
		add(family.table, family.chain, family.proto+" unsupported", "action=drop")
	}
	for _, kind := range []int{3, 11, 12} {
		add("/ip/firewall/mangle", "sb-gateway-divert", fmt.Sprintf("divert related %d", kind), fmt.Sprintf("action=return protocol=icmp icmp-options=%d:0-255 connection-state=related", kind))
	}
	disabled := "yes"
	if allowPing {
		disabled = "no"
	}
	for _, kind := range []int{8, 0} {
		add("/ip/firewall/mangle", "sb-gateway-divert", fmt.Sprintf("divert echo %d", kind), fmt.Sprintf("action=return protocol=icmp icmp-options=%d:0-255 disabled=%s", kind, disabled))
	}
	add("/ip/firewall/mangle", "sb-gateway-divert", "divert multicast", `action=return dst-address="224.0.0.0/4"`)
	add("/ip/firewall/mangle", "sb-gateway-divert", "divert broadcast", "action=return dst-address-type=broadcast")
	add("/ip/firewall/filter", "sb-gateway-forward", "forward v4 jump", `action=jump jump-target="sb-gateway-protocol-v4"`)
	add("/ipv6/firewall/filter", "forward", "forward v6 jump", `action=jump jump-target="sb-gateway-protocol-v6"`)
	for _, r := range rules {
		fields := fmt.Sprintf(`chain="%s" %s`, r.chain, r.fields)
		if !strings.Contains(r.fields, "disabled=") {
			fields += " disabled=no"
		}
		lines = append(lines,
			fmt.Sprintf(`:local pr [%s/find where comment="%s"]`, r.table, r.label),
			`:if ([:len $pr] > 1) do={ :error "SB-GATEWAY protocol rule is ambiguous" }`,
			fmt.Sprintf(`:if ([:len $pr] = 0) do={ %s/add %s comment="%s" } else={ %s/set $pr %s }`, r.table, fields, r.label, r.table, fields),
		)
	}
	for i := len(rules) - 1; i >= 0; i-- {
		r := rules[i]
		lines = append(lines, fmt.Sprintf(`:local pr [%s/find where comment="%s"]; :local first [%s/find where chain="%s"]; :if (([:len $first] > 0) && ([:pick $first 0 1] != $pr)) do={ %s/move $pr destination=[:pick $first 0 1] }`, r.table, r.label, r.table, r.chain, r.table))
	}
	return strings.Join(lines, "\n") + "\n"
}
