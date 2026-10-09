package runtimeconfig

import (
	"fmt"
	"strings"
)

func renderRouterOSManagedDNS(model RouterOSRenderModel) []string {
	disabled := "yes"
	if model.ManagedDNS {
		disabled = "no"
	}
	lines := []string{}
	// Only the shared readiness gate admits packets into this chain. DNS
	// receives a connection mark, but local traffic never gets a routing mark.
	for _, proto := range []string{"udp", "tcp"} {
		comment := "SB-GATEWAY managed DNS mark " + strings.ToUpper(proto)
		fields := fmt.Sprintf(`chain="sb-gateway-divert" action=mark-connection connection-state=new connection-mark=no-mark in-interface-list=!WAN dst-address-type=local protocol=%s dst-port=53 new-connection-mark="sb-managed" passthrough=yes disabled=%s`, proto, disabled)
		lines = append(lines,
			fmt.Sprintf(`:if ([:len [/ip/firewall/mangle/find where comment="%s"]] = 0) do={ /ip/firewall/mangle/add %s comment="%s" }`, comment, fields, comment),
			fmt.Sprintf(`:local dnsMark [/ip/firewall/mangle/find where comment="%s"]`, comment),
			`:if ([:len $dnsMark] != 1) do={ :error "SB-GATEWAY managed DNS mark missing or ambiguous" }`,
			`/ip/firewall/mangle/set $dnsMark `+fields,
		)
	}
	for _, bypass := range []struct{ name, fields string }{
		{"local", `dst-address-type=local`},
		{"internal", `dst-address-list="SB_INTERNAL_NETWORKS"`},
	} {
		comment := "SB-GATEWAY diversion " + bypass.name + " bypass"
		fields := `chain="sb-gateway-divert" action=return disabled=no ` + bypass.fields
		lines = append(lines,
			fmt.Sprintf(`:if ([:len [/ip/firewall/mangle/find where comment="%s"]] = 0) do={ /ip/firewall/mangle/add %s comment="%s" }`, comment, fields, comment),
			fmt.Sprintf(`:local dnsBypass [/ip/firewall/mangle/find where comment="%s"]`, comment),
			`:if ([:len $dnsBypass] != 1) do={ :error "SB-GATEWAY diversion bypass missing or ambiguous" }`,
			`/ip/firewall/mangle/set $dnsBypass `+fields,
		)
	}
	// Move in reverse order to keep the original endpoint bypass next.
	lines = append(lines, `:local dnsBefore $endpointBypass`)
	for _, comment := range []string{"SB-GATEWAY diversion internal bypass", "SB-GATEWAY diversion local bypass", "SB-GATEWAY managed DNS mark TCP", "SB-GATEWAY managed DNS mark UDP"} {
		lines = append(lines, fmt.Sprintf(`/ip/firewall/mangle/move [/ip/firewall/mangle/find where comment="%s"] destination=$dnsBefore`, comment))
		// Subsequent moves must precede the newly placed rule.
		lines = append(lines, fmt.Sprintf(`:set dnsBefore [/ip/firewall/mangle/find where comment="%s"]`, comment))
	}
	for _, proto := range []string{"udp", "tcp"} {
		comment := "SB-GATEWAY managed DNS " + strings.ToUpper(proto)
		fields := fmt.Sprintf(`chain=dstnat action=dst-nat src-address-list="SB_MANAGED_CLIENTS" connection-mark="sb-managed" dst-address-type=local protocol=%s dst-port=53 to-addresses="%s" to-ports=%d disabled=%s`, proto, model.ContainerIP, ManagedDNSPort, disabled)
		lines = append(lines,
			fmt.Sprintf(`:if ([:len [/ip/firewall/nat/find where comment="%s"]] = 0) do={ /ip/firewall/nat/add %s comment="%s" }`, comment, fields, comment),
			fmt.Sprintf(`:local dnsNat [/ip/firewall/nat/find where comment="%s"]`, comment),
			`:if ([:len $dnsNat] != 1) do={ :error "SB-GATEWAY managed DNS NAT missing or ambiguous" }`,
			`/ip/firewall/nat/set $dnsNat `+fields,
			`:local firstDNSNat [/ip/firewall/nat/find]; :if (([:len $firstDNSNat] > 0) && ([:pick $firstDNSNat 0 1] != $dnsNat)) do={ /ip/firewall/nat/move $dnsNat destination=[:pick $firstDNSNat 0 1] }`,
		)
	}
	return lines
}
