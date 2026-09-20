package runtimeconfig

import (
	"fmt"
	"strconv"
)

func rosQuote(value string) string { return strconv.Quote(value) }

// Checked once during Apply, before any renderer-owned state is changed.
// Conservative overlap detection never steals another service or NAT port.
func renderRouterOSPanelPortCheck(model RouterOSRenderModel) []string {
	if model.PanelPort == 0 {
		return []string{"# Router-local panel access is not configured."}
	}
	return []string{
		fmt.Sprintf(`:local panelPort %d`, model.PanelPort),
		`:local panelPortContains do={ :local spec [:tostr $1]; :local port $2; :if ([:len $spec] = 0) do={ :return true }; :foreach item in=[:toarray $spec] do={ :local dash [:find $item "-"]; :if ([:typeof $dash] = "nil") do={ :if ([:tonum $item] = $port) do={ :return true } } else={ :local low [:tonum [:pick $item 0 $dash]]; :local high [:tonum [:pick $item ($dash + 1) [:len $item]]]; :if (($port >= $low) && ($port <= $high)) do={ :return true } } }; :return false }`,
		`:foreach service in=[/ip/service/find where disabled=no and dynamic=no] do={ :local ports [/ip/service/get $service port]; :if (([:len [:tostr $ports]] > 0) && [$panelPortContains $ports $panelPort]) do={ :error ("SB-GATEWAY panel port " . $panelPort . " conflicts with service " . [/ip/service/get $service name] . "; choose another panel port") } }`,
		`:foreach rule in=[/ip/firewall/nat/find where disabled=no] do={ :local chain [/ip/firewall/nat/get $rule chain]; :local comment [/ip/firewall/nat/get $rule comment]; :if (($chain = "dstnat") && ([:pick $comment 0 17] != "SB-GATEWAY panel ")) do={ :local protocol [:tostr [/ip/firewall/nat/get $rule protocol]]; :if (($protocol = "tcp") || ($protocol = "6") || ([:len $protocol] = 0)) do={ :local ports [/ip/firewall/nat/get $rule dst-port]; :if ([$panelPortContains $ports $panelPort]) do={ :error ("SB-GATEWAY panel port " . $panelPort . " overlaps NAT " . $rule . " " . $comment . "; choose another panel port") } } } }`,
		`:foreach rule in=[/ip/firewall/nat/find where chain="sb-gateway-panel"] do={ :local comment [/ip/firewall/nat/get $rule comment]; :if (($comment != "SB-GATEWAY panel WAN return") && ($comment != "SB-GATEWAY panel target")) do={ :error "SB-GATEWAY panel chain contains an unowned rule" } }`,
	}
}

func renderRouterOSPanelIngress(model RouterOSRenderModel) []string {
	comments := []string{"SB-GATEWAY panel LAN jump", "SB-GATEWAY panel WG jump", "SB-GATEWAY panel WAN return", "SB-GATEWAY panel target"}
	lines := []string{}
	// Missing setting is opt-in for existing installations and a precise rollback
	// target for the first Apply. Fresh installs still receive the direct :9443
	// WireGuard recovery path from install.rsc.
	if model.PanelPort == 0 {
		for _, comment := range comments {
			lines = append(lines, fmt.Sprintf(`/ip/firewall/nat/remove [find where comment=%s]`, rosQuote(comment)))
		}
		return lines
	}
	// WireGuard membership and the symmetric forward path protect both the
	// router-local port and the direct recovery endpoint on container :9443.
	lines = append(lines,
		`:if ([:len [/interface/list/find where name="SB_WIREGUARD_INGRESS"]] = 0) do={ /interface/list/add name="SB_WIREGUARD_INGRESS" comment="SB-GATEWAY WireGuard panel ingress list" }`,
		`:local panelWireGuardList [/interface/list/find where name="SB_WIREGUARD_INGRESS" and comment="SB-GATEWAY WireGuard panel ingress list"]`,
		`:if ([:len $panelWireGuardList] != 1) do={ :error "SB-GATEWAY WireGuard panel ingress interface-list is missing or ambiguous" }`,
		`:foreach member in=[/interface/list/member/find where list="SB_WIREGUARD_INGRESS"] do={ :if ([/interface/list/member/get $member comment] != "SB-GATEWAY WireGuard panel ingress") do={ :error "SB-GATEWAY refusing to alter an unowned WireGuard panel ingress member" } }`,
		`/interface/list/member/remove [find where list="SB_WIREGUARD_INGRESS" and comment="SB-GATEWAY WireGuard panel ingress"]`,
		`:foreach wireguard in=[/interface/wireguard/find where disabled=no] do={ /interface/list/member/add list="SB_WIREGUARD_INGRESS" interface=[/interface/wireguard/get $wireguard name] comment="SB-GATEWAY WireGuard panel ingress" }`,
		`:local managementDeny [/ip/firewall/filter/find where comment="SB-GATEWAY management deny"]`,
		`:local containerLanDeny [/ip/firewall/filter/find where comment="SB-GATEWAY container LAN deny"]`,
		`:if (([:len $managementDeny] != 1) || ([:len $containerLanDeny] != 1)) do={ :error "SB-GATEWAY panel forward anchors are missing or ambiguous" }`,
		`:local wireguardPanelAllow [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel allow"]`,
		`:if ([:len $wireguardPanelAllow] > 1) do={ :error "SB-GATEWAY WireGuard panel allow is ambiguous" }`,
		fmt.Sprintf(`:if ([:len $wireguardPanelAllow] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface-list="SB_WIREGUARD_INGRESS" dst-address=%s protocol=tcp dst-port=9443 place-before=$managementDeny comment="SB-GATEWAY WireGuard panel allow"; :set wireguardPanelAllow [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel allow"] }`, rosQuote(model.ContainerIP)),
		fmt.Sprintf(`/ip/firewall/filter/set $wireguardPanelAllow chain="sb-gateway-forward" action=accept in-interface-list="SB_WIREGUARD_INGRESS" dst-address=%s protocol=tcp dst-port=9443 disabled=no`, rosQuote(model.ContainerIP)),
		`:local wireguardPanelReturn [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel return"]`,
		`:if ([:len $wireguardPanelReturn] > 1) do={ :error "SB-GATEWAY WireGuard panel return is ambiguous" }`,
		fmt.Sprintf(`:if ([:len $wireguardPanelReturn] = 0) do={ /ip/firewall/filter/add chain="sb-gateway-forward" action=accept in-interface=%s out-interface-list="SB_WIREGUARD_INGRESS" src-address=%s protocol=tcp src-port=9443 connection-state=established,related connection-nat-state=dstnat place-before=$containerLanDeny comment="SB-GATEWAY WireGuard panel return"; :set wireguardPanelReturn [/ip/firewall/filter/find where comment="SB-GATEWAY WireGuard panel return"] }`, rosQuote(model.BridgeName), rosQuote(model.ContainerIP)),
		fmt.Sprintf(`/ip/firewall/filter/set $wireguardPanelReturn chain="sb-gateway-forward" action=accept in-interface=%s out-interface-list="SB_WIREGUARD_INGRESS" src-address=%s protocol=tcp src-port=9443 connection-state=established,related connection-nat-state=dstnat disabled=no`, rosQuote(model.BridgeName), rosQuote(model.ContainerIP)),
		`/ip/firewall/filter/move $wireguardPanelAllow destination=$managementDeny`,
		`/ip/firewall/filter/move $wireguardPanelReturn destination=$containerLanDeny`,
	)
	properties := []string{
		fmt.Sprintf(`chain=dstnat action=jump jump-target="sb-gateway-panel" in-interface-list="SB_MANAGEMENT_INGRESS" src-address-list="SB_MANAGEMENT_SOURCES" dst-address-type=local protocol=tcp dst-port=%d`, model.PanelPort),
		fmt.Sprintf(`chain=dstnat action=jump jump-target="sb-gateway-panel" in-interface-list="SB_WIREGUARD_INGRESS" dst-address-type=local protocol=tcp dst-port=%d`, model.PanelPort),
		`chain="sb-gateway-panel" action=return in-interface-list=WAN`,
		fmt.Sprintf(`chain="sb-gateway-panel" action=dst-nat protocol=tcp to-addresses=%s to-ports=9443`, rosQuote(model.ContainerIP)),
	}
	for index, comment := range comments {
		lines = append(lines,
			fmt.Sprintf(`:local panelRule%d [/ip/firewall/nat/find where comment=%s]`, index, rosQuote(comment)),
			fmt.Sprintf(`:if ([:len $panelRule%d] > 1) do={ :error "SB-GATEWAY panel NAT rule is ambiguous" }`, index),
			fmt.Sprintf(`:if ([:len $panelRule%d] = 0) do={ /ip/firewall/nat/add %s comment=%s; :set panelRule%d [/ip/firewall/nat/find where comment=%s] }`, index, properties[index], rosQuote(comment), index, rosQuote(comment)),
			fmt.Sprintf(`/ip/firewall/nat/set $panelRule%d %s disabled=no`, index, properties[index]),
		)
	}
	lines = append(lines, `/ip/firewall/nat/move $panelRule2 destination=$panelRule3`)
	// Only our two narrow jumps move. Foreign rules retain their relative order.
	for _, index := range []int{1, 0} {
		lines = append(lines, fmt.Sprintf(`:local panelFirst%d [:pick [/ip/firewall/nat/find] 0 1]; :if ($panelFirst%d != $panelRule%d) do={ /ip/firewall/nat/move $panelRule%d destination=$panelFirst%d }`, index, index, index, index, index))
	}
	return lines
}
