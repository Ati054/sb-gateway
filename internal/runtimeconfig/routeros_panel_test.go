package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestRouterOSPanelPortScopesAccessAndSupportsSafeDelta(t *testing.T) {
	config := routerOSModelConfig()
	previous, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	management := objectValue(objectValue(config["system"])["management"])
	management["routeros_panel_port"] = 17443
	desired, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	delta := BuildRouterOSDelta(previous, desired, 1)
	if delta == nil || !reflect.DeepEqual(delta.Sections, []string{"panel-port-check", "panel-ingress"}) {
		t.Fatalf("unexpected first activation delta: %#v", delta)
	}
	for _, required := range []string{
		`:local panelPort 17443`, `/ip/service/find where disabled=no and dynamic=no`, `/ip/service/get $service port`,
		`[:len [:tostr $ports]] > 0`,
		`/interface/list/find where name="SB_WIREGUARD_INGRESS"`,
		`/interface/list/member/remove [find where list="SB_WIREGUARD_INGRESS" and comment="SB-GATEWAY WireGuard panel ingress"]`,
		`/interface/wireguard/find where disabled=no`,
		`comment="SB-GATEWAY WireGuard panel return"`,
		`out-interface-list="SB_WIREGUARD_INGRESS"`,
		`connection-state=established,related connection-nat-state=dstnat`,
		`/ip/firewall/filter/move $wireguardPanelReturn destination=$containerLanDeny`,
		`in-interface-list="SB_MANAGEMENT_INGRESS" src-address-list="SB_MANAGEMENT_SOURCES" dst-address-type=local protocol=tcp dst-port=17443`,
		`in-interface-list="SB_WIREGUARD_INGRESS" dst-address-type=local protocol=tcp dst-port=17443`,
		`action=return in-interface-list=WAN`, `action=dst-nat protocol=tcp to-addresses=`, `to-ports=9443`,
		`/ip/firewall/nat/move $panelRule2 destination=$panelRule3`,
	} {
		if !strings.Contains(delta.ApplyScript, required) {
			t.Errorf("missing %q", required)
		}
	}
	for _, forbidden := range []string{`/ip/service/set`, `/ip/service/disable`, `/ip/service/remove`, `action=masquerade`, `192.168.98.1`, `192.168.88.1`} {
		if strings.Contains(delta.ApplyScript, forbidden) {
			t.Errorf("unsafe/hardcoded operation %q", forbidden)
		}
	}
	if strings.Index(delta.ApplyScript, `/ip/service/find`) > strings.Index(delta.ApplyScript, `/ip/firewall/nat/add`) {
		t.Fatal("collision check runs after mutation")
	}
	if strings.Index(delta.ApplyScript, `/interface/wireguard/find where disabled=no`) > strings.Index(delta.ApplyScript, `comment="SB-GATEWAY panel LAN jump"`) {
		t.Fatal("WireGuard ingress inventory is reconciled after panel NAT")
	}
	if !strings.Contains(delta.RollbackScript, `/ip/firewall/nat/remove [find where comment="SB-GATEWAY panel LAN jump"]`) {
		t.Fatal("first activation cannot roll back")
	}
	management["routeros_panel_port"] = 18444
	next, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := BuildRouterOSDelta(desired, next, 1)
	if changed == nil || !strings.Contains(changed.ApplyScript, "dst-port=18444") || !strings.Contains(changed.RollbackScript, "dst-port=17443") {
		t.Fatal("port change is not reversible")
	}
}

func TestRouterOSPanelPortCheckIgnoresDynamicAndPortlessServices(t *testing.T) {
	config := routerOSModelConfig()
	objectValue(objectValue(config["system"])["management"])["routeros_panel_port"] = 17443
	candidate, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	script := candidate
	if !strings.Contains(script, `/ip/service/find where disabled=no and dynamic=no`) {
		t.Fatal("panel check can mistake a transient dynamic SSH service for a configured listener")
	}
	if !strings.Contains(script, `([:len [:tostr $ports]] > 0) && [$panelPortContains $ports $panelPort]`) {
		t.Fatal("panel check can mistake a portless RouterOS service for an all-port listener")
	}
	if !strings.Contains(script, `:if ([$panelPortContains $ports $panelPort])`) {
		t.Fatal("NAT rules without dst-port must continue to be treated as all-port listeners")
	}
}

func TestRouterOSPanelRejectsInvalidAndPublicPorts(t *testing.T) {
	for _, port := range []any{0, 443, 9443, 65536, 17443.5, "17443"} {
		config := routerOSModelConfig()
		objectValue(objectValue(config["system"])["management"])["routeros_panel_port"] = port
		if _, err := RenderRouterOSTrafficCandidate(config, nil); err == nil {
			t.Errorf("accepted invalid port %v", port)
		}
	}
	config := routerOSModelConfig()
	objectValue(objectValue(config["system"])["management"])["routeros_panel_port"] = 17443
	config["transports"] = []any{map[string]any{"id": "reality", "kind": "reality", "enabled": true, "listen_port": 17443}}
	if _, err := RenderRouterOSTrafficCandidate(config, nil); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("public TCP conflict was not detected: %v", err)
	}
	config["transports"] = []any{map[string]any{"id": "hy2", "kind": "hysteria2", "enabled": true, "listen_port": 17443}}
	if _, err := RenderRouterOSTrafficCandidate(config, nil); err != nil {
		t.Fatalf("unrelated UDP port rejected: %v", err)
	}
}

func TestRouterOSPanelReconcilesWireGuardIngressWithUnrelatedRouterOSDelta(t *testing.T) {
	config := routerOSModelConfig()
	management := objectValue(objectValue(config["system"])["management"])
	management["routeros_panel_port"] = 17443
	previous, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	objectValue(objectValue(config["dns"])["direct_resolver"])["provider"] = "quad9"
	desired, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	delta := BuildRouterOSDelta(previous, desired, 1)
	if delta == nil || !reflect.DeepEqual(delta.Sections, []string{"panel-port-check", "dns", "panel-ingress"}) {
		t.Fatalf("unrelated delta did not refresh WireGuard panel ingress: %#v", delta)
	}
}
