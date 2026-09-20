package runtimeconfig

import (
	"os"
	"strings"
	"testing"
)

func TestRouterOSCandidateDoesNotOwnUserManagementServices(t *testing.T) {
	config := routerOSModelConfig()
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"/ip/service/",
		`action=drop protocol=tcp dst-port=`,
		`action=drop in-interface-list="SB_MANAGEMENT_INGRESS"`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("RouterOS candidate may alter user management access through %q", forbidden)
		}
	}
	for _, obsolete := range []string{
		"SB-GATEWAY RouterOS www-ssl management allow",
		"SB-GATEWAY RouterOS www-ssl deny",
	} {
		if !strings.Contains(source, `/ip/firewall/filter/remove $obsoleteRules`) || !strings.Contains(source, obsolete) {
			t.Fatalf("RouterOS candidate does not remove obsolete owned rule %q", obsolete)
		}
	}
}

func TestRouterOSInstallReturnsUnownedInputTrafficToUserFirewall(t *testing.T) {
	body, err := os.ReadFile("../../routeros/install.rsc")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, forbidden := range []string{
		"/ip/service/set",
		`action=drop protocol=tcp dst-port=$"SB_ROUTEROS_REST_PORT"`,
		`action=drop protocol=tcp dst-port=8291`,
		`:local remoteManagementPorts ("22,`,
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("RouterOS install may override user management access through %q", forbidden)
		}
	}
	for _, required := range []string{
		`:local sshService [/ip/service/find where name="ssh" and dynamic=no]`,
		`:local winboxService [/ip/service/find where name="winbox" and dynamic=no]`,
		`[/ip/service/get $sshService port]`,
		`[/ip/service/get $winboxService port]`,
		`/ip/firewall/filter/set $routerManagementDeny chain="sb-gateway-input" action=drop src-address=$"SB_CONTAINER_IP" disabled=no`,
		`/ip/firewall/filter/set $inputReturn chain="sb-gateway-input" action=return disabled=no`,
		`:foreach obsoleteComment in={"SB-GATEWAY RouterOS www-ssl management allow";"SB-GATEWAY RouterOS www-ssl deny"}`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("RouterOS install lacks scoped management invariant %q", required)
		}
	}
}

func TestRouterOSInstallCreatesFailClosedPublicDropBeforeReturn(t *testing.T) {
	body, err := os.ReadFile("../../routeros/install.rsc")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, required := range []string{
		`/ip/firewall/filter/add chain="sb-gateway-forward" action=drop src-address-list="SB_FAIL_CLOSED_CLIENTS" dst-address-list="!SB_INTERNAL_NETWORKS" comment="SB-GATEWAY fail-closed public drop"`,
		`/ip/firewall/filter/set $failClosedDrop chain="sb-gateway-forward" action=drop src-address-list="SB_FAIL_CLOSED_CLIENTS" dst-address-list="!SB_INTERNAL_NETWORKS" disabled=no`,
		`/ip/firewall/filter/move $failClosedDrop destination=$forwardReturn`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("RouterOS install lacks fail-closed invariant %q", required)
		}
	}
}
