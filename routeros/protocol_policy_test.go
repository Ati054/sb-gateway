package routerosassets

import (
	"strings"
	"testing"
)

func TestProtocolPolicyEchoToggleNeverDisablesRelatedErrors(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		s := ProtocolPolicySource("192.0.2.2", enabled)
		for _, fragment := range []string{
			"protocol=icmp icmp-options=3:0-255 connection-state=related",
			"protocol=icmp icmp-options=11:0-255 connection-state=related",
			"protocol=icmpv6 icmp-options=2:0-255 connection-state=related",
			`dst-address="224.0.0.0/4"`, `dst-address="ff00::/8"`,
			`jump-target="sb-gateway-protocol-v4"`, `jump-target="sb-gateway-protocol-v6"`,
		} {
			if !strings.Contains(s, fragment) {
				t.Fatal(fragment)
			}
		}
		action := "drop"
		if enabled {
			action = "accept"
		}
		for _, fragment := range []string{"action=" + action + " protocol=icmp icmp-options=8:0-255", "action=" + action + " protocol=icmpv6 icmp-options=128:0-255"} {
			if !strings.Contains(s, fragment) {
				t.Fatal(fragment)
			}
		}
		if strings.Contains(s, "connection-state=established,related") {
			t.Fatal("broad forwarding bypass")
		}
	}
}
