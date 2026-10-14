package runtimeconfig

import (
	"strings"
	"testing"
)

func TestProtocolPolicyDefaultsAndFixedControlNetworks(t *testing.T) {
	config := routerOSModelConfig()
	config["networks"] = []any{}
	model, err := BuildRouterOSRenderModel(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !model.AllowWANPing {
		t.Fatal("WAN ping is not enabled by default")
	}
	for _, cidr := range []string{"224.0.0.0/4", "255.255.255.255/32"} {
		if !containsText(model.Internal4, cidr) {
			t.Fatalf("missing fixed control network %s", cidr)
		}
	}
	if !containsText(model.Internal6, "ff00::/8") {
		t.Fatal("missing IPv6 multicast")
	}
	body, err := RenderTransparentExclusions(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, cidr := range controlPlaneMulticastCIDRs {
		if !strings.Contains(string(body), cidr+"\n") {
			t.Fatal(cidr)
		}
	}
	networking := config["system"].(map[string]any)["networking"].(map[string]any)
	networking["allow_wan_ping"] = false
	model, err = BuildRouterOSRenderModel(config, nil)
	if err != nil || model.AllowWANPing {
		t.Fatalf("explicit ping block was ignored: %v", err)
	}
}

func TestLegacyProtocolRollbackRemovesOnlyNewOwnedRules(t *testing.T) {
	previous := routerOSCandidateHeader + "\n# old candidate\n"
	desired := routerOSCandidateHeader + "\n" + routerOSSectionPrefix + "protocol-policy\n"
	rollback := WithLegacyProtocolCleanup(previous, desired)
	if !strings.HasPrefix(rollback, routerOSCandidateHeader+"\n") || !strings.Contains(rollback, `comment~"^SB-GATEWAY protocol "`) || !strings.HasSuffix(rollback, "# old candidate\n") {
		t.Fatal("legacy rollback cleanup missing")
	}
	if WithLegacyProtocolCleanup(desired, desired) != desired {
		t.Fatal("current rollback changed")
	}
}
