package runtimeconfig

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildRouterOSDeltaSelectsCompleteSymmetricSections(t *testing.T) {
	config := routerOSModelConfig()
	previous, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	objectValue(objectValue(config["dns"])["direct_resolver"])["provider"] = "quad9"
	desired, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := BuildRouterOSDelta(previous, desired, 1)
	if plan == nil || !reflect.DeepEqual(plan.Sections, []string{"dns"}) {
		t.Fatalf("DNS delta = %#v", plan)
	}
	if !strings.Contains(plan.ApplyScript, `servers="9.9.9.9,149.112.112.112"`) || !strings.Contains(plan.RollbackScript, `servers="1.1.1.1,1.0.0.1"`) {
		t.Fatalf("delta is not symmetric:\n%s\n%s", plan.ApplyScript, plan.RollbackScript)
	}
}

func TestBuildRouterOSDeltaAddsFinalizerForTrafficChanges(t *testing.T) {
	config := routerOSModelConfig()
	previous, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	objectValue(objectValue(config["system"])["networking"])["wireguard_egress_enabled"] = false
	desired, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	plan := BuildRouterOSDelta(previous, desired, 1)
	if plan == nil || !containsText(plan.Sections, "wireguard-egress") || !containsText(plan.Sections, "address-lists") || !containsText(plan.Sections, "finalize") {
		t.Fatalf("WireGuard delta sections = %#v", plan)
	}
	if strings.Contains(plan.ApplyScript, routerOSSectionPrefix+"core") || !strings.Contains(plan.ApplyScript, `:local sbBridgeName`) {
		t.Fatalf("standalone WireGuard delta prelude is missing:\n%s", plan.ApplyScript)
	}
}

func TestBuildRouterOSDeltaFallsBackForUnknownOrLargeChanges(t *testing.T) {
	config := routerOSModelConfig()
	previous, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan := BuildRouterOSDelta("# foreign script\n", previous, 1); plan != nil {
		t.Fatalf("foreign script produced delta: %#v", plan)
	}
	changed := strings.Replace(previous, "interval=5s", "interval=7s", 1)
	if plan := BuildRouterOSDelta(previous, changed, 0.01); plan != nil {
		t.Fatalf("oversized delta did not fall back: %#v", plan)
	}
	if plan := BuildRouterOSDelta(previous, previous, 1); plan != nil {
		t.Fatalf("identical candidates produced delta: %#v", plan)
	}
	large := strings.Replace(previous, routerOSSectionPrefix+"dns\n", routerOSSectionPrefix+"dns\n#"+strings.Repeat("x", 17*1024)+"\n", 1)
	if plan := BuildRouterOSDelta(previous, large, 1); plan != nil {
		t.Fatal("REST source limit must force file import even when the ratio allows a delta")
	}
}
