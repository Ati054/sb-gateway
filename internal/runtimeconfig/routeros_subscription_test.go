package runtimeconfig

import (
	"strings"
	"testing"
)

func TestUpdateRouterOSEndpointSourcePreservesInfrastructure(t *testing.T) {
	old, fresh := []string{"192.0.2.1/32"}, []string{"192.0.2.2/32", "192.0.2.3/32"}
	block := strings.Join(renderRouterOSAddressList("Bypass", "SB_BYPASS_ENDPOINTS", "SB-GATEWAY loop bypass", old), "\n") + "\n"
	committed := "# previous-version firewall rules\n" + block + "# previous-version guard rules\n"
	updated, err := UpdateRouterOSEndpointSource(committed, old, fresh)
	if err != nil || !strings.Contains(updated, `"192.0.2.2/32"`) || strings.Contains(updated, `"192.0.2.1/32"`) {
		t.Fatalf("endpoint replacement failed: %v", err)
	}
	restored, err := UpdateRouterOSEndpointSource(updated, fresh, old)
	if err != nil || restored != committed {
		t.Fatal("non-endpoint rules changed")
	}
	unchanged, err := UpdateRouterOSEndpointSource(committed, old, old)
	if err != nil || unchanged != committed {
		t.Fatal("no-op changed source")
	}
	for _, source := range []string{"", block + block, strings.Replace(block, "loop bypass", "foreign", 1), strings.Replace(block, "192.0.2.1", "192.0.2.9", 1)} {
		if _, err := UpdateRouterOSEndpointSource(source, old, fresh); err == nil {
			t.Fatal("inconsistent source accepted")
		}
	}
	if _, err := UpdateRouterOSEndpointSource(committed, old, []string{"0.0.0.0/0"}); err == nil {
		t.Fatal("non-host bypass accepted")
	}
	if _, err := UpdateRouterOSEndpointSource(committed, old, nil); err != nil {
		t.Fatal(err)
	}
}
