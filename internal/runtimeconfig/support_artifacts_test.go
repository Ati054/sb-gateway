package runtimeconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderWatchdogEnvironmentMatchesRuntimeContract(t *testing.T) {
	body, err := RenderWatchdogEnvironment(map[string]any{"watchdog": map[string]any{
		"interval_seconds":      json.Number("7"),
		"failure_threshold":     float64(4),
		"recovery_threshold":    2,
		"max_restarts_per_hour": int64(9),
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := "SB_WATCHDOG_INTERVAL_SECONDS=7\n" +
		"SB_WATCHDOG_FAILURE_THRESHOLD=4\n" +
		"SB_WATCHDOG_RECOVERY_THRESHOLD=2\n" +
		"SB_WATCHDOG_MAX_RESTARTS_PER_HOUR=9\n"
	if got := string(body); got != want {
		t.Fatalf("watchdog environment:\n%s\nwant:\n%s", got, want)
	}
	if _, err := RenderWatchdogEnvironment(map[string]any{"watchdog": map[string]any{"interval_seconds": 1.5}}); err == nil {
		t.Fatal("fractional watchdog interval was accepted")
	}
}

func TestRenderClientTelemetryNFTMatchesCounterOnlyContract(t *testing.T) {
	config := map[string]any{"local_clients": []any{
		map[string]any{
			"id": "iphone", "enabled": true,
			"source_cidrs": []any{"192.168.3.5/24", "192.168.3.0/24", "2001:db8::/64", "invalid"},
		},
		map[string]any{"id": "disabled", "enabled": false, "source_cidrs": []any{"10.0.0.1/32"}},
	}}
	body, err := RenderClientTelemetryNFT(config)
	if err != nil {
		t.Fatal(err)
	}
	uplink, downlink := TelemetryCounterNames("iphone")
	want := "table inet sb_gateway_client_telemetry {\n" +
		"  counter " + uplink + " { }\n" +
		"  counter " + downlink + " { }\n" +
		"  chain client_uplink {\n" +
		"    ip saddr 192.168.3.0/24 counter name " + uplink + " return\n" +
		"  }\n" +
		"  chain client_downlink {\n" +
		"    ip daddr 192.168.3.0/24 counter name " + downlink + " return\n" +
		"  }\n" +
		"  chain prerouting {\n" +
		"    type filter hook prerouting priority raw; policy accept;\n" +
		"    jump client_uplink\n" +
		"  }\n" +
		"  chain output {\n" +
		"    type filter hook output priority raw; policy accept;\n" +
		"    jump client_downlink\n" +
		"  }\n" +
		"}\n"
	if got := string(body); got != want {
		t.Fatalf("telemetry nft:\n%s\nwant:\n%s", got, want)
	}
	for _, forbidden := range []string{" drop", " mark", " redirect", " dnat", " snat"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("telemetry changed packet verdict with %q", forbidden)
		}
	}
	if _, err := RenderClientTelemetryNFT(config); err != nil {
		t.Fatalf("telemetry should not depend on a TUN interface: %v", err)
	}
}

func TestRenderClientTelemetryNFTCountsMostSpecificClientFirst(t *testing.T) {
	config := map[string]any{"local_clients": []any{
		map[string]any{
			"id": "all-lan", "enabled": true, "source_kind": "lan", "source_scope": "lan-all",
			"source_cidrs": []any{"192.168.50.0/24"},
		},
		map[string]any{
			"id": "pc", "enabled": true, "source_kind": "lan",
			"source_cidrs": []any{"192.168.50.245/32"},
		},
	}}
	body, err := RenderClientTelemetryNFT(config)
	if err != nil {
		t.Fatal(err)
	}
	allUp, allDown := TelemetryCounterNames("all-lan")
	pcUp, pcDown := TelemetryCounterNames("pc")
	text := string(body)
	assertBefore := func(earlier, later string) {
		t.Helper()
		earlierIndex := strings.Index(text, earlier)
		laterIndex := strings.Index(text, later)
		if earlierIndex < 0 || laterIndex < 0 || earlierIndex >= laterIndex {
			t.Fatalf("telemetry specificity order is wrong: %q at %d, %q at %d\n%s", earlier, earlierIndex, later, laterIndex, text)
		}
	}
	assertBefore(
		"ip saddr 192.168.50.245/32 counter name "+pcUp+" return",
		"ip saddr 192.168.50.0/24 counter name "+allUp+" return",
	)
	assertBefore(
		"ip daddr 192.168.50.245/32 counter name "+pcDown+" return",
		"ip daddr 192.168.50.0/24 counter name "+allDown+" return",
	)
}

func TestRenderTransparentExclusionsMatchesTunSource(t *testing.T) {
	config := map[string]any{
		"networks": []any{
			map[string]any{"id": "lan", "enabled": true, "kind": "internal", "cidrs": []any{"192.168.3.0/24"}},
			map[string]any{"id": "management", "enabled": true, "kind": "management", "cidrs": []any{"10.10.0.0/16", "192.168.3.0/24"}},
			map[string]any{"id": "disabled", "enabled": false, "kind": "internal", "cidrs": []any{"10.20.0.0/16"}},
			map[string]any{"id": "external", "enabled": true, "kind": "external", "cidrs": []any{"203.0.113.0/24"}},
		},
		"system": map[string]any{"networking": map[string]any{"container_address": "172.31.255.2/30"}},
	}
	body, err := RenderTransparentExclusions(config)
	if err != nil {
		t.Fatal(err)
	}
	want := "192.168.3.0/24\n10.10.0.0/16\n172.31.255.0/30\n"
	if got := string(body); got != want {
		t.Fatalf("transparent exclusions = %q, want %q", got, want)
	}
	config["system"].(map[string]any)["networking"].(map[string]any)["container_address"] = "2001:db8::1/64"
	if _, err := RenderTransparentExclusions(config); err == nil {
		t.Fatal("IPv6 container address was accepted")
	}
}
