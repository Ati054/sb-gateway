package routerosassets

import (
	"strings"
	"testing"
)

func TestWatchdogReconcilesActualGateAfterFreshHealth(t *testing.T) {
	source := HealthWatchdogSource()
	fetch := strings.Index(source, `:local response [/tool/fetch`)
	healthy := strings.Index(source, `:if ($healthy = true)`)
	actual := strings.Index(source, `:local gateDisabled [/ip/firewall/mangle/get $gate disabled]`)
	enable := strings.Index(source, `/ip/firewall/mangle/enable $gate`)
	if fetch < 0 || healthy < fetch || actual < healthy || enable < actual {
		t.Fatal("gate reconciliation must follow fresh readiness")
	}
	for _, fragment := range []string{`($gateDisabled = true) && (($sbStartupSafety = true) || ($sbFailOpen = false) ||`, `SB_HEALTH_RECOVERY_THRESHOLD`, `SB_HEALTH_COOLDOWN_TICKS`} {
		if !strings.Contains(source, fragment) {
			t.Fatalf("missing drift recovery/hysteresis: %s", fragment)
		}
	}
	if strings.Contains(source, "reverse") || strings.Contains(source, "selector_health") {
		t.Fatal("router readiness must not depend on exit availability")
	}
}

func TestWatchdogExpiresOnlyRecoveredManagedRouterDNS(t *testing.T) {
	source := HealthWatchdogSource()
	cleanup := strings.Index(source, "      $clearRecoveredDNS")
	if strings.Contains(source, `dst-address~":53$"`) {
		t.Fatal("RouterOS quoted regex anchors must be escaped, including inside imported script bodies")
	}
	if strings.Contains(source, `connection-mark=no-mark`) {
		t.Fatal("unmarked conntrack entries have an empty mark, not a literal no-mark value")
	}
	if cleanup < strings.Index(source, `:if ($healthy = true)`) || cleanup > strings.Index(source, `/ip/firewall/mangle/enable $gate`) {
		t.Fatal("DNS conntrack cleanup must follow fresh readiness and precede gate admission")
	}
	for _, fragment := range []string{
		`:if ([:len $dnsNat] != 1) do={ :return false }`,
		`find where dst-address~":53\$"`,
		`($dnsFlows, [/ip/firewall/connection/find where dst-port=53])`,
		`:foreach flow in=$dnsFlows do={`,
		`:if ([:typeof $sourceColon] = "num") do={ :set source [:pick $source 0 $sourceColon] }`,
		`:if ([:typeof $destinationColon] = "num") do={ :set destinationIP [:pick $destinationIP 0 $destinationColon] }`,
		`:local sourceIP [:toip $source]`,
		`:local connectionMark [/ip/firewall/connection/get $flow connection-mark]`,
		`:if ([:len [:tostr $connectionMark]] = 0) do={`,
		`($protocol = "udp") || ($protocol = "tcp")`,
		`($localDestination = true) && ([:tostr $sourceIP] != [:tostr $containerIP])`,
		`list="SB_MANAGED_CLIENTS"`,
		`($sourceIP >> (32 - $bits)) = ($networkIP >> (32 - $bits))`,
		`:if ($managed = true) do={ /ip/firewall/connection/remove $flow }`,
	} {
		if !strings.Contains(source, fragment) {
			t.Fatalf("missing DNS cleanup scope: %s", fragment)
		}
	}
}
