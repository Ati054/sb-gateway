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
