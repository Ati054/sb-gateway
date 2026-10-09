package watchdog

import (
	"testing"
	"time"
)

func TestCoreRecoveryNeedsVerifiedGenerationAndActualRestart(t *testing.T) {
	now := time.Unix(1000, 0)
	var window coreRecoveryWindow
	reasons := []string{"core_startup", "core_process"}
	if window.deferFailures(now, time.Minute, "", reasons) {
		t.Fatal("unverified startup received another recovery window")
	}
	window.verified("101 1")
	if window.deferFailures(now, time.Minute, "101 1", []string{"tcp_listener"}) {
		t.Fatal("a wedged live generation was treated as a restart")
	}
	if !window.deferFailures(now, time.Minute, "", reasons) {
		t.Fatal("supervised restart did not receive bounded recovery time")
	}
}

func TestCoreRecoveryDeadlineCannotBeRenewedByCrashLoop(t *testing.T) {
	now := time.Unix(1000, 0)
	var window coreRecoveryWindow
	window.verified("101 1")
	reasons := []string{"core_startup", "tcp_listener", "transparent_nft"}
	if !window.deferFailures(now, time.Minute, "", reasons) {
		t.Fatal("missing recovery window")
	}
	deadline := window.deadline
	for _, generation := range []string{"", "202 2", "", "303 3"} {
		if !window.deferFailures(now.Add(30*time.Second), time.Minute, generation, reasons) || window.deadline != deadline {
			t.Fatal("crash loop changed the original recovery deadline")
		}
	}
	if window.deferFailures(deadline, time.Minute, "404 4", reasons) ||
		window.deferFailures(deadline.Add(time.Minute), time.Minute, "", reasons) {
		t.Fatal("expired recovery window postponed watchdog escalation")
	}
	window.verified("")
	if window.deadline != deadline {
		t.Fatal("an unverified marker cleared the expired recovery deadline")
	}
	window.verified("404 4")
	if !window.deadline.IsZero() || !window.deferFailures(deadline.Add(2*time.Minute), time.Minute, "", reasons) {
		t.Fatal("full recovery did not arm a new independent restart window")
	}
}

func TestCoreRecoveryDoesNotHideUnrelatedOrInvalidState(t *testing.T) {
	for _, reason := range []string{"dns_lane_udp", "dns_lane_tcp", "dns_lane_config", "api_ready", "api_configured",
		"core_config", "config_validation", "listener_inventory", "tcp_listener_inventory", "unknown"} {
		t.Run(reason, func(t *testing.T) {
			var window coreRecoveryWindow
			window.verified("101 1")
			if window.deferFailures(time.Unix(1000, 0), time.Minute, "", []string{"core_startup", reason}) {
				t.Fatal("core restart suppressed an unrelated watchdog failure")
			}
		})
	}
	var window coreRecoveryWindow
	window.verified("101 1")
	if window.deferFailures(time.Unix(1000, 0), 0, "", []string{"core_startup"}) {
		t.Fatal("disabled grace still deferred recovery failures")
	}
}
