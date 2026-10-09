package watchdog

import "time"

// A supervised core restart gets one bounded window after a verified healthy
// generation. Repeated crashes cannot renew it without full dataplane recovery.
type coreRecoveryWindow struct {
	generation string
	deadline   time.Time
}

func (window *coreRecoveryWindow) verified(generation string) {
	if generation == "" {
		return
	}
	window.generation = generation
	window.deadline = time.Time{}
}

func (window *coreRecoveryWindow) deferFailures(now time.Time, maximum time.Duration, generation string, reasons []string) bool {
	if window.generation == "" || maximum <= 0 || len(reasons) == 0 {
		return false
	}
	if window.deadline.IsZero() {
		if generation == window.generation {
			return false
		}
		window.deadline = now.Add(maximum)
	}
	if !now.Before(window.deadline) {
		return false
	}
	for _, reason := range reasons {
		switch reason {
		case "core_startup", "core_process", "tcp_listener", "udp_listener",
			"tproxy_policy_rule", "tproxy_local_route", "transparent_nft":
		default:
			return false
		}
	}
	return true
}
