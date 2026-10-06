package runtimeconfig

var obsoleteURLTestSpeedSettings = []string{
	"speed_check_enabled", "speed_improvement_percent", "speed_degradation_percent",
	"speed_check_interval_seconds", "speed_probe_bytes", "speed_candidate_count",
}

var obsoleteURLTestPolicySettings = append(append([]string(nil), obsoleteURLTestSpeedSettings...),
	"quality_window", "max_packet_loss_percent", "failure_threshold", "recovery_threshold",
	"active_check_interval_seconds", "backup_check_interval_seconds", "full_scan_interval_seconds",
	"max_active_candidates", "max_probe_candidates", "probe_batch_size",
	"active_liveness_interval_seconds", "failure_retry_interval_seconds", "block_recovery_interval_seconds",
	"switch_cooldown", "switch_improvement_percent", "return_to_primary", "interrupt_exist_connections",
	"switch_cooldown_seconds", "max_latency_ms",
)

var obsoleteRoutingMonitorSettings = []string{
	"failure_retry_interval_seconds", "block_recovery_interval_seconds",
	"reserve_check_interval_seconds", "full_scan_interval_seconds",
}

// NormalizeURLTestPolicies removes retired controls without changing routes,
// the global probe budget, historical metrics or client traffic counters.
func NormalizeURLTestPolicies(config map[string]any) {
	for _, policy := range objectSlice(config["policies"]) {
		removeRetiredURLTestSettings(policy)
	}
	monitor := objectValue(objectValue(config["system"])["routing_monitor"])
	for _, field := range obsoleteRoutingMonitorSettings {
		delete(monitor, field)
	}
}

func removeRetiredURLTestSettings(policy map[string]any) {
	for _, field := range obsoleteURLTestPolicySettings {
		delete(policy, field)
	}
}
