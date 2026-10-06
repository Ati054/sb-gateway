const obsoletePolicySettings = [
  "speed_check_enabled",
  "speed_improvement_percent",
  "speed_degradation_percent",
  "speed_check_interval_seconds",
  "speed_probe_bytes",
  "speed_candidate_count",
  "quality_window",
  "max_packet_loss_percent",
  "failure_threshold",
  "recovery_threshold",
  "active_check_interval_seconds",
  "backup_check_interval_seconds",
  "full_scan_interval_seconds",
  "max_active_candidates",
  "max_probe_candidates",
  "probe_batch_size",
  "active_liveness_interval_seconds",
  "failure_retry_interval_seconds",
  "block_recovery_interval_seconds",
  "switch_cooldown",
  "switch_cooldown_seconds",
  "max_latency_ms",
  "switch_improvement_percent",
  "return_to_primary",
  "interrupt_exist_connections",
] as const;

export function withoutRetiredURLTestSettings<T extends Record<string, unknown>>(policy: T): T {
  const result = { ...policy };
  for (const key of obsoletePolicySettings) delete result[key];
  return result;
}
