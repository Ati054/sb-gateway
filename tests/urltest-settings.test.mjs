import assert from "node:assert/strict";
import test from "node:test";
import { withoutRetiredURLTestSettings } from "../app/urltest-settings.ts";

test("editing a legacy route removes retired controls without changing routes or counters", () => {
  const legacy = {
    id: "route", mode: "best", speed_check_enabled: true, speed_improvement_percent: 25,
    speed_degradation_percent: 50, speed_check_interval_seconds: 10800,
    speed_probe_bytes: 2097152, speed_candidate_count: 2,
    switch_cooldown_seconds: 600, max_latency_ms: 2000, switch_improvement_ms: 50, recovery_threshold: 3, probe_batch_size: 5,
    max_active_candidates: 3, selection_order: ["finland", "sweden"],
    bandwidth_limit_mbps: 20,
  };
  const original = structuredClone(legacy);
  const cleaned = withoutRetiredURLTestSettings(legacy);
  assert.deepEqual(cleaned, {
    id: "route", mode: "best", switch_improvement_ms: 50, selection_order: ["finland", "sweden"],
    bandwidth_limit_mbps: 20,
  });
  assert.deepEqual(legacy, original);
  assert.deepEqual(withoutRetiredURLTestSettings(cleaned), cleaned);
});
