import assert from "node:assert/strict";
import test from "node:test";

import { activeQualityMetrics, freshLatencyComparison, qualityStatsSince } from "../app/quality-window.ts";

test("qualityStatsSince starts a fresh visible window without changing raw history", () => {
  const history = {
    sweden: [
      { at: 100, ok: true, delay_ms: 900 },
      { at: 201, ok: true, delay_ms: 420 },
      { at: 202, ok: false, delay_ms: null },
      { at: 203, ok: true, delay_ms: 510 },
      { at: 204, ok: true, delay_ms: 450 },
    ],
  };
  const before = structuredClone(history);
  const stats = qualityStatsSince(history, ["sweden", "finland"], 200);

  assert.deepEqual(stats.sweden, {
    samples: 4,
    successes: 3,
    failures: 1,
    loss_percent: 25,
    availability_percent: 75,
    median_ms: 450,
    p95_ms: 510,
  });
  assert.deepEqual(stats.finland, {
    samples: 0,
    successes: 0,
    failures: 0,
    loss_percent: null,
    availability_percent: null,
    median_ms: null,
    p95_ms: null,
  });
  assert.deepEqual(history, before);
});

test("comparison uses fresh controller evidence, never historical medians", () => {
  const pair = { active: "active", active_delay_ms: 600, candidate_delay_ms: 350,
    active_at: 200, candidate_at: 210, expires_at: 320 };
  const health = { runtime_selected: "active", runtime_confirmed: true,
    latency_comparisons: { reserve: pair },
    daily_stats: { active: { median_ms: 503 }, reserve: { median_ms: 900 } } };
  assert.deepEqual(freshLatencyComparison(health, "reserve", 215),
    { percent: -41.7, activeAt: 200, candidateAt: 210 });
  assert.equal(freshLatencyComparison(health, "active", 215), null);
  assert.equal(freshLatencyComparison(health, "reserve", 320), null);
  assert.equal(freshLatencyComparison(health, "reserve", 215, 201), null);
  for (const change of [
    { runtime_selected: "other" }, { runtime_confirmed: false },
    { runtime_error: "unconfirmed" }, { latency_comparisons: null },
  ]) assert.equal(freshLatencyComparison({ ...health, ...change }, "reserve", 215), null);
  for (const change of [
    { active_delay_ms: 0 }, { candidate_delay_ms: NaN }, { active_at: 220 },
    { candidate_at: 220 }, { expires_at: Infinity }, { active: "block" },
  ]) assert.equal(freshLatencyComparison({ ...health, latency_comparisons: {
    reserve: { ...pair, ...change },
  } }, "reserve", 215), null);
  assert.deepEqual(freshLatencyComparison({ ...health, latency_comparisons: {
    reserve: { ...pair, candidate_delay_ms: 900 },
  } }, "reserve", 215), { percent: 50, activeAt: 200, candidateAt: 210 });
});

test("active metrics use recent latency and ignore legacy speed history", () => {
  const health = {
    median_delay_ms: { active: 496 }, last_probe_at: { active: 215 }, last_good_at: { active: 210 },
    speed_samples_bps: { active: [12_200_000, 14_650_257] },
    speed_median_bps: { active: 12_200_000 }, last_speed_success_at: { active: 205 },
    last_speed_probe_at: { active: 215 }, last_speed_probe_status: { active: "failed" },
    daily_stats: { active: { median_ms: 481 } },
  };
  assert.deepEqual(activeQualityMetrics(health, "active"), { median: 496, medianAt: 210 });
  assert.deepEqual(activeQualityMetrics(health, "active", 211), { median: null, medianAt: null });
  assert.deepEqual(activeQualityMetrics({}, "unknown"), { median: null, medianAt: null });
});

test("a failed latency probe does not refresh old active metrics after a window reset", () => {
  const health = {
    median_delay_ms: { active: 496 }, last_good_at: { active: 200 },
    last_probe_at: { active: 215 }, availability_ok: { active: false },
  };
  assert.deepEqual(activeQualityMetrics(health, "active"), { median: 496, medianAt: 200 });
  assert.deepEqual(activeQualityMetrics(health, "active", 211), { median: null, medianAt: null });
  assert.deepEqual(activeQualityMetrics({ ...health, last_good_at: {} }, "active"), { median: null, medianAt: null });
});
