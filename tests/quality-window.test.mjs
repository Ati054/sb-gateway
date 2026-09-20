import assert from "node:assert/strict";
import test from "node:test";

import { latestSpeedSince, qualityStatsSince } from "../app/quality-window.ts";

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

test("latestSpeedSince hides the old median until a fresh probe arrives", () => {
  const samples = { sweden: [8_000_000, 9_000_000] };
  assert.equal(latestSpeedSince(samples, { sweden: 199 }, "sweden", 200), null);
  assert.equal(latestSpeedSince(samples, { sweden: 205 }, "sweden", 200), 9_000_000);
});
