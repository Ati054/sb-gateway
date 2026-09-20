import assert from "node:assert/strict";
import test from "node:test";

import { mergeRuntimeStatus, reverseAvailability } from "../app/runtime-status.ts";

test("late history response cannot overwrite newer confirmed selection", () => {
  const old = {selector_health:{europe:{runtime_selected:"canada", runtime_confirmed:true, runtime_observed_at:"2026-09-07T10:00:05Z", candidate_labels:{canada:"Canada"}, runtime_error:""}}};
  const delayed = {selector_health:{europe:{runtime_selected:"reverse", runtime_confirmed:true, runtime_observed_at:"2026-09-07T10:00:00Z", candidate_labels:{reverse:"Reverse"}, period_stats:{"7d":{reverse:{samples:2}}}}}};
  const health = mergeRuntimeStatus(old, delayed).selector_health.europe;
  assert.equal(health.runtime_selected, "canada");
  assert.deepEqual(health.candidate_labels, {canada:"Canada"});
  assert.deepEqual(health.period_stats, delayed.selector_health.europe.period_stats);
  const failure = mergeRuntimeStatus(old, {selector_health:{europe:{runtime_confirmed:false, runtime_error:"core unavailable", runtime_observed_at:"2026-09-07T10:00:06Z"}}});
  assert.equal(failure.selector_health.europe.runtime_confirmed, false);
});

test("late history cannot put a failed reserve back into the working pool", () => {
  const current = {selector_health:{route:{runtime_observed_at:"2026-09-07T10:00:05Z", shortlist:["active", "new"]}}};
  const stale = {selector_health:{route:{runtime_observed_at:"2026-09-07T10:00:00Z", shortlist:["active", "dead"]}}};
  assert.deepEqual(mergeRuntimeStatus(current, stale).selector_health.route.shortlist, ["active", "new"]);
});

test("reverse status uses recent availability, not enabled or quality", () => {
  const now = Date.parse("2026-09-07T00:00:00Z");
  const candidate = "reverse-vless-home";
  const health = {
    checked_at: new Date(now).toISOString(),
    last_probe_at: { [candidate]: now / 1000 - 10 },
    availability_ok: { [candidate]: true },
    quality_ok: { [candidate]: false },
    shortlist: [candidate],
    probe_limits: { backup_seconds: 300 },
  };
  const status = (value) => reverseAvailability({ selector_health: { europe: value } }, "home", now).state;
  assert.equal(status(health), "available");
  assert.equal(status({ ...health, availability_ok: { [candidate]: false } }), "unavailable");
  assert.equal(status({ ...health, runtime_error: "core unavailable" }), "unknown");
  assert.equal(status({ ...health, last_probe_at: {} }), "unknown");
  assert.equal(status({ ...health, last_probe_at: { [candidate]: now / 1000 - 421 } }), "unknown");
  assert.equal(status({ ...health, checked_at: new Date(now - 121_000).toISOString() }), "unknown");
  assert.equal(reverseAvailability(undefined, "home", now).state, "unknown");
  assert.equal(reverseAvailability({ selector_health: {
    old: health,
    recent: { ...health, last_probe_at: { [candidate]: now / 1000 }, availability_ok: { [candidate]: false } },
  } }, "home", now).state, "unavailable");
});

test("compact runtime refresh preserves detailed selector history", () => {
  const previous = {
    state: "healthy",
    selector_health: {
      europe: {
        selected: "reverse-xhttp",
        checked_at: "2026-09-02T16:00:00Z",
        period_stats: {
          "7d": {
            "reverse-xhttp": { samples: 120, availability_percent: 99.2 },
          },
        },
      },
    },
  };
  const compact = {
    state: "healthy",
    selector_health: {
      europe: {
        selected: "reverse-reality",
        checked_at: "2026-09-02T16:01:00Z",
      },
    },
  };

  const merged = mergeRuntimeStatus(previous, compact);
  assert.equal(merged.selector_health.europe.selected, "reverse-reality");
  assert.deepEqual(
    merged.selector_health.europe.period_stats,
    previous.selector_health.europe.period_stats,
  );
});

test("detailed runtime refresh replaces current selector history fields", () => {
  const previous = {
    selector_health: {
      europe: {
        selected: "reverse-xhttp",
        period_stats: { "7d": { old: { samples: 1 } } },
      },
    },
  };
  const detailed = {
    selector_health: {
      europe: {
        period_stats: { "7d": { current: { samples: 2 } } },
      },
    },
  };

  const merged = mergeRuntimeStatus(previous, detailed);
  assert.equal(merged.selector_health.europe.selected, "reverse-xhttp");
  assert.deepEqual(merged.selector_health.europe.period_stats, detailed.selector_health.europe.period_stats);
});
