import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import { mergeRuntimeStatus, reverseAvailability } from "../app/runtime-status.ts";

test("Reverse status clock refreshes with telemetry outside render", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const section = page.slice(page.indexOf("function ReverseVlessSettings("), page.indexOf("function WireGuard", page.indexOf("function ReverseVlessSettings(")));
  assert.match(section, /const reverseSampledAt = asText\(asObject\(runtime\?\.reverse_telemetry\)\.sampled_at, ""\)/);
  assert.match(section, /window\.setInterval\(refresh, 30_000\)/);
  assert.match(section, /\}, \[reverseSampledAt\]\)/);
  assert.match(section, /reverseAvailability\(runtime, id, statusNow\)/);
  assert.doesNotMatch(section, /reverseAvailability\([^;]*Date\.now/);
});

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

test("a delayed history response cannot revive withdrawn latency comparisons", () => {
  const pair = { reserve: { active: "active", active_delay_ms: 600, candidate_delay_ms: 350 } };
  const current = { selector_health: { route: {
    runtime_selected: "active", runtime_confirmed: true,
    runtime_observed_at: "2026-10-06T10:00:05Z", latency_comparisons: null,
  } } };
  const history = { selector_health: { route: {
    runtime_observed_at: "2026-10-06T10:00:00Z", latency_comparisons: pair,
    period_stats: { "24h": { active: { median_ms: 503 } } },
  } } };
  const merged = mergeRuntimeStatus(current, history).selector_health.route;
  assert.equal(merged.latency_comparisons, null);
  assert.deepEqual(merged.period_stats, history.selector_health.route.period_stats);
  const later = { selector_health: { route: {
    runtime_observed_at: "2026-10-06T10:00:06Z", latency_comparisons: pair,
  } } };
  assert.deepEqual(mergeRuntimeStatus(current, later).selector_health.route.latency_comparisons, pair);
});

test("reverse connection status uses Xray online telemetry, not HTTPS health", () => {
  const now = Date.parse("2026-09-07T00:00:00Z");
  const telemetry = {
    sampled_at: new Date(now).toISOString(),
    reverse_connections: { home: true },
    sources: { xray: "available" },
  };
  const status = value => reverseAvailability({ reverse_telemetry: value }, "home", now).state;
  assert.equal(status(telemetry), "available");
  assert.equal(status({ ...telemetry, reverse_connections: { home: false } }), "unavailable");
  assert.equal(status({ ...telemetry, sources: { xray: "unavailable" } }), "unknown");
  assert.equal(status({ ...telemetry, sources: { xray: "unavailable", xray_online: "available" } }), "available");
  assert.equal(status({ ...telemetry, sources: { xray: "available", xray_online: "unavailable" } }), "unknown");
  assert.equal(status({ ...telemetry, reverse_connections: {} }), "unknown");
  assert.equal(status({ ...telemetry, reverse_connections: { home: "true" } }), "unknown");
  assert.equal(status({ ...telemetry, sampled_at: new Date(now - 75_001).toISOString() }), "unknown");
  assert.equal(status({ ...telemetry, sampled_at: new Date(now + 5_001).toISOString() }), "unknown");
  assert.equal(status({ ...telemetry, sampled_at: "invalid" }), "unknown");
  assert.equal(reverseAvailability(undefined, "home", now).state, "unknown");
  assert.equal(reverseAvailability({ selector_health: {
    route: { checked_at: telemetry.sampled_at, last_probe_at: { "reverse-vless-home": now / 1000 }, availability_ok: { "reverse-vless-home": true } },
  } }, "home", now).state, "unknown");
  assert.equal(reverseAvailability({ reverse_telemetry: telemetry }, "home", NaN).state, "unknown");
});

test("unused Reverse indicator is independent of route probes and other profiles", () => {
  const now = Date.parse("2026-09-07T00:00:00Z");
  const runtime = {
    reverse_telemetry: { sampled_at: new Date(now).toISOString(), sources: { xray_online: "available" }, reverse_connections: { used: true, unused: true } },
    selector_health: { route: { availability_ok: { "reverse-vless-used": false } } },
  };
  assert.equal(reverseAvailability(runtime, "unused", now).state, "available");
  runtime.reverse_telemetry.reverse_connections.unused = false;
  assert.equal(reverseAvailability(runtime, "unused", now).state, "unavailable");
  assert.equal(reverseAvailability(runtime, "used", now).state, "available");
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
