import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { qualitySheet } from "../app/node-quality.ts";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const node = (label, extra = {}) => ({ id: label, label, selected: false, inRuntimePool: false, available: true, quality: true, availability: 100, loss: 0, speedBps: 10e6, p95: 500, median: 400, decisionMedian: 400, ...extra });
const policies = [
  { key: "europe", name: "Европа", mode: "best", nodeStats: [node("Canada", { selected: true })] },
  { key: "best", name: "URLTest", mode: "best", nodeStats: Array.from({ length: 19 }, (_, i) => node(`B${i}`, { speedBps: i * 1e6, selected: i === 0, inRuntimePool: i === 0 || i === 4 })) },
  { key: "empty", name: "Без замеров", nodeStats: [] },
];

test("quality table keeps live reserves in the selected sheet top ten", () => {
  const first = qualitySheet(policies, "");
  assert.equal(first.policy.key, "europe");
  assert.equal(first.total, 1);
  const second = qualitySheet(policies, "best");
  assert.equal(second.total, 19);
  assert.equal(second.rows.length, 10);
  assert.deepEqual(second.rows.slice(0, 4).map(n => n.label), ["B0", "B4", "B18", "B17"]);
  assert.deepEqual(second.rows.map(n => n.rank), Array.from({ length: 10 }, (_, index) => index + 1));
  assert.equal(policies[1].nodeStats[1].label, "B1", "source order is not mutated");
});

test("selection follows stable ID through refresh/rename/reorder and falls back after deletion", () => {
  const reordered = [policies[2], { ...policies[1], name: "Новое имя" }, policies[0]];
  assert.equal(qualitySheet(reordered, "best").policy.name, "Новое имя");
  assert.equal(qualitySheet([policies[0]], "best").policy.key, "europe");
  assert.deepEqual(qualitySheet([], "best"), { policy: undefined, total: 0, rows: [] });
  assert.equal(qualitySheet(policies, "empty").total, 0);
  assert.equal(qualitySheet(policies, "empty").policy.key, "empty");
});

test("stable responsive node outranks slower perfect-history background node", () => {
  const sheet = qualitySheet([{ key: "route", name: "Route", mode: "best", nodeStats: [
    node("Active", { selected: true }),
    node("Finland", { availability: 95.8, loss: 4.2, speedBps: 14.24e6, decisionMedian: 338 }),
    node("Perfect but slow", { availability: 100, loss: 0, speedBps: 10.1e6, decisionMedian: 900 }),
  ] }], "route");
  assert.deepEqual(sheet.rows.map(item => item.label), ["Active", "Finland", "Perfect but slow"]);
});

test("priority table follows configured order without promoting the active or statistically better node", () => {
  const sheet = qualitySheet([{
    key: "route",
    name: "Priority",
    mode: "priority",
    priorityOrder: ["france", "uk", "mexico"],
    nodeStats: [
      node("Mexico", { id: "mexico", availability: 100, loss: 0 }),
      node("France", { id: "france", availability: 99, loss: 1 }),
      node("United Kingdom", { id: "uk", selected: true, availability: 98, loss: 2 }),
    ],
  }], "route");
  assert.deepEqual(sheet.rows.map(item => item.label), ["France", "United Kingdom", "Mexico"]);
  assert.deepEqual(sheet.rows.map(item => item.rank), [1, 2, 3]);
  assert.equal(sheet.rows[1].selected, true);
});

test("route buttons are numeric in top-to-bottom policy order with accessible names", () => {
  const page = normalizeLocalizedSource(readFileSync(new URL("../app/page.tsx", import.meta.url), "utf8"));
  const controls = page.match(/<div className="quality-periods quality-sheets"[\s\S]*?<\/div>/)?.[0];
  assert.ok(controls);
  assert.match(controls, /policyRows\.map\(\(policy, index\)/);
  assert.match(controls, /aria-label=\{tr\("Лист \{value1\}: \{value2\}", \{ value1: index \+ 1, value2: policy.name \}\)\}/);
  assert.match(controls, /title=\{`\$\{index \+ 1\}\. \$\{policy.name\}`\}/);
  assert.match(controls, />\s*\{index \+ 1\}\s*<\/button>/);
  assert.match(page, /const quality = qualitySheet\(policyRows, qualityPolicyId\)/);
  assert.match(page, /if \(qualityPolicyId !== selectedQualityKey\) \{\s*setQualityPolicyId\(selectedQualityKey\);\s*\}/);
  assert.doesNotMatch(page, /useEffect\(\(\) => \{\s*setQualityPolicyId/);
});
