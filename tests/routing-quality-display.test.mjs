import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const routing = page.slice(page.indexOf("function Routing("), page.indexOf("function Connections("));

test("quality table follows configured priority or URLTest quality ranking", async () => {
  const helper = await readFile(new URL("../app/node-quality.ts", import.meta.url), "utf8");
  assert.match(routing, /const quality = qualitySheet\(policyRows, qualityPolicyId\)/);
  assert.match(routing, /quality\.rows\.map\(\(node\) =>/);
  assert.match(routing, /Показано \{quality.rows.length\}\s+из \{quality.total\}/);
  assert.match(helper, /rows: rows\.slice\(0, 10\)/);
  assert.match(helper, /policy\?\.mode === "priority"/);
  assert.match(helper, /priorityPositions\.get\(left\.id\)/);
  assert.match(helper, /if \(left\.inRuntimePool !== right\.inRuntimePool\) return left\.inRuntimePool \? -1 : 1/);
  assert.match(helper, /if \(left\.quality !== right\.quality\) return left\.quality \? -1 : 1/);
  assert.match(helper, /responsiveScoreOrder\(left, right\)/);
  assert.ok(helper.indexOf('if (left.selected !== right.selected)') < helper.indexOf('if (left.inRuntimePool !== right.inRuntimePool)'));
  assert.ok(helper.indexOf('if (left.inRuntimePool !== right.inRuntimePool)') < helper.indexOf('if (left.available !== right.available)'));
  assert.match(routing, /mode: normalizePolicySelectionMode\(policy\.mode\)/);
  assert.match(routing, /priorityOrder: chosenCandidateIds/);
  assert.match(routing, /quality\.policy\?\.mode === "priority" \? "Приоритет" : "Рейтинг"/);
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(css, /th:nth-child\(1\) \{ width: 78px; \}/);
});

test("expanded policy uses the full selected inventory, not the capped runtime pool", async () => {
  assert.match(routing, /orderedCandidateNodeIds\(displayOrder, routingNodes, configuredWireguardExits, configuredReverseVlessExits\)/);
  assert.match(routing, /const queueNodes = routeCandidateIds\(health, dailyStats,/);
  assert.match(routing, /chosenIds\.map\(\(nodeId\) =>/);
  assert.match(routing, /compareRouteCandidates\(left, right\)/);
  assert.match(routing, /const queueRows = policy.queueNodes.length\s+\? policy.queueNodes/);
  assert.match(routing, /inRuntimePool: asStringList\(health.shortlist\).includes\(nodeId\)/);
  assert.match(routing, /"Рабочий резерв" : "Доступен · фоновая проверка"/);
  assert.doesNotMatch(routing, /queueNodes\.slice|chosenIds\.slice/);
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(css, /\.policy-reserve-queue > div \{[^}]*repeat\(auto-fit, minmax\(min\(100%, 300px\), 1fr\)\)/);
});

test("selection expansion retains every matching server, including more than ten, in selection order", () => {
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const names = ["selectorNodeIds", "orderedCandidateNodeIds", "decodeCitySelectionToken", "normalizedSelectorLabel", "selectorLocationName"];
  const source = parsed.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text)).map(node => node.getText(parsed)).join("\n");
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const expand = new Function("asText", "regionIdForCountry", `${compiled}; return orderedCandidateNodeIds;`)(
    (value, fallback = "") => typeof value === "string" ? value : fallback,
    country => country === "SE" ? "europe" : "other",
  );
  const nodes = Array.from({ length: 18 }, (_, index) => ({ id: `node-${index}`, country: "SE", city: "Malmö", location_key: `loc-${index}` }));
  const order = ["reverse:home", "city:SE:Malm%C3%B6", "country:SE", "wireguard:wg"];
  assert.deepEqual(expand(order, nodes, [{ id: "wg" }], [{ id: "home" }]), ["reverse:home", ...nodes.map(node => node.id), "wireguard:wg"]);
  assert.deepEqual(expand(["region:europe"], nodes, [], []), nodes.map(node => node.id));
  assert.deepEqual(
    expand([`city:CA:${encodeURIComponent("🇨🇦 ⭐️ Канада")}`], [
      { id: "canada", country: "CA", city: "🇨🇦 ⚡️ ⭐️ Канада", location_key: "canada" },
      { id: "toronto", country: "CA", city: "🇨🇦 Toronto", location_key: "toronto" },
    ], [], []),
    ["canada"],
  );
});

test("active pool size is visible and editable in advanced switching parameters", () => {
  assert.match(page, /\[candidateLimit, setCandidateLimit\] = useState/);
  assert.match(page, /Дополнительные параметры переключения[\s\S]*?Узлов в активном пуле[\s\S]*?name="max_active_candidates" value=\{candidateLimit\} onChange=\{\(event\) => setCandidateLimit\(Number\(event.target.value\)\)\}/);
  assert.match(page, /max_active_candidates: candidateLimit,\s+max_probe_candidates: candidateLimit/);
  assert.match(page, /const activeNodeCount = mode === "priority" \? eligibleNodeCount : Math.min\(candidateLimit, eligibleNodeCount\)/);
});

test("priority editor retains the whole ordered queue and decouples probe batch from URLTest limit", () => {
  assert.match(page, /const activePriorityItems = selectionOrder;/);
  assert.doesNotMatch(page, /selectionOrder.slice\(0, candidateLimit\)|coldPriorityItems/);
  assert.doesNotMatch(page, /probe_batch_size: mode === "best" \? 2 : 3/);
  assert.match(page, /Авто · URLTest: 2, приоритет: 3/);
});

test("route monitoring is one global form with concise scheduling controls", () => {
  assert.match(page, /function RoutingMonitorSettings/);
  assert.match(page, /Мониторинг маршрутов/);
  assert.match(page, /Доступность активного узла, сек\./);
  assert.match(page, /Максимум проверок за цикл/);
  assert.match(page, /<option value=\{10\}>10<\/option>/);
  assert.match(page, /\["probe_batch_size", 0, 10\]/);
  assert.match(page, /При аварии — одновременно; активный пул не меняется\./);
  assert.match(page, /routing_monitor: routingMonitor/);
  assert.match(page, /const monitorRanges/);
  assert.doesNotMatch(page, /Сохранить мониторинг/);
  assert.doesNotMatch(page, /active_check_interval_seconds: 60/);
  assert.doesNotMatch(page, /backup_check_interval_seconds: 300/);
});

test("actual pool field JSX is absent in priority and present in URLTest", async () => {
  const React = await import("react");
  const { renderToStaticMarkup } = await import("react-dom/server");
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let field;
  function visit(node) {
    if (ts.isConditionalExpression(node) && node.condition.getText(parsed) === 'mode === "best"'
      && node.whenTrue.getText(parsed).includes('name="max_active_candidates"')) field = node;
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  assert.ok(field, "pool field must be guarded by the mode");
  const source = `function renderField(mode) { return (${field.getText(parsed)}); }`;
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React } }).outputText;
  const renderField = new Function("React", "candidateLimit", "setCandidateLimit", `${compiled}; return renderField;`)(React, 3, () => {});
  assert.equal(renderToStaticMarkup(renderField("priority")), "");
  assert.match(renderToStaticMarkup(renderField("best")), /name="max_active_candidates"/);
});

test("runtime candidates are not falsely advertised as healthy reserves", () => {
  assert.match(routing, /readyReserves: queueNodes\.filter\(\(node\) => !node.selected && node.available && node.inRuntimePool\).length/);
  assert.match(routing, /\+\{policy.readyReserves\}\s+в резерве/);
  assert.doesNotMatch(routing, /policy.route.length - 1|`Резерв \$\{rank\}`/);
  assert.match(routing, /"Узлы маршрута" : "Выбранные направления"/);
  assert.match(routing, /node.availabilityKnown \? "Недоступен" : "Нет проверки"/);
  assert.match(routing, /node.availabilityKnown \? "is-down" : "is-unknown"/);
});
