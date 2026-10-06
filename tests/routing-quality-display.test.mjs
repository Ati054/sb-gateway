import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const routing = page.slice(page.indexOf("function Routing("), page.indexOf("function Connections("));

test("quality table follows configured priority or visible URLTest median ranking", async () => {
  const helper = await readFile(new URL("../app/node-quality.ts", import.meta.url), "utf8");
  assert.match(routing, /const quality = qualitySheet\(policyRows, qualityPolicyId\)/);
  assert.match(routing, /quality\.rows\.map\(\(node\) =>/);
  assert.match(routing, /Показано \{quality.rows.length\}\s+из \{quality.total\}/);
  assert.match(helper, /rows: rows\.slice\(0, 10\)/);
  assert.match(helper, /policy\?\.mode === "priority"/);
  assert.match(helper, /priorityPositions\.get\(left\.id\)/);
  assert.doesNotMatch(helper, /if \(left\.inRuntimePool !== right\.inRuntimePool\)/);
  assert.match(helper, /if \(left\.quality !== right\.quality\) return left\.quality \? -1 : 1/);
  assert.match(helper, /latencyOrder\(left, right\)/);
  assert.doesNotMatch(helper, /speedBps|responsiveScoreOrder|decisionMedian/);
  assert.ok(helper.indexOf('if (left.selected !== right.selected)') < helper.indexOf('const latency = latencyOrder'));
  assert.ok(helper.indexOf('if (latency) return latency') < helper.indexOf('if (left.available !== right.available)'));
  assert.match(routing, /mode: normalizePolicySelectionMode\(policy\.mode\)/);
  assert.match(routing, /priorityOrder: chosenCandidateIds/);
  assert.match(routing, /quality\.policy\?\.mode === "priority" \? "Приоритет" : "Рейтинг"/);
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(css, /th:nth-child\(1\) \{ width: 78px; \}/);
});

test("only a current confirmed route outage replaces the historical percentage", () => {
  assert.doesNotMatch(routing, /outage_penalty/);
  assert.match(routing, /confirmedUnstableRoute\(\s*asObject\(health\.availability_ok\)\[candidate\]/);
  assert.doesNotMatch(routing, /max_packet_loss_percent \?\? 40/);
  assert.doesNotMatch(routing, /lastOutageAt > 0 && Date\.now\(\) \/ 1000/);
  assert.match(routing, /node\.unstable \? "Нестабилен" : node\.availability == null/);
  assert.match(routing, /node\.unstable \? <small>Срыв маршрута<\/small>/);
});

test("a short outage is not labeled unstable without sustained measured loss", async () => {
  const helper = await readFile(new URL("../app/node-quality.ts", import.meta.url), "utf8");
  const compiled = ts.transpileModule(helper, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const exports = {};
  new Function("exports", compiled)(exports);
  const unstable = exports.confirmedUnstableRoute;
  assert.equal(unstable(false, 145, 1.4, 40), false);
  assert.equal(unstable(false, 145, 41, 40), true);
  assert.equal(unstable(false, 2, 100, 40), false);
  assert.equal(unstable(true, 145, 41, 40), false);
  assert.equal(unstable(undefined, 145, 41, 40), false);
});

test("expanded policy uses the full selected inventory, not the capped runtime pool", async () => {
  assert.match(routing, /orderedCandidateNodeIds\(displayOrder, routingNodes, configuredWireguardExits, configuredReverseVlessExits, asObjectList\(policy\.node_groups\)\)/);
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
  const names = ["selectorNodeIds", "orderedCandidateNodeIds", "nodeMatchesUserGroup", "decodeCitySelectionToken", "normalizedSelectorLabel", "selectorLocationName"];
  const source = parsed.statements.filter(node => ts.isFunctionDeclaration(node) && names.includes(node.name?.text)).map(node => node.getText(parsed)).join("\n");
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const expand = new Function("asText", "asStringList", "regionIdForCountry", `${compiled}; return orderedCandidateNodeIds;`)(
    (value, fallback = "") => typeof value === "string" ? value : fallback,
    value => Array.isArray(value) ? value.filter(item => typeof item === "string") : [],
    country => country === "SE" ? "europe" : "other",
  );
  const nodes = Array.from({ length: 18 }, (_, index) => ({ id: `node-${index}`, country: "SE", city: "Malmö", location_key: `loc-${index}` }));
  const order = ["reverse:home", "city:SE:Malm%C3%B6", "country:SE", "wireguard:wg"];
  assert.deepEqual(expand(order, nodes, [{ id: "wg" }], [{ id: "home" }]), ["reverse:home", ...nodes.map(node => node.id), "wireguard:wg"]);
  assert.deepEqual(expand(["region:europe"], nodes, [], []), nodes.map(node => node.id));
  assert.deepEqual(expand(["group:sweden"], nodes, [], [], [{ id: "sweden", countries: ["SE"] }]), nodes.map(node => node.id));
  assert.deepEqual(
    expand([`city:CA:${encodeURIComponent("🇨🇦 ⭐️ Канада")}`], [
      { id: "canada", country: "CA", city: "🇨🇦 ⚡️ ⭐️ Канада", location_key: "canada" },
      { id: "toronto", country: "CA", city: "🇨🇦 Toronto", location_key: "toronto" },
    ], [], []),
    ["canada"],
  );
});

test("user groups match multiple emoji tokens across presentation variants", () => {
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const source = parsed.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === "nodeMatchesUserGroup")?.getText(parsed);
  assert.ok(source);
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const matches = new Function("asText", "asStringList", `${compiled}; return nodeMatchesUserGroup;`)(
    (value, fallback = "") => typeof value === "string" ? value : fallback,
    value => Array.isArray(value) ? value.filter(item => typeof item === "string") : [],
  );
  assert.equal(matches({ name_contains: "⚡, ⭐" }, { label: "🇸🇪 ⚡️ Быстрый ⭐️ Швеция" }), true);
  assert.equal(matches({ name_contains: "⚡, ⭐" }, { label: "🇸🇪 ⚡️ Швеция" }), false);
  assert.equal(matches({ name_contains: "⚡, ⭐", name_excludes: "резерв, TEST" }, { label: "⚡️ ⭐️ Швеция резерв" }), false);
  assert.equal(matches({ name_contains: "⚡, ⭐", name_excludes: "резерв, TEST" }, { label: "⚡️ ⭐️ Sweden testing" }), true);
  assert.equal(matches({ name_excludes: "test" }, { label: "Sweden" }), false);
  assert.equal(matches({ subscription_ids: ["*"], countries: ["CA"] }, { subscription_id: "provider-a", country: "CA" }), true);
  assert.equal(matches({ subscription_ids: ["*"], countries: ["CA"] }, { subscription_id: "provider-b", country: "CA" }), true);
  assert.equal(matches({ subscription_ids: ["*"], countries: ["CA"] }, { country: "CA" }), false);
  assert.equal(matches({ subscription_ids: ["*"], countries: ["CA"] }, { subscription_id: "provider-b", country: "DE" }), false);
  assert.equal(matches({ subscription_ids: [], countries: ["CA"] }, { country: "CA" }), true);
});

test("rule-based group editor offers all subscriptions and provider-neutral examples", async () => {
  const source = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(source, /<option value="\*">\{tr\("Все подписки"\)\}<\/option>/);
  assert.match(source, /<option value="">\{tr\("Любой источник \(старое правило\)"\)\}<\/option>/);
  assert.match(source, /subscription_ids: \[newSubscription\]/);
  assert.doesNotMatch(source, /placeholder="⚡, ⭐"/);
  assert.doesNotMatch(source, /Например: для мобильных операторов/);
});

test("route editor keeps view controls horizontal and scopes protocol filters to domain or IP", async () => {
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(css, /\.subscription-location-heading > div:not\(\.subscription-view-switch\)/);
  assert.match(css, /\.policy-editor-modal \.subscription-view-switch \{ display: flex;/);
  assert.match(css, /\.custom-route-row \{ display: grid;/);
  assert.match(css, /\.custom-route-row \{[^\n]*align-items: start;/);
  assert.match(css, /\.custom-route-protocol-filter \{ grid-column: 3 \/ -2;/);
  assert.match(css, /\.custom-route-row \.custom-route-protocol-filter \{ grid-column: 2 \/ 4; grid-row: 4; \}/);
  assert.match(css, /\.custom-route-row \.custom-route-remove \{ grid-column: 3; grid-row: 1; \}/);
  assert.doesNotMatch(page, /<option value="protocol">/);
  assert.match(page, /rule\.kind === "domain" \|\| rule\.kind === "ip"/);
  assert.match(page, /\["http", "tls", "quic"\]\.map/);
  assert.match(page, /<label className="field custom-route-value">/);
});

test("switching editor no longer exposes independent pool limits", () => {
  assert.doesNotMatch(page, /name="max_active_candidates"|setCandidateLimit/);
  assert.doesNotMatch(page, /max_active_candidates:|max_probe_candidates:/);
  assert.match(page, /const candidateLimit = routingMonitorValues\(config\).probe_batch_size/);
});

test("priority editor retains the whole ordered queue and decouples probe batch from URLTest limit", () => {
  assert.match(page, /const activePriorityItems = selectionOrder;/);
  assert.doesNotMatch(page, /selectionOrder.slice\(0, candidateLimit\)|coldPriorityItems/);
  assert.doesNotMatch(page, /probe_batch_size: mode === "best" \? 2 : 3/);
  assert.match(page, /probe_batch_size: 10/);
  assert.doesNotMatch(page, /Авто · общий бюджет: 5/);
});



test("route monitoring is one global form with concise scheduling controls", () => {
  assert.match(page, /function RoutingMonitorSettings/);
  assert.match(page, /Мониторинг маршрутов/);
  assert.match(page, /Доступность активного узла, сек\./);
  assert.match(page, /Максимум проверок за цикл/);
  assert.match(page, /\["probe_batch_size", 1, 64\]/);
  assert.match(page, /Общий лимит одновременно проверяемых узлов/);
  assert.match(page, /routing_monitor: routingMonitor/);
  assert.match(page, /const monitorRanges/);
  assert.doesNotMatch(page, /Сохранить мониторинг/);
  assert.doesNotMatch(page, /active_check_interval_seconds: 60/);
  assert.doesNotMatch(page, /backup_check_interval_seconds: 300/);
});

test("global probe count is numeric and independent from the working pool", async () => {
  const React = await import("react");
  const { renderToStaticMarkup } = await import("react-dom/server");
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let field;
  function visit(node) {
    if (ts.isJsxElement(node) && node.openingElement.tagName.getText(parsed) === "label"
      && node.getText(parsed).includes('update("probe_batch_size"')) field = node;
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  assert.ok(field);
  const compiled = ts.transpileModule(`function renderField() { return (${field.getText(parsed)}); }`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React },
  }).outputText;
  for (const count of [1, 5, 10, 24, 64]) {
    const render = new Function("React", "tr", "values", "disabled", "update", `${compiled}; return renderField;`)(React, value => value, { probe_batch_size: count }, false, () => {});
    const html = renderToStaticMarkup(render());
    assert.match(html, /type="number" min="1" max="64" step="1"/);
    assert.match(html, new RegExp(`value="${count}"`));
    assert.doesNotMatch(html, /<select/);
  }
  assert.match(page, /probe_batch_size: 10/);
  assert.match(page, /key === "probe_batch_size" && value === 0/);
  assert.doesNotMatch(page, /name="quality_window"|name="failure_threshold"|name="recovery_threshold"|name="max_packet_loss_percent"/);
  assert.doesNotMatch(page, /update\("failure_retry_interval_seconds"|update\("reserve_check_interval_seconds"|update\("full_scan_interval_seconds"/);
  assert.match(page, /Интервал оценки задержки, сек\./);
});

test("URLTest latency threshold is absent in priority and no speed setting remains", async () => {
  const React = await import("react");
  const { renderToStaticMarkup } = await import("react-dom/server");
  const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let field;
  function visit(node) {
    if (ts.isConditionalExpression(node) && node.condition.getText(parsed) === 'mode === "best"'
      && node.whenTrue.getText(parsed).includes('name="switch_improvement_ms"')) field = node;
    ts.forEachChild(node, visit);
  }
  visit(parsed);
  assert.ok(field);
  assert.doesNotMatch(page, /name="speed_/);
  assert.doesNotMatch(page, /speedDegradationPercent|speedBps|speedAt/);
  const compiled = ts.transpileModule(`function renderField(mode) { return (${field.getText(parsed)}); }`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React },
  }).outputText;
  const render = new Function("React", "tr", "asText", "existingPolicy", `${compiled}; return renderField;`)(
    React, value => value, (value, fallback) => value ?? fallback, {},
  );
  assert.equal(renderToStaticMarkup(render("priority")), "");
  assert.match(renderToStaticMarkup(render("best")), /name="switch_improvement_ms"/);
});



test("runtime candidates are not falsely advertised as healthy reserves", () => {
  assert.match(routing, /readyReserves: queueNodes\.filter\(\(node\) => !node.selected && node.available && node.inRuntimePool\).length/);
  assert.match(routing, /\+\{policy.readyReserves\}\s+в резерве/);
  assert.doesNotMatch(routing, /policy.route.length - 1|`Резерв \$\{rank\}`/);
  assert.match(routing, /"Узлы маршрута" : "Выбранные направления"/);
  assert.match(routing, /node.availabilityKnown \? "Недоступен" : "Нет проверки"/);
  assert.match(routing, /node.availabilityKnown \? "is-down" : "is-unknown"/);
});
