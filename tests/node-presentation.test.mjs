import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";
import { nodePresentation, selectorCandidateIds, routeCandidateIds, compareRouteCandidates, nodeDisplayLabel, nodeLocationDetail, nodeProtocolSuffix } from "../app/node-presentation.ts";
import { normalizeLocalizedSource } from "./source-localization.mjs";

test("country flags render as local SVG while preserving the provider name", async () => {
  for (const [name, country, expected, text] of [
    ["🇨🇦 ⭐ Канада", "", "ca", "⭐ Канада"],
    ["🇩🇪 Германия", "", "de", "Германия"],
    ["США (Нью-Йорк)", "US", "us", "США (Нью-Йорк)"],
  ]) {
    const node = nodePresentation(name, country);
    assert.deepEqual(node, {label: text, flag: `/flags/${expected}.svg`});
    await access(new URL(`../public${node.flag}`, import.meta.url));
  }
  assert.deepEqual(nodePresentation("Reverse Reality"), {label: "Reverse Reality", flag: ""});
  assert.equal(nodePresentation("Unknown", "../../bad").flag, "");
  assert.equal(nodePresentation("Unknown", "ZZ").flag, "");
});

test("active node appears before its first historical sample; removed nodes do not linger", () => {
  const health = {runtime_confirmed:true, runtime_selected:"canada", candidate_labels:{canada:"🇨🇦 Канада", reserve:"Reverse"}};
  assert.deepEqual(selectorCandidateIds(health, {removed:{samples:42}}), ["canada", "reserve"]);
  assert.deepEqual(selectorCandidateIds({runtime_confirmed:true, runtime_selected:"canada"}, {}), ["canada"]);
  assert.deepEqual(selectorCandidateIds({runtime_confirmed:true, runtime_selected:"block", candidate_labels:{}}, {}), []);
  assert.deepEqual(selectorCandidateIds({runtime_confirmed:false, runtime_selected:"unknown"}, {}), []);
});

test("applied candidates do not mix with refreshed IDs or deduplicate by name", () => {
  const health = {candidate_labels:{old:"Germany",ws:"Warsaw",reality:"Warsaw"},runtime_confirmed:true,runtime_selected:"old"};
  assert.deepEqual(routeCandidateIds(health, {}, ["new","ws","reality"]), ["old","ws","reality"]);
  assert.deepEqual(routeCandidateIds({candidate_labels:{}}, {}, ["new"]), []);
  assert.deepEqual(routeCandidateIds({}, {}, ["new", "new"]), ["new"]);
});

test("route candidates put active and working reserves first even when unconfirmed", () => {
  const base = {selected:false,available:false,inRuntimePool:false,availabilityKnown:true};
  const nodes = [{...base,id:"failed"},{...base,id:"background",available:true},{...base,id:"reserve",available:true,inRuntimePool:true},{...base,id:"active",selected:true},{...base,id:"unknown",availabilityKnown:false}];
  assert.deepEqual(nodes.toSorted(compareRouteCandidates).map(n=>n.id), ["active","reserve","background","unknown","failed"]);
});

test("protocol suffix comes from metadata, never guessed from node name", () => {
  for (const [protocol,transport,suffix] of [["vless","ws","WS"],["reality","tcp","R"],["reality","grpc","gRPC+R"],["vless","xhttp","XHTTP"],["hysteria2","tcp","H2"],["vless","httpupgrade","HU"],["routeros-wireguard","","WG"]]) {
    assert.equal(nodeProtocolSuffix({protocol,transport}), suffix);
  }
  assert.equal(nodeDisplayLabel("Unknown Reality"), "Unknown Reality");
});

test("route labels disambiguate exact names across independent subscriptions", () => {
  const ws = {id:"ws",label:"🇵🇱 Poland - Warsaw",subscription_id:"one",subscription_display_name:"Provider WS",protocol:"vless",transport:"ws"};
  const reality = {...ws,id:"reality",protocol:"reality",transport:"tcp"};
  const other = {...ws,id:"other",subscription_id:"two",subscription_display_name:"Provider gRPC",transport:"grpc"};
  const different = {...ws,id:"different",label:"🇵🇱 🎮 ⭐️ Польша",transport:"grpc"};
  const germany = {...ws,id:"germany",label:"🇩🇪 🎮 ⚡️ 0.1X - LTE №59 - Hysteria2",protocol:"hysteria2"};
  const peers = [ws,reality,other,different,germany];
  assert.equal(nodeDisplayLabel(ws.label,ws,peers), `${ws.label} (WS)`);
  assert.equal(nodeDisplayLabel(reality.label,reality,peers), `${reality.label} (R)`);
  assert.equal(nodeDisplayLabel(other.label,other,peers), `${other.label} (gRPC)`);
  for (const node of [different,germany]) assert.equal(nodeDisplayLabel(node.label,node,peers), node.label);
});

test("same-protocol collisions use public source names and a stable final occurrence", () => {
  const first = {id:"b",label:"Shared",subscription_display_name:"One",protocol:"vless",transport:"ws"};
  const second = {...first,id:"a",subscription_display_name:"Two"};
  assert.equal(nodeDisplayLabel(first.label,first,[first,second]), "Shared (WS · One)");
  assert.equal(nodeDisplayLabel(second.label,second,[first,second]), "Shared (WS · Two)");

  const duplicate = {...first,id:"a"};
  assert.equal(nodeDisplayLabel(first.label,first,[first,duplicate]), "Shared (WS · One · #2)");
  assert.equal(nodeDisplayLabel(duplicate.label,duplicate,[first,duplicate]), "Shared (WS · One · #1)");
});

test("priority location detail does not repeat country and city already present in the node label", () => {
  assert.equal(
    nodeLocationDetail(
      "FR France - Strasbourg (WS)",
      "🇫🇷 Франция",
      "FR France - Strasbourg",
      "Vpnd WS",
      "VLESS",
    ),
    "Vpnd WS · VLESS",
  );
  assert.equal(
    nodeLocationDetail("Fast node", "🇫🇮 Финляндия", "Helsinki", "Provider", "VLESS"),
    "🇫🇮 Финляндия · Helsinki · Provider · VLESS",
  );
  assert.equal(
    nodeLocationDetail("Mexico · Vpnd Reality · REALITY", "🇲🇽 Мексика", "Mexico", "Vpnd Reality", "REALITY"),
    "",
  );
});

test("subscription is a hover hint without visible provider codes", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  const nodeName = page.split("function NodeName(")[1].split("function protocolLabel(")[0];
  assert.match(nodeName, /title=\{provider \?/);
  assert.match(nodeName, /tr\("\{node\} · Подписка: \{provider\}", \{ node: node\.label, provider \}\)/);
  assert.doesNotMatch(page, /node-provider-code|providerBadges|subscription\.code/);
  assert.equal((page.match(/<NodeName label=.*provider=/g) ?? []).length, 3);
});

test("settings save action follows the complete settings grid", async () => {
  const source = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const settingsStart = source.indexOf("function Settings(");
  const settingsEnd = source.indexOf("function ResetDraftDialog(", settingsStart);
  const settingsSource = source.slice(settingsStart, settingsEnd);
  const gridStart = settingsSource.indexOf('<section className="settings-grid">');
  const gridEnd = settingsSource.lastIndexOf("</section>");
  const action = settingsSource.indexOf('<div className="settings-save-actions">');

  assert.ok(settingsStart >= 0 && settingsEnd > settingsStart);
  assert.ok(gridStart >= 0 && gridEnd > gridStart);
  assert.ok(action > gridEnd, "save action must follow every settings card");
  assert.equal((settingsSource.match(/settings-save-actions/g) ?? []).length, 1);
});

test("TLS export lives in the edit footer between deletion and cancel", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  const dialog = page.split("function TlsProfileDialog(")[1].split("function ConnectionDialog(")[0];
  assert.match(dialog, /Подготовить удаление[\s\S]*setExportOpen\(true\)[\s\S]*>Экспорт<[\s\S]*>Отмена</);
  assert.match(dialog, /exportOpen && workingId.*TlsTransferDialog/);
  assert.doesNotMatch(page.split("function TlsProfileDialog(")[0], /setTlsTransfer\(profile\)/);
});

test("routing uses lightweight visible-only polling and shares one node label", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.equal((page.match(/<NodeName label=/g) ?? []).length, 3);
  assert.match(page, /if \(screen !== "routing"\) return;[\s\S]*visibilityState === "visible"[\s\S]*setInterval\(refresh, 5_000\)/);
  assert.match(page, /refreshDetailedStatus\(\), refreshSelectorStatus\(\)/);
});
