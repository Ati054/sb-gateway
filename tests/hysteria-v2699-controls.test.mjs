import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const source = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);

function conditionalWithField(condition, fieldName) {
  let result;
  function visit(node) {
    if (
      ts.isConditionalExpression(node) &&
      node.condition.getText(source) === condition &&
      node.whenTrue.getText(source).includes(`name="${fieldName}"`)
    ) {
      result = node;
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  assert.ok(result, `${fieldName} must stay behind ${condition}`);
  return result;
}

function compileConditional(name, node, declarations) {
  const compiled = ts.transpileModule(
    `function ${name}(props) {
      const { ${declarations} } = props;
      return (${node.getText(source)});
    }`,
    { compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React } },
  ).outputText;
  return new Function("React", "asText", `const { Fragment } = React; ${compiled}; return ${name};`)(
    React,
    (value, fallback = "—") =>
      typeof value === "string" || typeof value === "number" ? String(value) : fallback,
  );
}

const brutal = compileConditional(
  "renderBrutal",
  conditionalWithField('hysteriaCongestion === "brutal"', "hysteria_brutal_disable_loss_compensation"),
  "hysteriaCongestion, existingXrayQuic",
);
const proxy = compileConditional(
  "renderProxy",
  conditionalWithField('hysteriaMasqueradeType === "proxy"', "hysteria_masquerade_x_forwarded"),
  "hysteriaMasqueradeType, existingXrayMasquerade",
);

test("new Brutal setting is rendered only for Brutal", () => {
  const html = renderToStaticMarkup(
    brutal({ hysteriaCongestion: "brutal", existingXrayQuic: { brutal_disable_loss_compensation: true } }),
  );
  assert.match(html, /name="hysteria_brutal_disable_loss_compensation"/);
  assert.match(html, /checked=""/);
  assert.match(html, /Не увеличивать скорость отправки для компенсации потерь/);
  for (const congestion of ["", "bbr"]) {
    assert.equal(
      renderToStaticMarkup(brutal({ hysteriaCongestion: congestion, existingXrayQuic: {} })),
      "",
    );
  }
});

test("X-Forwarded control is isolated to the local proxy form", () => {
  const html = renderToStaticMarkup(
    proxy({ hysteriaMasqueradeType: "proxy", existingXrayMasquerade: { x_forwarded: true } }),
  );
  assert.match(html, /name="hysteria_masquerade_x_forwarded"/);
  assert.match(html, /Только доверенному локальному HTTP-сервису/);
  for (const type of ["", "string", "website"]) {
    assert.equal(
      renderToStaticMarkup(proxy({ hysteriaMasqueradeType: type, existingXrayMasquerade: {} })),
      "",
    );
  }
});

test("new Hysteria values and the REALITY version limit preserve explicit-only semantics", () => {
  assert.match(page, /placeholder="Без ограничения версии"/);
  assert.match(
    page,
    /submittedHysteriaCongestion === "brutal"\s*&&\s*data\.get\("hysteria_brutal_disable_loss_compensation"\) === "on"/,
  );
  assert.match(page, /data\.get\("hysteria_disable_gso"\) === "on"/);
  assert.match(page, /data\.get\("hysteria_disable_stateless_reset"\) === "on"/);
  assert.match(
    page,
    /submittedHysteriaMasqueradeType === "proxy"\s*&&\s*data\.get\("hysteria_masquerade_x_forwarded"\) === "on"/,
  );
  assert.doesNotMatch(
    conditionalWithField('hysteriaMasqueradeType === "website"', "hysteria_masquerade_bandwidth_mbps").whenTrue.getText(source),
    /hysteria_masquerade_x_forwarded/,
  );
});

test("UDP hopping is opt-in and keeps the complete range behind its switch", () => {
  const conditional = conditionalWithField("hysteriaUDPHopEnabled", "hysteria_udp_hop_port_start");
  const body = conditional.whenTrue.getText(source);
  for (const field of [
    "hysteria_udp_hop_port_start",
    "hysteria_udp_hop_port_end",
    "hysteria_udp_hop_interval_min",
    "hysteria_udp_hop_interval_max",
    "hysteria_udp_hop_excluded_ports",
  ]) {
    assert.match(body, new RegExp(`name="${field}"`));
  }
  assert.match(page, /existingXrayUDPHop\.enabled === true/);
  assert.match(page, /submittedHysteriaUDPHopEnabled\s*\?\s*\{\s*udp_hop:/);
});

test("the primary Hysteria masquerade selector keeps the standard field width", () => {
  assert.match(
    page,
    /<label className="field">\s*Masquerade для неизвестных запросов\s*<select\s*name="hysteria_masquerade_type"/,
  );
  assert.doesNotMatch(
    page,
    /<label className="field form-span">\s*Masquerade для неизвестных запросов/,
  );
});
