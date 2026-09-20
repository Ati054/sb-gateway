import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";
import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const parsed = ts.createSourceFile("page.tsx", page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
let websiteFields;

function findWebsiteFields(node) {
  if (
    ts.isConditionalExpression(node) &&
    node.condition.getText(parsed) === 'hysteriaMasqueradeType === "website"' &&
    node.whenTrue.getText(parsed).includes('name="hysteria_masquerade_bandwidth_mbps"')
  ) {
    websiteFields = node;
  }
  ts.forEachChild(node, findWebsiteFields);
}

findWebsiteFields(parsed);
assert.ok(websiteFields, "website bandwidth fields must stay isolated to website mode");

const compiled = ts.transpileModule(
  `function renderWebsiteFields(props) {
    const {
      hysteriaMasqueradeType, hysteriaWebsiteURL, setHysteriaWebsiteURL,
      hysteriaWebsiteBandwidth, setHysteriaWebsiteBandwidth, hysteriaObfsEnabled,
    } = props;
    return (${websiteFields.getText(parsed)});
  }`,
  { compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React } },
).outputText;
const renderWebsiteFields = new Function(
  "React",
  `const { Fragment } = React; ${compiled}; return renderWebsiteFields;`,
)(React);

function render(mode) {
  return renderToStaticMarkup(
    renderWebsiteFields({
      hysteriaMasqueradeType: mode,
      hysteriaWebsiteURL: "https://example.com/",
      setHysteriaWebsiteURL: () => {},
      hysteriaWebsiteBandwidth: "1",
      setHysteriaWebsiteBandwidth: () => {},
      hysteriaObfsEnabled: false,
    }),
  );
}

test("website bandwidth control has safe bounds and default", () => {
  const html = render("website");
  assert.match(html, /name="hysteria_masquerade_bandwidth_mbps"/);
  assert.match(html, /min="0.1"/);
  assert.match(html, /max="100"/);
  assert.match(html, /step="0.1"/);
  assert.match(html, /value="1"/);
  assert.match(html, /required=""/);
});

test("website controls do not appear in static or local proxy modes", () => {
  for (const mode of ["", "string", "proxy"]) {
    assert.doesNotMatch(render(mode), /hysteria_masquerade_(url|bandwidth_mbps)/);
  }
});

test("persisted website bandwidth is emitted only by website masquerade", () => {
  const submitStart = page.indexOf("function ConnectionDialog(");
  const submitEnd = page.indexOf("function Connections(", submitStart);
  const submit = page.slice(submitStart, submitEnd);
  assert.match(submit, /submittedHysteriaMasqueradeType === "website"\s*\? \{ bandwidth_mbps: websiteBandwidth \}/);
});

test("masquerade keeps only the concise HTTP/3 caption", () => {
  assert.match(page, /С Salamander сайт недоступен обычным HTTP\/3-клиентам\./);
  assert.doesNotMatch(page, /Это ответ постороннему HTTP\/3-клиенту, а не TLS SNI или внешний CDN\./);
});
