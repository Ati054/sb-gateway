import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
const asText = (value, fallback) => typeof value === "string" ? value : fallback;

test("adding several CDNs creates distinct names without enabling or copying their endpoint", () => {
  const body = page.match(/function cloneCdnDeployment\(index: number, duplicate = true\) \{([\s\S]*?)\n  \}\n  async function showHttpPath/)?.[1];
  assert.ok(body);
  let deployments = [{id: "primary", display_name: "Основной CDN", hostname: "edge.test", enabled: true}];
  const context = {asText, generateOriginHeaderSecret: () => "test-only", setCdnDeployments: (update) => { deployments = update(deployments); }};
  for (let index = 0; index < 2; index++) {
    vm.runInNewContext(`((index, duplicate) => {${body}})(${index}, false)`, context);
  }
  assert.deepEqual(Array.from(deployments, (d) => d.display_name), ["Основной CDN", "CDN 2", "CDN 3"]);
  assert.equal(new Set(deployments.map((d) => d.id)).size, 3);
  for (const d of deployments.slice(1)) { assert.equal(d.enabled, false); assert.equal(d.hostname, ""); }
  const editor = css.match(/\.cdn-deployments-editor\s*\{([^}]+)\}/)?.[1];
  assert.ok(editor);
  assert.doesNotMatch(editor, /background|border|padding/);
  assert.match(css, /\.cdn-deployments-list\s*\{[^}]*gap: 24px/s);
  assert.match(page, /<fieldset className="cdn-deployment-row"[^>]*>\s*<legend>/);
});
