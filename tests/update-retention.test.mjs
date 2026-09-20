import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(readFileSync(new URL("../app/page.tsx", import.meta.url), "utf8"));
test("plain toggle labels inherit the readable form label size", () => {
  const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(css, /\.toggle-row strong\s*\{\s*font-size: inherit;\s*\}/);
  assert.doesNotMatch(css, /\.toggle-row strong\s*\{\s*font-size: 9px;/);
});
test("previous-version setting has one short label and persists zero or one", () => {
  const toggle = page.match(/<Toggle\s+checked=\{keepPreviousVersion\}[\s\S]*?\/>/)?.[0];
  assert.ok(toggle);
  assert.match(toggle, /label="Хранить предыдущую версию"/);
  assert.match(toggle, /onChange=\{setKeepPreviousVersion\}/);
  assert.doesNotMatch(toggle, /description=/);
  assert.match(page, /retain_previous_images: keepPreviousVersion \? 1 : 0/);
  assert.match(page, /Number\(asObject\(config.updates\).retain_previous_images \?\? 0\) === 1/);
});
