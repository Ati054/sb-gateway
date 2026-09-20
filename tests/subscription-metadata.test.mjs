import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { mergeSubscriptionMetadata } from "../app/subscription-metadata.ts";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const old = { provider: { expires_at: "2026-12-26T16:06:00Z" }, refreshed_at: "2026-09-07T10:00:00Z" };
test("subscription dates survive missing or late responses without retaining deleted subscriptions", () => {
  assert.deepEqual(mergeSubscriptionMetadata({ a: old, removed: old }, {}, ["a"]), { a: old });
  for (const next of [{ provider: {} }, { provider: {}, refreshed_at: "2026-09-06T10:00:00Z" }]) {
    assert.equal(mergeSubscriptionMetadata({ a: old }, { a: next }, ["a"]).a, old);
  }
});
test("new authoritative metadata can change or remove the provider expiry", () => {
  const newer = { provider: {}, refreshed_at: "2026-09-08T10:00:00Z" };
  assert.equal(mergeSubscriptionMetadata({ a: old }, { a: newer }, ["a"]).a, newer);
});
test("connections load compact metadata without waiting for node inventories and keep cache outside the screen", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  const start = page.indexOf("function Connections(");
  const effect = page.slice(page.indexOf("  useEffect(() => {\n    let active = true;", start), page.indexOf("  const tlsProfilesById", start));
  assert.match(effect, /getSubscriptionMetadata/);
  assert.doesNotMatch(effect, /getSubscriptionNodes|Promise\.all/);
  assert.match(effect, /visibilityState !== "visible" \|\| inFlight/);
  assert.match(effect, /setInterval\(refresh, 30_000\)/);
  const connections = page.match(/<Connections\s[\s\S]*?\/>/)?.[0];
  assert.ok(connections);
  assert.match(connections, /subscriptionMetadata=\{subscriptionMetadata\}/);
  assert.match(connections, /setSubscriptionMetadata=\{setSubscriptionMetadata\}/);
  const css = await readFile(new URL("../app/globals.css", import.meta.url), "utf8");
  assert.match(css, /\.node-country-flag \{[^}]*width: 16px;[^}]*height: 12px;/);
});
