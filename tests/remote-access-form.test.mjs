import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const asText = (value, fallback) => typeof value === "string" ? value : fallback;

test("client policy controls state their full-profile scope", () => {
  assert.match(page, /<legend>Полный профиль · Xray \/ Sing-box \/ Mihomo<\/legend>/);
  for (const field of ["client_individual_routing", "client_auto_fallback", "client_adblock"]) {
    assert.match(page, new RegExp(`name="${field}"`));
  }
});

test("remote user has an explicit subscription format", () => {
  const format = page.match(/<select\s+name="subscription_format"[\s\S]*?<\/select>/)?.[0];
  assert.ok(format);
  assert.deepEqual(
    [...format.matchAll(/<option value="([^"]+)"/g)].map((match) => match[1]),
    ["auto", "array", "xray", "singbox", "mihomo", "links"],
  );
  assert.match(format, /Совместимый список · рекомендуется/);
  assert.match(format, /JSON-массив · узлы и автовыбор/);
  assert.match(format, /Xray JSON · только Xray-клиенты/);
  assert.match(format, /Sing-box JSON · Hiddify\/Karing/);
  assert.match(page, /subscription_format:\s*String\(/);
});

test("remote user owns the client TLS fingerprint", () => {
  const fingerprint = page.match(/<select\s+name="client_fingerprint"[\s\S]*?<\/select>/)?.[0];
  assert.ok(fingerprint);
  assert.deepEqual(
    [...fingerprint.matchAll(/<option value="([^"]+)"/g)].map((match) => match[1]),
    ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"],
  );
  assert.match(page, /client_fingerprint:\s*String\(/);
  assert.doesNotMatch(page, /<select\s+name="fingerprint"/);
});

test("LAN access offers only three roles; only the toggle controls enablement", () => {
  const select = page.match(/<select\s+name="role"[\s\S]*?<\/select>/)?.[0];
  assert.ok(select);
  assert.deepEqual([...select.matchAll(/<option value="([^"]+)"/g)].map((m) => m[1]), ["trusted-full", "trusted-limited", "internet-only"]);
  assert.doesNotMatch(page, /data\.get\("enabled"\) === "on"\s*&&/);
  const body = page.match(/const \[remoteRole, setRemoteRole\] = useState\(\(\) => \{([\s\S]*?)\n  \}\);/)?.[1];
  assert.ok(body);
  for (const role of ["trusted-full", "trusted-limited", "internet-only", "disabled"]) {
    const result = vm.runInNewContext(`(() => {${body}})()`, {existingItem: {role, enabled: false}, asText});
    assert.equal(result, role === "disabled" ? "internet-only" : role);
  }
});
