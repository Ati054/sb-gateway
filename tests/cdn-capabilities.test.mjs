import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { AUTOMATIC_CIDR_PROVIDERS, supportsAutomaticCidr, automaticCidrHint } from "../app/cdn-capabilities.ts";

test("official feed choices match backend adapters and preserve honest unsupported modes", async () => {
  const backend = await readFile(new URL("../internal/cdnfeed/feed.go", import.meta.url), "utf8");
  const adapters = Array.from(backend.matchAll(/\{"([a-z]+)", "https:/g), (m) => m[1]);
  assert.deepEqual([...AUTOMATIC_CIDR_PROVIDERS].sort(), [...new Set(adapters)].sort());
  for (const id of AUTOMATIC_CIDR_PROVIDERS) assert.equal(supportsAutomaticCidr(id), true);
  for (const id of ["vk", "cdnetworks", "custom", ""]) assert.equal(supportsAutomaticCidr(id), false);
  assert.match(automaticCidrHint("gcore"), /15 минут/);
  assert.match(automaticCidrHint("cloudflare"), /Автообновление/);
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(page, /supportsAutomaticCidr\(subscriptionCdnProvider\)/);
  assert.match(page, /supportsAutomaticCidr\(deploymentProvider\)/);
  assert.doesNotMatch(page, /без официального машинного CIDR feed/);
});
