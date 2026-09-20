import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(
  await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
);

test("all-LAN device mode is not blocked by per-device inventory validation", () => {
  assert.match(
    page,
    /\(kind === "local" && !allLanDevices && Boolean\(invalidSelectedSource\)\)/,
  );
  assert.match(
    page,
    /if \(kind === "local" && !allLanDevices && invalidSelectedSource\)/,
  );
});

test("all-LAN mode follows discovered subnets while individual mode keeps exact selections", () => {
  assert.match(
    page,
    /const effectiveSourceCidrs = allLanDevices\s*\? allLANInventoryComplete\s*\? discoveredAllLANCidrs\s*: selectedSourceCidrs\s*: sourceInventoryComplete\s*\? selectedSourceCidrs\.filter/,
  );
  assert.match(page, /source_scope: allLanDevices \? "lan-all" : undefined/);
  assert.match(
    page,
    /Отдельные устройства исключаются автоматически и используют свой маршрутный лист и DNS\./,
  );
});
