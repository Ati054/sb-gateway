import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
const config = JSON.parse(
  await readFile(new URL("../internal/controlplane/default-config.json", import.meta.url), "utf8"),
);

test("operations offers one bounded gateway log viewer with fixed sources", () => {
  assert.match(page, /Журналы SB Gateway/);
  assert.match(page, /type RuntimeLogSource = "error" \| "process" \| "system" \| "routing" \| "nginx" \| "lifecycle"/);
  assert.match(page, /id="gateway-log-tab-routing"[\s\S]*?tr\("Маршруты"\)/);
  assert.match(page, /getXrayLogs<JsonObject>\(xrayLogSource, 300\)/);
  assert.match(page, /getSystemLogs<JsonObject>\(xrayLogSource, 300\)/);
  assert.match(page, /window\.setInterval\(\(\) => void loadXrayLog\(true\), 3_000\)/);
  assert.match(page, /role="tabpanel"/);
  assert.match(page, /aria-label=\{xrayLogCollapsed \? tr\("Развернуть журнал"\) : tr\("Свернуть журнал"\)\}/);
  assert.match(page, /hidden=\{xrayLogCollapsed\}/);
  assert.match(page, /Access-log подключений остаётся выключенным/);
});

test("Xray debug logging is explicit, temporary, and warning by default", () => {
  assert.equal(config.system.logging.xray_level, "warning");
  assert.equal(config.system.logging.xray_debug_timeout_minutes, 15);
  assert.match(page, /<option value="debug">Debug · 15/);
  assert.match(page, /автоматически вернёт Warning и перезапустит только Xray/);
  assert.match(page, /saveCurrentDraft\(/);
});
