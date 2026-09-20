import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);
const [page, client, css] = await Promise.all([
  readFile(new URL("app/page.tsx", projectRoot), "utf8"),
  readFile(new URL("app/api-client.ts", projectRoot), "utf8"),
  readFile(new URL("app/globals.css", projectRoot), "utf8"),
]);

test("browser upload preflights before streaming and reports byte progress", () => {
  assert.match(page, /await preflightContainerImageUpload\(file\);\s+const result = await uploadContainerImage<JsonObject>\(file, setImageUploadProgress\)/);
  assert.match(client, /request\.upload\.addEventListener\("progress"/);
  assert.match(page, /role="progressbar" aria-label=\{tr\("Загрузка образа на SSD"\)\}/);
  assert.match(css, /\.image-upload-progress/);
});

test("scheduled update becomes a persistent monitored dialog", () => {
  assert.match(page, /setUpdateDialogOpen\(false\);\s+setUpdateProgressOpen\(true\);/);
  assert.match(page, /window\.setInterval\(\(\) => void refresh\(\), 2_000\)/);
  assert.match(page, /function LifecycleUpdateProgressDialog/);
  assert.match(page, /RouterOS готовит переключение/);
  assert.match(page, /Health-check и контрольный период/);
  assert.match(css, /\.lifecycle-progress-dialog/);
});
