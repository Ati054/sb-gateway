import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

test("operations diagnostics separate skipped reasons from compact outcomes", async () => {
  const [page, css, translations] = await Promise.all([
    readFile(new URL("app/page.tsx", projectRoot), "utf8"),
    readFile(new URL("app/globals.css", projectRoot), "utf8"),
    readFile(new URL("app/i18n-text.ts", projectRoot), "utf8"),
  ]);

  assert.match(page, /className="validation-check-copy"/);
  assert.match(page, /className="validation-check-outcome"/);
  assert.match(page, /diagnosticReasonLabels\[rawReason\] \?\? rawReason/);
  assert.match(css, /\.validation-check-copy \{[\s\S]*?min-width: 0;[\s\S]*?flex-direction: column;/);
  assert.match(css, /\.validation-check-copy small \{[\s\S]*?overflow-wrap: anywhere;/);
  assert.match(css, /\.validation-check-outcome \{[\s\S]*?white-space: nowrap;/);
  assert.match(translations, /Активная конфигурация сейчас не запущена\./);
  assert.match(translations, /Диагностика не запускает внешние подключения/);
});
