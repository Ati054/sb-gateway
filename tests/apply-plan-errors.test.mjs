import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

test("Apply dialog exposes exact draft validation errors", async () => {
  const [page, css, translations] = await Promise.all([
    readFile(new URL("app/page.tsx", projectRoot), "utf8"),
    readFile(new URL("app/globals.css", projectRoot), "utf8"),
    readFile(new URL("app/i18n-text.ts", projectRoot), "utf8"),
  ]);

  assert.match(page, /asObjectList\(asObject\(applyPlan\.check\)\.errors\)/);
  assert.match(page, /className="apply-plan-errors"/);
  assert.match(page, /planValidationIssueLabel\(path, locale\)/);
  assert.match(page, /planValidationIssueMessage\(issue, locale\)/);
  assert.match(css, /\.apply-plan-errors li \{[\s\S]*?min-width: 0;[\s\S]*?overflow-wrap: anywhere;/);
  assert.match(translations, /Выбранный TLS-профиль выключен или не содержит пару сертификата и private key/);
});
