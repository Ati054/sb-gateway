import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import ts from "typescript";
import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { acmeDNSDomains, acmeDNSDelegations, importAcmeDNSAccounts } from "../app/acme-dns.ts";
import { acmeDNSTimeoutMinutes } from "../app/acme-timeout.ts";

const account = { username: "test-user", password: "test-secret", subdomain: "record1", fulldomain: "record1.auth.example.net", allowfrom: [] };
test("ACME-DNS registration import keeps secrets separate from public CNAME rows", () => {
  const domains = ["api.example.com", "*.api.example.com"];
  assert.deepEqual(acmeDNSDomains(domains), ["api.example.com"]);
  const encoded = importAcmeDNSAccounts(JSON.stringify(account), domains);
  assert.equal(JSON.parse(encoded)[domains[0]].password, "test-secret");
  assert.equal(encoded.includes("allowfrom"), false);
  const rows = acmeDNSDelegations(encoded);
  assert.deepEqual(rows, [{ domain: "api.example.com", name: "_acme-challenge.api.example.com", target: account.fulldomain }]);
  assert.equal(JSON.stringify(rows).includes("test-secret"), false);
  assert.equal(JSON.stringify(rows).includes("test-user"), false);
});
test("ACME-DNS SANs require distinct registrations, wildcard shares its base", () => {
  const domains = ["api.example.com", "msk.example.com"];
  assert.throws(() => importAcmeDNSAccounts(JSON.stringify(account), domains));
  assert.throws(() => importAcmeDNSAccounts(JSON.stringify(Object.fromEntries(domains.map(d => [d, account]))), domains));
  const entries = { [domains[0]]: account, [domains[1]]: { ...account, subdomain: "record2", fulldomain: "record2.auth.example.net" } };
  assert.equal(acmeDNSDelegations(importAcmeDNSAccounts(JSON.stringify(entries), domains)).length, 2);
  assert.throws(() => importAcmeDNSAccounts(JSON.stringify(entries), [domains[0]]));
});
test("ACME-DNS import errors never include JSON fragments or keys", () => {
  for (const value of ["test-secret", "null", "[]", "{}", JSON.stringify({...account, password: "test-secret\n"}), "x".repeat(20481)]) {
    assert.throws(() => importAcmeDNSAccounts(value, ["api.example.com"]), error => !error.message.includes("test-secret"));
  }
});
test("ACME-DNS form guards endpoint changes and stale asynchronous responses", () => {
  const source = readFileSync(new URL("../app/acme-fields.tsx", import.meta.url), "utf8");
  assert.match(source, /value="acmedns">ACME-DNS/);
  assert.match(source, /storedProvider === settings.provider/);
  assert.match(source, /acme_dns_server === settings.acme_dns_server/);
  assert.match(source, /current.current === started/);
  assert.match(source, /generation !== reading.current/);
  assert.match(source, /check.signature === signature/);
  assert.match(source, /reading.current\+\+; setCredentials\(\{\}\)/);
  assert.match(source, /type="button"[^>]+disabled=\{checking \|\| !model.loaded\}/);
  assert.match(source, /!loadError && typeof status.message === "string"/);
  assert.doesNotMatch(source, /catch\s*\{[\s\S]{0,200}setStatus/);
  assert.doesNotMatch(source, /Провайдер DNS-записей, не CDN/);
});

test("ACME-DNS manual wait parser serializes only valid integer minutes", () => {
  assert.equal(acmeDNSTimeoutMinutes(""), undefined);
  assert.equal(acmeDNSTimeoutMinutes("120"), 120);
  for (const value of ["0", "1.5", "1441", "-1", "x"]) assert.equal(acmeDNSTimeoutMinutes(value), undefined, value);
});

test("actual ACME form exposes CNAME, keeps other provider forms unchanged, and renders only current running status", () => {
  const source = readFileSync(new URL("../app/acme-fields.tsx", import.meta.url), "utf8");
  const parsed = ts.createSourceFile("acme-fields.tsx", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const functions = parsed.statements.filter(node => ts.isFunctionDeclaration(node) && ["canonicalAcmeDomains", "sameAcmeDomains", "acmeIssueAvailable", "acmeRunningStage", "acmeRunningOperationStatus", "AcmeFields", "AcmeDNSFields"].includes(node.name?.text))
    .map(node => node.getText(parsed).replace(/^export /, "")).join("\n");
  const compiled = ts.transpileModule(functions, { compilerOptions: { target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.React } }).outputText;
  const exports = new Function("React", "acmeDNSDelegations", "acmeDNSDomains", "importAcmeDNSAccounts", `${"const {useState,useEffect,useRef}=React;"}${compiled};return { AcmeFields, acmeRunningStage, acmeRunningOperationStatus, acmeIssueAvailable };`)(React, acmeDNSDelegations, acmeDNSDomains, importAcmeDNSAccounts);
  const Fields = exports.AcmeFields;
  const settings = {provider:"acmedns", acme_dns_server:"https://auth.example.net", domains:["api.example.com"], email:"admin@example.com", enabled:true, terms_accepted:true};
  const model = {settings, credentials:{accounts:importAcmeDNSAccounts(JSON.stringify(account),settings.domains)}, status:{}, loaded:true};
  const html = renderToStaticMarkup(React.createElement(Fields,{model}));
  assert.match(html, /_acme-challenge.api.example.com/);
  assert.match(html, /record1.auth.example.net/);
  assert.match(html, /Проверить CNAME/);
  assert.doesNotMatch(html, /test-secret|test-user/);
  assert.match(html, /Ожидание DNS[\s\S]*Автоматически/);
  assert.doesNotMatch(html, />Минуты</);
  const manualWait = {...model, settings:{...settings, propagation_timeout_minutes:120}};
  assert.match(renderToStaticMarkup(React.createElement(Fields,{model:manualWait})), /Минуты[\s\S]*value="120"/);
  const saved = {...model, credentials:{}, status:{settings, credentials_configured:true, delegations:acmeDNSDelegations(model.credentials.accounts)}};
  assert.match(renderToStaticMarkup(React.createElement(Fields,{model:saved})), /Учётные записи сохранены/);
  saved.settings = {...settings, acme_dns_server:"https://changed.example.net"};
  assert.doesNotMatch(renderToStaticMarkup(React.createElement(Fields,{model:saved})), /Учётные записи сохранены|record1.auth.example.net/);
  for (const provider of ["gcore", "cloudflare", "regru", "yandexcloud"]) {
    const other = renderToStaticMarkup(React.createElement(Fields,{model:{...model,settings:{...settings,provider},credentials:{}}}));
    assert.doesNotMatch(other, /name="acme_dns_server"|Проверить CNAME/);
    assert.doesNotMatch(other, /Ожидание DNS|Минуты/);
  }
  const failureSettings = {...settings, provider:"gcore"};
  const initialFailure = renderToStaticMarkup(React.createElement(Fields,{model:{...model,settings:failureSettings,credentials:{},status:{state:"failed", message:"Выпуск не выполнен. Повторите вручную.", manual_retry_only:true, ca_retry_not_before:"2026-09-10T00:00:00Z"}}}));
  assert.match(initialFailure, /Ручной повтор возможен после:/);
  assert.doesNotMatch(initialFailure, /Следующая попытка:/);
  const renewalFailure = renderToStaticMarkup(React.createElement(Fields,{model:{...model,settings:failureSettings,credentials:{},status:{state:"failed", message:"Продление не выполнено.", next_attempt:"2026-09-10T00:00:00Z", ca_retry_not_before:"2026-09-11T00:00:00Z"}}}));
  assert.match(renewalFailure, /Следующая попытка:/);
  assert.doesNotMatch(renewalFailure, /Ручной повтор возможен после:/);
  const running = {...model, settings:failureSettings, credentials:{}, status:{state:"running", message:"Проверка DNS и выпуск сертификата…", operation_stage:"dns_precheck", settings:failureSettings, credentials_configured:true, last_attempt:"2026-09-08T16:26:37.739Z", operation_timeout_seconds:16260}};
  const runningHTML = renderToStaticMarkup(React.createElement(Fields,{model:running}));
  assert.match(runningHTML, /Проверка DNS и подтверждение домена…/);
  assert.doesNotMatch(runningHTML, />Проверка DNS и выпуск сертификата…</);
  assert.match(runningHTML, /Начато:/);
  assert.match(runningHTML, /Лимит ожидания: 4 ч 31 мин/);
  for (const lastAttempt of [undefined, "not-a-timestamp"]) {
    const invalid = renderToStaticMarkup(React.createElement(Fields,{model:{...running, status:{...running.status, last_attempt:lastAttempt}}}));
    assert.doesNotMatch(invalid, /Invalid Date|Начато:|Лимит ожидания:/);
  }
  const staleRunning = renderToStaticMarkup(React.createElement(Fields,{model:{...running, loadError:"Не удалось получить статус сертификата."}}));
  assert.doesNotMatch(staleRunning, /Проверка DNS и выпуск сертификата|Лимит ожидания:/);
  assert.match(staleRunning, /API-токен\s*<input[^>]*placeholder="Сохранён"/);
  assert.doesNotMatch(staleRunning, /API-токен\s*<input[^>]*\srequired(?:=|\s|>)/);
  assert.equal(exports.acmeRunningStage({state:"running", operation_stage:"certificate_received"}), "Сертификат получен.");
  assert.equal(exports.acmeRunningStage({state:"running", operation_stage:"unknown"}), undefined);
  assert.equal(exports.acmeRunningStage({state:"running", operation_stage:"__proto__"}), undefined);
  assert.equal(exports.acmeRunningStage({state:"failed", operation_stage:"dns_precheck"}), undefined);
  assert.equal(exports.acmeRunningOperationStatus({state:"failed", last_attempt:"2026-09-08T16:26:37.739Z", operation_timeout_seconds:16260}), undefined);
  const issued = {settings, manual_issue_needed:false};
  assert.equal(exports.acmeIssueAvailable(true, "", settings, issued), false);
  assert.equal(exports.acmeIssueAvailable(true, "", {...settings, domains:["API.EXAMPLE.COM."]}, issued), false);
  assert.equal(exports.acmeIssueAvailable(true, "", {...settings, domains:["api.example.com", "new.example.com"]}, issued), true);
  assert.equal(exports.acmeIssueAvailable(true, "", settings, {}), true);
  assert.equal(exports.acmeIssueAvailable(false, "", settings, {}), false);
  assert.equal(exports.acmeIssueAvailable(true, "Не удалось получить статус сертификата.", settings, {}), false);
});
