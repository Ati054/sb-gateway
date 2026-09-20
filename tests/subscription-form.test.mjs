import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const page = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
const start = page.indexOf('                  Имя подписки');
const end = page.indexOf('                {!cdnTransportKind', start);
const form = page.slice(start, end);

test("subscription editor keeps concise labels and all existing controls", () => {
  assert.ok(start > 0 && end > start);
  for (const label of ["Имя подписки", "URL подписки", "Проверять каждые", "Подписка включена", "Пути обновления", "WAN → VPN", "Рабочие каналы", "Резервные VLESS"]) {
    assert.ok(form.includes(label), label);
  }
  for (const name of ["display_name", "url", "refresh_value", "refresh_unit", "enabled"]) {
    assert.ok(form.includes(`name="${name}"`), name);
  }
  for (const handler of ["setRefreshViaDirect", "setRefreshViaVpn", "setRefreshViaActiveOutbounds", "setRefreshViaIndependentReserves", "setSubscriptionUrl"]) {
    assert.ok(form.includes(handler), handler);
  }
  assert.match(form, /\{refreshViaVpn \? \(/);
  assert.match(form, /discoveryMessage \? \(/);
  assert.match(form, /role="status">Загрузка ссылки/);
});

test("subscription toggle follows metadata and update modes preserve existing settings", () => {
  assert.ok(form.indexOf('label="Подписка включена"') > form.indexOf("Данные подписки"));
  assert.match(form, /id: "wan", label: "WAN", direct: true, vpn: false/);
  assert.match(form, /id: "wan-vpn", label: "WAN → VPN", direct: true, vpn: true/);
  assert.match(form, /id: "vpn", label: "VPN", direct: false, vpn: true/);
  assert.match(form, /type="radio"\s+name="refresh_route_mode"/);
  assert.match(form, /checked=\{refreshViaDirect === mode.direct && refreshViaVpn === mode.vpn\}/);
  assert.match(form, /setRefreshViaDirect\(mode.direct\);\s+setRefreshViaVpn\(mode.vpn\)/);
  assert.match(page, /refresh_via_direct: refreshViaDirect,\s+refresh_via_vpn: refreshViaVpn/);
  assert.match(form, /checked=\{refreshViaActiveOutbounds\} onChange=\{setRefreshViaActiveOutbounds\}/);
  assert.match(form, /checked=\{refreshViaIndependentReserves\} onChange=\{setRefreshViaIndependentReserves\}/);
  assert.doesNotMatch(form, /setRefreshViaActiveOutbounds\(false\)|setRefreshViaIndependentReserves\(false\)/);
});

test("name and interval precede the full-width URL with matching keyboard order", () => {
  assert.ok(form.indexOf('name="display_name"') < form.indexOf('name="refresh_value"'));
  assert.ok(form.indexOf('name="refresh_unit"') < form.indexOf('name="url"'));
  assert.match(form, /<label className="field form-span">\s+URL подписки/);
  assert.doesNotMatch(form, /<details className="subscription-refresh/);
});

test("subscription editor removes redundant explanatory copy", () => {
  assert.doesNotMatch(form, /Понятное имя|Служебный идентификатор|Ссылка показывается полностью|Выключенную подписку нельзя|Запрос идёт без системного|Если прямой WAN выключен|Узлы, названия, эмодзи|Сначала панель безопасно/);
  assert.doesNotMatch(page, /URL виден только авторизованному администратору панели/);
});
