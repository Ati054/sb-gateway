import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { normalizeLocalizedSource } from "./source-localization.mjs";

const projectRoot = new URL("../", import.meta.url);

test("URLTest responsiveness help matches the balanced speed threshold", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("app/page.tsx", projectRoot), "utf8"));
  assert.match(page, /name="speed_improvement_percent"/);
  assert.match(page, /Порог приоритета скорости, %/);
  assert.match(page, /предел потери — 35%/);
  assert.doesNotMatch(page, /Плановая смена канала не выполняется, если прирост ниже этого порога/);
});

test("node quality offers a reversible local 24-hour display baseline", async () => {
  const [page, css] = await Promise.all([
    readFile(new URL("app/page.tsx", projectRoot), "utf8").then(normalizeLocalizedSource),
    readFile(new URL("app/globals.css", projectRoot), "utf8"),
  ]);
  assert.match(page, /QUALITY_24H_BASELINE_STORAGE_KEY/);
  assert.match(page, /aria-label=\{qualityWindowResetActive/);
  assert.match(page, /Начать новый отсчёт статистики за 24 часа/);
  assert.match(page, /Вернуть полную статистику за 24 часа/);
  assert.match(page, /qualityStatsSince\(health\.daily_samples/);
  assert.match(css, /\.screen-routing \.quality-window-reset/);
  assert.match(css, /\.screen-routing \.quality-overview-actions \{[\s\S]*flex-direction: row;/);
});

test("sidebar waits for the reported container version without flashing a historical fallback", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("app/page.tsx", projectRoot), "utf8"));
  assert.match(page, /const containerVersion = asText\(build\.container_version, ""\)/);
  assert.match(page, /containerVersion \? `v\$\{containerVersion\}` : "—"/);
  assert.doesNotMatch(page, /asText\(build\.container_version, "1\.5\.10"\)/);
});

test("overview shows the live RouterOS restart count for the current container start", async () => {
  const [page, apiClient] = await Promise.all([
    readFile(new URL("app/page.tsx", projectRoot), "utf8").then(normalizeLocalizedSource),
    readFile(new URL("app/api-client.ts", projectRoot), "utf8"),
  ]);
  assert.match(page, /Количество перезапусков:/);
  assert.match(page, /после восстановления/);
  assert.doesNotMatch(page, /после health/);
  assert.match(page, /asText\(routerosContainer\.restart_count, "—"\)/);
  assert.doesNotMatch(page, /asText\(watchdogState\.restarts, "0"\)/);
  assert.match(page, /window\.setInterval\(refreshVisible, 30_000\)/);
  assert.match(apiClient, /\/routeros\/container-status/);
});

test("TCP tuning uses shared defaults and exposes its actual scope", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("app/page.tsx", projectRoot), "utf8"));
  const fields = page.match(/const tcpStabilityFields = \([\s\S]*?\n  \);/)?.[0];
  assert.ok(fields);
  assert.match(fields, /Xray JSON · клиент → CDN/);
  assert.match(fields, /Таймаут TCP · мс · Linux/);
  assert.match(fields, /name="tcp_user_timeout" type="number" min="0"/);
  assert.match(fields, /Не зависит от Keep-Alive/);
  assert.doesNotMatch(fields, /Рекомендуется|Одни значения|60 000 мс =/);
  assert.equal([...page.matchAll(/const TCP_RECOMMENDATION_FIELDS/g)].length, 1);
  assert.equal([...page.matchAll(/\.\.\.TCP_RECOMMENDATION_FIELDS/g)].length, 3);
});

test("new Hysteria transports use the 15-second QUIC keepalive default", async () => {
  const [page, defaults] = await Promise.all([
    readFile(new URL("app/page.tsx", projectRoot), "utf8").then(normalizeLocalizedSource),
    readFile(new URL("internal/controlplane/default-config.json", projectRoot), "utf8"),
  ]);
  assert.match(page, /hysteria_keep_alive_period", label: "Keepalive QUIC", value: "15"/);
  assert.match(page, /existingXrayQuic\.keep_alive_period\) \|\| \(Object\.keys\(existingTransport\)\.length \? "" : "15"\)/);
  assert.equal(JSON.parse(defaults).transports.find((transport) => transport.kind === "hysteria2").xray_hysteria.quic_params.keep_alive_period, 15);
});

test("direct REALITY fallback help describes unverified connections without CDN deployment advice", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("app/page.tsx", projectRoot), "utf8"));
  const section = page.match(/<legend>Ограничение непроверенного fallback[\s\S]*?<\/fieldset>/)?.[0];
  assert.ok(section);
  assert.match(section, /Ограничивает только подключения, не прошедшие проверку REALITY\. Скорость 0 отключает ограничение\./);
  assert.doesNotMatch(section, /CDN|target вынужденно/);
  assert.equal([...section.matchAll(/name="reality_fallback_/g)].length, 6);
});

test("Reverse VLESS offers only the three direct REALITY transports", async () => {
  const page = normalizeLocalizedSource(await readFile(new URL("app/page.tsx", projectRoot), "utf8"));
  const section = page.match(/function ReverseVlessSettings\([\s\S]*?const transports =/)?.[0];
  assert.ok(section);
  const kinds = section.match(/const supportedKinds = new Set\(\[([\s\S]*?)\]\);/)?.[1];
  assert.ok(kinds);
  assert.match(kinds, /"reality"/);
  assert.match(kinds, /"reality-grpc"/);
  assert.match(kinds, /"xhttp-reality"/);
  assert.doesNotMatch(kinds, /"ws"|"grpc"|"httpupgrade"|"xhttp"/);
});

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the Russian management panel", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(
    html,
    /<title>SB Gateway — управление VLESS на MikroTik<\/title>/i,
  );
  assert.match(html, /Проверяем локальный сеанс/);
  assert.doesNotMatch(html, /Отказ панели не отключает интернет/);
  assert.match(html, /HTTPS · management LAN/);
  assert.doesNotMatch(html, /Интернет работает штатно/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape/i);
});

test("offers a persistent RU/EN choice before the first browser session", async () => {
  const [page, i18n, css] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8").then(normalizeLocalizedSource),
    readFile(new URL("../app/i18n.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
  ]);
  assert.match(page, /<LanguageProvider>/);
  assert.match(page, /className="language-toggle"/);
  assert.match(i18n, /sb-gateway:locale/);
  assert.match(i18n, /saved === "ru" \|\| saved === "en"/);
  assert.match(i18n, /setNeedsChoice\(true\)/);
  assert.match(i18n, /Выберите язык \/ Choose language/);
  assert.match(i18n, /document\.documentElement\.lang = locale/);
  assert.match(css, /\.language-choice-shell \{[\s\S]*position: fixed;/);
});

test("ships without starter artifacts and encodes the outage policy", async () => {
  const [page, apiClient, layout, css, packageJson, i18n] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8").then(normalizeLocalizedSource),
    readFile(new URL("../app/api-client.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../app/i18n.tsx", import.meta.url), "utf8"),
  ]);
  const addDialogSource = page.slice(
    page.indexOf("function AddDialog"),
    page.indexOf("function PolicyDialog"),
  );
  const lifecycleDialogsSource = page.slice(
    page.indexOf("{updateDialogOpen ?"),
    page.indexOf("{rollbackOpen ?"),
  );
  const policyDialogSource = page.slice(
    page.indexOf("function PolicyDialog"),
    page.indexOf("function TlsProfileDialog"),
  );
  const subscriptionPickerSource = page.slice(
    page.indexOf("function SubscriptionLocationPicker"),
    page.indexOf("function resultRows"),
  );
  const reverseVlessSettingsSource = page.slice(
    page.indexOf("function ReverseVlessSettings"),
    page.indexOf("function Connections"),
  );
  const reverseTransportLabelSource = page.slice(
    page.indexOf("function reverseTransportKindLabel"),
    page.indexOf("function transportChangeLead"),
  );
  assert.equal(
    (page.match(/await markCurrentDraftUnready\(\);/g) ?? []).length,
    1,
    "draft mutations must invalidate readiness atomically in the backend",
  );
  const overviewSource = page.slice(
    page.indexOf("function Overview"),
    page.indexOf("function Clients"),
  );
  const routingInfrastructureGridStart = css.indexOf(
    ".screen-routing .routing-infrastructure-grid",
  );
  const routingInfrastructureGridCss = css.slice(
    routingInfrastructureGridStart,
    css.indexOf("@media (max-width: 1100px)", routingInfrastructureGridStart),
  );

  assert.match(page, /tone\?: "plain" \| "state" \| "warning" \| "danger"/);
  assert.equal((page.match(/tone="state"/g) ?? []).length, 8);
  assert.match(page, /name=\{name\}/);
  assert.match(page, /defaultChecked=\{existingSubscription\.enabled !== false\}/);
  assert.match(page, /checked=\{transportEnabled\}/);
  assert.match(css, /\.toggle-row\.toggle-tone-state\.is-checked \{[\s\S]*background: #f0fdf4;/);
  assert.match(css, /\.toggle-row\.toggle-tone-warning \{[\s\S]*background: #fff8e8;/);
  assert.match(css, /\.toggle-row\.toggle-tone-danger \{[\s\S]*background: var\(--red-soft\);/);
  assert.match(css, /\.modal-actions-split \{\s*justify-content: flex-end;/);
  assert.doesNotMatch(css, /\.policy-editor-footer \.button-danger \{\s*margin-right: auto;/);

  assert.doesNotMatch(i18n, /Локальные управляемые клиенты переходят на обычный WAN/);
  assert.doesNotMatch(i18n, /удалённые VLESS остаются fail-closed/);
  assert.match(page, /long-term/i);
  assert.match(page, /Совместимость определяется по возможностям/);
  assert.match(page, /Long-term, stable, testing и development/);
  assert.match(page, /без флага show-sensitive/);
  assert.match(overviewSource, /className="card overview-status-card"/);
  assert.match(overviewSource, />Выходной узел</);
  assert.match(overviewSource, /Трафик за месяц/);
  assert.match(
    css,
    /\.overview-traffic-total > strong \{[\s\S]*font-size: 38px;[\s\S]*\.overview-traffic-total > span \{[\s\S]*font-size: 15px;/,
  );
  assert.match(overviewSource, /className="overview-device-table"/);
  assert.match(overviewSource, /Устройства локальной сети и удалённые клиенты/);
  assert.match(overviewSource, /activityEvents\.slice\(0, 3\)/);
  assert.match(overviewSource, /onAddClient/);
  assert.match(overviewSource, /onEditClient/);
  assert.match(overviewSource, /available && hasSpeedMeasurement/);
  assert.match(overviewSource, /policy_name: policy[\s\S]*itemName\(policy\)/);
  assert.match(overviewSource, /className=\{`overview-rate-pair/);
  assert.match(overviewSource, /aria-label="Исходящая скорость"/);
  assert.match(overviewSource, /aria-label="Входящая скорость"/);
  assert.match(overviewSource, /"— бит\/с"/);
  assert.match(overviewSource, /stableTelemetryClients/);
  assert.match(overviewSource, /data-live-telemetry="traffic-summary"/);
  assert.match(overviewSource, /data-live-telemetry="client-table"/);
  assert.match(overviewSource, /data-client-key=/);
  assert.match(page, /clientTelemetryRefreshInFlight/);
  assert.match(page, /currentSample === nextSample/);
  assert.match(page, /window\.setInterval\(refreshVisible, 15_000\)/);
  assert.match(page, /value === null \|\| value === undefined \|\| value === ""/);
  assert.doesNotMatch(overviewSource, /Гарантированный порядок маршрутизации/);
  assert.match(css, /\.overview-status-card \{[\s\S]*grid-template-columns:/);
  assert.match(css, /\.overview-device-table \{[\s\S]*table-layout: fixed;/);
  assert.match(css, /\.overview-device-table th \{[\s\S]*font-size: 11px;/);
  assert.match(css, /\.overview-device-table td \{[\s\S]*font-size: 12px;/);
  assert.match(css, /\.overview-device-identity strong \{[\s\S]*font-size: 13px;/);
  assert.match(css, /\.overview-device-table td::before \{[\s\S]*font-size: 11px;[\s\S]*text-transform: none;/);
  assert.match(
    css,
    /\.screen-routing \.wireguard-egress-choice span \{[\s\S]*display: flex;[\s\S]*align-items: baseline;[\s\S]*gap: 8px;/,
  );
  assert.doesNotMatch(
    css,
    /\.screen-routing \.wireguard-egress-choice span \{\s*display: grid;/,
  );
  assert.match(apiClient, /\/drafts\/\$\{operation\}/);
  assert.match(apiClient, /\/routeros\/import/);
  assert.match(apiClient, /\/routeros\/credentials/);
  assert.match(apiClient, /\/auth\/bootstrap/);
  assert.match(
    apiClient,
    /\/remote-users\/\$\{encodeURIComponent\(id\)\}\/exports\/download/,
  );
  assert.match(apiClient, /response\.blob\(\)/);
  assert.match(apiClient, /X-CSRF-Token/);
  assert.match(apiClient, /function safeErrorDetail/);
  assert.match(apiClient, /contentType\.includes\("text\/html"\)/);
  assert.match(apiClient, /"upstream_unavailable"/);
  assert.match(page, /isUncertainOperationError\(error\)/);
  assert.match(page, /getCurrentDraft<DraftEnvelope>/);
  assert.match(page, /getBootstrapState<JsonObject>\(\),\s*getStatus<JsonObject>\(\)/);
  assert.match(page, /runtimeDetailsReady/);
  assert.match(page, /Сверяю с ядром…/);
  assert.match(page, /ROUTING_SAVE_MESSAGE_STORAGE_KEY/);
  assert.match(page, /Маршрутизация сохранена\. Примените изменения\./);
  assert.match(
    page,
    /sessionStorage\.setItem\(\s*ROUTING_SAVE_MESSAGE_STORAGE_KEY/,
  );
  assert.match(page, /persistedMessage !== saveMessage/);
  assert.match(page, /bootstrap_required/);
  assert.doesNotMatch(
    page,
    /Пример · (не сохранён|недоступно|нет фактических данных)/,
  );
  assert.doesNotMatch(page, /Shadowsocks/i);
  assert.match(page, /saveCurrentDraft\(\{\s*config:/);
  assert.match(page, /ca_certificate/);
  assert.match(page, /Пароль RouterOS · минимум 16 символов/);
  assert.match(page, /name="tls_profile_id"/);
  assert.doesNotMatch(page, /name="origin_certificate"|name="origin_private_key"/);
  assert.match(page, /client_tun_address/);
  assert.match(page, /Имя подключения/);
  assert.match(page, /Имя уже используется подключением/);
  assert.match(page, /Адрес уже занят: найдено пересечение/);
  assert.match(page, /Boolean\(remoteNameError\)/);
  assert.match(page, /Boolean\(remoteTunError\)/);
  assert.match(page, /Индивидуальная маршрутизация/);
  assert.match(page, /client_individual_routing/);
  assert.match(page, /Доступ к LAN/);
  assert.match(page, /client_auto_fallback/);
  assert.match(page, /client_adblock/);
  assert.doesNotMatch(page, /name="client_preserve_local_lan"/);
  assert.match(page, /На устройстве WireGuard при/);
  assert.match(page, /AllowedIPs 0\.0\.0\.0\/0 · DNS \{directClientDns\}/);
  assert.match(page, /yandex:\s*"77\.88\.8\.8"/);
  assert.match(page, /cloudflare:\s*"1\.1\.1\.1"/);
  assert.match(page, /google:\s*"8\.8\.8\.8"/);
  assert.match(page, /quad9:\s*"9\.9\.9\.9"/);
  assert.match(page, /Отключать QUIC для сервисных карточек/);
  assert.match(
    page,
    /force_tcp_for_proxy_services:\s*forceTcpForProxyServices/,
  );
  assert.match(page, /UDP\/443 блокируется только для выбранных карточек/);
  assert.match(page, /Обновить список/);
  assert.match(page, /onRefresh=\{routerSources\.refresh\}/);
  assert.match(css, /\.client-profile-option-grid/);
  assert.match(css, /\.router-source-picker-heading/);
  assert.doesNotMatch(css, /\.client-routing-execution-grid/);
  assert.match(page, /secret_values: \{ certificate, private_key: privateKey \}/);
  assert.match(page, /Добавить TLS-профиль/);
  assert.match(page, /Связанные транспорты получат изменения после Apply/);
  assert.match(page, /Через CDN \+ TLS/);
  assert.match(page, /Прямые \+ REALITY/);
  assert.match(page, /Hysteria 2/);
  assert.match(page, /t\("common\.advanced"\)\} · QUIC \/ masquerade/);
  // sing-box is a client subscription document, not a second server core.
  assert.doesNotMatch(page, /proxyCore|TUIC|AnyTLS/i);
  assert.match(page, /XTLS Vision/);
  assert.match(page, /gRPC \+ Reality/);
  assert.doesNotMatch(page, /обычный VLESS без XTLS-Vision/);
  assert.match(page, /\["ws", "httpupgrade", "xhttp", "xhttp-reality"\]\.includes\(transportKind\)/);
  assert.match(page, /VLESS \+ XHTTP \+ REALITY/);
  assert.match(page, /XHTTP \$\{xhttpMode\} \+ REALITY/);
  assert.doesNotMatch(page, /XHTTP packet-up \+ REALITY · GET uplink/);
  assert.match(page, /field\.name === "uplink_http_method"[\s\S]*value: "POST"/);
  assert.match(page, /field\.name === "uplink_data_placement"[\s\S]*value: "auto"/);
  assert.doesNotMatch(page, /Размещение параметров|xhttpSettings\.extra/);
  assert.match(page, /QQ Browser/);
  assert.match(page, /Timeweb Cloud CDN/);
  assert.match(page, /Yandex Cloud CDN/);
  assert.match(page, /CLOUDFLARE_HTTPS_PORTS = \[443, 2053, 2083, 2087, 2096, 8443\]/);
  assert.match(page, /CDN-развёртывания/);
  assert.match(page, /TLS-профиль origin/);
  assert.match(page, /TCP-порт origin на MikroTik/);
  assert.match(page, /origin_server_name/);
  assert.match(page, /cdn-add-button/);
  assert.match(page, /Gcore/);
  assert.match(page, /EdgeCenter \/ EdgeCDN/);
  assert.match(page, /CDNetworks/);
  assert.match(page, /Проверьте поддержку порта у выбранного CDN/);
  assert.match(page, /Cloudflare gRPC использует TCP 443/);
  assert.doesNotMatch(page, /HTTPS-порт status \/ health/);
  assert.match(page, /HTTPS-ссылка клиентской подписки/);
  assert.match(page, /subscriptionCdnProviderNote/);
  assert.match(page, /\n\s+CDN\n\s+<select/);
  assert.doesNotMatch(page, /QQ теперь доступен/);
  assert.doesNotMatch(page, /Маскировка задаётся SNI и target REALITY/);
  assert.doesNotMatch(page, /Путь\/service и XHTTP extra общие/);
  assert.doesNotMatch(page, /для XHTTP это отдельный ресурс/);
  assert.match(page, /transportChangeLead\(transportKind\)/);
  assert.match(page, /cdnDeploymentScopeNote\(transportKind\)/);
  assert.match(page, /cdnOriginNameNote\(transportKind\)/);
  assert.match(page, /tls-profile-usage-strip/);
  assert.doesNotMatch(page, /tls-profile-metadata/);
  assert.doesNotMatch(page, /Общий публичный HTTPS-порт Cloudflare/);
  assert.match(page, /TLS-профили/);
  assert.doesNotMatch(page, /TLS-профиль status \/ health/);
  assert.doesNotMatch(page, /Контейнер контролирует MikroTik/);
  assert.match(page, /subscription-mode-menu/);
  assert.match(page, /createPortal/);
  assert.match(page, /subscription-dialog-body/);
  assert.match(page, /subscription-advanced-settings/);
  assert.doesNotMatch(page, /subscription-settings-section/);
  assert.doesNotMatch(page, /Одна подписка может открываться через CDN/);
  assert.match(page, /updateDialogOpen/);
  assert.match(page, /uninstallDialogOpen/);
  assert.doesNotMatch(lifecycleDialogsSource, /name="password"/);
  assert.doesNotMatch(page, /Сертификат должен включать публичный домен подписки/);
  assert.doesNotMatch(page, /Секретный путь создаётся автоматически/);
  assert.doesNotMatch(page, /Секретный HTTP-путь/);
  assert.match(page, /Будет создан автоматически при сохранении/);
  assert.match(page, /Новый образ SB Gateway/);
  assert.match(page, /один \.tar/i);
  assert.match(page, /Promise\.allSettled\(\[/);
  assert.doesNotMatch(
    lifecycleDialogsSource,
    /type="file"[^>]*disabled=\{[^}]*!lifecycleStorageRoot/,
  );
  assert.doesNotMatch(
    lifecycleDialogsSource,
    /!candidateReference\s*\|\|\s*!lifecycleStorageRoot/,
  );
  assert.doesNotMatch(page, /Загрузить резервный образ с компьютера/);
  assert.doesNotMatch(page, /Введите УДАЛИТЬ SB-GATEWAY/);
  assert.doesNotMatch(page, /Секретное имя gRPC-сервиса/);
  assert.match(page, /\["direct", "Напрямую"\]/);
  assert.match(page, /\["direct-and-cdn", "Два адреса"\]/);
  assert.match(page, /<strong>TCP Keep-Alive<\/strong>/);
  assert.match(page, /Проверить target и SNI/);
  assert.match(page, /Дополнительные допустимые SNI/);
  assert.match(page, /\["reality", "reality-grpc", "xhttp-reality"\]\.includes/);
  assert.match(page, /Стратегия домена/);
  assert.match(page, /Точечные домены/);
  assert.match(page, /LTE_PINPOINT_DOMAINS/);
  assert.match(page, /LTE_PINPOINT_DOMAINS_BY_PACK/);
  assert.match(page, /mergePinpointDomains/);
  assert.match(page, /recommendedPinpointDomainsKey/);
  assert.match(page, /automaticPinpointDomainsRef/);
  assert.match(page, /setPinpointDomainsText\(\(current\) => \{/);
  assert.doesNotMatch(page, /Рабочий набор и резервы/);
  assert.doesNotMatch(page, /Фильтры подписок/);
  assert.doesNotMatch(page, /unsupportedLabel/);
  assert.match(page, /deployment_ready:\s*deploymentReady/);
  assert.match(page, /container_address:\s*containerAddress/);
  assert.match(page, /addresses_confirmed:\s*true/);
  assert.match(page, /address_confirmed:\s*true/);
  assert.match(page, /max_restarts_per_hour:\s*restartBudget/);
  assert.match(page, /recovery_cooldown_seconds:\s*recoveryCooldown/);
  assert.match(page, /onNavigate\("settings"\)/);
  assert.doesNotMatch(page, /Проверить маршрут/);
  assert.doesNotMatch(page, /Настроить города|Обновить подписку/);
  assert.match(page, /Новый маршрутный лист/);
  assert.doesNotMatch(policyDialogSource, />\s*Идентификатор\s*</);
  assert.match(policyDialogSource, /entityIdFromName\(/);
  assert.match(policyDialogSource, /Название маршрута/);
  assert.doesNotMatch(policyDialogSource, /placeholder=.*Европа/);
  assert.match(policyDialogSource, /modal modal-wide policy-editor-modal/);
  assert.match(policyDialogSource, /modal-backdrop policy-editor-backdrop/);
  assert.match(policyDialogSource, /Конфигурация листа/);
  assert.doesNotMatch(policyDialogSource, /Текущее состояние выбора узла/);
  assert.ok(
    subscriptionPickerSource.lastIndexOf("{renderPriorityBuilder()}") >
      subscriptionPickerSource.indexOf('className="subscription-location-tree"'),
    "priority ordering must follow the server picker",
  );
  assert.ok(
    policyDialogSource.indexOf("<DirectServicePackPicker") <
      policyDialogSource.indexOf("<CatalogServiceAdder") &&
      policyDialogSource.indexOf("<CatalogServiceAdder") <
        policyDialogSource.indexOf('className="policy-route-toggles"'),
    "trusted catalog input must stay directly below service cards",
  );
  assert.match(css, /\.policy-editor-modal \.service-pack-grid \{[\s\S]*?max-height: 380px;[\s\S]*?overflow-y: auto;/);
  assert.match(css, /\.policy-editor-modal \.subscription-location-tree \{[\s\S]*?overflow: auto;/);
  assert.match(css, /\.policy-editor-backdrop \{[\s\S]*?backdrop-filter: none;/);
  assert.match(css, /\.policy-editor-modal \.service-pack-option-shell \{[\s\S]*?content-visibility: auto;/);
  assert.match(css, /\.policy-editor-modal \.policy-check-grid \.field \{[\s\S]*?grid-template-rows: 36px 36px/);
  assert.match(page, /mergeRuntimeStatus\(/);
  assert.match(addDialogSource, /Имя устройства/);
  assert.doesNotMatch(addDialogSource, /placeholder="Телефон/);
  assert.match(css, /\.router-source-option > \.router-source-copy \{[\s\S]*?display: flex;[\s\S]*?white-space: nowrap;/);
  assert.match(css, /\.router-source-option > \.router-source-copy > span::before \{[\s\S]*?content: "·";/);
  assert.match(page, /<strong>Reverse VLESS<\/strong>/);
  assert.match(page, /<strong>WireGuard<\/strong>/);
  assert.match(page, /service-pack-remove/);
  assert.match(page, /Вернуть скрытые карточки/);
  assert.doesNotMatch(policyDialogSource, /name="exception_domains"/);
  assert.doesNotMatch(policyDialogSource, /Доменные исключения через/);
  assert.match(page, /Добавить сервис вручную из доверенного каталога/);
  assert.doesNotMatch(page, /ежедневное обновление/);
  assert.doesNotMatch(page, /Если полного пакета нет, ресурс не будет добавлен частично или молча/);
  assert.doesNotMatch(page, /Выбранный сервис пойдёт через/);
  assert.match(policyDialogSource, /direct_domains:\s*pinpointDomains/);
  assert.match(policyDialogSource, /destinationLabel=\{trafficMode ===/);
  assert.doesNotMatch(page, /<code title=\{policy\.key\}>\{policy\.key\}<\/code>/);
  assert.match(page, /Добавить подписку/);
  assert.match(page, /subscription-url-input/);
  assert.match(page, /wrap="off"/);
  assert.match(page, /Настроить устройство/);
  assert.doesNotMatch(page, /Быстрый старт/);
  assert.doesNotMatch(page, /Последняя операция получена/);
  assert.match(page, /overview\?\.recent_events/);
  assert.match(page, /Открыть журнал/);
  assert.match(page, /IPv6 подключённого MikroTik/);
  assert.match(page, /IPv6 удалённых VLESS-клиентов/);
  assert.match(page, /remote_ipv6_mode:/);
  assert.match(page, /displayedRouteros\.live_available === true/);
  assert.match(page, /liveIpv6\.inventory_complete !== false/);
  assert.match(page, /discovery: liveRouteros/);
  assert.match(page, /loadRouterOSDiscovery/);
  assert.match(page, /routerOSDiscoveryRequest/);
  assert.match(page, /setLiveRouteros\(response\)/);
  assert.match(page, /\.\.\.overviewData, routeros: routerosSummary/);
  assert.match(page, /screen === "routing" \|\| screen === "operations"/);
  assert.match(page, /visibilitychange", refreshVisibleState/);
  assert.match(page, /configurationHydrated \? \(/);
  assert.match(page, /Загружаю настройки маршрутизации/);
  assert.doesNotMatch(page, /Нет live-данных/);
  assert.match(page, /IPv4-only WAN/);
  assert.match(page, /Root-dir контейнера/);
  assert.match(page, /Лимит памяти контейнера/);
  assert.doesNotMatch(page, /Kernel TPROXY/);
  assert.doesNotMatch(page, /Без userspace TUN\/gVisor/);
  assert.match(page, /Без ограничения/);
  assert.doesNotMatch(page, /<strong>Ядро · Xray-core<\/strong>/);
  assert.match(page, /Один IP\/CIDR на строку/);
  assert.match(page, /Один интерфейс на строку\. WireGuard добавляется автоматически/);
  assert.doesNotMatch(page, /Публичные VLESS-домены, локальный API ядра/);
  assert.doesNotMatch(page, /Смена root-dir требует пересоздания RouterOS Container/);
  assert.doesNotMatch(page, /RouterOS не предоставляет этому control plane/);
  assert.doesNotMatch(page, /Единственное ядро шлюза/);
  assert.doesNotMatch(page, /По карточкам устройств/);
  assert.match(page, /Интернет защищён от падения контейнера/);
  assert.doesNotMatch(page, /Домашний интернет защищён от падения контейнера/);
  assert.doesNotMatch(page, /Интернет работает штатно/);
  assert.doesNotMatch(page, /Удалённые VLESS-подключения останутся закрыты/);
  assert.match(page, /services: policy\.id \? itemName\(policy\) : "Не назначен"/);
  assert.match(css, /\.transport-detail\s*\{[\s\S]*?flex-wrap:\s*nowrap/);
  assert.match(css, /\.transport-detail > span:last-child\s*\{[\s\S]*?overflow-wrap:\s*anywhere/);
  assert.match(css, /\.transport-summary\s*\{[\s\S]*?grid-template-columns:\s*280px\s+minmax\(260px,\s*1fr\)/);
  assert.doesNotMatch(page, /disabled[\s\S]{0,120}Пороги · только просмотр/);
  assert.match(
    page,
    /Разрешаю применить этот проверенный черновик/,
  );
  assert.match(page, /pending_config_change_count/);
  assert.match(page, /pending_config_changes/);
  assert.match(page, /Что изменилось/);
  assert.match(page, /pendingChangeText/);
  assert.match(css, /\.draft-change-popover/);
  assert.match(page, /runtime_update_only/);
  assert.match(page, /Есть обновление шлюза/);
  assert.match(page, /доступно обновление компонентов шлюза/);
  assert.match(page, /Применить обновление/);
  assert.match(page, /Обновить runtime/);
  assert.match(page, /Применить с автооткатом/);
  assert.match(page, /Будет выполнено/);
  assert.doesNotMatch(page, /Для подтверждения введите/);
  assert.match(page, /\.rsc разобран офлайн — это не live preflight/);
  assert.match(page, /Неопределённо · требуется live REST/);
  assert.match(page, /management_ingress_suggestions/);
  assert.match(
    page,
    /allowed_ingress_interfaces:\s*\[managementIngressInterface\]/,
  );
  assert.match(page, /Принять как внутреннюю/);
  assert.match(page, /Принять видимые/);
  assert.match(page, /Игнорировать видимые/);
  assert.match(page, /Игнорировать/);
  assert.match(page, /Все подсказки классифицированы/);
  assert.match(page, /Выберите bridge или введите точное имя/);
  assert.match(page, /Интерфейс введён вручную/);
  assert.match(page, /www-ssl, не api-ssl/);
  assert.match(page, /172\.31\.255\.1:59443/);
  assert.match(page, /явным портом www-ssl/);
  assert.match(page, /без 0\.0\.0\.0\/0/);
  assert.match(page, /explicitPort >= 1/);
  assert.match(page, /explicitPort <= 65535/);
  assert.doesNotMatch(page, /Boolean\(url\.port\)/);
  assert.match(page, /isIpv4Cidr\(managementCidr, false\)/);
  assert.match(page, /TCP 443 нельзя считать/);
  assert.match(page, /topology_suggestions/);
  assert.match(page, /management_network_suggestions/);
  assert.match(page, /if \(!current\.trim\(\) && candidate\)/);
  assert.match(page, /Заполнены офлайн-кандидаты/);
  assert.match(page, /Вы подтверждаете офлайн-кандидаты/);
  assert.match(page, /addresses_confirmed:\s*false/);
  assert.match(page, /address_confirmed:\s*false/);
  assert.match(page, /bridge_name:\s*bridgeName/);
  assert.match(page, /veth_name:\s*vethName/);
  assert.match(page, /container_dns:\s*internalDns/);
  assert.match(page, /networkReviewPending > 0/);
  assert.match(page, /status:\s*networkReviewStatus\(networkDecisions\[cidr\]\)/);
  assert.match(page, /status_hostname:\s*""/);
  assert.match(page, /subscription_hostname:\s*subscriptionHost/);
  assert.doesNotMatch(page, /Публичный health выключен/);
  assert.match(page, /HTTPS-ссылка клиентской подписки/);
  assert.match(page, /HTTPS-ссылка клиентской подписки/);
  assert.doesNotMatch(page, /Готовый CDN-домен/);
  assert.match(page, /Новый CDN-домен/);
  assert.match(page, /Публичный HTTPS-порт/);
  assert.doesNotMatch(page, /Accept-Language: ru-RU/);
  assert.match(page, /Пути обновления/);
  assert.match(page, /id: "wan-vpn", label: "WAN → VPN", direct: true, vpn: true/);
  assert.match(page, /id: "wan", label: "WAN", direct: true, vpn: false/);
  assert.match(page, /id: "vpn", label: "VPN", direct: false, vpn: true/);
  assert.match(page, /label="Рабочие каналы" checked=\{refreshViaActiveOutbounds\}/);
  assert.match(page, /label="Резервные VLESS"/);
  assert.match(page, /Независимые VLESS/);
  assert.match(page, /subscription-reserves/);
  assert.match(page, /DNS по маршруту/);
  assert.match(page, /Яндекс DNS/);
  assert.doesNotMatch(page, /MikroTik \/ провайдер/);
  assert.doesNotMatch(page, /Обычный DNS RouterOS/);
  assert.match(page, /DoH · HTTPS/);
  assert.match(page, /DoT · TLS/);
  assert.match(page, /Выбрать отдельный узел/);
  assert.match(page, /subscription_display_name/);
  assert.match(page, /subscription-essential-grid/);
  assert.doesNotMatch(page, /subscription-common-fields/);
  assert.match(page, /markCurrentDraftUnready/);
  assert.match(page, /runDraftOperation\("rollback",\s*\{\s*password,/);
  assert.match(page, /confirmation:\s*"ОТКАТИТЬ"/);
  assert.match(page, /Подтверждаю откат к предыдущей проверенной версии/);
  assert.match(page, /disabled=\{busy \|\| !confirmed\}/);
  assert.match(page, /Откатить к предыдущей проверенной версии/);
  assert.match(page, /Готовые сервисы напрямую через WAN MikroTik/);
  assert.match(page, /DIRECT_SERVICE_PACKS/);
  assert.match(page, /Torrent \/ BitTorrent/);
  assert.match(page, /id: "binance", name: "Binance"/);
  assert.match(page, /AWS WAF challenge/);
  assert.match(page, /direct_services:\s*trafficMode === "vless_with_wan_exceptions"/);
  assert.match(page, /entityIdFromName/);
  assert.match(page, /suggestedClientTunAddress/);
  assert.match(page, /Полный доступ к LAN/);
  assert.match(page, /Ограниченный доступ к LAN/);
  assert.match(page, /Без доступа к LAN/);
  assert.doesNotMatch(page, /selectedRemoteTransportIds/);
  assert.match(page, /selectedAllowedCidrs/);
  assert.match(page, /allowed_cidrs/);
  assert.match(page, /К каким внутренним сетям разрешить доступ/);
  assert.match(page, /Новые маршруты MikroTik/);
  assert.match(page, /Внутренние маршрутизируемые сети/);
  assert.match(page, /адреса VPN-транспорта здесь не/);
  assert.match(page, /lan-network-list/);
  assert.match(page, /VLESS-клиент/);
  assert.match(page, /Ссылка подписки/);
  assert.match(page, /По умолчанию отмечены все включённые транспорты/);
  assert.match(page, /excluded_transports/);
  assert.match(page, /Новые — автоматически/);
  assert.doesNotMatch(page, /Куда пойдёт трафик/);
  assert.doesNotMatch(page, /Безопасный патч/);
  assert.match(page, /Клиента и постоянную ссылку можно создать уже сейчас/);
  assert.doesNotMatch(
    page,
    /kind === "remote" && !remoteTransportOptions\.length/,
  );
  assert.match(page, /getRemoteUserSubscriptionLink/);
  assert.match(page, /CDN-ссылка/);
  assert.match(page, /Прямая ссылка/);
  assert.match(page, /copySubscription\(endpoint\.url, endpoint\.id\)/);
  assert.doesNotMatch(page, />Скопировать ссылку</);
  assert.match(page, /URLTest с резервированием/);
  assert.match(page, /Приоритет с резервированием/);
  assert.match(page, /Приоритет активных направлений/);
  assert.doesNotMatch(page, /Количество резервов/);
  assert.match(page, /policy-priority-replace/);
  assert.match(page, /selection_order:.*selectionOrder/);
  assert.match(page, /active_quality_interval_seconds: 60/);
  assert.match(page, /reserve_check_interval_seconds: 300/);
  assert.match(page, /full_scan_interval_seconds: 1800/);
  assert.match(page, /active_liveness_interval_seconds: 3/);
  assert.match(page, /block_recovery_interval_seconds: 15/);
  assert.match(page, /max_active_candidates:.*candidateLimit/);
  assert.match(page, /max_probe_candidates:.*candidateLimit/);
  assert.doesNotMatch(page, /name="switch_improvement_percent"/);
  assert.match(page, /name="speed_improvement_percent"/);
  assert.match(page, /speed_improvement_percent:.*25/);
  assert.match(page, /candidate_service_access/);
  assert.doesNotMatch(page, /name="exception_domains"/);
  assert.doesNotMatch(page, /direct_domains:\s*\[\]/);
  assert.match(page, /Блокировка сервисов через этот узел/);
  assert.match(page, /policy-priority-meta/);
  assert.match(page, /policy-priority-order-label/);
  assert.match(page, /Заблокированные сервисы:/);
  assert.match(page, /<span>Блок:<\/span>/);
  assert.match(page, /checked=\{blockedCandidateServices\(token\)\.includes\(pack\.id\)\}/);
  assert.match(page, /setCandidateServiceBlocked\(token, pack\.id, event\.target\.checked\)/);
  assert.match(page, /selectionOrder\.map\(\(token\) => \[/);
  assert.match(page, /Object\.entries\(saved\)\.map\(\(\[token, values\]\) => \[token, asStringList\(values\)\]\)/);
  assert.match(page, /hasOwnProperty\.call\(normalized, token\)/);
  assert.match(page, /className="subscription-discovery-empty reverse-vless-empty"/);
  assert.match(css, /\.screen-routing \.reverse-vless-empty\s*\{[\s\S]*?padding:\s*16px 20px;/);
  assert.match(css, /@media \(max-width: 680px\)[\s\S]*?\.screen-routing \.reverse-vless-empty\s*\{[\s\S]*?padding:\s*14px 20px;/);
  assert.match(css, /\.priority-service-options > label:has\(input:checked\)\s*\{[\s\S]*?background:\s*#fff7f5;/);
  assert.match(css, /\.priority-service-options input\s*\{[\s\S]*?accent-color:\s*#a74638;/);
  assert.doesNotMatch(css, /\.policy-editor-modal \.policy-priority-replace > span\s*\{[\s\S]*?display:\s*none;/);
  assert.match(page, /reverse_vless_exits: reverseVlessExits/);
  assert.match(page, /reverseVlessCollector\.current\?\.\(\)/);
  assert.match(
    page,
    /Number\(selectedInterfaces\.has\(asText\(right\.interface,[\s\S]*Number\(selectedInterfaces\.has\(asText\(left\.interface/,
  );
  assert.match(
    reverseVlessSettingsSource,
    /Number\(exitEnabledValue\(right\)\) - Number\(exitEnabledValue\(left\)\)/,
  );
  assert.match(reverseVlessSettingsSource, /checked=\{enabled\}/);
  assert.match(reverseVlessSettingsSource, /navigator\.clipboard\.writeText/);
  assert.match(reverseVlessSettingsSource, /<span>Конфиг<\/span>/);
  assert.match(reverseTransportLabelSource, /reality: "Reality \+ Vision"/);
  assert.match(reverseTransportLabelSource, /"reality-grpc": "gRPC \+ Reality"/);
  assert.match(reverseTransportLabelSource, /"xhttp-reality": "XHTTP \+ Reality"/);
  assert.doesNotMatch(reverseTransportLabelSource, /reality: "VLESS"/);
  assert.doesNotMatch(reverseVlessSettingsSource, />Сохранить</);
  assert.doesNotMatch(reverseVlessSettingsSource, /reverse-vless-hint/);
  assert.doesNotMatch(css, /reverse-vless-batch-actions/);
  assert.match(
    css,
    /\.screen-routing \.wireguard-egress-list \{[\s\S]*max-height: 128px;[\s\S]*overflow-y: auto;[\s\S]*scrollbar-gutter: stable;/,
  );
  assert.match(
    css,
    /\.screen-routing \.reverse-vless-exit-list \{[\s\S]*max-height: 190px;[\s\S]*overflow-y: auto;[\s\S]*scrollbar-gutter: stable;/,
  );
  assert.match(
    routingInfrastructureGridCss,
    /reverse-vless-settings[\s\S]*grid-column: 1 \/ -1;[\s\S]*grid-row: 1;/,
  );
  assert.match(
    routingInfrastructureGridCss,
    /wireguard-egress-settings[\s\S]*grid-column: 1 \/ -1;[\s\S]*grid-row: 2;/,
  );
  assert.match(
    routingInfrastructureGridCss,
    /routing-behavior-settings[\s\S]*grid-column: 1;[\s\S]*grid-row: 3;/,
  );
  assert.match(
    routingInfrastructureGridCss,
    /dns-path-settings[\s\S]*grid-column: 2;[\s\S]*grid-row: 3;/,
  );
  assert.match(page, /routing-policy-section/);
  assert.match(page, /policy-reserve-queue/);
  assert.match(
    css,
    /\.policy-card-summary \{[\s\S]*grid-template-columns: fit-content\(360px\) minmax\(180px, 1fr\) auto;/,
  );
  assert.match(page, /className="routing-marker-slot"/);
  assert.match(page, /className="quality-marker-slot"/);
  assert.match(
    css,
    /\.routing-marker-slot,[\s\S]*\.quality-marker-slot \{[\s\S]*width: 24px;[\s\S]*place-items: center;/,
  );
  assert.match(css, /\.policy-reserve-queue \{[\s\S]*padding: 12px 14px;/);
  const routingSource = page.slice(
    page.indexOf("function Routing("),
    page.indexOf("function RoutingInfrastructureSettings"),
  );
  assert.match(routingSource, /sessionStorage\.getItem\(ROUTING_EXPANDED_POLICY_STORAGE_KEY\)/);
  assert.match(routingSource, /const expanded = expandedPolicyId === policy\.key/);
  assert.doesNotMatch(routingSource, /index === 0/);
  assert.doesNotMatch(routingSource, /selected:\s*rank === 0/);
  assert.match(routingSource, /node\.selected\s*\? "Активный узел"/);
  assert.match(routingSource, /node\.inRuntimePool \? "Рабочий резерв" : "Доступен · фоновая проверка"/);
  assert.doesNotMatch(routingSource, /`Резерв \$\{rank\}`/);
  assert.match(page, /sessionStorage\.removeItem\(ROUTING_EXPANDED_POLICY_STORAGE_KEY\)/);
  assert.match(page, /startViewTransition\(commitNavigation\)/);
  assert.match(page, /transition\.ready\?\.catch/);
  assert.match(page, /transition\.updateCallbackDone\?\.catch/);
  assert.match(page, /transition\.finished\?\.catch/);
  assert.match(page, /window\.matchMedia\("\(prefers-reduced-motion: reduce\)"\)/);
  assert.match(css, /html \{[\s\S]*scrollbar-gutter: stable;/);
  assert.match(css, /\.topbar \{[\s\S]*height: 56px;[\s\S]*min-height: 56px;/);
  assert.match(css, /\.draft-actions > \.button \{[\s\S]*height: 40px;/);
  assert.match(css, /\.main-content \{[\s\S]*width: min\(1480px, 100%\);[\s\S]*view-transition-name: workspace-content;/);
  assert.doesNotMatch(css, /\.main-content\.screen-overview/);
  const overviewSetupSource = page.slice(
    page.indexOf("function Overview("),
    page.indexOf("function ClientTrafficBars"),
  );
  assert.match(overviewSetupSource, /unconfigured \? \([\s\S]*Настроить шлюз/);
  assert.match(page, /onOpenSetup=\{\(\) => setSetupOpen\(true\)\}/);
  assert.match(css, /::view-transition-new\(workspace-content\)/);
  assert.match(css, /::view-transition-old\(root\),[\s\S]*opacity: 0;/);
  assert.match(css, /workspace-screen-in 120ms/);
  assert.match(css, /@keyframes workspace-screen-in/);
  assert.doesNotMatch(css, /\.screen-routing-workspace \.topbar/);
  assert.match(css, /\.section-title h2 \{[\s\S]*font-size: 22px;[\s\S]*font-weight: 800;/);
  assert.match(page, /resetRoutingInfrastructure/);
  assert.match(css, /\.routing-master-toggle \.toggle-control \{\s*display: block;/);
  assert.match(page, /WAN DNS \(локальные запросы\)/);
  assert.match(page, /VPN DNS \(запросы через туннель\)/);
  assert.ok(
    page.indexOf('className="routing-save-bar"') >
      page.indexOf('className="card settings-card dns-path-settings"'),
    "кнопка сохранения маршрутизации должна находиться после последнего сохраняемого блока",
  );
  assert.doesNotMatch(page, /Контейнер контролирует MikroTik/);
  assert.doesNotMatch(page, /Сохранять выбранный узел/);
  assert.doesNotMatch(page, /Первый доступный с резервом/);
  assert.doesNotMatch(addDialogSource, /name="id"/);
  assert.doesNotMatch(addDialogSource, /name="allowed_network_ids"/);
  assert.doesNotMatch(addDialogSource, /name="direct_domains"/);
  assert.doesNotMatch(addDialogSource, /DirectServicePackPicker/);
  assert.doesNotMatch(page, /onAddDevice=\{\(\) => \{/);
  assert.doesNotMatch(page, /setAddKind\("local"\)/);
  assert.doesNotMatch(page, /onAddSubscription=\{\(\) => \{/);
  assert.match(page, /Каталожные пакеты обновляются\s+раз в сутки/);
  assert.match(page, /Госуслуги и государственные сайты/);
  assert.match(page, /Маркетплейсы, объявления, доставка и ритейл РФ/);
  assert.match(page, /Экосистема Яндекса/);
  assert.match(page, /VK, Mail\.ru, OK, Дзен и MAX/);
  assert.match(page, /Мобильные операторы и провайдеры связи РФ/);
  assert.match(page, /Медиа, ТВ, видеостриминг и музыка РФ/);
  assert.match(page, /Образование, работа и ИТ-сервисы РФ/);
  assert.doesNotMatch(page, /\{ id: "ozon", name: "Ozon"/);
  assert.match(page, /FaceTime/);
  assert.match(page, /Не используются/);
  assert.match(page, /доменов добавлены к выбранным карточкам/);
  assert.doesNotMatch(page, /iMessage и APNs не перенаправляются/);
  assert.match(page, /автообновление доменов \+ правила звонков/);
  assert.match(page, /name: "Bybit"/);
  assert.match(page, /name: "Gate\.io"/);
  assert.match(page, /name: "OKX"/);
  assert.match(page, /Сайт, приложение, REST\/WebSocket API/);
  assert.match(page, /<th>Доступность \/ потери<\/th>/);
  assert.match(page, /<th>Медиана<\/th>/);
  assert.match(page, /<th>Скорость<\/th>/);
  assert.match(page, /<th>p95 HTTPS<\/th>/);
  assert.match(page, /<th>К активному<\/th>/);
  assert.match(page, /node\.loss\.toFixed\(1\)\}% потерь/);
  assert.match(page, /Качество узлов/);
  assert.doesNotMatch(page, /Подробные замеры хранятся 24 часа/);
  assert.match(page, /setHistoryPeriod/);
  const quality = await readFile(new URL("app/node-quality.ts", projectRoot), "utf8");
  assert.match(
    quality,
    /if \(left\.selected !== right\.selected\) return left\.selected \? -1 : 1;/,
  );
  assert.match(page, /const quality = qualitySheet\(policyRows, qualityPolicyId\)/);
  assert.match(quality, /\(right\.availability \?\? -1\) - \(left\.availability \?\? -1\)/);
  assert.match(quality, /rank: policy\?\.mode === "priority" && priorityPositions\.has\(node\.id\)/);
  assert.match(page, /quality\.policy\?\.mode === "priority" \? "Приоритет" : "Рейтинг"/);
  assert.match(page, /<th>Маршрут и узел<\/th>/);
  assert.match(page, /className="quality-node-label"/);
  assert.match(page, /<small>\(\{quality\.policy\?\.name\}\)<\/small>/);
  assert.match(page, /className="quality-availability-value"/);
  assert.match(
    css,
    /\.screen-routing \.quality-node-cell > \.quality-node-label,[\s\S]*\.quality-availability-value \{[\s\S]*display: inline-flex;[\s\S]*flex-flow: row nowrap;[\s\S]*white-space: nowrap;/,
  );
  assert.match(page, /Первая проверка ещё не завершена/);
  assert.match(page, /switch_improvement_ms/);
  assert.doesNotMatch(page, /Поведение, выходы и DNS/);
  assert.match(page, /RoutingInfrastructureSettings/);
  assert.match(page, /torrent_direct/);
  assert.match(page, /LAN \/ Wi‑Fi MikroTik/);
  assert.match(page, /<option value="ppp-vpn">PPP \/ OpenVPN \/ другой VPN<\/option>/);
  assert.match(page, /Разрешённые IP\/CIDR/);
  assert.match(page, /Доверенные входные интерфейсы RouterOS/);
  assert.match(page, /managementSources\.length/);
  assert.match(page, /allowed_source_cidrs:\s*managementSources/);
  assert.match(
    page,
    /allowed_ingress_interfaces:\s*managementIngressInterfaces/,
  );
  assert.match(page, /LAN и OpenVPN · IP\/CIDR \+ интерфейс/);
  assert.match(page, /WireGuard добавляется автоматически/);
  assert.equal(
    [...page.matchAll(/placeholder="Заполняется мастером первого запуска"/g)].length,
    2,
  );
  assert.doesNotMatch(page, /192\.168\.98\.0\/24/);
  assert.doesNotMatch(page, /wireguard-admin/);
  assert.match(page, /Сначала выполните первичную настройку/);
  assert.match(page, /https:\/\/172\.31\.255\.1:59443/);
  assert.match(page, /Найти домены и CDN/);
  assert.match(page, /Например: avito или avito\.ru/);
  assert.match(page, /resolveServicePack/);
  assert.match(page, /selectedValues=\{selectedExceptionServices\}/);
  assert.match(page, /onSelectedValuesChange=\{setExceptionServices\}/);
  assert.match(apiClient, /\/service-packs\/resolve/);
  assert.doesNotMatch(page, /refreshSubscription\("provider-main"\)/);
  assert.doesNotMatch(page, /value=\{providerUrl\}/);
  assert.doesNotMatch(page, /SkeletonPreview|react-loading-skeleton/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  assert.match(layout, /<html lang="ru">/);
  assert.match(layout, /index:\s*false/);
  assert.match(css, /@media \(max-width: 680px\)/);
  assert.match(css, /prefers-reduced-motion: reduce/);

  await assert.rejects(
    access(new URL("app/_sites-preview", projectRoot)),
  );
});

test("requires provisioned named TLS profiles before Apply", async () => {
  const source = normalizeLocalizedSource(await readFile(
    new URL("../app/page.tsx", import.meta.url),
    "utf8",
  ));
  assert.match(source, /asObjectList\(config\.tls_profiles\)/);
  assert.match(source, /asText\(profile\?\.certificate_secret_ref, ""\)/);
  assert.match(source, /asText\(profile\?\.private_key_secret_ref, ""\)/);
  assert.match(source, /required\.every\(\(transport\)/);
  assert.doesNotMatch(source, /Общая пара из WebSocket/);
});

test("offers a reversible form-only parameter reset for every Xray transport", async () => {
  const [source, i18n] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8").then(normalizeLocalizedSource),
    readFile(new URL("../app/i18n.tsx", import.meta.url), "utf8"),
  ]);
  for (const transport of [
    "ws",
    "httpupgrade",
    "grpc",
    "xhttp",
    "reality",
    "reality-grpc",
    "grpc-tls",
    "xhttp-reality",
    "hysteria2",
  ]) {
    assert.match(source, new RegExp(`(?:^|\\n)\\s*["']?${transport.replace("-", "\\-")}["']?: \\{`));
  }
  assert.match(source, /name: "reset_transport_parameters"/);
  assert.match(source, /applyTransportParameterDefaults\(\)/);
  assert.match(source, /restoreTransportParameters\(\)/);
  assert.match(source, /transportParameterSnapshotRef/);
  assert.match(i18n, /"transport\.reset": "Базовые параметры"/);
  assert.match(i18n, /Выберите изменения\. Они выполнятся после сохранения\./);
  assert.match(i18n, /"transport\.resetStatus": "Будет выполнено:"/);
  assert.doesNotMatch(source, /onClick=\{resetTransportParameters\}/);
  assert.doesNotMatch(source, /recommendationPreview|recommendationDifferences|Проверить рекомендации|Заполнить форму/);
});

test("combines transport reset and rotations in one compact pending-action menu", async () => {
  const [source, css, i18n] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8").then(normalizeLocalizedSource),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../app/i18n.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(source, /const regenerationOptions = \[/);
  assert.match(source, /const transportActionOptions = \[/);
  assert.match(source, /className="transport-regeneration-menu"/);
  assert.match(source, /title=\{t\("regenerate\.title"\)\}/);
  assert.match(source, /\{t\("regenerate\.action"\)\}/);
  assert.match(source, /transportActionCount \? ` \(\$\{transportActionCount\}\)` : ""/);
  assert.match(source, /transportActionCount \? "button-primary" : "button-tertiary"/);
  assert.match(source, /selectedTransportActionLabels\.join\(" · "\)/);
  assert.match(source, /closeTransportActionMenu/);
  assert.match(source, /event\.key !== "Escape"/);
  assert.match(i18n, /"regenerate\.action": "Сбросить"/);
  for (const field of [
    "regenerate_http_path",
    "regenerate_vless_encryption",
    "regenerate_grpc_service_name",
    "regenerate_reality_keys",
    "regenerate_reality_mldsa65",
    "regenerate_hysteria2_obfs",
  ]) {
    assert.equal([...source.matchAll(new RegExp(`name: "${field}"`, "g"))].length, 1);
  }
  assert.doesNotMatch(source, /<input[\s\S]{0,160}name="grpc_service_name"/);
  assert.doesNotMatch(source, /Обычно менять не нужно\. gRPC\+REALITY/);
  assert.match(css, /\.transport-regeneration-options/);
  assert.match(css, /\.transport-regeneration-options label:has\(input:checked\)/);
  assert.match(css, /\.transport-reset-summary/);
});

test("keeps automatic client address inline and delegates WAN binding to the server", async () => {
  const source = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  assert.match(source, /<option value="auto">Автоматически<\/option>/);
  assert.match(source, /<option value="manual">Вручную<\/option>/);
  assert.doesNotMatch(source, /Привязка входящего порта|name="wan_destination_address"|direct-wan-binding/);
  assert.match(source, /const ownedWanAddresses = asObjectList\(connectionAddress.wan_addresses\)/);
  assert.match(source, /const wanDestinationAddress = selectedWanAddress \? manualHostname.trim\(\) : ""/);
  assert.match(source, /wan_destination_address: undefined/);
  assert.match(source, /connection-address-row/);
  const row = source.slice(source.indexOf('<div className={directInboundKind ? "connection-address-row"'));
  assert(row.indexOf('name="hostname"') < row.indexOf('name="hostname_mode"'));
  assert.match(source, /hostname_mode: directInboundKind \? hostnameMode : undefined/);
  assert.match(source, /readOnly=\{directInboundKind && hostnameMode === "auto"\}/);
  assert.match(source, /ConnectionAddressContext.Provider value=\{asObject\(overviewData\?\.connection_address\)\}/);
  assert.match(source, /if \(!savedTargetUnchanged && !currentProbeAccepted\)/);
  assert.match(source, /existingTransport.enabled === true/);
  assert.match(source, /signature === savedSignature/);
  assert.match(source, /overviewData\?\.draft_revision, ""\) === draftRevision/);
  assert.match(source, /overviewForDraft\?\.pending_config_change_count/);
});

test("a stale overview cannot hide a newly saved draft from Apply", async () => {
  const source = normalizeLocalizedSource(await readFile(new URL("../app/page.tsx", import.meta.url), "utf8"));
  const start = source.indexOf('  const draftRevision = asText(draftEnvelope?.revision');
  const end = source.indexOf('  const pendingConfigChanges =', start);
  assert(start > 0 && end > start);
  const calculate = (overviewRevision, draftRevision, draftPending) => Array.from(vm.runInNewContext(
    source.slice(start, end) + '\n[pendingChangeCount, pendingConfigChangeCount];', {
      asText: (value, fallback) => typeof value === "string" ? value : fallback,
      overviewData: { active_revision: "applied", draft_revision: overviewRevision, pending_change_count: 0, pending_config_change_count: 0 },
      draftEnvelope: { revision: draftRevision, pending_change_count: draftPending, pending_config_change_count: draftPending },
    },
  ));
  assert.deepEqual(calculate("applied", "just-saved", 1), [1, 1]);
  assert.deepEqual(calculate("applied", "applied", 0), [0, 0]);
});
