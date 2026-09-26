"use client";

import {
  FormEvent,
  createContext,
  useContext,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { createPortal, flushSync } from "react-dom";
import {
  LTE_PINPOINT_DOMAINS,
  LTE_PINPOINT_DOMAINS_BY_PACK,
} from "./lte-pinpoint-domains";
import { mergeRuntimeStatus, reverseAvailability } from "./runtime-status";
import { nodePresentation, selectorCandidateIds, routeCandidateIds, compareRouteCandidates, nodeDisplayLabel, nodeLocationDetail } from "./node-presentation";
import { qualitySheet } from "./node-quality";
import { latestSpeedSince, qualityStatsSince } from "./quality-window";
import { automaticCidrHint, supportsAutomaticCidr } from "./cdn-capabilities";
import { AcmeFields, useAcmeProfile } from "./acme-fields";
import { TlsTransferDialog } from "./tls-transfer";
import { mergeSubscriptionMetadata } from "./subscription-metadata";
import { disableSubscriptionPublication } from "./subscription-publication";
import { LanguageProvider, useLanguage, type Locale, type MessageKey } from "./i18n";
import { localizedText } from "./i18n-text";
import {
  cdnDeploymentAfterTLSProfileChange,
  cdnDeploymentForTLSInitialization,
  certificateCoversHostname,
  hostnameAfterTLSProfileChange,
  hostnameForTLSProfileInitialization,
  subscriptionEndpointValueAfterConfigRefresh,
  subscriptionEndpointUsesTLSHostname,
  tlsConcreteHostnames,
  tlsProfileIdForHostname,
} from "./tls-hostnames";
import {
  GatewayApiError,
  JsonObject,
  RemoteUserSubscriptionLink,
  bootstrapAdministrator,
  changeAdministratorPassword,
  createRecoveryBackup,
  createCollectionItem,
  deleteCollectionItem,
  downloadReverseVlessClientConfig,
  downloadRecoveryBackup,
  discoverRouterOs,
  getRemoteUserSubscriptionLink,
  getBootstrapState,
  getCurrentDraft,
  getClientTelemetry,
  getLifecycleStatus,
  getOverview,
  getRecoveryBackups,
  getRouterOsContainerStatus,
  getSubscriptionNodes,
  getSubscriptionMetadata,
  getSubscriptionUrl,
  getStatus,
  getSelectorStatus,
  getSystemLogs,
  getUninstallPreview,
  getXrayLogs,
  importRouterOsExport,
  isUncertainOperationError,
  logout,
  provisionRouterOsCredentials,
  probeTlsEndpoint,
  preflightContainerImageUpload,
  revealTransportHttpPath,
  refreshSubscription,
  resolveServicePack,
  rotateRemoteUserSubscriptionLink,
  runDiagnostics,
  runDraftOperation,
  saveCurrentDraft,
  scheduleFullUninstall,
  scheduleImageUpdate,
  session,
  restoreRecoveryBackup,
  updateCollectionItem,
  uploadContainerImage,
  uploadRecoveryBackup,
} from "./api-client";

type Screen =
  | "overview"
  | "clients"
  | "routing"
  | "connections"
  | "operations"
  | "settings";

type RuntimeLogSource = "error" | "process" | "system" | "routing" | "nginx" | "lifecycle";

function runtimeLogTabId(source: RuntimeLogSource): string {
  return `gateway-log-tab-${source}`;
}

type ViewTransitionDocument = Document & {
  startViewTransition?: (update: () => void) => {
    ready?: Promise<unknown>;
    updateCallbackDone?: Promise<unknown>;
    finished?: Promise<unknown>;
  };
};

const SCREEN_IDS: readonly Screen[] = [
  "overview",
  "clients",
  "routing",
  "connections",
  "operations",
  "settings",
];

function screenFromHash(hash: string): Screen {
  const candidate = hash.replace(/^#\/?/, "").split(/[/?]/, 1)[0];
  return SCREEN_IDS.includes(candidate as Screen)
    ? (candidate as Screen)
    : "overview";
}

function screenHash(screen: Screen): string {
  return `#/${screen}`;
}

const ROUTING_EXPANDED_POLICY_STORAGE_KEY =
  "sb-gateway:routing:expanded-policy";
const ROUTING_SAVE_MESSAGE_STORAGE_KEY =
  "sb-gateway:routing:save-message";
const QUALITY_24H_BASELINE_STORAGE_KEY =
  "sb-gateway:routing:quality-24h-baselines";

type Tone = "ok" | "warn" | "danger" | "info" | "muted";

const ConnectionAddressContext = createContext<JsonObject>({});

function useConnectionHostname() {
  const snapshot = useContext(ConnectionAddressContext);
  const { tr } = useLanguage();
  return (transport: JsonObject, fallback = tr("Адрес не задан")): string =>
    transport.hostname_mode === "auto"
      ? snapshot.state === "ready"
        ? asText(snapshot.address, tr("WAN недоступен"))
        : snapshot.state === "ambiguous"
          ? tr("Выберите адрес вручную")
          : tr("WAN недоступен")
      : asText(transport.hostname, tr(fallback));
}

const CLOUDFLARE_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443] as const;

const CDN_PROVIDERS = [
  { id: "cloudflare", name: "Cloudflare", note: "WebSocket, gRPC, HTTPUpgrade и XHTTP; набор публичных HTTPS-портов проверяется панелью." },
  { id: "gcore", name: "Gcore", note: "WebSocket и TLS; доступны официальный список адресов origin и секретный заголовок." },
  { id: "edgecenter", name: "EdgeCenter / EdgeCDN", note: "WebSocket включается у провайдера отдельно. Защита origin: официальные CIDR или секретный заголовок." },
  { id: "cdnetworks", name: "CDNetworks", note: "WebSocket включается в HTTP Protocol Optimization; для origin рекомендуется секретный header." },
  { id: "timeweb", name: "Timeweb Cloud CDN", note: "Используйте свой CDN-ресурс и отдельный origin-домен. Защита origin: официальные CIDR или секретный заголовок." },
  { id: "beeline", name: "Beeline CDN", note: "Нужны свой CDN-ресурс и отдельный origin-домен. Защита origin: официальные CIDR или секретный заголовок." },
  { id: "vk", name: "VK Cloud CDN", note: "Укажите домен раздачи собственного ресурса и отдельный origin; XHTTP packet-up использует TLS/HTTP/2 до CDN." },
  { id: "yandex", name: "Yandex Cloud CDN", note: "Используйте свой ресурс и origin. Защита origin: официальные CIDR или секретный заголовок." },
  { id: "custom", name: "Другой CDN · ручная настройка", note: "Укажите hostname и поддерживаемый провайдером порт; TLS, транспорт и ограничение доступа к origin настраиваются у выбранного CDN." },
] as const;

type TransportRecommendationField = {
  name: string;
  label: string;
  value: string | boolean;
};

type TransportRecommendation = {
  title: string;
  note: string;
  fields: TransportRecommendationField[];
};

const XHTTP_RECOMMENDATION_FIELDS: TransportRecommendationField[] = [
  { name: "mode", label: "Режим XHTTP", value: "packet-up" },
  { name: "x_padding_bytes", label: "XHTTP padding", value: "100-1000" },
  { name: "vless_encryption_enabled", label: "VLESS Encryption", value: true },
  { name: "vless_encryption_authentication", label: "Аутентификация VLESS Encryption", value: "mlkem768" },
  { name: "uplink_http_method", label: "Uplink HTTP method", value: "GET" },
  { name: "uplink_data_placement", label: "Размещение uplink", value: "header" },
  { name: "uplink_data_key", label: "Ключ uplink", value: "X-Data" },
  { name: "uplink_chunk_size", label: "Размер uplink chunk", value: "2048-3072" },
  { name: "x_padding_obfs_mode", label: "Рандомизация padding", value: true },
  { name: "x_padding_placement", label: "Размещение padding", value: "query" },
  { name: "x_padding_method", label: "Вид padding", value: "tokenish" },
  { name: "x_padding_key", label: "Ключ padding", value: "_v" },
  { name: "x_padding_header", label: "Заголовок padding", value: "X-Padding" },
  { name: "session_id_placement", label: "Размещение session ID", value: "cookie" },
  { name: "session_id_key", label: "Ключ session ID", value: "_sid" },
  { name: "session_id_table", label: "Таблица session ID", value: "" },
  { name: "session_id_length", label: "Длина session ID", value: "" },
  { name: "seq_placement", label: "Размещение seq", value: "query" },
  { name: "seq_key", label: "Ключ seq", value: "_seq" },
  { name: "server_max_header_bytes", label: "Максимум HTTP-заголовков", value: "16384" },
  { name: "xhttp_headers", label: "Дополнительные XHTTP-заголовки", value: "" },
  { name: "download_settings_json", label: "downloadSettings", value: "" },
  { name: "no_grpc_header", label: "Отключить gRPC-заголовок", value: false },
  { name: "no_sse_header", label: "Отключить SSE-заголовок", value: false },
  { name: "sc_max_each_post_bytes", label: "Максимум одного POST", value: "" },
  { name: "sc_min_posts_interval_ms", label: "Интервал POST", value: "" },
  { name: "sc_max_buffered_posts", label: "Буфер POST", value: "" },
  { name: "sc_stream_up_server_secs", label: "Время stream-up", value: "" },
  { name: "xmux_max_connections", label: "XMUX maxConnections", value: "3" },
  { name: "xmux_max_concurrency", label: "XMUX maxConcurrency", value: "0" },
  { name: "xmux_h_max_request_times", label: "XMUX hMaxRequestTimes", value: "600-900" },
  { name: "xmux_h_max_reusable_secs", label: "XMUX hMaxReusableSecs", value: "1800-3000" },
  { name: "xmux_c_max_reuse_times", label: "XMUX cMaxReuseTimes", value: "" },
  { name: "xmux_h_keep_alive_period", label: "XMUX hKeepAlivePeriod", value: "" },
];

const XHTTP_REALITY_RECOMMENDATION_FIELDS: TransportRecommendationField[] =
  XHTTP_RECOMMENDATION_FIELDS.map((field) => {
    if (field.name === "mode") return { ...field, value: "auto" };
    if (field.name === "uplink_http_method") return { ...field, value: "POST" };
    if (field.name === "uplink_data_placement") return { ...field, value: "auto" };
    return field;
  });

const TCP_RECOMMENDATION_FIELDS: TransportRecommendationField[] = [
  { name: "tcp_keep_alive_enabled", label: "TCP Keep-Alive", value: true },
  { name: "tcp_keep_alive_idle", label: "Keep-Alive idle", value: "30" },
  { name: "tcp_keep_alive_interval", label: "Keep-Alive interval", value: "10" },
  { name: "tcp_user_timeout", label: "TCP User Timeout", value: "60000" },
];

const REALITY_RECOMMENDATION_FIELDS: TransportRecommendationField[] = [
  ...TCP_RECOMMENDATION_FIELDS,
  { name: "min_client_ver", label: "Минимальная версия клиента", value: "" },
  { name: "reality_show", label: "Подробный журнал REALITY", value: false },
  { name: "reality_fallback_upload_after_bytes", label: "Fallback upload after", value: "0" },
  { name: "reality_fallback_upload_bytes_per_sec", label: "Fallback upload rate", value: "0" },
  { name: "reality_fallback_upload_burst_bytes_per_sec", label: "Fallback upload burst", value: "0" },
  { name: "reality_fallback_download_after_bytes", label: "Fallback download after", value: "0" },
  { name: "reality_fallback_download_bytes_per_sec", label: "Fallback download rate", value: "0" },
  { name: "reality_fallback_download_burst_bytes_per_sec", label: "Fallback download burst", value: "0" },
  { name: "max_client_ver", label: "Максимальная версия клиента", value: "" },
  { name: "max_time_diff", label: "Допуск времени", value: "0" },
  { name: "xver", label: "PROXY protocol xver", value: "0" },
  { name: "spider_x", label: "SpiderX", value: "" },
  { name: "reality_mldsa65_enabled", label: "ML-DSA-65", value: false },
];

const GRPC_RECOMMENDATION_FIELDS: TransportRecommendationField[] = [
  { name: "grpc_multi_mode", label: "gRPC multiMode", value: false },
  { name: "grpc_user_agent", label: "gRPC User-Agent", value: "" },
  { name: "grpc_idle_timeout", label: "gRPC idle timeout", value: "0" },
  { name: "grpc_health_check_timeout", label: "gRPC health check", value: "20" },
  { name: "grpc_permit_without_stream", label: "Keepalive без потока", value: false },
  { name: "grpc_initial_windows_size", label: "Начальное окно gRPC", value: "0" },
];

const DIRECT_GRPC_RECOMMENDATION_FIELDS: TransportRecommendationField[] =
  GRPC_RECOMMENDATION_FIELDS.map((field) => {
    if (field.name === "grpc_idle_timeout") return { ...field, value: "60" };
    if (field.name === "grpc_permit_without_stream") return { ...field, value: true };
    return field;
  });

const TRANSPORT_RECOMMENDATIONS: Record<string, TransportRecommendation> = {
  ws: {
    title: "WebSocket · совместимые значения Xray",
    note: "Без Early Data и нестандартных заголовков; heartbeat оставлен выключенным.",
    fields: [
      { name: "early_data", label: "Early Data", value: "0" },
      { name: "ws_heartbeat_period", label: "Heartbeat WebSocket", value: "0" },
      { name: "client_http_headers", label: "Клиентские HTTP-заголовки", value: "" },
    ],
  },
  httpupgrade: {
    title: "HTTPUpgrade · совместимые значения Xray",
    note: "Без Early Data и нестандартных клиентских заголовков.",
    fields: [
      { name: "early_data", label: "Early Data", value: "0" },
      { name: "client_http_headers", label: "Клиентские HTTP-заголовки", value: "" },
    ],
  },
  grpc: {
    title: "gRPC · совместимые значения Xray",
    note: "HTTP/2 и TCP-параметры клиентского Xray JSON.",
    fields: [...GRPC_RECOMMENDATION_FIELDS, ...TCP_RECOMMENDATION_FIELDS],
  },
  xhttp: {
    title: "XHTTP · packet-up и XMUX",
    note: "GET uplink, рандомизированный padding и безопасные значения XMUX; все поля остаются редактируемыми.",
    fields: XHTTP_RECOMMENDATION_FIELDS,
  },
  reality: {
    title: "VLESS Reality · Vision",
    note: "Chrome ClientHello и TCP Keep-Alive для нестабильных каналов; SNI, target и ключи не изменяются.",
    fields: REALITY_RECOMMENDATION_FIELDS,
  },
  "reality-grpc": {
    title: "gRPC + Reality",
    note: "Настройки REALITY и gRPC без изменения SNI, target, service name и ключей.",
    fields: [...REALITY_RECOMMENDATION_FIELDS, ...DIRECT_GRPC_RECOMMENDATION_FIELDS],
  },
  "grpc-tls": {
    title: "gRPC + TLS Pin",
    note: "HTTP/2, закреплённый сертификат и стабильные TCP-параметры.",
    fields: [...DIRECT_GRPC_RECOMMENDATION_FIELDS, ...TCP_RECOMMENDATION_FIELDS],
  },
  "xhttp-reality": {
    title: "XHTTP + Reality",
    note: "Auto выбирает stream-one для REALITY; XMUX и параметры маскировки остаются редактируемыми, секреты не ротируются.",
    fields: [...XHTTP_REALITY_RECOMMENDATION_FIELDS, ...REALITY_RECOMMENDATION_FIELDS],
  },
  hysteria2: {
    title: "Hysteria 2 · QUIC",
    note: "BBR, QUIC keepalive и нейтральная API-маскировка; TLS-пара, SNI и секреты не изменяются.",
    fields: [
      { name: "hysteria_udp_idle_timeout", label: "UDP idle timeout", value: "60" },
      { name: "hysteria_congestion", label: "Управление перегрузкой QUIC", value: "bbr" },
      { name: "hysteria_max_idle_timeout", label: "Max idle timeout QUIC", value: "" },
      { name: "hysteria_keep_alive_period", label: "Keepalive QUIC", value: "15" },
      { name: "hysteria_max_incoming_streams", label: "Максимум входящих потоков", value: "" },
      { name: "hysteria_disable_path_mtu_discovery", label: "Отключить Path MTU Discovery", value: false },
      { name: "hysteria_brutal_disable_loss_compensation", label: "Brutal без компенсации потерь", value: false },
      { name: "hysteria_disable_gso", label: "Отключить GSO", value: false },
      { name: "hysteria_disable_stateless_reset", label: "Отключить Stateless Reset", value: false },
      { name: "hysteria_init_stream_receive_window", label: "Начальное окно потока", value: "0" },
      { name: "hysteria_max_stream_receive_window", label: "Максимальное окно потока", value: "0" },
      { name: "hysteria_init_connection_receive_window", label: "Начальное окно соединения", value: "0" },
      { name: "hysteria_max_connection_receive_window", label: "Максимальное окно соединения", value: "0" },
      { name: "hysteria_masquerade_type", label: "Masquerade", value: "api" },
      { name: "hysteria_masquerade_x_forwarded", label: "Передавать X-Forwarded-*", value: false },
      { name: "hysteria_udp_hop_enabled", label: "UDP port hopping", value: false },
      { name: "obfs_enabled", label: "Salamander obfuscation", value: false },
      { name: "tls_pin_certificate", label: "Закрепление TLS-сертификата", value: false },
    ],
  },
};

function subscriptionCdnProviderNote(value: unknown): string {
  const id = asText(value, "cloudflare");
  if (id === "cloudflare") {
    return "Origin: официальные CIDR · авто.";
  }
  if (id === "custom") {
    return "Origin: секретный заголовок или CIDR вручную.";
  }
  return "Origin: секретный HTTP-заголовок.";
}

function cdnProviderName(value: unknown): string {
  const id = asText(value, "cloudflare");
  return CDN_PROVIDERS.find((provider) => provider.id === id)?.name ?? id;
}

const DIRECT_SERVICE_PACKS = [
  { id: "ru-government", name: "Госуслуги и государственные сайты", category: "Россия · важное", description: "Федеральные и региональные порталы, налоги, Госключ.", updateMode: "daily", broad: false },
  { id: "ru-banks", name: "Банки и платежи РФ", category: "Россия · важное", description: "Банки, СБП/НСПК и основные платежные кабинеты.", updateMode: "daily", broad: false },
  { id: "ru-marketplaces", name: "Маркетплейсы, объявления, доставка и ритейл РФ", category: "Россия · покупки", description: "Маркетплейсы, объявления, магазины, службы доставки и их CDN.", updateMode: "daily", broad: false },
  { id: "yandex", name: "Экосистема Яндекса", category: "Россия · сервисы", description: "Поиск, карты, почта, облако, Диск, Go, Такси, Еда, Маркет, Кинопоиск и общие CDN.", updateMode: "daily", broad: false },
  { id: "mailru-group", name: "VK, Mail.ru, OK, Дзен и MAX", category: "Россия · общение", description: "Сайты, приложения, CDN и звонки экосистемы VK/Mail.ru/MAX.", updateMode: "daily", broad: false },
  { id: "ru-travel", name: "Транспорт и путешествия РФ", category: "Россия · транспорт", description: "Билеты, РЖД, авиакомпании, карты и поездки.", updateMode: "daily", broad: false },
  { id: "ru-telecom", name: "Мобильные операторы и провайдеры связи РФ", category: "Россия · связь", description: "Личные кабинеты, сайты, приложения и CDN российских операторов связи.", updateMode: "daily", broad: false },
  { id: "ru-media", name: "Медиа, ТВ, видеостриминг и музыка РФ", category: "Россия · медиа", description: "Новости, телеканалы, онлайн-кинотеатры, видео, радио, музыка и CDN.", updateMode: "daily", broad: false },
  { id: "ru-education-work-it", name: "Образование, работа и ИТ-сервисы РФ", category: "Россия · работа", description: "Образовательные платформы, вакансии, разработка, облака, хостинг и ИТ-медиа.", updateMode: "daily", broad: false },
  { id: "ru-all", name: "Вся зона RU/РФ", category: "Россия · широкий доступ", description: "Разрешает практически всю российскую доменную зону.", updateMode: "daily", broad: true },
  { id: "youtube", name: "YouTube", category: "Видео", description: "YouTube и медиадомены Google.", updateMode: "daily", broad: false },
  { id: "telegram", name: "Telegram", category: "Общение", description: "Web, API, официальные сети и звонки Telegram.", updateMode: "daily", broad: false },
  { id: "whatsapp", name: "WhatsApp", category: "Общение", description: "WhatsApp Web, приложение и связанные звонки.", updateMode: "daily", broad: false },
  { id: "calls", name: "FaceTime", category: "Общение · звонки", description: "Медиа-трафик FaceTime.", updateMode: "builtin", broad: false },
  { id: "torrent", name: "Torrent / BitTorrent", category: "P2P", description: "По умолчанию напрямую через WAN; TCP, uTP и UDP-трекеры распознаются по протоколу.", updateMode: "protocol", broad: false },
  { id: "discord", name: "Discord", category: "Общение", description: "Discord и его CDN.", updateMode: "daily", broad: false },
  { id: "instagram", name: "Instagram", category: "Соцсети", description: "Instagram и CDN изображений.", updateMode: "daily", broad: false },
  { id: "facebook", name: "Facebook", category: "Соцсети", description: "Facebook и связанные CDN.", updateMode: "daily", broad: false },
  { id: "tiktok", name: "TikTok", category: "Видео", description: "TikTok и медиадомены.", updateMode: "daily", broad: false },
  { id: "netflix", name: "Netflix", category: "Видео", description: "Netflix и потоковые CDN.", updateMode: "daily", broad: false },
  { id: "spotify", name: "Spotify", category: "Музыка", description: "Spotify и CDN аудио.", updateMode: "daily", broad: false },
  { id: "openai", name: "OpenAI / ChatGPT", category: "Работа", description: "ChatGPT, OpenAI API и статика.", updateMode: "daily", broad: false },
  { id: "claude", name: "Claude", category: "Работа · AI", description: "Claude, Claude Code, Anthropic API и собственная статика.", updateMode: "official", broad: false },
  { id: "antigravity", name: "Antigravity", category: "Работа · AI", description: "Antigravity и точечные Google AI API без общего правила для Google.", updateMode: "official", broad: false },
  { id: "github", name: "GitHub", category: "Работа", description: "GitHub, assets и raw-контент.", updateMode: "daily", broad: false },
  { id: "steam", name: "Steam", category: "Игры", description: "Steam, Community и CDN загрузок.", updateMode: "daily", broad: false },
  { id: "binance", name: "Binance", category: "Биржи", description: "Сайт, приложение, CDN, REST/WebSocket API и AWS WAF challenge.", updateMode: "daily + release", broad: false },
  { id: "bybit", name: "Bybit", category: "Биржи", description: "Сайт, приложение, REST/WebSocket API, testnet, demo и региональные endpoints.", updateMode: "daily + release", broad: false },
  { id: "gateio", name: "Gate.io", category: "Биржи", description: "Сайт, приложение, REST API v4, WebSocket, futures и testnet.", updateMode: "daily + release", broad: false },
  { id: "okx", name: "OKX", category: "Биржи", description: "Сайт, приложение, REST, public/private WebSocket, demo и регионы.", updateMode: "daily + release", broad: false },
] as const;

const PINPOINT_DOMAINS_BY_PACK: Record<string, string[]> = {
  ...Object.fromEntries(
    Object.entries(LTE_PINPOINT_DOMAINS_BY_PACK).map(([packId, domains]) => [
      packId,
      [...domains],
    ]),
  ),
  "ru-all": [...LTE_PINPOINT_DOMAINS],
};

function parsePinpointDomains(value: string): string[] {
  return [...new Set(
    value
      .split(/[\n,]/)
      .map((domain) => domain.trim().toLowerCase().replace(/^\.+/, ""))
      .filter(Boolean),
  )];
}

function mergePinpointDomains(current: string, recommended: string[]): string {
  return [...new Set([
    ...parsePinpointDomains(current),
    ...recommended.map((domain) => domain.trim().toLowerCase()).filter(Boolean),
  ])].join(", ");
}

function currentUiLocale(): Locale {
  return typeof document !== "undefined" && document.documentElement.lang === "en"
    ? "en"
    : "ru";
}

function errorMessage(error: unknown, locale: Locale = currentUiLocale()): string {
  if (error instanceof GatewayApiError) {
    const request = error.requestId
      ? locale === "en"
        ? ` · request ${error.requestId}`
        : ` · запрос ${error.requestId}`
      : "";
    const details = Array.isArray(error.details)
      ? error.details.filter(
          (value): value is JsonObject => Boolean(value && typeof value === "object"),
        )
      : [];
    const issue = details[0];
    const code = asText(issue?.code, error.code);
    const path = asText(issue?.path, "");
    const translated =
      error.code === "apply_rolled_back"
        ? "Новая конфигурация отклонена, предыдущая конфигурация восстановлена."
      : error.code === "apply_recovery_pending"
        ? "Применение не завершено. Аварийный откат RouterOS остаётся активным, восстановление ожидается. Проверьте статус перед повтором."
      : error.code === "apply_state_unconfirmed"
        ? "Итог применения не подтверждён. Перед повтором проверьте состояние RouterOS и контейнера."
      : error.code === "storage_root_required"
        ? "Сначала укажите в Настройки → Контейнер и хранилище → Каталог проекта на внешнем SSD. Архив не загружался."
      : error.code === "invalid_image_filename"
        ? "Выберите один архив .tar с простым именем файла."
      : error.code === "invalid_image_size"
        ? "Размер выбранного архива контейнера выходит за допустимые пределы."
      : error.code === "persistent_storage_read_only"
        ? "Внешнее хранилище недоступно для записи. Загрузка образа не началась."
      : error.code === "invalid_id" || path.endsWith(".id")
        ? "Идентификатор должен начинаться и заканчиваться строчной латинской буквой или цифрой; внутри допустимы точка, дефис и подчёркивание."
        : path.endsWith(".refresh_minutes")
          ? "Интервал проверки должен быть от 1 минуты до 7 суток."
          : code === "invalid_scheme"
            ? "URL подписки должен начинаться с https://."
            : code === "secret_not_provisioned" || code === "subscription_url_not_provisioned"
              ? "Сохранённая ссылка недоступна. Введите URL ещё раз и сохраните подписку."
            : code === "tls_probe_hostname_invalid"
              ? "Введите доменное имя или IP-адрес без https:// и пути."
              : code === "tls_probe_port_invalid"
                ? "Порт TLS-проверки должен быть от 1 до 65535."
                : code === "tls_probe_dns_failed"
                  ? "Публичный DNS не вернул адрес для указанного имени."
                  : code === "tls_probe_certificate_mismatch"
                    ? "Сертификат target не подходит для указанного SNI."
                    : code === "tls_probe_sni_rejected"
                      ? "Target отклонил TLS-рукопожатие с указанным SNI."
                  : code === "tls_probe_handshake_failed"
                    ? "TLS-рукопожатие не прошло. Проверьте порт, SNI, сертификат и доступность сервера."
            : code === "dns_failed"
              ? "Не удалось определить адрес сервера подписки. Проверьте URL и DNS."
              : code === "unavailable"
                ? "Сервер подписки не ответил. Проверьте URL и повторите попытку."
                : code === "upstream_http_error"
                  ? "Сервер подписки отклонил запрос. Проверьте, что ссылка активна."
                  : code === "non_public_destination"
                    ? "Ссылка ведёт на локальный или служебный адрес; разрешены только публичные HTTPS-адреса."
                    : code === "too_large"
                      ? "Подписка превышает безопасный размер."
                    : code === "too_many_redirects"
                        ? "Ссылка подписки содержит слишком много перенаправлений."
                        : code === "unsupported_nodes"
                          ? "Формат подписки распознан, но в ней нет поддерживаемых VLESS/REALITY или Hysteria 2 узлов."
                          : code === "unsupported_transport"
                            ? "В подписке найден вариант транспорта, который пока не поддерживается."
                            : code === "invalid_node"
                              ? "Один из узлов подписки содержит неполные или неверные параметры."
                    : code === "too_many_nodes"
                                ? "В подписке слишком много узлов для безопасной загрузки."
                                : code === "unresolved_location_selection"
                                  ? "Выбранное расположение исчезло из обновлённой подписки. Выберите доступную группу, страну, город или узел — рабочий маршрут пока не изменён."
                                : code === "invalid_content"
                                  ? "Формат подписки не распознан или один из узлов повреждён."
                        : error.code === "subscription_refresh_failed"
                          ? "Подписка загрузилась с ошибкой или содержит неподдерживаемые узлы. Проверьте ссылку."
                          : error.code === "subscription_publication_disabled"
                            ? "Публикация подписки отключена."
                            : error.message;
    return `${localizedText(translated, locale)}${request}`;
  }
  const message = error instanceof Error ? error.message : String(error);
  return localizedText(message, locale);
}

function planValidationIssueLabel(path: string, locale: Locale): string {
  const label =
    path === "ingress.tls_profile_id"
      ? "TLS-профиль публичного входа"
      : path === "ingress.subscription_tls_profile_id"
        ? "TLS-профиль клиентской подписки"
        : path.startsWith("transports[") && path.endsWith(".tls_profile_id")
          ? "TLS-профиль транспорта"
          : "Параметр черновика";
  return localizedText(label, locale);
}

function planValidationIssueMessage(issue: JsonObject, locale: Locale): string {
  const code = asText(issue.code, "");
  const message =
    code === "inactive_tls_profile"
      ? "Выбранный TLS-профиль выключен или не содержит пару сертификата и private key."
      : asText(issue.message, "Параметр не прошёл проверку.");
  return localizedText(message, locale);
}

async function copyText(value: string): Promise<void> {
  if (!navigator.clipboard?.writeText) {
    throw new Error("Браузер не разрешил копирование. Выделите ссылку и скопируйте её вручную.");
  }
  await navigator.clipboard.writeText(value);
}

function resultMessage(
  value: unknown,
  fallback = "Операция подтверждена локальным control plane.",
  locale: Locale = currentUiLocale(),
): string {
  if (!value || typeof value !== "object") return localizedText(fallback, locale);
  const object = value as JsonObject;
  for (const key of ["message", "summary", "result"]) {
    if (typeof object[key] === "string") {
      return localizedText(object[key] as string, locale);
    }
  }
  return localizedText(fallback, locale);
}

function prefixedErrorMessage(error: unknown, locale: Locale = currentUiLocale()): string {
  return `${locale === "en" ? "Error" : "Ошибка"}: ${errorMessage(error, locale)}`;
}

function isErrorMessage(message: string): boolean {
  return message.startsWith("Ошибка:") || message.startsWith("Error:");
}

function formatElapsed(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return `${minutes}:${String(remainder).padStart(2, "0")}`;
}

const CYRILLIC_ID_PARTS: Record<string, string> = {
  а: "a",
  б: "b",
  в: "v",
  г: "g",
  д: "d",
  е: "e",
  ё: "yo",
  ж: "zh",
  з: "z",
  и: "i",
  й: "y",
  к: "k",
  л: "l",
  м: "m",
  н: "n",
  о: "o",
  п: "p",
  р: "r",
  с: "s",
  т: "t",
  у: "u",
  ф: "f",
  х: "h",
  ц: "ts",
  ч: "ch",
  ш: "sh",
  щ: "sch",
  ъ: "",
  ы: "y",
  ь: "",
  э: "e",
  ю: "yu",
  я: "ya",
};

function entityIdFromName(
  value: string,
  occupiedIds: Set<string>,
  fallback: string,
): string {
  const transliterated = value
    .trim()
    .toLowerCase()
    .replace(/[а-яё]/g, (character) => CYRILLIC_ID_PARTS[character] ?? "");
  const base =
    transliterated
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64)
      .replace(/-+$/g, "") || fallback;
  if (!occupiedIds.has(base)) return base;
  for (let suffix = 2; suffix < 10_000; suffix += 1) {
    const suffixText = `-${suffix}`;
    const candidate = `${base.slice(0, 64 - suffixText.length).replace(/-+$/g, "")}${suffixText}`;
    if (!occupiedIds.has(candidate)) return candidate;
  }
  return `${fallback}-${Date.now().toString(36)}`.slice(0, 64);
}

function ipv4Number(value: string): number | null {
  const octets = value.split(".");
  if (
    octets.length !== 4 ||
    octets.some(
      (octet) =>
        !/^\d{1,3}$/.test(octet) || Number(octet) < 0 || Number(octet) > 255,
    )
  ) {
    return null;
  }
  return octets.reduce((result, octet) => result * 256 + Number(octet), 0);
}

function ipv4Text(value: number): string {
  return [24, 16, 8, 0]
    .map((shift) => Math.floor(value / 2 ** shift) % 256)
    .join(".");
}

function ipv4CidrRange(value: string): [number, number] | null {
  const [addressText, prefixText = "32", extra] = value.trim().split("/");
  const address = ipv4Number(addressText);
  const prefix = Number(prefixText);
  if (
    extra !== undefined ||
    address === null ||
    !Number.isInteger(prefix) ||
    prefix < 0 ||
    prefix > 32
  ) {
    return null;
  }
  const size = 2 ** (32 - prefix);
  const start = Math.floor(address / size) * size;
  return [start, start + size - 1];
}

function ipv4RangesOverlap(
  left: [number, number],
  right: [number, number],
): boolean {
  return left[0] <= right[1] && right[0] <= left[1];
}

function isPrivateIpv4Cidr(value: string): boolean {
  const candidate = ipv4CidrRange(value);
  if (!candidate) return false;
  return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    .map(ipv4CidrRange)
    .some(
      (range) =>
        range !== null && candidate[0] >= range[0] && candidate[1] <= range[1],
    );
}

type OccupiedIpv4Range = {
  start: number;
  end: number;
  label: string;
};

function occupiedClientIpv4Ranges(
  config: JsonObject,
  discovery: JsonObject,
  currentRemoteId: string,
  locale: Locale = "ru",
): OccupiedIpv4Range[] {
  const occupied = new Map<string, string>();
  const add = (value: unknown, label: string) => {
    if (typeof value !== "string" || !value.trim()) return;
    const cidr = value.trim();
    if (!occupied.has(cidr)) occupied.set(cidr, label);
  };
  for (const value of asStringList(discovery.networks)) add(value, localizedText("сеть MikroTik", locale));
  for (const value of asStringList(discovery.router_addresses)) add(value, localizedText("адрес MikroTik", locale));
  for (const source of Object.values(asObject(discovery.client_sources))) {
    for (const row of asObjectList(source)) add(row.cidr, localizedText("адрес подключённого устройства", locale));
  }
  for (const network of asObjectList(config.networks)) {
    for (const value of asStringList(network.cidrs)) add(value, locale === "en" ? `network “${itemName(network)}”` : `сеть «${itemName(network)}»`);
  }
  for (const network of importReviewNetworks(config)) add(network.cidr, localizedText("сеть MikroTik", locale));
  for (const client of asObjectList(config.local_clients)) {
    for (const value of asStringList(client.source_cidrs)) {
      add(value, locale === "en" ? `device “${itemName(client)}”` : `устройство «${itemName(client)}»`);
    }
  }
  for (const user of asObjectList(config.remote_users)) {
    if (asText(user.id, "") !== currentRemoteId) {
      add(user.client_tun_address, locale === "en" ? `connection “${itemName(user)}”` : `подключение «${itemName(user)}»`);
    }
  }
  const systemNetworking = asObject(asObject(config.system).networking);
  for (const field of [
    "routeros_address",
    "routeros_gateway",
    "container_address",
    "container_dns",
    "tun_address",
  ]) {
    add(systemNetworking[field], localizedText("служебная сеть SB Gateway", locale));
  }
  for (const value of asStringList(asObject(config.routeros).router_addresses)) {
    add(value, localizedText("адрес MikroTik", locale));
  }
  return [...occupied.entries()].flatMap(([cidr, label]) => {
    const range = ipv4CidrRange(cidr);
    return range ? [{ start: range[0], end: range[1], label }] : [];
  });
}

function clientTunAddressError(
  config: JsonObject,
  discovery: JsonObject,
  currentRemoteId: string,
  value: string,
  locale: Locale = "ru",
): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const range = ipv4CidrRange(trimmed);
  const [addressText, prefixText = "32"] = trimmed.split("/");
  const address = ipv4Number(addressText);
  const prefix = Number(prefixText);
  const loopbackStart = ipv4Number("127.0.0.0") ?? 0;
  const loopbackEnd = ipv4Number("127.255.255.255") ?? 0;
  const linkLocalStart = ipv4Number("169.254.0.0") ?? 0;
  const linkLocalEnd = ipv4Number("169.254.255.255") ?? 0;
  const multicastStart = ipv4Number("224.0.0.0") ?? 0;
  const multicastEnd = ipv4Number("239.255.255.255") ?? 0;
  if (
    !range ||
    address === null ||
    prefix > 30 ||
    address === range[0] ||
    address === range[1] ||
    address === 0 ||
    (address >= loopbackStart && address <= loopbackEnd) ||
    (address >= linkLocalStart && address <= linkLocalEnd) ||
    (address >= multicastStart && address <= multicastEnd)
  ) {
    return localizedText("Укажите адрес узла IPv4 с маской /30 или шире.", locale);
  }
  const conflict = occupiedClientIpv4Ranges(
    config,
    discovery,
    currentRemoteId,
    locale,
  ).find(({ start, end }) => range[0] <= end && range[1] >= start);
  return conflict
    ? locale === "en"
      ? `The address is already in use; it overlaps ${conflict.label}.`
      : `Адрес уже занят: найдено пересечение — ${conflict.label}.`
    : "";
}

function remoteConnectionNameError(
  config: JsonObject,
  currentRemoteId: string,
  value: string,
  locale: Locale = "ru",
): string {
  const normalized = value.trim().toLocaleLowerCase("ru");
  if (!normalized) return "";
  const conflict = asObjectList(config.remote_users).find(
    (user) =>
      asText(user.id, "") !== currentRemoteId &&
      asText(user.display_name, "").trim().toLocaleLowerCase("ru") === normalized,
  );
  return conflict
    ? locale === "en"
      ? `The name is already used by connection “${itemName(conflict)}”.`
      : `Имя уже используется подключением «${itemName(conflict)}».`
    : "";
}

function suggestedClientTunAddress(
  config: JsonObject,
  discovery: JsonObject,
  currentRemoteId: string,
): string {
  const occupiedRanges = occupiedClientIpv4Ranges(
    config,
    discovery,
    currentRemoteId,
  );
  const poolStart = ipv4Number("172.19.0.0") ?? 0;
  const poolEnd = ipv4Number("172.19.255.255") ?? 0;
  for (let network = poolStart; network + 3 <= poolEnd; network += 4) {
    const overlaps = occupiedRanges.some(
      ({ start, end }) => network <= end && network + 3 >= start,
    );
    if (!overlaps) return `${ipv4Text(network + 1)}/30`;
  }
  return "";
}

function countryFlag(country: string): string {
  if (!/^[A-Z]{2}$/.test(country)) return "";
  return String.fromCodePoint(
    ...country.split("").map((character) => 0x1f1e6 + character.charCodeAt(0) - 65),
  );
}

function NodeName({ label, country = "", provider }: { label: string; country?: string; provider?: string }) {
  const { tr } = useLanguage();
  const node = nodePresentation(label, country);
  return <span className="node-name" title={provider ? tr("{node} · Подписка: {provider}", { node: node.label, provider }) : node.label}>
    {node.flag ? (
      // Local static SVGs keep flags consistent on Windows without a font/CDN.
      // eslint-disable-next-line @next/next/no-img-element
      <img className="node-country-flag" src={node.flag} width={16} height={12} alt="" />
    ) : null}
    <span>{node.label}</span>
  </span>;
}

function protocolLabel(value: unknown): string {
  const protocol = asText(value, "vless").toLowerCase();
  const labels: Record<string, string> = {
    vless: "VLESS",
    reality: "REALITY",
    hysteria2: "Hysteria 2",
  };
  return labels[protocol] ?? protocol;
}

function transportKindLabel(value: unknown): string {
  const kind = asText(value, "").toLowerCase();
  const labels: Record<string, string> = {
    ws: "WebSocket + TLS",
    grpc: "gRPC + TLS",
    "grpc-tls": "VLESS + gRPC + TLS Pin",
    httpupgrade: "HTTPUpgrade + TLS",
    xhttp: "XHTTP + TLS",
    "xhttp-reality": "XHTTP + Reality",
    reality: "VLESS Reality",
    "reality-grpc": "gRPC + Reality",
    hysteria2: "Hysteria 2",
  };
  return labels[kind] ?? (kind || "Транспорт");
}

function reverseTransportKindLabel(value: unknown): string {
  const kind = asText(value, "").toLowerCase();
  const labels: Record<string, string> = {
    ws: "WS",
    grpc: "gRPC",
    httpupgrade: "HTTPUpgrade",
    xhttp: "XHTTP",
    "xhttp-reality": "XHTTP + Reality",
    reality: "Reality + Vision",
    "reality-grpc": "gRPC + Reality",
  };
  return labels[kind] ?? transportKindLabel(kind);
}

function transportChangeLead(kind: string): string {
  if (kind === "ws") {
    return "Изменение вступит в силу после применения. Путь WebSocket создаётся локальным control plane.";
  }
  if (kind === "httpupgrade") {
    return "Изменение вступит в силу после применения. Путь HTTPUpgrade создаётся локальным control plane.";
  }
  if (["xhttp", "xhttp-reality"].includes(kind)) {
    return "Изменение вступит в силу после применения. Путь XHTTP создаётся локальным control plane.";
  }
  if (["grpc", "reality-grpc", "grpc-tls"].includes(kind)) {
    return "Изменение вступит в силу после применения. Имя gRPC-сервиса создаётся локальным control plane.";
  }
  return "Изменение вступит в силу после применения.";
}

function cdnDeploymentScopeNote(kind: string): string {
  if (kind === "grpc") {
    return "Имя gRPC-сервиса общее. Домен раздачи, origin-порт, origin-домен и TLS-профиль задаются отдельно для каждого CDN.";
  }
  if (kind === "xhttp") {
    return "HTTP-путь и XHTTP extra общие. Домен раздачи, origin-порт, origin-домен и TLS-профиль задаются отдельно для каждого CDN.";
  }
  if (kind === "httpupgrade") {
    return "Путь HTTPUpgrade общий. Домен раздачи, origin-порт, origin-домен и TLS-профиль задаются отдельно для каждого CDN.";
  }
  return "Путь WebSocket общий. Домен раздачи, origin-порт, origin-домен и TLS-профиль задаются отдельно для каждого CDN.";
}

function cdnOriginNameNote(kind: string): string {
  if (kind === "grpc") {
    return "TLS SNI соединения CDN → origin шлюза.";
  }
  if (kind === "xhttp") {
    return "SNI/Host соединения CDN → origin; это отдельный origin-домен, не домен раздачи.";
  }
  return "SNI/Host соединения CDN → origin шлюза.";
}

function formatBytes(value: unknown, locale: Locale = "ru"): string {
  const bytes = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = locale === "en"
    ? ["B", "KB", "MB", "GB", "TB"]
    : ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let amount = bytes;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount >= 10 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
}

function formatNodeCount(value: number, locale: Locale = "ru"): string {
  if (locale === "en") return `${value} ${value === 1 ? "node" : "nodes"}`;
  const remainder100 = value % 100;
  const remainder10 = value % 10;
  const noun =
    remainder10 === 1 && remainder100 !== 11
      ? "узел"
      : remainder10 >= 2 && remainder10 <= 4 && (remainder100 < 12 || remainder100 > 14)
        ? "узла"
        : "узлов";
  return `${value} ${noun}`;
}

function formatBitRate(value: unknown, locale: Locale = "ru"): string {
  if (value === null || value === undefined || value === "" || typeof value === "boolean") {
    return "—";
  }
  const bytesPerSecond = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond < 0) return "—";
  const bitsPerSecond = bytesPerSecond * 8;
  const units = locale === "en"
    ? ["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"]
    : ["бит/с", "Кбит/с", "Мбит/с", "Гбит/с"];
  let amount = bitsPerSecond;
  let unit = 0;
  while (amount >= 1000 && unit < units.length - 1) {
    amount /= 1000;
    unit += 1;
  }
  return `${amount >= 10 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
}

function expiryText(value: unknown, locale: Locale = "ru"): string {
  if (typeof value !== "string" || !value) {
    return locale === "en" ? "Expiry not provided" : "Срок действия не указан";
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return locale === "en" ? "Expiry not provided" : "Срок действия не указан";
  }
  const remaining = timestamp - Date.now();
  const absolute = new Intl.DateTimeFormat(locale === "en" ? "en-GB" : "ru-RU", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(timestamp));
  if (remaining <= 0) return locale === "en" ? `Expired ${absolute}` : `Истекла ${absolute}`;
  const days = Math.floor(remaining / 86_400_000);
  const hours = Math.floor((remaining % 86_400_000) / 3_600_000);
  if (locale === "en") {
    return `Valid until ${absolute} · ${days > 0 ? `${days} d` : `${hours} h`} remaining`;
  }
  return `Действует до ${absolute} · осталось ${days > 0 ? `${days} дн.` : `${hours} ч.`}`;
}

function subscriptionIntervalText(subscription: JsonObject, locale: Locale = "ru"): string {
  const minutes = Number(
    subscription.refresh_minutes ?? Number(subscription.refresh_hours ?? 24) * 60,
  );
  if (!Number.isFinite(minutes) || minutes < 1) {
    return locale === "en" ? "interval not set" : "интервал не задан";
  }
  if (locale === "en") {
    return minutes % 60 === 0
      ? `every ${minutes / 60} h`
      : `every ${minutes} min`;
  }
  if (minutes % 60 === 0) return `каждые ${minutes / 60} ч`;
  return `каждые ${minutes} мин`;
}

type SubscriptionCityGroup = {
  key: string;
  name: string;
  locationKeys: string[];
  labels: string[];
  protocols: string[];
  providers: string[];
  entries: {
    key: string;
    label: string;
    protocol: string;
    provider: string;
  }[];
  nodes: number;
  inferredFromLabel: boolean;
};

type SubscriptionCountryGroup = {
  code: string;
  name: string;
  cities: SubscriptionCityGroup[];
  locationKeys: string[];
  nodes: number;
};

type SubscriptionRegionGroup = {
  id: string;
  name: string;
  countries: SubscriptionCountryGroup[];
  locationKeys: string[];
  nodes: number;
};

const REGION_COUNTRIES = {
  europe: new Set("AD AL AT AX BA BE BG BY CH CY CZ DE DK EE ES FI FO FR GB GG GI GR HR HU IE IM IS IT JE LI LT LU LV MC MD ME MK MT NL NO PL PT RO RS RU SE SI SJ SK SM UA VA".split(" ")),
  asia: new Set("AE AF AM AZ BD BH BN BT CN GE HK ID IL IN IQ IR JO JP KG KH KP KR KW KZ LA LB LK MM MN MO MV MY NP OM PH PK PS QA SA SG SY TH TJ TL TM TR TW UZ VN YE".split(" ")),
  america: new Set("AG AI AR AW BB BL BM BO BQ BR BS BZ CA CL CO CR CU CW DM DO EC FK GD GF GL GP GT GY HN HT JM KN KY LC MF MQ MS MX NI PA PE PM PR PY SR SV SX TC TT US UY VC VE VG VI".split(" ")),
  africa: new Set("AO BF BI BJ BW CD CF CG CI CM CV DJ DZ EG EH ER ET GA GH GM GN GQ GW KE KM LR LS LY MA MG ML MR MU MW MZ NA NE NG RE RW SC SD SH SL SN SO SS ST SZ TD TG TN TZ UG YT ZA ZM ZW".split(" ")),
  oceania: new Set("AS AU CC CK CX FJ FM GU HM KI MH MP NC NF NR NU NZ PF PG PN PW SB TK TO TV UM VU WF WS".split(" ")),
} as const;

const REGION_META = [
  { id: "europe", name: "Европа" },
  { id: "asia", name: "Азия" },
  { id: "america", name: "Америка" },
  { id: "africa", name: "Африка" },
  { id: "oceania", name: "Австралия и Океания" },
  { id: "other", name: "Другие расположения" },
] as const;

const countryDisplayNames = {
  ru: new Intl.DisplayNames(["ru"], { type: "region" }),
  en: new Intl.DisplayNames(["en"], { type: "region" }),
};

function countryName(code: string, locale: Locale = "ru"): string {
  if (code === "ZZ") {
    return locale === "en" ? "Country not identified" : "Страна не определена";
  }
  const name = countryDisplayNames[locale].of(code);
  if (name && name !== code) return name;
  return locale === "en" ? `Country ${code}` : `Страна ${code}`;
}

function stableShortHex(value: string): string {
  let hash = 0x811c9dc5;
  for (const character of value) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function wireguardEgressId(interfaceName: string): string {
  return `wg-${stableShortHex(interfaceName)}`;
}

function regionIdForCountry(code: string): string {
  for (const region of ["europe", "asia", "america", "africa", "oceania"] as const) {
    if (REGION_COUNTRIES[region].has(code)) return region;
  }
  return "other";
}

function selectorLocationName(value: string): string {
  return value
    .normalize("NFC")
    .trim()
    .replace(/\s+/g, " ")
    .replace(/^[^\p{L}\p{N}]+/u, "");
}

function normalizedSelectorLabel(value: string): string {
  return selectorLocationName(value)
    .toLocaleLowerCase("ru");
}

function subscriptionLocationGroups(
  nodes: JsonObject[],
  locale: Locale = "ru",
): SubscriptionCountryGroup[] {
  const countries = new Map<string, Map<string, SubscriptionCityGroup>>();
  for (const node of nodes) {
    const country = /^[A-Za-z]{2}$/.test(asText(node.country, ""))
      ? asText(node.country).toUpperCase()
      : "ZZ";
    const label = asText(node.label, asText(node.id, "Без названия"));
    const city = asText(node.city, label) || label;
    const locationKey = asText(node.location_key, "");
    if (!locationKey) continue;
    if (!countries.has(country)) countries.set(country, new Map());
    const cityKey = `${country}\u0000${normalizedSelectorLabel(city)}`;
    const cityMap = countries.get(country)!;
    const current = cityMap.get(cityKey) ?? {
      key: cityKey,
      name: city,
      locationKeys: [],
      labels: [],
      protocols: [],
      providers: [],
      entries: [],
      nodes: 0,
      inferredFromLabel: asText(node.city_source, "unknown") === "label",
    };
    if (!current.locationKeys.includes(locationKey)) current.locationKeys.push(locationKey);
    if (!current.labels.includes(label)) current.labels.push(label);
    const protocol = protocolLabel(node.protocol);
    if (!current.protocols.includes(protocol)) current.protocols.push(protocol);
    const provider = asText(
      node.subscription_display_name,
      asText(node.subscription_id, "Провайдер не указан"),
    );
    if (!current.providers.includes(provider)) current.providers.push(provider);
    if (!current.entries.some((entry) => entry.key === locationKey)) {
      current.entries.push({ key: locationKey, label: nodeDisplayLabel(label, node, nodes), protocol, provider });
    }
    current.nodes += 1;
    current.inferredFromLabel &&= asText(node.city_source, "unknown") === "label";
    cityMap.set(cityKey, current);
  }
  return [...countries.entries()]
    .map(([code, cityMap]) => {
      const cities = [...cityMap.values()].sort((left, right) =>
        left.name.localeCompare(right.name, locale, { sensitivity: "base" }),
      );
      return {
        code,
        name: countryName(code, locale),
        cities,
        locationKeys: [...new Set(cities.flatMap((city) => city.locationKeys))],
        nodes: cities.reduce((total, city) => total + city.nodes, 0),
      };
    })
    .sort((left, right) => {
      if (left.code === "ZZ") return 1;
      if (right.code === "ZZ") return -1;
      return left.name.localeCompare(right.name, locale, { sensitivity: "base" });
    });
}

function subscriptionRegionGroups(
  nodes: JsonObject[],
  locale: Locale = "ru",
): SubscriptionRegionGroup[] {
  const byRegion = new Map<string, SubscriptionCountryGroup[]>();
  for (const country of subscriptionLocationGroups(nodes, locale)) {
    const id = regionIdForCountry(country.code);
    byRegion.set(id, [...(byRegion.get(id) ?? []), country]);
  }
  return REGION_META.flatMap((region) => {
    const countries = byRegion.get(region.id) ?? [];
    if (!countries.length) return [];
    return [{
      ...region,
      name: localizedText(region.name, locale),
      countries,
      locationKeys: [...new Set(countries.flatMap((country) => country.locationKeys))],
      nodes: countries.reduce((total, country) => total + country.nodes, 0),
    }];
  });
}

type PolicySelectionMode = "best" | "priority";

function normalizePolicySelectionMode(value: unknown): PolicySelectionMode {
  return ["priority", "fallback", "city_priority", "select"].includes(
    asText(value, "best"),
  )
    ? "priority"
    : "best";
}

function citySelectionToken(country: string, city: string): string {
  return `city:${country}:${encodeURIComponent(selectorLocationName(city))}`;
}

function decodeCitySelectionToken(token: string): { country: string; city: string } | null {
  const match = token.match(/^city:([A-Z]{2}|\*):(.+)$/);
  if (!match) return null;
  try {
    return { country: match[1], city: selectorLocationName(decodeURIComponent(match[2])) };
  } catch {
    return null;
  }
}

function initialPolicySelectionOrder(policy: JsonObject): string[] {
  const saved = asStringList(policy.selection_order);
  if (saved.length) return saved;
  return [
    ...asStringList(policy.cities).map((city) => citySelectionToken("*", city)),
    ...asStringList(policy.countries).map((country) => `country:${country.toUpperCase()}`),
    ...asStringList(policy.locations).map((location) => `location:${location}`),
    ...asStringList(policy.outbounds)
      .filter((outbound) => outbound.startsWith("wg-egress-"))
      .map((outbound) => `wireguard:${outbound.slice("wg-egress-".length)}`),
    ...asStringList(policy.outbounds)
      .filter((outbound) => outbound.startsWith("reverse-vless-"))
      .map((outbound) => `reverse:${outbound.slice("reverse-vless-".length)}`),
  ];
}

function policySelectionMirrorsFromOrder(
  order: string[],
  nodes: JsonObject[],
): { countries: string[]; locations: string[] } {
  const regions = subscriptionRegionGroups(nodes);
  const countries = regions.flatMap((region) => region.countries);
  const selectedCountries = new Set<string>();
  const selectedLocations = new Set<string>();

  for (const token of order) {
    if (token.startsWith("region:")) {
      const region = regions.find((item) => item.id === token.slice(7));
      for (const country of region?.countries ?? []) {
        if (country.code === "ZZ") {
          country.locationKeys.forEach((key) => selectedLocations.add(key));
        } else {
          selectedCountries.add(country.code);
        }
      }
      continue;
    }
    if (token.startsWith("country:")) {
      const code = token.slice(8).toUpperCase();
      if (countries.some((country) => country.code === code)) {
        selectedCountries.add(code);
      }
      continue;
    }
    const cityToken = decodeCitySelectionToken(token);
    if (cityToken) {
      const country = countries.find(
        (item) => cityToken.country === "*" || item.code === cityToken.country,
      );
      const city = country?.cities.find(
        (item) =>
          normalizedSelectorLabel(item.name) ===
          normalizedSelectorLabel(cityToken.city),
      );
      city?.locationKeys.forEach((key) => selectedLocations.add(key));
      continue;
    }
    if (token.startsWith("location:")) {
      const key = token.slice(9);
      const migratedKeys = nodes
        .filter(
          (node) =>
            asText(node.location_key, "") === key ||
            asText(node.legacy_location_key, "") === key,
        )
        .map((node) => asText(node.location_key, ""))
        .filter(Boolean);
      migratedKeys.forEach((location) => selectedLocations.add(location));
    }
  }
  return {
    countries: [...selectedCountries],
    locations: [...selectedLocations],
  };
}

function selectorDescription(
  token: string,
  regions: SubscriptionRegionGroup[],
  wireguardExits: JsonObject[] = [],
  reverseVlessExits: JsonObject[] = [],
  locale: Locale = "ru",
): { title: string; detail: string } {
  if (token.startsWith("wireguard:")) {
    const id = token.slice("wireguard:".length);
    const exit = wireguardExits.find((item) => asText(item.id, "") === id);
    return {
      title: exit
        ? `WG · ${asText(exit.interface, id)}`
        : localizedText("Недоступный WireGuard-выход", locale),
      detail: exit
        ? localizedText("WireGuard-интерфейс MikroTik", locale)
        : localizedText("Выход снят в настройках", locale),
    };
  }
  if (token.startsWith("reverse:")) {
    const id = token.slice("reverse:".length);
    const exit = reverseVlessExits.find((item) => asText(item.id, "") === id);
    return {
      title: exit
        ? asText(exit.display_name, id)
        : localizedText("Недоступный обратный VLESS", locale),
      detail: exit
        ? locale === "en"
          ? `Reverse VLESS client · ${asStringList(exit.transport_ids).length || 1} connections`
          : `Reverse VLESS клиент · ${asStringList(exit.transport_ids).length || 1} подключ.`
        : localizedText("Обратный выход удалён или выключен", locale),
    };
  }
  if (token.startsWith("region:")) {
    const id = token.slice("region:".length);
    const region = regions.find((item) => item.id === id);
    const regionName = region?.name ?? REGION_META.find((item) => item.id === id)?.name;
    return {
      title: regionName ?? localizedText("Недоступная группа", locale),
      detail: region
        ? locale === "en"
          ? `${region.nodes} nodes in group`
          : `${region.nodes} узл. в группе`
        : localizedText("Группа исчезла из подписки", locale),
    };
  }
  if (token.startsWith("country:")) {
    const code = token.slice("country:".length).toUpperCase();
    const country = regions.flatMap((region) => region.countries).find((item) => item.code === code);
    return {
      title: country ? `${countryFlag(code)} ${country.name}` : countryName(code, locale),
      detail: country
        ? locale === "en"
          ? `${country.nodes} nodes in country`
          : `${country.nodes} узл. в стране`
        : localizedText("Страна исчезла из подписки", locale),
    };
  }
  const cityToken = decodeCitySelectionToken(token);
  if (cityToken) {
    const country = regions
      .flatMap((region) => region.countries)
      .find((item) => cityToken.country === "*" || item.code === cityToken.country);
    const city = country?.cities.find(
      (item) => normalizedSelectorLabel(item.name) === normalizedSelectorLabel(cityToken.city),
    );
    return {
      title: cityToken.city,
      detail: city
        ? locale === "en"
          ? `${countryFlag(country!.code)} ${country!.name} · ${city.protocols.join(" / ")} · ${city.nodes} nodes`
          : `${countryFlag(country!.code)} ${country!.name} · ${city.protocols.join(" / ")} · ${city.nodes} узл.`
        : localizedText("Город исчез из подписки", locale),
    };
  }
  if (token.startsWith("location:")) {
    const key = token.slice("location:".length);
    for (const region of regions) {
      for (const country of region.countries) {
        const city = country.cities.find((item) => item.locationKeys.includes(key));
        const entry = city?.entries.find((item) => item.key === key);
        if (city && entry) {
          return {
            title: entry.label,
            detail: nodeLocationDetail(
              entry.label,
              `${countryFlag(country.code)} ${country.name}`.trim(),
              city.name,
              entry.provider,
              entry.protocol,
            ),
          };
        }
      }
    }
    return {
      title: localizedText("Недоступное расположение", locale),
      detail: localizedText("Узел исчез из подписки", locale),
    };
  }
  return { title: token, detail: localizedText("Неизвестный тип выбора", locale) };
}

function selectorNodeIds(
  token: string,
  nodes: JsonObject[],
  wireguardExits: JsonObject[],
  reverseVlessExits: JsonObject[],
): string[] {
  if (token.startsWith("wireguard:")) {
    const id = token.slice("wireguard:".length);
    return wireguardExits.some((item) => asText(item.id, "") === id)
      ? [`wireguard:${id}`]
      : [];
  }
  if (token.startsWith("reverse:")) {
    const id = token.slice("reverse:".length);
    return reverseVlessExits.some((item) => asText(item.id, "") === id)
      ? [`reverse:${id}`]
      : [];
  }
  const cityToken = decodeCitySelectionToken(token);
  return nodes.flatMap((node) => {
    const id = asText(node.id, asText(node.location_key, ""));
    if (!id) return [];
    const country = asText(node.country, "ZZ").toUpperCase();
    const city = asText(node.city, asText(node.label, ""));
    const matches = token.startsWith("region:")
      ? regionIdForCountry(country) === token.slice("region:".length)
      : token.startsWith("country:")
        ? country === token.slice("country:".length).toUpperCase()
        : token.startsWith("location:")
          ? asText(node.location_key, "") === token.slice("location:".length)
          : cityToken
            ? (cityToken.country === "*" || cityToken.country === country) &&
              normalizedSelectorLabel(city) === normalizedSelectorLabel(cityToken.city)
            : false;
    return matches ? [id] : [];
  });
}

function orderedCandidateNodeIds(
  order: string[],
  nodes: JsonObject[],
  wireguardExits: JsonObject[],
  reverseVlessExits: JsonObject[],
): string[] {
  const claimed = new Set<string>();
  const result: string[] = [];
  for (const token of order) {
    for (const id of selectorNodeIds(token, nodes, wireguardExits, reverseVlessExits)) {
      if (claimed.has(id)) continue;
      claimed.add(id);
      result.push(id);
    }
  }
  return result;
}

function MixedCheckbox({
  checked,
  mixed = false,
  onChange,
  ariaLabel,
}: {
  checked: boolean;
  mixed?: boolean;
  onChange: () => void;
  ariaLabel: string;
}) {
  const reference = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (reference.current) reference.current.indeterminate = mixed;
  }, [mixed]);
  return (
    <input
      ref={reference}
      type="checkbox"
      checked={checked}
      onChange={onChange}
      aria-label={ariaLabel}
    />
  );
}

function SubscriptionLocationPicker({
  nodes,
  wireguardExits,
  reverseVlessExits,
  mode,
  selectedCountries,
  selectedLocations,
  selectedWireguardExits,
  selectedReverseVlessExits,
  selectionOrder,
  candidateLimit,
  candidateServiceIds,
  candidateServiceAccess,
  customPacks,
  onCountriesChange,
  onLocationsChange,
  onWireguardExitsChange,
  onSelectionOrderChange,
  onCandidateServiceIdsChange,
  onCandidateServiceAccessChange,
  onCustomPackAdded,
}: {
  nodes: JsonObject[];
  wireguardExits: JsonObject[];
  reverseVlessExits: JsonObject[];
  mode: PolicySelectionMode;
  selectedCountries: string[];
  selectedLocations: string[];
  selectedWireguardExits: string[];
  selectedReverseVlessExits: string[];
  selectionOrder: string[];
  candidateLimit: number;
  candidateServiceIds: string[];
  candidateServiceAccess: Record<string, string[]>;
  customPacks: JsonObject[];
  onCountriesChange: (values: string[]) => void;
  onLocationsChange: (values: string[]) => void;
  onWireguardExitsChange: (values: string[]) => void;
  onSelectionOrderChange: (values: string[]) => void;
  onCandidateServiceIdsChange: (values: string[]) => void;
  onCandidateServiceAccessChange: (value: Record<string, string[]>) => void;
  onCustomPackAdded: (pack: JsonObject) => void;
}) {
  const { locale, tr } = useLanguage();
  const regions = subscriptionRegionGroups(nodes, locale);
  const countries = regions.flatMap((region) => region.countries);
  const [expandedRegions, setExpandedRegions] = useState<string[] | null>(null);
  const [expandedCountries, setExpandedCountries] = useState<string[]>([]);
  const [serviceEditorToken, setServiceEditorToken] = useState("");
  const visibleExpandedRegions =
    expandedRegions ?? (regions[0] ? [regions[0].id] : []);

  function tokenSelected(
    token: string,
    nextCountries: string[],
    nextLocations: string[],
  ): boolean {
    if (token.startsWith("wireguard:")) {
      return selectedWireguardExits.includes(token.slice("wireguard:".length));
    }
    if (token.startsWith("reverse:")) {
      return selectedReverseVlessExits.includes(token.slice("reverse:".length));
    }
    if (token.startsWith("region:")) {
      const region = regions.find((item) => item.id === token.slice(7));
      if (!region) return false;
      return region.countries.every((country) =>
        country.code === "ZZ"
          ? country.locationKeys.every((key) => nextLocations.includes(key))
          : nextCountries.includes(country.code),
      );
    }
    if (token.startsWith("country:")) {
      return nextCountries.includes(token.slice(8).toUpperCase());
    }
    const cityToken = decodeCitySelectionToken(token);
    if (cityToken) {
      const country = countries.find(
        (item) => cityToken.country === "*" || item.code === cityToken.country,
      );
      const city = country?.cities.find(
        (item) => normalizedSelectorLabel(item.name) === normalizedSelectorLabel(cityToken.city),
      );
      return Boolean(
        country &&
          city &&
          !nextCountries.includes(country.code) &&
          city.locationKeys.every((key) => nextLocations.includes(key)),
      );
    }
    return token.startsWith("location:") && nextLocations.includes(token.slice(9));
  }

  function selectorCoverage(token: string): { countries: string[]; locations: string[] } {
    if (token.startsWith("region:")) {
      const region = regions.find((item) => item.id === token.slice(7));
      return {
        countries: region?.countries.filter((country) => country.code !== "ZZ").map((country) => country.code) ?? [],
        locations: region?.countries.filter((country) => country.code === "ZZ").flatMap((country) => country.locationKeys) ?? [],
      };
    }
    if (token.startsWith("country:")) {
      return { countries: [token.slice(8).toUpperCase()], locations: [] };
    }
    const cityToken = decodeCitySelectionToken(token);
    if (cityToken) {
      const country = countries.find(
        (item) => cityToken.country === "*" || item.code === cityToken.country,
      );
      const city = country?.cities.find(
        (item) => normalizedSelectorLabel(item.name) === normalizedSelectorLabel(cityToken.city),
      );
      return { countries: [], locations: city?.locationKeys ?? [] };
    }
    return token.startsWith("location:")
      ? { countries: [], locations: [token.slice(9)] }
      : { countries: [], locations: [] };
  }

  function reconciledOrder(
    nextCountries: string[],
    nextLocations: string[],
    preferred: string[] = [],
  ): string[] {
    const ordered: string[] = [];
    const coveredCountries = new Set<string>();
    const coveredLocations = new Set<string>();
    for (const token of [...preferred, ...selectionOrder]) {
      if (ordered.includes(token) || !tokenSelected(token, nextCountries, nextLocations)) {
        continue;
      }
      if (token.startsWith("wireguard:") || token.startsWith("reverse:")) {
        ordered.push(token);
        continue;
      }
      const coverage = selectorCoverage(token);
      const fullyCovered =
        coverage.countries.every((country) => coveredCountries.has(country)) &&
        coverage.locations.every((location) => {
          const parent = countries.find((country) => country.locationKeys.includes(location));
          return coveredLocations.has(location) || Boolean(parent && coveredCountries.has(parent.code));
        });
      if (fullyCovered) continue;
      ordered.push(token);
      coverage.countries.forEach((country) => coveredCountries.add(country));
      coverage.locations.forEach((location) => coveredLocations.add(location));
    }
    for (const country of nextCountries) {
      if (!coveredCountries.has(country)) {
        ordered.push(`country:${country}`);
        coveredCountries.add(country);
      }
    }
    for (const country of countries) {
      if (nextCountries.includes(country.code)) continue;
      for (const city of country.cities) {
        if (
          city.locationKeys.length &&
          city.locationKeys.every(
            (key) => nextLocations.includes(key) && !coveredLocations.has(key),
          )
        ) {
          ordered.push(citySelectionToken(country.code, city.name));
          city.locationKeys.forEach((key) => coveredLocations.add(key));
        }
      }
    }
    for (const location of nextLocations) {
      if (!coveredLocations.has(location)) ordered.push(`location:${location}`);
    }
    for (const exitId of selectedWireguardExits) {
      const token = `wireguard:${exitId}`;
      if (!ordered.includes(token)) ordered.push(token);
    }
    for (const exitId of selectedReverseVlessExits) {
      const token = `reverse:${exitId}`;
      if (!ordered.includes(token)) ordered.push(token);
    }
    return ordered;
  }

  function commitSelection(
    nextCountries: string[],
    nextLocations: string[],
    preferred: string[] = [],
  ) {
    onCountriesChange(nextCountries);
    onLocationsChange(nextLocations);
    commitSelectionOrder(reconciledOrder(nextCountries, nextLocations, preferred));
  }

  function commitSelectionOrder(nextOrder: string[]) {
    const missingTokens = nextOrder.filter((token) =>
      !Object.prototype.hasOwnProperty.call(candidateServiceAccess, token),
    );
    if (missingTokens.length) {
      onCandidateServiceAccessChange({
        ...candidateServiceAccess,
        ...Object.fromEntries(
          missingTokens.map((token) => [token, [...candidateServiceIds]]),
        ),
      });
    }
    onSelectionOrderChange(nextOrder);
  }

  function applyOrder(nextOrder: string[]) {
    const nextCountries: string[] = [];
    const nextLocations: string[] = [];
    for (const token of nextOrder) {
      if (token.startsWith("wireguard:") || token.startsWith("reverse:")) continue;
      const coverage = selectorCoverage(token);
      coverage.countries.forEach((country) => {
        if (!nextCountries.includes(country)) nextCountries.push(country);
      });
      coverage.locations.forEach((location) => {
        if (!nextLocations.includes(location)) nextLocations.push(location);
      });
    }
    onCountriesChange(nextCountries);
    onLocationsChange(nextLocations);
    onWireguardExitsChange(
      nextOrder
        .filter((token) => token.startsWith("wireguard:"))
        .map((token) => token.slice("wireguard:".length)),
    );
    commitSelectionOrder(nextOrder);
  }

  function toggleWireguardExit(exit: JsonObject) {
    const id = asText(exit.id, "");
    if (!id) return;
    const selected = selectedWireguardExits.includes(id);
    const next = selected
      ? selectedWireguardExits.filter((value) => value !== id)
      : [...selectedWireguardExits, id];
    onWireguardExitsChange(next);
    commitSelectionOrder(
      selected
        ? selectionOrder.filter((token) => token !== `wireguard:${id}`)
        : [...selectionOrder, `wireguard:${id}`],
    );
  }

  function toggleReverseVlessExit(exit: JsonObject) {
    const id = asText(exit.id, "");
    if (!id) return;
    const token = `reverse:${id}`;
    commitSelectionOrder(
      selectedReverseVlessExits.includes(id)
        ? selectionOrder.filter((value) => value !== token)
        : [...selectionOrder, token],
    );
  }

  function countryState(country: SubscriptionCountryGroup) {
    const wholeCountry =
      country.code !== "ZZ" && selectedCountries.includes(country.code);
    const selectedLocationCount = country.locationKeys.filter((key) =>
      selectedLocations.includes(key),
    ).length;
    return {
      checked:
        wholeCountry || selectedLocationCount === country.locationKeys.length,
      mixed:
        !wholeCountry &&
        selectedLocationCount > 0 &&
        selectedLocationCount < country.locationKeys.length,
      wholeCountry,
    };
  }

  function toggleCountry(country: SubscriptionCountryGroup) {
    const state = countryState(country);
    const selected = state.checked || state.mixed;
    const nextCountries =
      country.code === "ZZ"
        ? selectedCountries
        : selected
          ? selectedCountries.filter((value) => value !== country.code)
          : [...new Set([...selectedCountries, country.code])];
    const outside = selectedLocations.filter(
      (key) => !country.locationKeys.includes(key),
    );
    const nextLocations =
      country.code === "ZZ" && !selected
        ? [...outside, ...country.locationKeys]
        : outside;
    commitSelection(
      nextCountries,
      nextLocations,
      !selected && country.code !== "ZZ" ? [`country:${country.code}`] : [],
    );
  }

  function toggleCity(
    country: SubscriptionCountryGroup,
    city: SubscriptionCityGroup,
  ) {
    const wholeCountry = selectedCountries.includes(country.code);
    const citySelected = city.locationKeys.every((key) =>
      selectedLocations.includes(key),
    );
    if (wholeCountry) {
      commitSelection(
        selectedCountries.filter((value) => value !== country.code),
        [
          ...new Set([
            ...selectedLocations,
            ...country.locationKeys.filter(
              (key) => !city.locationKeys.includes(key),
            ),
          ]),
        ],
      );
      return;
    }
    const nextLocations = citySelected
      ? selectedLocations.filter((key) => !city.locationKeys.includes(key))
      : [...new Set([...selectedLocations, ...city.locationKeys])];
    commitSelection(
      selectedCountries,
      nextLocations,
      citySelected ? [] : [citySelectionToken(country.code, city.name)],
    );
  }

  function toggleLocation(
    country: SubscriptionCountryGroup,
    locationKey: string,
  ) {
    const wholeCountry = selectedCountries.includes(country.code);
    const locationSelected = selectedLocations.includes(locationKey);
    if (wholeCountry) {
      commitSelection(
        selectedCountries.filter((value) => value !== country.code),
        [
          ...new Set([
            ...selectedLocations,
            ...country.locationKeys.filter((key) => key !== locationKey),
          ]),
        ],
      );
      return;
    }
    const nextLocations = locationSelected
      ? selectedLocations.filter((key) => key !== locationKey)
      : [...new Set([...selectedLocations, locationKey])];
    commitSelection(
      selectedCountries,
      nextLocations,
      locationSelected ? [] : [`location:${locationKey}`],
    );
  }

  function toggleRegion(region: SubscriptionRegionGroup) {
    const countryCodes = region.countries
      .map((country) => country.code)
      .filter((code) => code !== "ZZ");
    const allSelected = region.countries.every(
      (country) => countryState(country).checked,
    );
    const nextCountries = allSelected
      ? selectedCountries.filter((code) => !countryCodes.includes(code))
      : [...new Set([...selectedCountries, ...countryCodes])];
    const outside = selectedLocations.filter(
      (key) => !region.locationKeys.includes(key),
    );
    const unknownKeys = region.countries
      .filter((country) => country.code === "ZZ")
      .flatMap((country) => country.locationKeys);
    const nextLocations = allSelected
      ? outside
      : [...new Set([...outside, ...unknownKeys])];
    commitSelection(
      nextCountries,
      nextLocations,
      allSelected ? [] : [`region:${region.id}`],
    );
  }

  const canonicalOrder = nodes.length
    ? reconciledOrder(selectedCountries, selectedLocations)
    : selectionOrder;
  const canonicalOrderKey = canonicalOrder.join("\n");
  const currentOrderKey = selectionOrder.join("\n");
  useEffect(() => {
    if (canonicalOrderKey !== currentOrderKey) {
      onSelectionOrderChange(canonicalOrder);
    }
  }, [canonicalOrder, canonicalOrderKey, currentOrderKey, onSelectionOrderChange]);

  function selectedCityCount(country: SubscriptionCountryGroup): number {
    if (selectedCountries.includes(country.code)) return country.cities.length;
    return country.cities.filter((city) =>
      city.locationKeys.some((key) => selectedLocations.includes(key)),
    ).length;
  }

  const selectedCitiesTotal = countries.reduce(
    (total, country) => total + selectedCityCount(country),
    0,
  );
  const eligibleNodeCount = orderedCandidateNodeIds(
    canonicalOrder,
    nodes,
    wireguardExits,
    reverseVlessExits,
  ).length;
  const activeNodeCount = mode === "priority" ? eligibleNodeCount : Math.min(candidateLimit, eligibleNodeCount);
  const activePriorityItems = selectionOrder;
  const candidateServiceOptions = [
    ...DIRECT_SERVICE_PACKS.filter((pack) => candidateServiceIds.includes(pack.id)),
    ...customPacks
      .filter((pack) => candidateServiceIds.includes(asText(pack.id, "")))
      .map((pack) => ({
        id: asText(pack.id, ""),
        name: asText(pack.name, asText(pack.id, "")),
        category: tr("Добавленный сервис"),
        description: tr("Домены, API и CDN из доверенного каталога."),
        updateMode: "daily",
        broad: false,
      })),
  ].filter((pack, index, values) =>
    Boolean(pack.id) && values.findIndex((value) => value.id === pack.id) === index,
  );

  function serviceName(serviceId: string): string {
    return candidateServiceOptions.find((pack) => pack.id === serviceId)?.name ?? serviceId;
  }

  function blockedCandidateServices(token: string): string[] {
    const allowed = candidateServiceAccess[token] ?? [];
    return candidateServiceOptions
      .map((pack) => pack.id)
      .filter((serviceId) => !allowed.includes(serviceId));
  }

  function setCandidateServiceBlocked(token: string, serviceId: string, blocked: boolean) {
    const current = candidateServiceAccess[token] ?? [];
    const next = blocked
      ? current.filter((value) => value !== serviceId)
      : [...new Set([...current, serviceId])];
    onCandidateServiceAccessChange({ ...candidateServiceAccess, [token]: next });
  }

  function allowNewCandidateService(serviceId: string) {
    onCandidateServiceAccessChange({
      ...candidateServiceAccess,
      ...Object.fromEntries(
        selectionOrder.map((token) => [
          token,
          [...new Set([...(candidateServiceAccess[token] ?? candidateServiceIds), serviceId])],
        ]),
      ),
    });
  }

  function renderPriorityBuilder() {
    if (mode !== "priority" || !selectionOrder.length) return null;
    return (
      <section className="policy-priority-builder" aria-labelledby="policy-priority-title">
        <div>
          <strong id="policy-priority-title">{tr("Приоритет активных направлений")}</strong>
          <small>{tr("Сверху — основной путь, ниже — резервы. Выбор в строке заменяет узел.")}</small>
        </div>
        <ol>
          {activePriorityItems.map((token, index) => {
            const description = selectorDescription(token, regions, wireguardExits, reverseVlessExits, locale);
            return (
              <li key={token}>
                <button
                  className="policy-priority-position"
                  type="button"
                  aria-expanded={serviceEditorToken === token}
                  aria-label={tr("Блокировка сервисов через {name}", { name: description.title })}
                  title={tr("Настроить блокировку сервисов через этот узел")}
                  onClick={() => setServiceEditorToken((current) => current === token ? "" : token)}
                >
                  {index + 1}
                </button>
                <label className="policy-priority-replace">
                  <span className="policy-priority-order-label">
                    {index === 0 ? tr("Основной") : tr("Резерв {number}", { number: index })}
                  </span>
                  <select
                    aria-label={tr("Заменить {name}", { name: description.title })}
                    value={token}
                    onChange={(event) => {
                      const replacementIndex = selectionOrder.indexOf(event.target.value);
                      if (replacementIndex < 0 || replacementIndex === index) return;
                      const next = [...selectionOrder];
                      [next[index], next[replacementIndex]] = [next[replacementIndex], next[index]];
                      applyOrder(next);
                    }}
                  >
                    {selectionOrder.map((option) => {
                      const optionDescription = selectorDescription(option, regions, wireguardExits, reverseVlessExits, locale);
                      return <option key={option} value={option}>{optionDescription.title}{optionDescription.detail ? ` — ${optionDescription.detail}` : ""}</option>;
                    })}
                  </select>
                  <span className="policy-priority-meta">
                    <small>{description.detail}</small>
                    {blockedCandidateServices(token).length ? (
                      <span
                        className="policy-priority-service-labels"
                        aria-live="polite"
                        aria-label={tr("Заблокированные сервисы: {services}", { services: blockedCandidateServices(token).map(serviceName).join(", ") })}
                        title={tr("Заблокированы через этот узел: {services}", { services: blockedCandidateServices(token).map(serviceName).join(", ") })}
                      >
                        <span>{tr("Блок:")}</span>
                        {blockedCandidateServices(token).map((serviceId) => (
                          <strong key={serviceId}>{serviceName(serviceId)}</strong>
                        ))}
                      </span>
                    ) : null}
                  </span>
                </label>
                <span className="policy-priority-actions">
                  <button
                    type="button"
                    onClick={() => {
                      const next = [...selectionOrder];
                      [next[index - 1], next[index]] = [next[index], next[index - 1]];
                      applyOrder(next);
                    }}
                    disabled={index === 0}
                  >
                     {tr("Выше")} </button>
                  <button
                    type="button"
                    onClick={() => {
                      const next = [...selectionOrder];
                      [next[index], next[index + 1]] = [next[index + 1], next[index]];
                      applyOrder(next);
                    }}
                    disabled={index === activePriorityItems.length - 1}
                  >
                     {tr("Ниже")} </button>
                  <button
                    type="button"
                    onClick={() => applyOrder(selectionOrder.filter((item) => item !== token))}
                  >
                     {tr("Убрать")} </button>
                </span>
                {serviceEditorToken === token ? (
                  <div className="priority-service-menu">
                    <div className="priority-service-menu-heading">
                      <span>
                        <strong>{tr("Блокировка сервисов через этот узел")}</strong>
                        <small>{tr("Установленная галочка блокирует сайт, приложение и API только при работе через этот приоритетный узел. По умолчанию доступ разрешён.")}</small>
                      </span>
                      <button type="button" onClick={() => setServiceEditorToken("")} aria-label={tr("Закрыть выбор сервисов")}>×</button>
                    </div>
                    <div className="priority-service-options">
                      {candidateServiceOptions.map((pack) => (
                        <label key={pack.id}>
                          <input
                            type="checkbox"
                            checked={blockedCandidateServices(token).includes(pack.id)}
                            onChange={(event) => setCandidateServiceBlocked(token, pack.id, event.target.checked)}
                          />
                          <span>
                            <strong>{tr(pack.name)}</strong>
                            <small>{tr(pack.description)}</small>
                          </span>
                        </label>
                      ))}
                    </div>
                    <CatalogServiceAdder
                      knownPacks={customPacks}
                      onResolved={(pack) => {
                        const id = asText(pack.id, "");
                        if (!id) return;
                        onCustomPackAdded(pack);
                        if (!candidateServiceIds.includes(id)) {
                          onCandidateServiceIdsChange([...candidateServiceIds, id]);
                        }
                        allowNewCandidateService(id);
                      }}
                    />
                  </div>
                ) : null}
              </li>
            );
          })}
        </ol>
      </section>
    );
  }

  if (!regions.length && !wireguardExits.length && !reverseVlessExits.length) {
    return (
      <div className="subscription-discovery-empty">
         {tr("В подключённых подписках пока нет загруженных поддерживаемых узлов.")} </div>
    );
  }

  return (
    <div className="subscription-picker-stack">
      <div className="subscription-location-heading">
        <div>
          <strong>{tr("Группы, страны и города подписки")}</strong>
          <small>{tr("Страны показаны полностью и по алфавиту. Названия городов, эмодзи и протоколы сохранены как в подписке.")}</small>
        </div>
      </div>
      <div className="subscription-location-tree">
        {reverseVlessExits.length ? (
          <div className="subscription-region policy-extra-exit-group">
            <div className="subscription-region-row">
              <button
                className="subscription-tree-toggle"
                type="button"
                aria-label={`${visibleExpandedRegions.includes("extra-reverse") ? tr("Свернуть") : tr("Раскрыть")} Reverse VLESS`}
                aria-expanded={visibleExpandedRegions.includes("extra-reverse")}
                onClick={() => setExpandedRegions((current) => {
                  const values = current ?? visibleExpandedRegions;
                  return values.includes("extra-reverse")
                    ? values.filter((value) => value !== "extra-reverse")
                    : [...values, "extra-reverse"];
                })}
              >
                <span aria-hidden="true">›</span>
              </button>
              <div className="policy-extra-exit-heading">
                <strong>Reverse VLESS</strong>
                <small>{selectedReverseVlessExits.length}  {tr("из")} {reverseVlessExits.length}</small>
              </div>
            </div>
            {visibleExpandedRegions.includes("extra-reverse") ? (
              <div className="subscription-region-countries policy-extra-exit-list">
                {reverseVlessExits.map((exit) => {
                  const id = asText(exit.id, "");
                  return (
                    <label className="subscription-city-row" key={id}>
                      <input
                        type="checkbox"
                        checked={selectedReverseVlessExits.includes(id)}
                        onChange={() => toggleReverseVlessExit(exit)}
                      />
                      <span>
                        <strong>{asText(exit.display_name, id)}</strong>
                        <small>{asStringList(exit.transport_ids).length || 1}  {tr("подключ.")}</small>
                      </span>
                    </label>
                  );
                })}
              </div>
            ) : null}
          </div>
        ) : null}
        {wireguardExits.length ? (
          <div className="subscription-region policy-extra-exit-group">
            <div className="subscription-region-row">
              <button
                className="subscription-tree-toggle"
                type="button"
                aria-label={`${visibleExpandedRegions.includes("extra-wireguard") ? tr("Свернуть") : tr("Раскрыть")} WireGuard`}
                aria-expanded={visibleExpandedRegions.includes("extra-wireguard")}
                onClick={() => setExpandedRegions((current) => {
                  const values = current ?? visibleExpandedRegions;
                  return values.includes("extra-wireguard")
                    ? values.filter((value) => value !== "extra-wireguard")
                    : [...values, "extra-wireguard"];
                })}
              >
                <span aria-hidden="true">›</span>
              </button>
              <div className="policy-extra-exit-heading">
                <strong>WireGuard</strong>
                <small>{selectedWireguardExits.length}  {tr("из")} {wireguardExits.length}</small>
              </div>
            </div>
            {visibleExpandedRegions.includes("extra-wireguard") ? (
              <div className="subscription-region-countries policy-extra-exit-list">
                {wireguardExits.map((exit) => {
                  const id = asText(exit.id, "");
                  const interfaceName = asText(exit.interface, id);
                  return (
                    <label className="subscription-city-row" key={id}>
                      <input
                        type="checkbox"
                        checked={selectedWireguardExits.includes(id)}
                        onChange={() => toggleWireguardExit(exit)}
                      />
                      <span>
                        <strong>WG · {interfaceName}</strong>
                        <small>{exit.ready === false ? tr("Недоступен") : tr("Готов")}</small>
                      </span>
                    </label>
                  );
                })}
              </div>
            ) : null}
          </div>
        ) : null}
        {regions.map((region) => {
        const expanded = visibleExpandedRegions.includes(region.id);
        const checked = region.countries.every(
          (country) => countryState(country).checked,
        );
        const mixed =
          !checked &&
          region.countries.some((country) => {
            const state = countryState(country);
            return state.checked || state.mixed;
          });
        const selectedRegionCities = region.countries.reduce(
          (total, country) => total + selectedCityCount(country),
          0,
        );
        return (
          <div className="subscription-region" key={region.id}>
            <div className="subscription-region-row">
              <button
                className="subscription-tree-toggle"
                type="button"
                aria-label={`${expanded ? tr("Свернуть") : tr("Раскрыть")} ${region.name}`}
                aria-expanded={expanded}
                onClick={() =>
                  setExpandedRegions((current) => {
                    const values = current ?? visibleExpandedRegions;
                    return (
                    expanded
                      ? values.filter((value) => value !== region.id)
                      : [...values, region.id]
                    );
                  })
                }
              >
                <span aria-hidden="true">›</span>
              </button>
              <label>
                <MixedCheckbox
                  checked={checked}
                  mixed={mixed}
                  onChange={() => toggleRegion(region)}
                  ariaLabel={tr("Выбрать группу {name} целиком", { name: region.name })}
                />
                <span>
                  <strong>{region.name}</strong>
                  <small>
                    {region.countries.length}  {tr("стран ·")} {region.nodes}  {tr("узл.")} {selectedRegionCities ? tr(" · выбрано городов: {count}", { count: selectedRegionCities }) : ""}
                  </small>
                </span>
              </label>
            </div>
            {expanded ? (
              <div className="subscription-region-countries">
                {region.countries.map((country) => {
                  const countryExpanded = expandedCountries.includes(country.code);
                  const state = countryState(country);
                  return (
                    <div className="subscription-country" key={country.code}>
                      <div className="subscription-country-row">
                        <button
                          className="subscription-tree-toggle"
                          type="button"
                          aria-label={`${countryExpanded ? tr("Свернуть") : tr("Раскрыть")} ${country.name}`}
                          aria-expanded={countryExpanded}
                          onClick={() =>
                            setExpandedCountries((current) =>
                              countryExpanded
                                ? current.filter((value) => value !== country.code)
                                : [...current, country.code],
                            )
                          }
                        >
                          <span aria-hidden="true">›</span>
                        </button>
                        <label>
                          <MixedCheckbox
                            checked={state.checked}
                            mixed={state.mixed}
                            onChange={() => toggleCountry(country)}
                            ariaLabel={tr("Выбрать {name} целиком", { name: country.name })}
                          />
                          <span>
                            <strong>
                              {country.code === "ZZ"
                                ? country.name
                                : `${countryFlag(country.code)} ${country.name}`}
                            </strong>
                            <small>
                              {country.cities.length}  {tr("город. ·")} {country.nodes}  {tr("узл.")} {selectedCityCount(country)
                                ? tr(" · выбрано городов: {count}", { count: selectedCityCount(country) })
                                : ""}
                            </small>
                          </span>
                        </label>
                      </div>
                      {countryExpanded ? (
                        <div className="subscription-city-list">
                          {country.cities.map((city) => {
                            const selectedCount = city.locationKeys.filter((key) =>
                              selectedLocations.includes(key),
                            ).length;
                            const cityChecked =
                              state.wholeCountry ||
                              selectedCount === city.locationKeys.length;
                            return (
                              <div className="subscription-city-group" key={city.key}>
                                <label className="subscription-city-row">
                                  <MixedCheckbox
                                    checked={cityChecked}
                                    mixed={!cityChecked && selectedCount > 0}
                                    onChange={() => toggleCity(country, city)}
                                    ariaLabel={tr("Выбрать {name}", { name: city.name })}
                                  />
                                  <span>
                                    <strong>{city.name}</strong>
                                    <small>
                                      {city.protocols.join(" / ")} · {city.nodes}  {tr("узл. ·")} {city.providers.join(" / ")}
                                    </small>
                                  </span>
                                </label>
                                {city.entries.length > 1 ? (
                                  <details className="subscription-node-details">
                                    <summary>{tr("Выбрать отдельный узел")}</summary>
                                    <div className="subscription-node-list">
                                      {city.entries.map((entry) => (
                                        <label key={entry.key}>
                                          <input
                                            type="checkbox"
                                            checked={
                                              state.wholeCountry ||
                                              selectedLocations.includes(entry.key)
                                            }
                                            onChange={() =>
                                              toggleLocation(country, entry.key)
                                            }
                                          />
                                          <span>
                                            <strong>{entry.label}</strong>
                                            <small>
                                              {entry.provider} · {entry.protocol}
                                            </small>
                                          </span>
                                        </label>
                                      ))}
                                    </div>
                                  </details>
                                ) : null}
                              </div>
                            );
                          })}
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}
          </div>
        );
        })}
      </div>
      <p className="subscription-selection-summary">
         {tr("Доступный набор:")} {eligibleNodeCount}  {tr("узл. ·")} {mode === "priority" ? tr("в очереди: {count}", { count: activeNodeCount }) : tr("мест в рабочем пуле: {count}", { count: activeNodeCount })}  {tr("· выбрано городов:")} {selectedCitiesTotal}  {tr("· стран целиком:")} {selectedCountries.length}
        {selectedWireguardExits.length ? ` · WireGuard: ${selectedWireguardExits.length}` : ""}
        {selectedReverseVlessExits.length ? ` · Reverse VLESS: ${selectedReverseVlessExits.length}` : ""}
      </p>
      {renderPriorityBuilder()}
    </div>
  );
}

function resultRows(value: unknown, locale: Locale = "ru"): Array<[string, string]> {
  if (!value || typeof value !== "object") {
    return [[localizedText("Результат", locale), String(value ?? localizedText("Нет данных", locale))]];
  }
  const object = value as JsonObject;
  const steps = Array.isArray(object.steps)
    ? object.steps
    : Array.isArray(object.path)
      ? object.path
      : null;
  if (steps) {
    return steps.map((step, index) => {
      if (step && typeof step === "object") {
        const row = step as JsonObject;
        const label =
          (typeof row.label === "string" && row.label) ||
          (typeof row.type === "string" && row.type) ||
          locale === "en" ? `Step ${index + 1}` : `Шаг ${index + 1}`;
        const value =
          (typeof row.value === "string" && row.value) ||
          (typeof row.description === "string" && row.description) ||
          (typeof row.route === "string" && row.route) ||
          (typeof row.action === "string" && row.action) ||
          JSON.stringify(row);
        return [label, value];
      }
      return [locale === "en" ? `Step ${index + 1}` : `Шаг ${index + 1}`, String(step)];
    });
  }
  return Object.entries(object)
    .filter(([, item]) => ["string", "number", "boolean"].includes(typeof item))
    .map(([key, item]): [string, string] => [key, String(item)])
    .slice(0, 8);
}

function asObject(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

function asText(value: unknown, fallback = "—"): string {
  return typeof value === "string" || typeof value === "number"
    ? String(value)
    : fallback;
}

function asOptionalPositiveText(value: unknown): string {
  const text = asText(value, "").trim();
  return Number(text) > 0 ? text : "";
}

function asObjectList(value: unknown): JsonObject[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is JsonObject =>
          Boolean(item && typeof item === "object" && !Array.isArray(item)),
      )
    : [];
}

function cdnDeploymentsForTransport(transport: JsonObject): JsonObject[] {
  const configured = asObjectList(transport.cdn_deployments);
  const deployments = configured.length ? configured : [
    {
      id: "primary",
      display_name: "Основной CDN",
      enabled: true,
      cdn_provider: asText(transport.cdn_provider, "cloudflare"),
      hostname: asText(transport.hostname, ""),
      listen_port: Number(transport.listen_port ?? 443),
      tls_server_name: asText(
        transport.tls_server_name,
        asText(transport.hostname, ""),
      ),
      origin_port: Number(
        transport.origin_port ?? transport.listen_port ?? 443,
      ),
      origin_server_name: asText(
        transport.origin_server_name,
        asText(transport.hostname, ""),
      ),
      tls_profile_id: asText(transport.tls_profile_id, ""),
      origin_allowed_cidrs: asStringList(transport.origin_allowed_cidrs),
    },
  ];
  return deployments.map((deployment) => {
    const provider = asText(deployment.cdn_provider, "cloudflare");
    const cidrs = asStringList(deployment.origin_allowed_cidrs);
    return {
      ...deployment,
      origin_protection_mode: asText(
        deployment.origin_protection_mode,
        provider === "cloudflare"
          ? "auto-cidr"
          : cidrs.length
            ? "manual-cidr"
            : "secret-header",
      ),
      origin_header_name: asText(
        deployment.origin_header_name,
        "X-SB-Origin",
      ),
      origin_port: Number(
        deployment.origin_port ?? transport.origin_port ?? transport.listen_port ?? 443,
      ),
      origin_server_name: asText(
        deployment.origin_server_name,
        asText(
          transport.origin_server_name,
          asText(transport.hostname, ""),
        ),
      ),
      tls_profile_id: asText(
        deployment.tls_profile_id,
        asText(transport.tls_profile_id, ""),
      ),
    };
  });
}

function generateOriginHeaderSecret(): string {
  if (typeof globalThis.crypto?.getRandomValues !== "function") return "";
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function asStringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean)
    : [];
}

function clientDnsAddress(config: JsonObject): string {
  const directResolver = asObject(asObject(config.dns).direct_resolver);
  const provider = asText(directResolver.provider, "yandex");
  return (
    {
      yandex: "77.88.8.8",
      cloudflare: "1.1.1.1",
      google: "8.8.8.8",
      quad9: "9.9.9.9",
    }[provider] ?? "из настроек WAN"
  );
}

type RouterSourceKind = "lan" | "wireguard" | "ppp-vpn";

let routerOSDiscoveryCache: JsonObject = {};
let routerOSDiscoveryCachedAt = 0;
let routerOSDiscoveryRequest: Promise<JsonObject> | null = null;

async function loadRouterOSDiscovery(force = false): Promise<JsonObject> {
  if (
    !force &&
    Object.keys(routerOSDiscoveryCache).length > 0 &&
    Date.now() - routerOSDiscoveryCachedAt < 30_000
  ) {
    return routerOSDiscoveryCache;
  }
  if (routerOSDiscoveryRequest) return routerOSDiscoveryRequest;
  routerOSDiscoveryRequest = discoverRouterOs<JsonObject>()
    .then((response) => {
      routerOSDiscoveryCache = asObject(response.routeros);
      routerOSDiscoveryCachedAt = Date.now();
      return routerOSDiscoveryCache;
    })
    .finally(() => {
      routerOSDiscoveryRequest = null;
    });
  return routerOSDiscoveryRequest;
}

function normalizeRouterSourceKind(value: unknown): RouterSourceKind {
  const kind = asText(value, "lan");
  if (kind === "wireguard") return "wireguard";
  if (["ppp-vpn", "openvpn", "other-vpn"].includes(kind)) return "ppp-vpn";
  return "lan";
}

function useRouterClientSources() {
  const [discovery, setDiscovery] = useState<JsonObject>(routerOSDiscoveryCache);
  const [busy, setBusy] = useState(
    Object.keys(routerOSDiscoveryCache).length === 0,
  );
  const [error, setError] = useState("");
  const requestSequence = useRef(0);

  const refresh = useCallback(async (force = true) => {
    const requestId = ++requestSequence.current;
    setBusy(true);
    setError("");
    try {
      const value = await loadRouterOSDiscovery(force);
      if (requestId === requestSequence.current) {
        setDiscovery(value);
      }
    } catch (reason) {
      if (requestId === requestSequence.current) {
        setError(errorMessage(reason));
      }
    } finally {
      if (requestId === requestSequence.current) {
        setBusy(false);
      }
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(false), 0);
    return () => {
      window.clearTimeout(timer);
      requestSequence.current += 1;
    };
  }, [refresh]);
  const forceRefresh = useCallback(() => refresh(true), [refresh]);
  return { discovery, busy, error, refresh: forceRefresh };
}

function sourceCidrsForRow(row: JsonObject): string[] {
  const grouped = asStringList(row.source_cidrs);
  const fallback = asText(row.cidr, "");
  return grouped.length ? grouped : fallback ? [fallback] : [];
}

function normalizedClientIdentity(value: unknown): string {
  return asText(value, "")
    .normalize("NFKD")
    .toLocaleLowerCase("ru")
    .replace(/[^a-z0-9а-яё]+/gi, "");
}

function wireGuardPeerMatchesDevice(peerName: unknown, deviceName: unknown): boolean {
  const peer = normalizedClientIdentity(peerName);
  const device = normalizedClientIdentity(deviceName);
  if (peer.length < 4 || device.length < 4) return false;
  return peer === device || peer.startsWith(device) || device.startsWith(peer);
}

function RouterSourcePicker({
  kind,
  selectedCidrs,
  selectedPeerRefs,
  onChange,
  onPeerRefsChange,
  discovery,
  busy,
  error,
  onRefresh,
}: {
  kind: RouterSourceKind;
  selectedCidrs: string[];
  selectedPeerRefs: string[];
  onChange: (values: string[]) => void;
  onPeerRefsChange: (values: string[]) => void;
  discovery: JsonObject;
  busy: boolean;
  error: string;
  onRefresh: () => Promise<void>;
}) {
  const { tr } = useLanguage();
  const sources = asObject(discovery.client_sources);
  const rows = asObjectList(sources[kind]);
  const completeness = asObject(discovery.client_source_inventory_complete);
  const complete = completeness[kind] === true;
  const knownCidrs = new Set(
    rows.flatMap(sourceCidrsForRow),
  );
  const visibleRows: JsonObject[] = [
    ...rows,
    ...(complete
      ? selectedCidrs
          .filter((cidr) => !knownCidrs.has(cidr))
          .map((cidr) => ({
            id: `missing-${cidr}`,
            cidr,
            valid: false,
            validation_message:
              tr("Этот адрес больше не принадлежит активному клиенту WireGuard. Снимите выбор и выберите актуальный peer."),
          }))
      : []),
  ];
  const titles: Record<RouterSourceKind, string> = {
    lan: tr("Статические клиенты LAN / Wi‑Fi"),
    wireguard: tr("Клиенты WireGuard"),
    "ppp-vpn": tr("PPP / VPN-учётные записи со статическим адресом"),
  };

  function summary(row: JsonObject): { primary: string; secondary: string } {
    const cidr = asText(row.cidr, "");
    if (kind === "lan") {
      const comment = asText(row.comment, "");
      const hostname = asText(row.hostname, "");
      const visibleHostname = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(hostname)
        ? ""
        : hostname;
      return {
        primary: comment || visibleHostname || cidr,
        secondary: [
          comment && visibleHostname && comment !== visibleHostname
            ? visibleHostname
            : "",
          comment || visibleHostname ? cidr : "",
        ]
          .filter(Boolean)
          .join(" · "),
      };
    }
    if (kind === "wireguard") {
      const peerName = asText(row.peer_name, "");
      const interfaceName = asText(row.interface, "");
      return {
        primary: peerName || "WireGuard peer",
        secondary: [
          sourceCidrsForRow(row).join(", "),
          interfaceName ? tr("интерфейс {value1}", { value1: interfaceName }) : "",
        ]
          .filter(Boolean)
          .join(" · "),
      };
    }
    return {
      primary: asText(row.account, "") || cidr,
      secondary: [cidr, asText(row.service, "PPP").toUpperCase(), asText(row.profile, "")]
        .filter(Boolean)
        .join(" · "),
    };
  }

  return (
    <fieldset className="field form-span router-source-picker">
      <legend className="sr-only">{titles[kind]}</legend>
      <div className="router-source-picker-heading">
        <strong>{titles[kind]}</strong>
        <button
          type="button"
          className="text-button"
          disabled={busy}
          onClick={() => void onRefresh()}
        >
          {busy ? tr("Обновляю…") : tr("Обновить список")}
        </button>
      </div>
      {busy ? (
        <div className="subscription-discovery-empty">{tr("Читаю безопасный список с подключённого MikroTik…")}</div>
      ) : error ? (
        <div className="inline-result inline-result-error" role="alert"><span>!</span>{error}</div>
      ) : visibleRows.length ? (
        <div className="router-source-list">
          {visibleRows.map((row) => {
            const rowCidrs = sourceCidrsForRow(row);
            const cidr = rowCidrs[0] ?? asText(row.cidr, "");
            const checked = rowCidrs.some((value) => selectedCidrs.includes(value));
            const invalid = row.valid === false;
            const copy = summary(row);
            const peerRef = asText(row.peer_ref, "");
            return (
              <label
                className={`router-source-option${invalid ? " router-source-option-invalid" : ""}`}
                key={asText(row.id, cidr)}
              >
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={invalid && !checked}
                  onChange={() => {
                    const nextCidrs = checked
                      ? selectedCidrs.filter((value) => !rowCidrs.includes(value))
                      : [...new Set([...selectedCidrs, ...rowCidrs])];
                    onChange(nextCidrs);
                    if (kind === "wireguard" && peerRef) {
                      onPeerRefsChange(
                        checked
                          ? selectedPeerRefs.filter((value) => value !== peerRef)
                          : [...new Set([...selectedPeerRefs, peerRef])],
                      );
                    }
                  }}
                />
                <span className="router-source-copy">
                  <strong>{copy.primary}</strong>
                  {copy.secondary ? <span title={copy.secondary}>{copy.secondary}</span> : null}
                  {invalid ? (
                    <small className="router-source-error" role="alert">{asText(row.validation_message, tr("Адреса WireGuard конфликтуют."))}</small>
                  ) : null}
                </span>
              </label>
            );
          })}
        </div>
      ) : (
        <div className="subscription-discovery-empty">
          {complete
            ? tr("Подходящих статических адресов этого типа на MikroTik нет.")
            : tr("RouterOS не вернул этот инвентарь. Проверьте права REST-пользователя.")}
        </div>
      )}
      <small>
        {kind === "wireguard"
          ? tr("Один peer — один клиент. Политика применяется к его исходным адресам; интерфейс показан только справочно.")
          : tr("Можно выбрать один или несколько адресов. В список не попадают динамические адреса и PPP-пулы.")}
      </small>
    </fieldset>
  );
}

function uniqueListInput(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ];
}

function isRouterOsInterfaceName(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_.:+@ -]{0,62}$/.test(value);
}

function isExplicitRouterHttpsOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    const authority = value.slice(value.indexOf("://") + 3).split(/[/?#]/, 1)[0];
    const portMatch =
      authority.match(/^\[[^\]]+\]:(\d+)$/) ??
      authority.match(/^[^:@]+:(\d+)$/);
    const explicitPort = portMatch ? Number(portMatch[1]) : 0;
    return (
      url.protocol === "https:" &&
      Boolean(url.hostname) &&
      Number.isInteger(explicitPort) &&
      explicitPort >= 1 &&
      explicitPort <= 65535 &&
      url.username === "" &&
      url.password === "" &&
      (url.pathname === "/" || url.pathname === "") &&
      url.search === "" &&
      url.hash === ""
    );
  } catch {
    return false;
  }
}

function isIpv4Cidr(value: string, allowDefault = true): boolean {
  const [address, prefixText, extra] = value.trim().split("/");
  if (extra !== undefined || prefixText === undefined) return false;
  const octets = address.split(".");
  const prefix = Number(prefixText);
  return (
    octets.length === 4 &&
    octets.every(
      (octet) =>
        /^\d{1,3}$/.test(octet) &&
        Number(octet) >= 0 &&
        Number(octet) <= 255,
    ) &&
    Number.isInteger(prefix) &&
    prefix >= (allowDefault ? 0 : 1) &&
    prefix <= 32
  );
}

type NetworkReviewStatus = "pending" | "accepted" | "ignored";

const routerCapabilityLabels: Array<[string, string]> = [
  ["routeros_major_7", "RouterOS major 7"],
  ["arm64", "Архитектура ARM64"],
  ["container_package", "Пакет container"],
  ["container_envs", "Переменные окружения container"],
  ["container_mounts", "Mounts контейнера"],
  ["container_start_on_boot", "Container start-on-boot"],
  ["container_auto_restart", "Container auto-restart"],
  ["policy_routing", "Policy routing"],
  ["firewall_mangle", "Firewall mangle"],
  ["watchdog_scheduler", "Scheduler для watchdog"],
];

const routerImportWarningLabels: Record<string, string> = {
  "Classify every imported RouterOS network before Apply.":
    "Классифицируйте каждую сеть из экспорта до Apply.",
  unresolved_interface_reference:
    "В экспорте есть неразрешённая ссылка RouterOS вида *id; проверьте интерфейсы вручную.",
  wireguard_default_allowed_address:
    "У активного WireGuard peer обнаружен default allowed-address; проверьте назначение маршрута.",
  socks_configured:
    "В RouterOS присутствует SOCKS; убедитесь, что он выключен или строго ограничен.",
  sstp_tcp_443_enabled:
    "В загруженном снимке SSTP использует TCP 443; после переноса загрузите свежий export, чтобы снять предупреждение.",
  disabled_wan_input_drop:
    "Защитное input drop-правило для WAN/non-LAN выключено.",
  disabled_wan_forward_drop:
    "Защитное forward drop-правило для входящего WAN-трафика выключено.",
};

function routerImportWarningText(value: string, locale: Locale = "ru"): string {
  return localizedText(routerImportWarningLabels[value] ?? value, locale);
}

function networkReviewStatus(value: unknown): NetworkReviewStatus {
  return value === "accepted" || value === "ignored" ? value : "pending";
}

function importReviewNetworks(config: JsonObject): JsonObject[] {
  const routeros = asObject(config.routeros);
  return asObjectList(asObject(routeros.import_review).networks);
}

function importReviewCounts(config: JsonObject): {
  accepted: number;
  ignored: number;
  pending: number;
} {
  return importReviewNetworks(config).reduce<{
    accepted: number;
    ignored: number;
    pending: number;
  }>(
    (counts, item) => {
      counts[networkReviewStatus(item.status)] += 1;
      return counts;
    },
    { accepted: 0, ignored: 0, pending: 0 },
  );
}

function importedNetworkKind(cidr: string, managementCidrs: string[]): string {
  if (managementCidrs.includes(cidr)) return "Management LAN";
  if (/\/(32|128)$/.test(cidr)) return "Адрес VPN / PPP";
  return "Маршрутизируемая или подключённая сеть";
}

function itemName(item: JsonObject): string {
  return asText(
    item.display_name ?? item.name ?? item.label ?? item.id,
    "Без названия",
  );
}

function shortRevision(value: unknown): string {
  const revision = asText(value, "");
  return revision ? revision.slice(0, 12) : "";
}

function formatTimestamp(value: unknown, locale: Locale = "ru"): string {
  if (typeof value !== "string" || !value) return localizedText("время не записано", locale);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(locale === "en" ? "en-GB" : "ru-RU", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(parsed);
}

function activityTitle(action: unknown, outcome: unknown, locale: Locale = "ru"): string {
  const actionName = asText(action, "");
  const result = asText(outcome, "");
  if (actionName === "apply") {
    if (result === "unchanged") return localizedText("Проверка завершена без изменений", locale);
    if (result === "rolled_back") return localizedText("Применение отменено откатом", locale);
    if (result === "failed" || result === "candidate_rejected") {
      return localizedText("Применение не выполнено", locale);
    }
    return localizedText("Конфигурация применена", locale);
  }
  if (actionName === "rollback") return localizedText("Выполнен откат конфигурации", locale);
  if (actionName === "draft.reset") return localizedText("Черновик сброшен", locale);
  if (actionName === "draft.save") return localizedText("Черновик сохранён", locale);
  if (actionName === "subscriptions.refresh") return localizedText("Подписки обновлены", locale);
  if (actionName === "routeros.import") return localizedText("Состояние RouterOS импортировано", locale);
  if (actionName === "recovery.mirror_reconciled") {
    return localizedText("Зеркало резервов синхронизировано", locale);
  }
  if (actionName === "recovery.backup_reconciled") {
    return localizedText("Резервная копия синхронизирована", locale);
  }
  if (actionName === "recovery.backup") return localizedText("Создана резервная копия", locale);
  if (actionName === "recovery.backup_scheduled") {
    return localizedText("Запланировано резервное копирование", locale);
  }
  if (actionName === "routeros.credentials.provision") {
    return localizedText("Доступ к RouterOS настроен", locale);
  }
  if (actionName === "remote_users.subscription_link") {
    return localizedText("Открыта ссылка клиентской подписки", locale);
  }
  if (actionName === "remote_users.export") return localizedText("Скачан клиентский профиль", locale);
  if (actionName === "reverse_vless_exits.client_config") {
    return localizedText("Скачана конфигурация Reverse VLESS", locale);
  }
  if (actionName.endsWith(".create")) return localizedText("Добавлен объект конфигурации", locale);
  if (actionName.endsWith(".update")) return localizedText("Настройки объекта изменены", locale);
  if (actionName.endsWith(".delete")) return localizedText("Объект конфигурации удалён", locale);
  return actionName || localizedText("Системное событие", locale);
}

function activityTone(outcome: unknown): "ok" | "info" | "warn" {
  const result = asText(outcome, "");
  if (["failed", "rolled_back", "candidate_rejected"].includes(result)) {
    return "warn";
  }
  if (["ok", "unchanged"].includes(result)) return "ok";
  return "info";
}

function activityMetadata(event: JsonObject, locale: Locale = "ru"): string {
  const details = asObject(event.details);
  const parts: string[] = [];
  const actor = asText(event.actor, "");
  if (actor) parts.push(actor);
  const revision = shortRevision(details.revision ?? details.candidate_revision);
  if (revision) parts.push(locale === "en" ? `revision ${revision}` : `ревизия ${revision}`);
  const entityId = asText(details.id, "");
  if (entityId) parts.push(locale === "en" ? `object: ${entityId}` : `объект: ${entityId}`);
  return parts.join(" · ") || localizedText("Системное событие", locale);
}

function withDeploymentReadiness(
  config: JsonObject,
  deploymentReady: boolean,
): JsonObject {
  const system = asObject(config.system);
  return {
    ...config,
    system: {
      ...system,
      deployment_ready: deploymentReady,
    },
  };
}

function draftValueForComparison(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(draftValueForComparison);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as JsonObject)
        .filter(([key, nested]) => key !== "deployment_ready" && nested !== undefined)
        .sort(([left], [right]) => left.localeCompare(right, "en"))
        .map(([key, nested]) => [key, draftValueForComparison(nested)]),
    );
  }
  return value;
}

function draftConfigsMatchIgnoringReadiness(
  left: JsonObject,
  right: JsonObject,
): boolean {
  return JSON.stringify(draftValueForComparison(left)) ===
    JSON.stringify(draftValueForComparison(right));
}

async function markCurrentDraftUnready(): Promise<void> {
  const draft = await getCurrentDraft<{ config?: JsonObject }>();
  const config = asObject(draft.config);
  const system = asObject(config.system);
  if (system.deployment_ready === false) return;
  await saveCurrentDraft({
    config: withDeploymentReadiness(config, false),
  });
}

function hasPublicTlsPair(config: JsonObject): boolean {
  const profiles = new Map(
    asObjectList(config.tls_profiles).map((profile) => [
      asText(profile.id, ""),
      profile,
    ]),
  );
  const tlsKinds = new Set([
    "ws",
    "grpc",
    "grpc-tls",
    "httpupgrade",
    "xhttp",
    "hysteria2",
  ]);
  const required = asObjectList(config.transports).filter(
    (transport) =>
      transport.enabled !== false && tlsKinds.has(asText(transport.kind, "")),
  );
  return required.every((transport) => {
    const kind = asText(transport.kind, "");
    const profileIds = ["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)
      ? cdnDeploymentsForTransport(transport)
          .filter((deployment) => deployment.enabled !== false)
          .map((deployment) => asText(
            deployment.tls_profile_id,
            asText(transport.tls_profile_id, ""),
          ))
      : [asText(transport.tls_profile_id, "")];
    return profileIds.every((profileId) => {
      const profile = profiles.get(profileId);
      return (
        profile?.enabled !== false &&
        Boolean(asText(profile?.certificate_secret_ref, "")) &&
        Boolean(asText(profile?.private_key_secret_ref, ""))
      );
    });
  });
}

function tlsProfileExpiry(profile: JsonObject, locale: Locale = "ru"): string {
  const metadata = asObject(profile.certificate_metadata);
  return asText(metadata.not_after, "")
    ? formatTimestamp(metadata.not_after, locale)
    : localizedText("срок не определён", locale);
}

interface DraftEnvelope {
  config?: JsonObject;
  revision?: string;
  validation?: JsonObject;
  pending_change_count?: number;
  pending_config_change_count?: number;
  pending_config_path_count?: number;
  pending_config_changes?: JsonObject[];
  runtime_update_required?: boolean;
  runtime_update_only?: boolean;
  has_active_configuration?: boolean;
}

function pendingChangeText(change: JsonObject, locale: Locale = "ru"): string {
  const operation = asText(change.op, "replace");
  const collection = asText(change.collection, "configuration");
  const name = asText(change.display_name, asText(change.entity_id, ""));
  const entities: Record<
    string,
    { noun: string; add: string; remove: string; replace: string }
  > = {
    subscriptions: {
      noun: "подписка",
      add: "Добавлена",
      remove: "Удалена",
      replace: "Изменена",
    },
    subscription_reserves: {
      noun: "резервная подписка",
      add: "Добавлена",
      remove: "Удалена",
      replace: "Изменена",
    },
    tls_profiles: {
      noun: "TLS-профиль",
      add: "Добавлен",
      remove: "Удалён",
      replace: "Изменён",
    },
    transports: {
      noun: "транспорт",
      add: "Добавлен",
      remove: "Удалён",
      replace: "Изменён",
    },
    policies: {
      noun: "маршрут",
      add: "Добавлен",
      remove: "Удалён",
      replace: "Изменён",
    },
    local_users: {
      noun: "локальный клиент",
      add: "Добавлен",
      remove: "Удалён",
      replace: "Изменён",
    },
    remote_users: {
      noun: "удалённый клиент",
      add: "Добавлен",
      remove: "Удалён",
      replace: "Изменён",
    },
    reverse_vless_exits: {
      noun: "Reverse VLESS-клиент",
      add: "Добавлен",
      remove: "Удалён",
      replace: "Изменён",
    },
  };
  const entity = entities[collection];
  if (entity) {
    const verb =
      operation === "add"
        ? entity.add
        : operation === "remove"
          ? entity.remove
          : entity.replace;
    if (locale === "en") {
      const englishEntities: Record<string, { noun: string; add: string; remove: string; replace: string }> = {
        subscriptions: { noun: "subscription", add: "Added", remove: "Removed", replace: "Updated" },
        subscription_reserves: { noun: "backup subscription", add: "Added", remove: "Removed", replace: "Updated" },
        tls_profiles: { noun: "TLS profile", add: "Added", remove: "Removed", replace: "Updated" },
        transports: { noun: "transport", add: "Added", remove: "Removed", replace: "Updated" },
        policies: { noun: "route", add: "Added", remove: "Removed", replace: "Updated" },
        local_users: { noun: "local client", add: "Added", remove: "Removed", replace: "Updated" },
        remote_users: { noun: "remote client", add: "Added", remove: "Removed", replace: "Updated" },
        reverse_vless_exits: { noun: "Reverse VLESS client", add: "Added", remove: "Removed", replace: "Updated" },
      };
      const english = englishEntities[collection];
      const englishVerb = operation === "add" ? english.add : operation === "remove" ? english.remove : english.replace;
      return `${englishVerb} ${english.noun}${name ? ` “${name}”` : ""}`;
    }
    return `${verb} ${entity.noun}${name ? ` «${name}»` : ""}`;
  }
  const sections: Record<string, string> = {
    ingress: "публичные подключения",
    public_exposure: "публичный доступ",
    routeros: "интеграция RouterOS",
    routing: "маршрутизация",
    system: "настройки шлюза",
  };
  if (locale === "en") {
    const englishSections: Record<string, string> = {
      ingress: "public connections",
      public_exposure: "public access",
      routeros: "RouterOS integration",
      routing: "routing",
      system: "gateway settings",
    };
    return `Updated ${englishSections[collection] ?? "configuration settings"}`;
  }
  return `Изменены ${sections[collection] ?? "настройки конфигурации"}`;
}

type RevisionState = "loading" | "applied" | "draft";

function configuredItemStatus(
  enabled: boolean,
  revisionState: RevisionState,
  disabledLabel: string,
  locale: Locale = "ru",
): string {
  if (!enabled) return localizedText(disabledLabel, locale);
  if (revisionState === "applied") return localizedText("Включено", locale);
  if (revisionState === "loading") return localizedText("Проверяется", locale);
  return localizedText("Настроено", locale);
}

function russianCount(
  count: number,
  forms: [string, string, string],
): string {
  const absolute = Math.abs(count) % 100;
  const last = absolute % 10;
  const form = absolute > 10 && absolute < 20
    ? forms[2]
    : last === 1
      ? forms[0]
      : last >= 2 && last <= 4
        ? forms[1]
        : forms[2];
  return `${count} ${form}`;
}

function configuredItemTone(
  enabled: boolean,
  revisionState: RevisionState,
): Tone {
  if (!enabled) return "muted";
  return revisionState === "applied"
    ? "ok"
    : revisionState === "loading"
      ? "muted"
      : "info";
}

const navigation: Array<{
  id: Screen;
  label: MessageKey;
  short: MessageKey;
  description: MessageKey;
}> = [
  {
    id: "overview",
    label: "nav.overview.label",
    short: "nav.overview.short",
    description: "nav.overview.description",
  },
  {
    id: "clients",
    label: "nav.clients.label",
    short: "nav.clients.short",
    description: "nav.clients.description",
  },
  {
    id: "routing",
    label: "nav.routing.label",
    short: "nav.routing.short",
    description: "nav.routing.description",
  },
  {
    id: "connections",
    label: "nav.connections.label",
    short: "nav.connections.short",
    description: "nav.connections.description",
  },
  {
    id: "operations",
    label: "nav.operations.label",
    short: "nav.operations.short",
    description: "nav.operations.description",
  },
  {
    id: "settings",
    label: "nav.settings.label",
    short: "nav.settings.short",
    description: "nav.settings.description",
  },
];

function StatusPill({
  children,
  tone = "muted",
}: {
  children: React.ReactNode;
  tone?: Tone;
}) {
  return <span className={`status-pill status-${tone}`}>{children}</span>;
}

function SectionTitle({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title?: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="section-title">
      <div>
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        {title ? <h2>{title}</h2> : null}
        {description ? <p>{description}</p> : null}
      </div>
      {action ? <div className="section-action">{action}</div> : null}
    </div>
  );
}

function Toggle({
  checked,
  defaultChecked = false,
  onChange,
  label,
  description,
  disabled = false,
  name,
  required = false,
  tone = "plain",
  className = "",
  title,
}: {
  checked?: boolean;
  defaultChecked?: boolean;
  onChange?: (value: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
  name?: string;
  required?: boolean;
  tone?: "plain" | "state" | "warning" | "danger";
  className?: string;
  title?: string;
}) {
  const [uncontrolledChecked, setUncontrolledChecked] = useState(defaultChecked);
  const effectiveChecked = checked ?? uncontrolledChecked;

  return (
    <label
      className={`toggle-row toggle-tone-${tone}${effectiveChecked ? " is-checked" : ""}${className ? ` ${className}` : ""}`}
      title={title}
    >
      <span>
        <strong>{label}</strong>
        {description ? <small>{description}</small> : null}
      </span>
      <input
        name={name}
        type="checkbox"
        checked={effectiveChecked}
        onChange={(event) => {
          if (checked === undefined) setUncontrolledChecked(event.target.checked);
          onChange?.(event.target.checked);
        }}
        disabled={disabled}
        required={required}
      />
      <span className="toggle-control" aria-hidden="true" />
    </label>
  );
}

function DirectServicePackPicker({
  defaultValues = [],
  selectedValues,
  onSelectedValuesChange,
  customPacks = [],
  legend = "Готовые сервисы напрямую через WAN MikroTik",
  description,
  inputName = "direct_services",
  lockedValues = [],
  excludedValues = [],
  hiddenValues = [],
  onRemovePack,
  onRestoreHidden,
}: {
  defaultValues?: string[];
  selectedValues?: string[];
  onSelectedValuesChange?: (values: string[]) => void;
  customPacks?: JsonObject[];
  legend?: string;
  description?: string;
  inputName?: string;
  lockedValues?: string[];
  excludedValues?: string[];
  hiddenValues?: string[];
  onRemovePack?: (packId: string, custom: boolean) => void;
  onRestoreHidden?: () => void;
}) {
  const { tr } = useLanguage();
  const controlled = selectedValues !== undefined;
  const selected = new Set(selectedValues ?? defaultValues);
  const locked = new Set(lockedValues);
  const excluded = new Set(excludedValues);
  const hidden = new Set(hiddenValues);
  const customIds = new Set(
    customPacks.map((pack) => asText(pack.id, "")).filter(Boolean),
  );
  const options = [
    ...DIRECT_SERVICE_PACKS,
    ...customPacks
      .filter((pack) => pack.enabled !== false && typeof pack.id === "string")
      .map((pack) => ({
        id: asText(pack.id, ""),
        name: asText(pack.name, asText(pack.id, "")),
        category: tr("Добавленный сервис"),
        description: tr("Домены, поддомены и CDN из доверенного каталога."),
        updateMode: "daily",
        broad: false,
      })),
  ].filter((pack) => !excluded.has(pack.id) && !hidden.has(pack.id));
  const activeOptionCount = options.filter(
    (pack) => selected.has(pack.id) || locked.has(pack.id),
  ).length;
  return (
    <fieldset className="field form-span service-pack-field">
      <legend className="service-pack-legend">
        <span>{legend}</span>
        <small>{activeOptionCount}  {tr("из")} {options.length}  {tr("активно")}</small>
      </legend>
      <div className="service-pack-grid">
        {options.map((pack) => (
          <div className="service-pack-option-shell" key={`${pack.id}-${locked.has(pack.id) ? "locked" : "editable"}`}>
            <label className="service-pack-option">
              <input
                type="checkbox"
                name={inputName}
                value={pack.id}
                {...(controlled
                  ? { checked: selected.has(pack.id) || locked.has(pack.id) }
                  : { defaultChecked: selected.has(pack.id) || locked.has(pack.id) })}
                onChange={controlled ? (event) => {
                  const next = new Set(selected);
                  if (event.target.checked) next.add(pack.id);
                  else next.delete(pack.id);
                  for (const value of locked) next.add(value);
                  onSelectedValuesChange?.([...next]);
                } : undefined}
                disabled={locked.has(pack.id)}
              />
              {locked.has(pack.id) ? (
                <input type="hidden" name={inputName} value={pack.id} />
              ) : null}
              <span>
                <strong>{tr(pack.name)}</strong>
                <small>
                  {tr(pack.category)}{pack.updateMode === "daily"
                    ? ""
                    : ` · ${pack.updateMode === "composite"
                      ? tr("автообновление доменов + правила звонков")
                      : pack.updateMode === "protocol"
                        ? tr("распознавание протокола")
                        : pack.updateMode === "builtin"
                          ? tr("правила FaceTime в релизе")
                          : tr("официальные endpoints релиза")}`}
                </small>
                <small>{tr(pack.description)}</small>
                {pack.broad ? <small>{tr("Широкое правило — включайте осознанно")}</small> : null}
              </span>
            </label>
            {onRemovePack && !locked.has(pack.id) ? (
              <button
                className="service-pack-remove"
                type="button"
                aria-label={`${tr("Удалить карточку")} ${tr(pack.name)}`}
                title={tr("Удалить карточку")}
                onClick={() => onRemovePack(pack.id, customIds.has(pack.id))}
              >
                ×
              </button>
            ) : null}
          </div>
        ))}
      </div>
      {hiddenValues.length && onRestoreHidden ? (
        <button className="service-pack-restore" type="button" onClick={onRestoreHidden}>
           {tr("Вернуть скрытые карточки")} </button>
      ) : null}
      <small>
        {description ??
          "Можно выбрать сразу несколько категорий. Каталожные пакеты обновляются раз в сутки; при ошибке остаётся последняя рабочая копия."}
      </small>
    </fieldset>
  );
}

function withoutServicePackReferences(
  value: JsonObject,
  removedIds: Set<string>,
): JsonObject {
  if (!removedIds.size) return value;
  const next: JsonObject = { ...value };
  for (const field of ["direct_services", "candidate_service_ids"] as const) {
    if (Array.isArray(next[field])) {
      next[field] = asStringList(next[field]).filter((id) => !removedIds.has(id));
    }
  }
  if (next.service_routes && typeof next.service_routes === "object") {
    next.service_routes = Object.fromEntries(
      Object.entries(asObject(next.service_routes)).filter(([id]) => !removedIds.has(id)),
    );
  }
  if (next.candidate_service_access && typeof next.candidate_service_access === "object") {
    next.candidate_service_access = Object.fromEntries(
      Object.entries(asObject(next.candidate_service_access)).map(([token, ids]) => [
        token,
        asStringList(ids).filter((id) => !removedIds.has(id)),
      ]),
    );
  }
  return next;
}

function CatalogServiceAdder({
  knownPacks,
  onResolved,
  destinationLabel,
}: {
  knownPacks: JsonObject[];
  onResolved: (pack: JsonObject) => void;
  destinationLabel?: string;
}) {
  const { tr } = useLanguage();
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function resolve() {
    const raw = value.trim().toLowerCase();
    if (!raw) return;
    setBusy(true);
    setMessage("");
    try {
      const result = await resolveServicePack<JsonObject>(raw);
      const pack = asObject(result.pack);
      if (!pack.id) throw new Error(tr("Каталог не вернул сервисный пакет."));
      const alreadyConfigured = knownPacks.some(
        (item) => asText(item.id, "") === asText(pack.id, ""),
      );
      onResolved(pack);
      setValue("");
      setMessage(
        tr("{value1} {value2}: правил — {value3}. Домены, поддомены, IP-диапазоны и CDN из пакета будут применены автоматически{value4}.", { value1: asText(pack.name, raw), value2: alreadyConfigured ? tr("уже загружен и выбран") : tr("выбран"), value3: asText(result.rules, tr("готово")), value4: destinationLabel ? ` через ${destinationLabel}` : "" }),
      );
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="field form-span custom-service-pack">
      <span>{tr("Добавить сервис вручную из доверенного каталога")}</span>
      <div className="custom-service-pack-row">
        <input
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={tr("Например: avito или avito.ru")}
          aria-label={tr("Сервис или домен для поиска в доверенном каталоге")}
        />
        <button
          className="button button-secondary"
          type="button"
          onClick={() => void resolve()}
          disabled={busy || !value.trim()}
        >
          {busy ? tr("Проверяю…") : tr("Найти домены и CDN")}
        </button>
      </div>
      <small>
         {tr("Панель принимает имя сервиса, домен или URL, находит соответствующий полный пакет в доверенном каталоге и хранит локальную последнюю рабочую копию.")} </small>
      {message ? <em>{message}</em> : null}
    </div>
  );
}

function Overview({
  onNavigate,
  onOpenSetup,
  onAddClient,
  onEditClient,
  runtime,
  runtimeError,
  overview,
  clientTelemetry,
  config,
}: {
  onNavigate: (screen: Screen) => void;
  onOpenSetup: () => void;
  onAddClient: () => void;
  onEditClient: (kind: "local" | "remote", id: string) => void;
  runtime?: JsonObject;
  runtimeError?: string;
  overview?: JsonObject;
  clientTelemetry?: JsonObject;
  config: JsonObject;
}) {
  const { locale, tr } = useLanguage();
  const runtimeState = asText(runtime?.state, "loading");
  const connectionHostname = useConnectionHostname();
  const watchdogState = asObject(runtime?.watchdog);
  const routerosContainer = asObject(asObject(overview?.routeros).container);
  const routingState = asObject(runtime?.routing);
  const lastApply = asObject(runtime?.last_apply);
  const lastAppliedRevision = asText(lastApply.revision, "");
  const recentEvents = asObjectList(overview?.recent_events);
  const activityEvents = [
    ...(asText(lastApply.committed_at, "")
      ? [
          {
            timestamp: lastApply.committed_at,
            actor: lastApply.actor,
            action: "apply",
            outcome: "ok",
            details: { revision: lastAppliedRevision },
          } satisfies JsonObject,
        ]
      : []),
    ...recentEvents.filter((event) => {
      if (asText(event.action, "") !== "apply") return true;
      const details = asObject(event.details);
      return (
        !lastAppliedRevision ||
        asText(details.revision, "") !== lastAppliedRevision
      );
    }),
  ]
    .sort((left, right) => {
      const leftTime = Date.parse(asText(left.timestamp, "")) || 0;
      const rightTime = Date.parse(asText(right.timestamp, "")) || 0;
      return rightTime - leftTime;
    })
    .slice(0, 5);
  const healthy = runtimeState === "healthy";
  const unconfigured = runtimeState === "unconfigured";
  const stateTitle = runtimeError
    ? tr("Не удалось получить фактическое состояние")
    : healthy
      ? undefined
      : unconfigured
        ? tr("Шлюз ещё не настроен")
        : runtimeState === "loading"
          ? tr("Получаем состояние шлюза")
          : tr("Шлюз требует внимания");
  const stateTone: Tone = healthy
    ? "ok"
    : unconfigured || runtimeState === "loading"
      ? "info"
      : "warn";
  const configuredPolicyById = new Map(
    asObjectList(config.policies).map((policy) => [asText(policy.id, ""), policy]),
  );
  const selectorHealth = asObject(runtime?.selector_health);
  const configuredClientByKey = new Map<string, JsonObject>();
  for (const client of asObjectList(config.local_clients)) {
    configuredClientByKey.set(`local:${asText(client.id, "")}`, client);
  }
  for (const client of asObjectList(config.remote_users)) {
    configuredClientByKey.set(`remote:${asText(client.id, "")}`, client);
  }
  const sampledClients = asObjectList(clientTelemetry?.clients);
  const fallbackClients = [
    ...asObjectList(config.local_clients).map((client): JsonObject => {
      const policy = configuredPolicyById.get(asText(client.policy_id, ""));
      return {
        ...client,
        kind: "local",
        available: false,
        active: false,
        policy_name: policy
          ? itemName(policy)
          : asText(client.policy_id, tr("Маршрут не назначен")),
      };
    }),
    ...asObjectList(config.remote_users).map((client): JsonObject => {
      const policy = configuredPolicyById.get(asText(client.policy_id, ""));
      return {
        ...client,
        kind: "remote",
        available: false,
        active: false,
        policy_name: policy
          ? itemName(policy)
          : asText(client.policy_id, tr("Маршрут не назначен")),
      };
    }),
  ];
  const sampledClientByKey = new Map(
    sampledClients.map((client) => [
      `${asText(client.kind, "local")}:${asText(client.id, "")}`,
      client,
    ]),
  );
  const stableTelemetryClients = [
    ...fallbackClients.map((client) => ({
      ...client,
      ...asObject(
        sampledClientByKey.get(
          `${asText(client.kind, "local")}:${asText(client.id, "")}`,
        ),
      ),
    })),
    ...sampledClients.filter(
      (client) =>
        !configuredClientByKey.has(
          `${asText(client.kind, "local")}:${asText(client.id, "")}`,
        ),
    ),
  ];
  const overviewClients = stableTelemetryClients
    .map((client): JsonObject => {
      const kind = asText(client.kind, "local");
      const id = asText(client.id, "");
      const mergedClient = {
        ...asObject(configuredClientByKey.get(`${kind}:${id}`)),
        ...client,
      };
      const policy = configuredPolicyById.get(asText(mergedClient.policy_id, ""));
      const policyHealth = asObject(selectorHealth[asText(mergedClient.policy_id, "")]);
      const runtimeConfirmed = policyHealth.runtime_confirmed === true;
      const selectedOutbound = runtimeConfirmed
        ? asText(policyHealth.runtime_selected, "")
        : "";
      return {
        ...mergedClient,
        policy_name: policy
          ? itemName(policy)
          : asText(mergedClient.policy_name, asText(mergedClient.policy_id, tr("Маршрут не назначен"))),
        outbound_name: asText(
          asObject(policyHealth.candidate_labels)[selectedOutbound],
          selectedOutbound === "block"
            ? tr("Нет доступного узла")
            : selectedOutbound || (policyHealth.checked_at ? tr("Не подтверждено ядром") : "—"),
        ),
      };
    });
  const overviewTransports = asObjectList(config.transports).map((transport) => {
    const kind = asText(transport.kind, "");
    return {
      id: asText(transport.id, kind || "transport"),
      name: reverseTransportKindLabel(kind),
      hostname: connectionHostname(transport, ""),
      port: asText(transport.listen_port, ""),
      enabled: transport.enabled !== false,
    };
  });
  const enabledTransports = overviewTransports.filter((transport) => transport.enabled);
  const disabledTransportCount = overviewTransports.length - enabledTransports.length;
  const ingressHosts = Array.from(
    new Set(enabledTransports.map((transport) => transport.hostname).filter(Boolean)),
  );
  const ingressHost = ingressHosts.length > 1
    ? `${ingressHosts[0]} +${ingressHosts.length - 1}`
    : ingressHosts[0] || "адрес не задан";
  const telemetryAvailable = overviewClients.some((client) => client.available === true);
  const activeClientCount = overviewClients.filter(
    (client) => client.available === true && client.active === true,
  ).length;
  const monthTrafficBytes = overviewClients.reduce(
    (total, client) => total + (client.available === true
      ? Number(client.month_total_bytes) || 0
      : 0),
    0,
  );
  const monthIncomingBytes = overviewClients.reduce(
    (total, client) => total + (client.available === true
      ? Number(client.month_downlink_bytes) || 0
      : 0),
    0,
  );
  const monthOutgoingBytes = overviewClients.reduce(
    (total, client) => total + (client.available === true
      ? Number(client.month_uplink_bytes) || 0
      : 0),
    0,
  );
  const monthTrafficLabel = telemetryAvailable ? formatBytes(monthTrafficBytes, locale) : "—";
  const [monthTrafficValue, ...monthTrafficUnitParts] = monthTrafficLabel.split(" ");
  const monthTrafficUnit = monthTrafficUnitParts.join(" ");

  return (
    <div className="overview-screen">
      <SectionTitle
        eyebrow={tr("Главная")}
        title={stateTitle}
        description={
          runtimeError ||
          "Состояние поступает из локального control plane. Настройки действуют только после проверки."
        }
        action={unconfigured ? (
          <button className="button button-primary" type="button" onClick={onOpenSetup}>
            {tr("Настроить шлюз")}
          </button>
        ) : undefined}
      />

      <section className="card overview-status-card" aria-label={tr("Общее состояние")}>
        <article className="overview-protection-column">
          <div className="overview-health-line">
            <span className={`overview-health-badge state-${stateTone}`}>
              <span className={healthy ? "pulse-dot" : "status-dot"} />
              {healthy
                ? tr("Система в норме")
                : unconfigured
                  ? tr("Ожидает первичной настройки")
                  : tr("Проверяется")}
            </span>
            <span className={`overview-watchdog-state ${healthy ? "is-healthy" : ""}`}>
              {watchdogState.enabled === true ? "✓ Watchdog healthy" : tr("Watchdog проверяется")}
            </span>
          </div>
          <h3>{tr("Интернет защищён от падения контейнера")}</h3>
          <p>
             {tr("При сбое sb-gateway локальные устройства автоматически перейдут на прямой WAN.")} </p>
          <dl className="overview-resilience-details">
            <div>
              <dt>{tr("Количество перезапусков:")}</dt>
              <dd>{asText(routerosContainer.restart_count, "—")}</dd>
            </div>
            <div>
              <dt>{tr("Возврат VLESS:")}</dt>
              <dd>
                {asText(routingState.remote_on_outage, "drop") === "drop"
                  ? tr("после восстановления")
                  : tr("проверьте политику")}
              </dd>
            </div>
          </dl>
          <button className="text-button overview-column-action" onClick={() => onNavigate("operations")}>
             {tr("Журнал отказоустойчивости →")} </button>
        </article>

        <article className="overview-traffic-column" data-live-telemetry="traffic-summary">
          <h3>{tr("Трафик за месяц")}</h3>
          <div className={`overview-traffic-total ${telemetryAvailable ? "has-data" : "is-empty"}`} data-live-field="month-total">
            <strong>{monthTrafficValue}</strong>
            {monthTrafficUnit ? <span>{monthTrafficUnit}</span> : null}
          </div>
          <dl className="overview-traffic-details">
            <div><dt>{tr("↓ Входящий:")}</dt><dd data-live-field="month-downlink">{telemetryAvailable ? formatBytes(monthIncomingBytes, locale) : "—"}</dd></div>
            <div><dt>{tr("↑ Исходящий:")}</dt><dd data-live-field="month-uplink">{telemetryAvailable ? formatBytes(monthOutgoingBytes, locale) : "—"}</dd></div>
            <div><dt>{tr("Активны сейчас:")}</dt><dd data-live-field="active-clients">{activeClientCount}  {tr("из")} {overviewClients.length}  {tr("устройств")}</dd></div>
          </dl>
          <span className="overview-column-note">{tr("Сброс: 1-го числа")}</span>
        </article>

        <article className="overview-ingress-column">
          <div className="overview-ingress-title">
            <h3>{tr("Входы снаружи")}</h3>
            <strong>{ingressHost}</strong>
            <StatusPill tone={enabledTransports.length ? "ok" : "warn"}>
              {enabledTransports.length}  {tr("активны")} </StatusPill>
          </div>
          <div className="overview-transport-chips">
            {enabledTransports.map((transport) => (
              <span className="overview-transport-chip" key={transport.id}>
                <i aria-hidden="true" />
                <strong>{transport.name.replace(/\s*\+\s*/g, "+")}</strong>
                {transport.port ? <small>:{transport.port}</small> : null}
              </span>
            ))}
            {!enabledTransports.length ? (
              <span className="overview-ingress-empty">{tr("Публичные входы выключены")}</span>
            ) : null}
          </div>
          <div className="overview-ingress-footer">
            <span>{disabledTransportCount ? tr("+ {value1} входа выключено", { value1: disabledTransportCount }) : tr("Все входы активны")}</span>
            <button className="text-button" onClick={() => onNavigate("connections")}>
               {tr("Настроить входы →")} </button>
          </div>
        </article>
      </section>

      <section className="card overview-devices-card" aria-labelledby="overview-devices-title" data-live-telemetry="client-table">
        <div className="overview-card-heading">
          <div>
            <p className="eyebrow">{tr("Мониторинг сети")}</p>
            <h3 id="overview-devices-title">
               {tr("Устройства локальной сети и удалённые клиенты (")}{overviewClients.length})
            </h3>
          </div>
          <button className="button button-primary" onClick={onAddClient}>
             {tr("+ Добавить устройство")} </button>
        </div>

        <div className="overview-device-table-wrap">
          <table className="overview-device-table">
            <thead>
              <tr>
                <th>{tr("Устройство / IP")}</th>
                <th>{tr("Тип клиента")}</th>
                <th>{tr("Маршрутный лист")}</th>
                <th>{tr("Выходной узел")}</th>
                <th>{tr("Текущая скорость")}</th>
                <th>{tr("Трафик (месяц)")}</th>
                <th>{tr("Действия")}</th>
              </tr>
            </thead>
            <tbody>
              {!overviewClients.length ? (
                <tr className="overview-device-empty-row">
                  <td colSpan={7}>{tr("Клиенты пока не настроены.")}</td>
                </tr>
              ) : null}
              {overviewClients.map((client) => {
                const available = client.available === true;
                const active = client.active === true && available;
                const clientId = asText(client.id, "unknown");
                const kind = asText(client.kind, "local") === "remote" ? "remote" : "local";
                const sourceCidrs = asStringList(client.source_cidrs);
                const clientAddress = sourceCidrs.join(", ") ||
                  asText(client.client_tun_address, kind === "remote" ? tr("Удалённый профиль") : tr("Адрес не задан"));
                const policyName = asText(client.policy_name, asText(client.policy_id, tr("Не назначен")));
                const outboundName = asText(client.outbound_name, "—");
                const uplinkRate = formatBitRate(client.uplink_bytes_per_second, locale);
                const downlinkRate = formatBitRate(client.downlink_bytes_per_second, locale);
                const hasSpeedMeasurement = uplinkRate !== "—" && downlinkRate !== "—";
                return (
                  <tr key={`${kind}:${clientId}`} data-client-key={`${kind}:${clientId}`}>
                    <td data-label={tr("Устройство / IP")}>
                      <div className="overview-device-identity">
                        <span
                          className={`overview-device-dot ${active ? "is-active" : available ? "is-idle" : "is-unavailable"}`}
                          aria-hidden="true"
                        />
                        <div>
                          <strong>{itemName(client)}</strong>
                          <small>{clientAddress}</small>
                        </div>
                      </div>
                    </td>
                    <td data-label={tr("Тип клиента")}>
                      <span className={`overview-client-kind kind-${kind}`}>
                        {kind === "remote" ? tr("Удалённый") : tr("Локальный")}
                      </span>
                    </td>
                    <td data-label={tr("Маршрутный лист")}>
                      <span className="overview-policy-chip">
                        <i aria-hidden="true" />
                        {policyName}
                      </span>
                    </td>
                    <td data-label={tr("Выходной узел")}>
                      <span className={`overview-outbound-chip ${active ? "is-active" : ""}`} data-live-field="outbound">
                        {outboundName}
                      </span>
                    </td>
                    <td data-label={tr("Текущая скорость")}>
                      <span className={`overview-rate-pair ${active ? "is-active" : ""} ${hasSpeedMeasurement ? "has-data" : "is-empty"}`} data-live-field="rate">
                        <span aria-label={tr("Исходящая скорость")}><i aria-hidden="true">↑</i>{available && hasSpeedMeasurement ? uplinkRate : tr("— бит/с")}</span>
                        <span aria-label={tr("Входящая скорость")}><i aria-hidden="true">↓</i>{available && hasSpeedMeasurement ? downlinkRate : tr("— бит/с")}</span>
                      </span>
                    </td>
                    <td data-label={tr("Трафик (месяц)")}>
                      <strong className="overview-month-total" data-live-field="month-total">
                        {available ? formatBytes(client.month_total_bytes, locale) : "—"}
                      </strong>
                    </td>
                    <td data-label={tr("Действия")}>
                      <button className="text-button" onClick={() => onEditClient(kind, clientId)}>
                         {tr("Настроить →")} </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="card overview-audit-card" aria-labelledby="overview-audit-title">
        <div className="overview-card-heading">
          <div>
            <p className="eyebrow">{tr("Аудит")}</p>
            <h3 id="overview-audit-title">{tr("Последние события шлюза")}</h3>
          </div>
          <button className="text-button" onClick={() => onNavigate("operations")}>
             {tr("Открыть журнал →")} </button>
        </div>
        <ol className="overview-audit-list">
          {!activityEvents.length ? (
            <li>
              <span className="timeline-info">i</span>
              <div>
                <strong>{tr("Операционных событий пока нет")}</strong>
                <small>{tr("История появится после изменения или применения конфигурации.")}</small>
              </div>
            </li>
          ) : null}
          {activityEvents.slice(0, 3).map((event, index) => {
            const tone = activityTone(event.outcome);
            const timestamp = asText(event.timestamp, "");
            return (
              <li key={`${timestamp || "unknown"}-${asText(event.action, "event")}-${index}`}>
                <span className={`timeline-${tone}`}>
                  {tone === "ok" ? "✓" : tone === "warn" ? "!" : "i"}
                </span>
                <div>
                  <strong>{activityTitle(event.action, event.outcome, locale)}</strong>
                  <small>{activityMetadata(event, locale)}</small>
                </div>
                <time dateTime={timestamp}>{formatTimestamp(timestamp, locale)}</time>
              </li>
            );
          })}
        </ol>
      </section>
    </div>
  );
}

function Clients({
  onAdd,
  onEditLocal,
  onEditRemote,
  config,
  revisionState,
}: {
  onAdd: (kind: "local" | "remote") => void;
  onEditLocal: (id: string) => void;
  onEditRemote: (id: string) => void;
  config: JsonObject;
  revisionState: RevisionState;
}) {
  const { locale, tr } = useLanguage();
  const [tab, setTab] = useState<"local" | "remote">("local");
  const [query, setQuery] = useState("");
  const [exportTarget, setExportTarget] = useState<{
    id: string;
    name: string;
  } | null>(null);

  const configuredPolicies = asObjectList(config.policies);
  const configuredTransports = asObjectList(config.transports);
  const policyById = new Map(
    configuredPolicies.map((policy) => [asText(policy.id, ""), policy]),
  );
  const localCollection = asObjectList(config.local_clients);
  const remoteCollection = asObjectList(config.remote_users);
  const sourceKindLabels: Record<string, string> = {
    lan: "LAN / Wi‑Fi",
    wireguard: "WireGuard",
    "ppp-vpn": tr("PPP / OpenVPN / другой VPN"),
    openvpn: tr("PPP / OpenVPN / другой VPN"),
    "other-vpn": tr("PPP / OpenVPN / другой VPN"),
  };

  const localClientRows = localCollection.map((client) => {
        const policy = policyById.get(asText(client.policy_id, "")) ?? {};
        const enabled = client.enabled !== false;
        const outageMode = asText(
          client.container_outage,
          "direct",
        );
        const outageSummary =
          outageMode === "lan_only"
            ? tr("только LAN + списки маршрутного листа")
            : tr("полный WAN");
        const trafficMode = asText(
          policy.traffic_mode,
          asText(policy.final, "direct") === "direct"
            ? "wan_with_vless_exceptions"
            : "vless_with_wan_exceptions",
        );
        return {
          name: itemName(client),
          id: asText(client.id, "unknown"),
          source: `${sourceKindLabels[asText(client.source_kind, "lan")] ?? "LAN / VPN"} · ${asText(client.source_scope, "") === "lan-all" ? tr("все устройства") : asStringList(client.source_cidrs).join(", ") || "не задан"}`,
          services: policy.id ? itemName(policy) : tr("Не назначен"),
          final: tr("{value1}; при сбое: {value2}", { value1: trafficMode === "wan_with_vless_exceptions" ? tr("WAN + исключения VLESS") : tr("VLESS + исключения WAN"), value2: outageSummary }),
          status: configuredItemStatus(
            enabled,
            revisionState,
            tr("Выключено"),
            locale,
          ),
        };
      });

  const roleLabels: Record<string, string> = {
    "trusted-full": tr("Полный доступ к LAN"),
    "trusted-limited": tr("Ограниченный доступ к LAN"),
    "internet-only": tr("Без доступа к LAN"),
    disabled: tr("Без доступа к LAN"),
  };
  const transportLabels: Record<string, string> = {
    ws: "WS",
    grpc: "gRPC",
    "grpc-tls": "gRPC + TLS Pin",
    httpupgrade: "HTTPUpgrade",
    xhttp: "XHTTP",
    "xhttp-reality": "XHTTP + Reality",
    reality: "REALITY + Vision",
    "reality-grpc": "gRPC + Reality",
    hysteria2: "Hysteria 2",
  };
  const remoteUserRows = remoteCollection.map((user) => {
        const policy = policyById.get(asText(user.policy_id, ""));
        const trafficMode = policy
          ? asText(
              policy.traffic_mode,
              asText(policy.final, "direct") === "direct"
                ? "wan_with_vless_exceptions"
                : "vless_with_wan_exceptions",
            )
          : "";
        const excludedTransports = new Set(
          asStringList(user.excluded_transports),
        );
        const activeTransports = configuredTransports
          .filter(
            (transport) =>
              transport.enabled !== false &&
              !excludedTransports.has(asText(transport.id, "")),
          )
          .map(
            (transport) =>
              transportLabels[asText(transport.kind, "")] ?? itemName(transport),
          );
        return {
          name: itemName(user),
          id: asText(user.id, "unknown"),
          role:
            roleLabels[asText(user.role, "")] ??
            asText(user.role, tr("Роль не задана")),
          policy: policy ? itemName(policy) : asText(user.policy_id, tr("Не задана")),
          execution:
            user.client_individual_routing === true
              ? tr("На устройстве")
              : tr("На шлюзе"),
          failMode:
            trafficMode === "wan_with_vless_exceptions"
              ? tr("Обычный WAN по маршрутному листу")
              : tr("Только WAN-исключения маршрутного листа"),
          clientTun: asText(user.client_tun_address, tr("не задан")),
          transports: activeTransports.length
            ? formatNodeCount(activeTransports.length, locale)
            : tr("Ожидает настройки транспорта"),
          transportDetails: activeTransports.length
            ? tr("Добавляются автоматически: {value1}", { value1: activeTransports.join(" · ") })
            : "",
          status: configuredItemStatus(
            user.enabled !== false,
            revisionState,
            tr("Выключен"),
            locale,
          ),
        };
      });

  const visibleLocalClients = localClientRows.filter((client) =>
    `${client.name} ${client.id} ${client.source}`
      .toLowerCase()
      .includes(query.trim().toLowerCase()),
  );

  return (
    <>
      <SectionTitle
        eyebrow={tr("Устройства")}
        title={tr("Кому и как направлять трафик")}
        description={tr("Локальным устройствам, VPN-клиентам и удалённым пользователям назначаются маршрутные листы.")}
        action={
          <button className="button button-primary" onClick={() => onAdd(tab)}>
            +{" "}
            {tab === "local"
              ? tr("Добавить устройство")
              : tr("Добавить пользователя")}
          </button>
        }
      />

      <div className="tabs" role="tablist" aria-label={tr("Типы устройств")}>
        <button
          role="tab"
          aria-selected={tab === "local"}
          className={tab === "local" ? "active" : ""}
          onClick={() => setTab("local")}
        >
           {tr("Локальные и VPN")} <span>{localCollection.length}</span>
        </button>
        <button
          role="tab"
          aria-selected={tab === "remote"}
          className={tab === "remote" ? "active" : ""}
          onClick={() => setTab("remote")}
        >
           {tr("Удалённые VPN")} <span>{remoteCollection.length}</span>
        </button>
      </div>

      {tab === "local" ? (
        <>
          {!localCollection.length ? (
            <aside className="notice notice-neutral">
              <span className="notice-icon">i</span>
              <div>
                <strong>{tr("Локальных устройств пока нет")}</strong>
                <p>
                   {tr("Добавьте отдельное устройство или назначьте один маршрут всем клиентам LAN / Wi‑Fi.")} </p>
              </div>
            </aside>
          ) : null}
          <div className="card data-card">
            <div className="data-toolbar">
              <label className="search-field">
                <span className="sr-only">{tr("Найти устройство")}</span>
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder={tr("Найти устройство или IP")}
                />
              </label>
              <span className="toolbar-result">
                 {tr("Показано:")} {visibleLocalClients.length}
              </span>
            </div>
            <div className="responsive-table">
              <table>
                <thead>
                  <tr>
                    <th>{tr("Устройство")}</th>
                    <th>{tr("Источник")}</th>
                    <th>{tr("Маршрутный лист")}</th>
                    <th>{tr("Режим и авария")}</th>
                    <th>{tr("Состояние")}</th>
                    <th>
                      <span className="sr-only">{tr("Действия")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {visibleLocalClients.map((client) => (
                    <tr key={client.id}>
                      <td data-label={tr("Устройство")}>
                        <strong>{client.name}</strong>
                        <small>{client.id}</small>
                      </td>
                      <td data-label={tr("Источник")}>
                        <code>{client.source}</code>
                      </td>
                      <td data-label={tr("Сервисы")}>{client.services}</td>
                      <td data-label={tr("Остальное")}>{client.final}</td>
                      <td data-label={tr("Состояние")}>
                        <StatusPill
                          tone={
                            client.status === "Выключено" ? "muted" : "warn"
                          }
                        >
                          {client.status}
                        </StatusPill>
                      </td>
                      <td>
                        <button
                          className="button button-tertiary"
                          onClick={() => onEditLocal(client.id)}
                        >
                           {tr("Настроить")} </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : (
        <>
          {!remoteCollection.length ? (
            <aside className="notice notice-neutral">
              <span className="notice-icon">i</span>
              <div>
                <strong>{tr("Удалённых пользователей пока нет")}</strong>
                <p>
                   {tr("Добавьте пользователя кнопкой выше. UUID и протокольные секреты для всех включённых транспортов будут созданы автоматически.")} </p>
              </div>
            </aside>
          ) : null}
          <div className="user-grid">
            {remoteUserRows.map((user) => (
              <article className="card user-card" key={user.id}>
                <div className="user-card-main">
                  <div className="user-card-head">
                    <div className="avatar">{user.name.slice(0, 1)}</div>
                    <div className="user-card-identity">
                      <div className="user-card-title">
                        <h3>{user.name}</h3>
                        <StatusPill tone={user.status === "Выключен" ? "muted" : "warn"}>
                          {user.status}
                        </StatusPill>
                      </div>
                      <small>{tr("VLESS-клиент")}</small>
                    </div>
                  </div>
                  <dl>
                    <div>
                      <dt>{tr("Доступ")}</dt>
                      <dd>{user.role}</dd>
                    </div>
                    <div>
                      <dt>{tr("Маршрутный лист")}</dt>
                      <dd className="user-card-policy">
                        <span>{user.policy}</span>
                        <small>{user.execution}</small>
                      </dd>
                    </div>
                    <div>
                      <dt>Client TUN</dt>
                      <dd><code>{user.clientTun}</code></dd>
                    </div>
                    <div>
                      <dt>{tr("Подписка")}</dt>
                      <dd className="user-card-subscription" title={user.transportDetails || undefined}>
                        {user.transports}
                      </dd>
                    </div>
                  </dl>
                </div>
                <div className="card-actions user-card-actions">
                  <button
                    className="button button-secondary"
                    onClick={() => {
                      setExportTarget({ id: user.id, name: user.name });
                    }}
                  >
                     {tr("Ссылка подписки")} </button>
                  <button
                    className="button button-tertiary"
                    onClick={() => onEditRemote(user.id)}
                  >
                     {tr("Настроить")} </button>
                </div>
              </article>
            ))}
            {!remoteUserRows.length ? (
              <div className="empty-result">{tr("Фактических удалённых пользователей пока нет.")}</div>
            ) : null}
          </div>
          {exportTarget ? (
            <SubscriptionDialog
              user={exportTarget}
              onClose={() => setExportTarget(null)}
            />
          ) : null}
        </>
      )}
    </>
  );
}

function SubscriptionDialog({
  user,
  onClose,
}: {
  user: { id: string; name: string };
  onClose: () => void;
}) {
  const { tr } = useLanguage();
  const [subscription, setSubscription] =
    useState<RemoteUserSubscriptionLink | null>(null);
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState("");
  const [copiedEndpointId, setCopiedEndpointId] = useState("");
  const [rotateArmed, setRotateArmed] = useState(false);

  useEffect(() => {
    let current = true;
    getRemoteUserSubscriptionLink(user.id)
      .then((value) => {
        if (current) setSubscription(value);
      })
      .catch((error) => {
        if (current) setMessage(prefixedErrorMessage(error));
      })
      .finally(() => {
        if (current) setBusy(false);
      });
    return () => {
      current = false;
    };
  }, [user.id]);

  async function copySubscription(url: string, endpointId: string) {
    setMessage("");
    try {
      await copyText(url);
      setCopiedEndpointId(endpointId);
    } catch (error) {
      setMessage(prefixedErrorMessage(error));
    }
  }

  async function rotateSubscription() {
    if (!rotateArmed) {
      setRotateArmed(true);
      setMessage(
        tr("Нажмите «Сменить адрес» ещё раз. Текущая ссылка сразу перестанет работать."),
      );
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      const next = await rotateRemoteUserSubscriptionLink(user.id);
      setSubscription(next);
      setCopiedEndpointId("");
      setRotateArmed(false);
      setMessage(tr("Адрес заменён. Предыдущая ссылка больше не действует."));
    } catch (error) {
      setMessage(prefixedErrorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="export-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        <div>
          <h2 id="export-title">{tr("Ссылки для")} {user.name}</h2>
          {busy ? (
            <div className="subscription-link-loading" role="status">
               {tr("Получаю постоянную ссылку…")} </div>
          ) : subscription ? (
            <>
              <div className="subscription-public-urls">
                {(subscription.urls?.length
                  ? subscription.urls
                  : [{ id: "primary", kind: "primary", url: subscription.url, primary: true }]
                ).map((endpoint, index) => (
                  <label className="field" key={`${endpoint.id}-${endpoint.url}`}>
                    {endpoint.kind === "direct"
                      ? tr("Прямая ссылка{value1}", { value1: endpoint.primary ? tr(" · основная") : "" })
                      : endpoint.kind === "cdn"
                        ? tr("CDN-ссылка{value1}", { value1: endpoint.primary ? tr(" · основная") : "" })
                        : tr("Ссылка подписки{value1}", { value1: endpoint.primary ? tr(" · основная") : "" })}
                    <span className="inline-field-actions">
                      <input
                        type="text"
                        value={endpoint.url}
                        readOnly
                        autoFocus={index === 0}
                        onFocus={(event) => event.currentTarget.select()}
                      />
                      <button
                        className="button button-secondary"
                        type="button"
                        onClick={() => void copySubscription(endpoint.url, endpoint.id)}
                      >
                        {copiedEndpointId === endpoint.id ? tr("Скопировано") : tr("Копировать")}
                      </button>
                    </span>
                  </label>
                ))}
              </div>
              <aside className={`notice ${subscription.active ? "notice-safe" : "notice-neutral"}`}>
                <span className="notice-icon">{subscription.active ? "✓" : "i"}</span>
                <div>
                  <strong>
                    {subscription.active
                      ? tr("Активно транспортов: {value1}", { value1: subscription.transport_count })
                      : tr("Ссылка создана и ожидает Apply")}
                  </strong>
                  <p>
                    {subscription.active
                      ? tr("Состав подписки берётся только из активной конфигурации. Сохранённые изменения появятся здесь после успешного применения.")
                      : tr("До первого успешного применения URL не отдаёт профиль. После Apply ссылка останется той же.")}
                  </p>
                </div>
              </aside>
            </>
          ) : null}
          {message ? (
            <div
              className={`inline-result ${isErrorMessage(message) ? "inline-result-error" : ""}`}
              role={isErrorMessage(message) ? "alert" : "status"}
            >
              <span>{isErrorMessage(message) ? "!" : "i"}</span>
              {message}
            </div>
          ) : null}
          <div className="modal-actions">
            <button
              className={rotateArmed ? "button button-danger" : "button button-secondary"}
              type="button"
              onClick={rotateSubscription}
              disabled={busy || !subscription}
            >
              {rotateArmed ? tr("Подтвердить смену") : tr("Сменить адрес")}
            </button>
            <button
              className="button button-tertiary"
              type="button"
              onClick={onClose}
            >
               {tr("Закрыть")} </button>
          </div>
        </div>
      </section>
    </div>
  );
}

function Routing({
  onAddPolicy,
  onEditPolicy,
  config,
  runtime,
  runtimeDetailsReady,
  revisionState,
  routeros,
  onDraftChanged,
}: {
  onAddPolicy: () => void;
  onEditPolicy: (id: string) => void;
  config: JsonObject;
  runtime?: JsonObject;
  runtimeDetailsReady: boolean;
  revisionState: RevisionState;
  routeros: JsonObject;
  onDraftChanged: () => Promise<void>;
}) {
  const { locale, tr } = useLanguage();
  const [historyPeriod, setHistoryPeriod] = useState<"24h" | "7d" | "30d">("7d");
  const [qualityPolicyId, setQualityPolicyId] = useState("");
  const [quality24hBaselines, setQuality24hBaselines] = useState<Record<string, number>>(() => {
    if (typeof window === "undefined") return {};
    try {
      const parsed = JSON.parse(
        window.localStorage.getItem(QUALITY_24H_BASELINE_STORAGE_KEY) ?? "{}",
      ) as Record<string, unknown>;
      const oldest = Date.now() / 1000 - 24 * 60 * 60;
      return Object.fromEntries(
        Object.entries(parsed).filter(([, value]) => {
          const baseline = Number(value);
          return Number.isFinite(baseline) && baseline >= oldest;
        }).map(([key, value]) => [key, Number(value)]),
      );
    } catch {
      return {};
    }
  });
  const [expandedPolicyId, setExpandedPolicyId] = useState(() => {
    if (typeof window === "undefined") return "";
    return (
      window.sessionStorage.getItem(ROUTING_EXPANDED_POLICY_STORAGE_KEY) ?? ""
    );
  });
  const updateExpandedPolicy = (policyId: string) => {
    setExpandedPolicyId(policyId);
    if (policyId) {
      window.sessionStorage.setItem(
        ROUTING_EXPANDED_POLICY_STORAGE_KEY,
        policyId,
      );
    } else {
      window.sessionStorage.removeItem(ROUTING_EXPANDED_POLICY_STORAGE_KEY);
    }
  };
  const configuredPolicies = asObjectList(config.policies);
  const subscriptionIds = asObjectList(config.subscriptions)
    .filter((subscription) => subscription.enabled !== false)
    .map((subscription) => asText(subscription.id, ""))
    .filter(Boolean);
  const providerNames = new Map(asObjectList(config.subscriptions).map(subscription => [asText(subscription.id, ""), itemName(subscription)]));
  const subscriptionIdsKey = subscriptionIds.join("\u0000") + "\u0000" + asText(runtime?.active_revision, "") + "\u0000" + asText(runtime?.runtime_revision, "");
  const [routingInventory, setRoutingInventory] = useState<{
    key: string;
    nodes: JsonObject[];
    error: string;
  }>({ key: "", nodes: [], error: "" });
  useEffect(() => {
    let current = true;
    let retryTimer: number | undefined;
    const loadRoutingInventory = (): void => {
      void Promise.all(
        subscriptionIds.map((id) => getSubscriptionNodes<JsonObject>(id)),
      ).then((results) => {
        if (!current) return;
        setRoutingInventory({
          key: subscriptionIdsKey,
          nodes: results.flatMap((result) => asObjectList(result.nodes)),
          error: "",
        });
      })
      .catch((error) => {
        if (!current) return;
        setRoutingInventory({
          key: subscriptionIdsKey,
          nodes: [],
          error: errorMessage(error),
        });
        if (isUncertainOperationError(error)) {
          retryTimer = window.setTimeout(loadRoutingInventory, 5_000);
        }
      });
    };
    loadRoutingInventory();
    return () => {
      current = false;
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
    };
    // Subscription IDs and applied revision refresh inventory after Apply,
    // without refetching on unrelated draft edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subscriptionIdsKey]);
  const routingNodesLoaded = routingInventory.key === subscriptionIdsKey;
  const routingNodes = routingNodesLoaded ? routingInventory.nodes : [];
  const routingNodesById = new Map(routingNodes.map((node) => [asText(node.id, ""), node]));
  const routingNodesError = routingNodesLoaded ? routingInventory.error : "";
  const routingRegions = subscriptionRegionGroups(routingNodes, locale);
  const configuredWireguardExits = asObjectList(
    asObject(asObject(config.system).networking).wireguard_egress_exits,
  );
  const configuredReverseVlessExits = asObjectList(
    config.reverse_vless_exits,
  ).filter((item) => item.enabled !== false);
  const selectorHealth = asObject(runtime?.selector_health);
  const configuredLocalClients = asObjectList(config.local_clients);
  const configuredRemoteUsers = asObjectList(config.remote_users);
  const policyRows = configuredPolicies.map((policy) => {
        const id = asText(policy.id, "unknown");
        const health = asObject(selectorHealth[id]);
        const countries = asStringList(policy.countries);
        const locations = asStringList(policy.locations);
        const cities = asStringList(policy.cities);
        const outbounds = asStringList(policy.outbounds);
        const selectionOrder = asStringList(policy.selection_order);
        const runtimeConfirmed = health.runtime_confirmed === true;
        const runtimeIssue = asText(health.runtime_error, "");
        const selected = runtimeConfirmed ? asText(health.runtime_selected, "") : "";
        const candidateMetadata = (candidate: string): JsonObject | undefined => {
          const applied = asObject(asObject(health.candidate_nodes)[candidate]);
          const inventory = routingNodesById.get(candidate);
          if (!Object.keys(applied).length) return inventory ? {...inventory, id: candidate} : undefined;
          // Older health contracts lack source presentation. Only an exact ID
          // match may enrich it; never infer a provider from a city or label.
          return {
            ...inventory,
            ...applied,
            id: candidate,
            subscription_id: asText(applied.subscription_id, asText(inventory?.subscription_id, "")),
          };
        };
        const labelPeers = selectorCandidateIds(health, {}).map(candidate => candidateMetadata(candidate)).filter((node): node is JsonObject => Boolean(node));
        const candidateProvider = (candidate: string) => providerNames.get(asText(candidateMetadata(candidate)?.subscription_id, ""));
        const selectedLabel = nodeDisplayLabel(asText(
          asObject(health.candidate_labels)[selected],
          selected === "block" ? tr("Нет доступного узла") : selected,
        ), candidateMetadata(selected), labelPeers);
        const periodStats = asObject(health.period_stats);
        const selectedPeriodStats = asObject(periodStats[historyPeriod]);
        const retainedStats = Object.keys(selectedPeriodStats).length
          ? selectedPeriodStats
          : asObject(health.daily_stats);
        const visibleBaseline = historyPeriod === "24h"
          ? quality24hBaselines[id]
          : undefined;
        const candidateIds = selectorCandidateIds(health, retainedStats);
        const dailyStats = visibleBaseline
          ? qualityStatsSince(health.daily_samples, candidateIds, visibleBaseline)
          : retainedStats;
        const currentDailyStats = asObject(dailyStats[selected]);
        const currentLoss = currentDailyStats.loss_percent;
        const currentP95 = currentDailyStats.p95_ms;
        const currentMedian =
          typeof currentDailyStats.median_ms === "number"
            ? currentDailyStats.median_ms
            : null;
        const nodeStats = candidateIds
          .map((candidate) => {
            const stats = asObject(dailyStats[candidate]);
            return {
              id: candidate,
              provider: candidateProvider(candidate),
              country: asText(candidateMetadata(candidate)?.country, ""),
              label: nodeDisplayLabel(asText(
                asObject(health.candidate_labels)[candidate],
                candidate,
              ), candidateMetadata(candidate), labelPeers),
              selected: candidate === selected,
              inRuntimePool: asStringList(health.shortlist).includes(candidate),
              available: asObject(health.availability_ok)[candidate] === true,
              quality: asObject(health.quality_ok)[candidate] === true,
              availabilityKnown: typeof asObject(health.availability_ok)[candidate] === "boolean",
              samples: Number(stats.samples ?? 0),
              loss: typeof stats.loss_percent === "number" ? stats.loss_percent : null,
              availability:
                typeof stats.availability_percent === "number"
                  ? stats.availability_percent
                  : null,
              median: typeof stats.median_ms === "number" ? stats.median_ms : null,
              decisionMedian: typeof asObject(health.median_delay_ms)[candidate] === "number"
                ? Number(asObject(health.median_delay_ms)[candidate])
                : null,
              p95: typeof stats.p95_ms === "number" ? stats.p95_ms : null,
              speedBps: visibleBaseline
                ? latestSpeedSince(
                    health.speed_samples_bps,
                    health.last_speed_probe_at,
                    candidate,
                    visibleBaseline,
                  )
                : typeof asObject(health.speed_median_bps)[candidate] === "number"
                    ? Number(asObject(health.speed_median_bps)[candidate])
                    : null,
              deltaMs:
                currentMedian != null && typeof stats.median_ms === "number"
                  ? stats.median_ms - currentMedian
                  : null,
              deltaPercent:
                currentMedian != null &&
                currentMedian > 0 &&
                typeof stats.median_ms === "number"
                  ? ((currentMedian - stats.median_ms) * 100) / currentMedian
                  : null,
            };
          })
          .sort((left, right) => {
            if (left.selected !== right.selected) return left.selected ? -1 : 1;
            if (left.available !== right.available) return left.available ? -1 : 1;
            const availability = (right.availability ?? -1) - (left.availability ?? -1);
            if (availability) return availability;
            const loss = (left.loss ?? 101) - (right.loss ?? 101);
            if (loss) return loss;
            const speed = (right.speedBps ?? -1) - (left.speedBps ?? -1);
            if (speed) return speed;
            const p95 = (left.p95 ?? Number.MAX_SAFE_INTEGER) - (right.p95 ?? Number.MAX_SAFE_INTEGER);
            if (p95) return p95;
            const latency = (left.median ?? Number.MAX_SAFE_INTEGER) - (right.median ?? Number.MAX_SAFE_INTEGER);
            if (latency) return latency;
            return left.label.localeCompare(right.label, "ru");
          });
        const displayOrder = selectionOrder.length ? selectionOrder : [
          ...countries.map((country) => `country:${country}`),
          ...locations.map((location) => `location:${location}`),
          ...outbounds.map((outbound) => outbound.startsWith("reverse-vless-")
            ? `reverse:${outbound.slice("reverse-vless-".length)}`
            : outbound.startsWith("wg-egress-") ? `wireguard:${outbound.slice("wg-egress-".length)}` : outbound),
        ];
        const chosenIds = orderedCandidateNodeIds(displayOrder, routingNodes, configuredWireguardExits, configuredReverseVlessExits);
        const chosenCandidateIds = chosenIds.map((nodeId) => nodeId
          .replace(/^reverse:/, "reverse-vless-")
          .replace(/^wireguard:/, "wg-egress-"));
        const runtimeStats = new Map(nodeStats.map((node) => [node.id, node]));
        const queueNodes = routeCandidateIds(health, dailyStats,
          chosenCandidateIds,
        ).map((nodeId) => {
          const live = runtimeStats.get(nodeId);
          const metadata = routingNodesById.get(nodeId);
          const token = nodeId.startsWith("reverse-vless-") ? `reverse:${nodeId.slice("reverse-vless-".length)}`
            : nodeId.startsWith("wg-egress-") ? `wireguard:${nodeId.slice("wg-egress-".length)}` : "";
          return {
            id: nodeId,
            provider: candidateProvider(nodeId),
            label: live?.label ?? nodeDisplayLabel(asText(metadata?.label, token ? selectorDescription(token, routingRegions, configuredWireguardExits, configuredReverseVlessExits, locale).title : nodeId), metadata, routingNodes),
            country: live?.country ?? asText(metadata?.country, ""),
            selected: live?.selected ?? false,
            available: live?.available ?? false,
            availabilityKnown: live?.availabilityKnown ?? false,
            inRuntimePool: asStringList(health.shortlist).includes(nodeId),
          };
        }).sort((left, right) => compareRouteCandidates(left, right)
          || (left.inRuntimePool && right.inRuntimePool ? asStringList(health.shortlist).indexOf(left.id) - asStringList(health.shortlist).indexOf(right.id) : 0));
        return {
          name: itemName(policy),
          key: id,
          mode: normalizePolicySelectionMode(policy.mode),
          priorityOrder: chosenCandidateIds,
          route: selectionOrder.length
            ? !routingNodesLoaded
              ? [tr("Проверяю выбранные узлы…")]
              : selectionOrder.map(
                  (token) => selectorDescription(token, routingRegions, configuredWireguardExits, configuredReverseVlessExits, locale).title,
                )
            : cities.length
            ? cities
            : countries.length
              ? [
                  ...countries.map((country) => countryName(country, locale)),
                  ...(locations.length ? [tr("{value1} отдельных расположений", { value1: locations.length })] : []),
                ]
              : locations.length
                ? [tr("{value1} отдельных расположений", { value1: locations.length })]
              : outbounds.length
                ? outbounds
                : ["—"],
          active: !runtimeDetailsReady
            ? tr("Сверяю с ядром…")
            : runtimeConfirmed
              ? selectedLabel || "Нет доступного узла"
              : health.checked_at
                ? tr("Не подтверждено ядром")
                : tr("После применения"),
          activeCountry: asText(candidateMetadata(selected)?.country, ""),
          activeProvider: candidateProvider(selected),
          strategy:
            normalizePolicySelectionMode(policy.mode) === "priority"
              ? tr("Приоритет + резерв")
              : tr("Лучший + резерв"),
          runtimeConfirmed,
          reserves: health.checked_at ? asText(health.healthy_reserves, "0") : "—",
          p95: typeof currentP95 === "number" ? tr("{value1} мс", { value1: currentP95 }) : "—",
          loss: typeof currentLoss === "number" ? `${currentLoss.toFixed(1)}%` : "—",
          nodeStats,
          queueNodes,
          readyReserves: queueNodes.filter((node) => !node.selected && node.available && node.inRuntimePool).length,
          thresholds: asObject(health.quality_thresholds),
          path:
            asText(policy.traffic_mode, asText(policy.final, "direct") === "direct" ? "wan_with_vless_exceptions" : "vless_with_wan_exceptions") === "wan_with_vless_exceptions"
              ? tr("WAN + исключения VLESS")
              : tr("VLESS + исключения WAN"),
          gatewayClients:
            configuredLocalClients.filter(
              (client) =>
                client.enabled !== false && client.policy_id === policy.id,
            ).length +
            configuredRemoteUsers.filter(
              (client) =>
                client.enabled !== false &&
                client.policy_id === policy.id &&
                client.client_individual_routing !== true,
            ).length,
          deviceClients: configuredRemoteUsers.filter(
            (client) =>
              client.enabled !== false &&
              client.policy_id === policy.id &&
              client.client_individual_routing === true,
          ).length,
          tone:
            policy.enabled === false
              ? ("muted" as Tone)
              : revisionState === "applied" && health.checked_at
                ? runtimeConfirmed && !runtimeIssue ? ("ok" as Tone) : ("warn" as Tone)
                : configuredItemTone(true, revisionState),
          status:
            policy.enabled === false
              ? tr("Выключена")
              : revisionState === "applied" && health.checked_at
                ? runtimeIssue
                  ? tr("Переключение не применено")
                  : runtimeConfirmed ? tr("Работает") : tr("Нужна сверка с ядром")
                : configuredItemStatus(true, revisionState, tr("Выключена"), locale),
        };
      });
  const quality = qualitySheet(policyRows, qualityPolicyId);
  const selectedQualityKey = quality.policy?.key ?? "";
  const selectedQualityBaseline = quality24hBaselines[selectedQualityKey];
  const qualityWindowResetActive = historyPeriod === "24h" && Boolean(selectedQualityBaseline);
  const toggleQualityWindow = () => {
    if (!selectedQualityKey) return;
    const next = { ...quality24hBaselines };
    if (next[selectedQualityKey]) {
      delete next[selectedQualityKey];
    } else {
      next[selectedQualityKey] = Date.now() / 1000;
      setHistoryPeriod("24h");
    }
    setQuality24hBaselines(next);
    try {
      window.localStorage.setItem(
        QUALITY_24H_BASELINE_STORAGE_KEY,
        JSON.stringify(next),
      );
    } catch {
      // The visible baseline still works for this session when storage is unavailable.
    }
  };
  // Keep the resolved sheet ID before committing children, without an effect
  // that commits the entire table twice after initial load or sheet deletion.
  if (qualityPolicyId !== selectedQualityKey) {
    setQualityPolicyId(selectedQualityKey);
  }
  return (
    <>
      <SectionTitle
        eyebrow={tr("Маршрутизация")}
        title={tr("Маршрутные листы для устройств")}
        description={tr("Один лист объединяет расположения подписки, режим WAN/VLESS и карточки исключений.")}
      />

      <section className="routing-list">
        <section className="card routing-policy-section">
          <div className="routing-section-header">
            <div className="routing-section-title">
              <strong>{tr("Маршрутные листы")}</strong>
              <span>{tr("• Группы, страны, города, основной маршрут и исключения")}</span>
            </div>
            <button className="button button-primary" onClick={onAddPolicy}>
               {tr("+ Добавить маршрутный лист")} </button>
          </div>
          {routingNodesError ? (
            <div className="inline-result inline-result-error routing-section-error" role="alert">
              <span>!</span>
               {tr("Не удалось сверить выбранные узлы с подписками:")} {routingNodesError}
            </div>
          ) : null}
          <div className="policy-cards">
            {!configuredPolicies.length ? (
              <aside className="notice notice-neutral">
                <span className="notice-icon">i</span>
                <div>
                  <strong>{tr("Маршрутных листов пока нет")}</strong>
                  <p>{tr("Создайте первый лист и затем назначьте его устройству.")}</p>
                </div>
              </aside>
            ) : null}
            {policyRows.map((policy) => {
              const expanded = expandedPolicyId === policy.key;
              const queueRows = policy.queueNodes.length
                ? policy.queueNodes
                : policy.route.map((label, rank) => ({
                    id: `${policy.key}:${rank}`,
                    label,
                    country: "",
                    selected: false,
                    available: false,
                    availabilityKnown: false,
                    inRuntimePool: false,
                    provider: undefined,
                  }));
              return (
                <article className={`policy-card ${expanded ? "is-expanded" : ""}`} key={policy.key}>
                  <div className="policy-card-summary">
                    <div className="policy-card-identity">
                      <span className="routing-marker-slot" aria-hidden="true">
                        <span className="policy-state-dot" />
                      </span>
                      <h3>{policy.name}</h3>
                      <span className="policy-client-count">
                        {policy.gatewayClients}  {tr("шлюз. ·")} {policy.deviceClients}  {tr("устр.")} </span>
                    </div>
                    <div className="policy-card-active">
                      <strong><NodeName label={policy.active} country={policy.activeCountry} provider={policy.activeProvider} /></strong>
                      {policy.p95 !== "—" ? <code>{policy.p95}</code> : null}
                      {policy.readyReserves > 0 ? (
                        <span>+{policy.readyReserves}  {tr("в резерве")}</span>
                      ) : null}
                    </div>
                    <div className="policy-card-actions">
                      <span className="policy-path-badge">{policy.path}</span>
                      <span className="policy-strategy-badge">{policy.strategy}</span>
                      <button
                        className="button button-secondary"
                        type="button"
                        onClick={() => onEditPolicy(policy.key)}
                      >
                         {tr("Настроить")} </button>
                      <button
                        className="policy-expand-button"
                        type="button"
                        aria-label={expanded ? tr("Свернуть {value1}", { value1: policy.name }) : tr("Развернуть {value1}", { value1: policy.name })}
                        aria-expanded={expanded}
                        onClick={() => updateExpandedPolicy(expanded ? "" : policy.key)}
                      >
                        <svg viewBox="0 0 24 24" aria-hidden="true">
                          <path d="m6 9 6 6 6-6" />
                        </svg>
                      </button>
                    </div>
                  </div>
                  {expanded ? (
                    <div className="policy-reserve-queue">
                      <strong>{policy.queueNodes.length ? tr("Узлы маршрута") : tr("Выбранные направления")} ({queueRows.length})</strong>
                      <div>
                        {queueRows.map((node, rank) => (
                          <div className="policy-reserve-row" key={node.id}>
                            <span className="routing-marker-slot">
                              {node.selected ? (
                                <span className="quality-active-marker" aria-label={tr("Активный узел")}>A</span>
                              ) : (
                                <span className={`quality-state ${node.available ? "is-up" : node.availabilityKnown ? "is-down" : "is-unknown"}`} />
                              )}
                            </span>
                            <strong><NodeName label={node.label} country={node.country} provider={node.provider} /></strong>
                            <small>
                              {node.selected
                                ? tr("Активный узел")
                                : policy.queueNodes.length
                                  ? node.available
                                    ? node.inRuntimePool ? tr("Рабочий резерв") : tr("Доступен · фоновая проверка")
                                    : node.availabilityKnown ? tr("Недоступен") : tr("Нет проверки")
                                  : tr("Приоритет {value1}", { value1: rank + 1 })}
                            </small>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        </section>

        <section className="card quality-dashboard" aria-labelledby="quality-dashboard-title">
          <div className="quality-overview routing-section-header">
            <div className="routing-section-title">
              <strong id="quality-dashboard-title">{tr("Качество узлов")}</strong>
              {quality.total > quality.rows.length ? <span>{tr("Показано")} {quality.rows.length}  {tr("из")} {quality.total}</span> : null}
            </div>
            <div className="quality-overview-actions">
              {policyRows.length ? (
                <div className="quality-periods quality-sheets" role="group" aria-label={tr("Маршрутный лист")}>
                  {policyRows.map((policy, index) => (
                    <button
                      className={selectedQualityKey === policy.key ? "is-active" : ""}
                      type="button"
                      onClick={() => setQualityPolicyId(policy.key)}
                      aria-pressed={selectedQualityKey === policy.key}
                      aria-label={tr("Лист {value1}: {value2}", { value1: index + 1, value2: policy.name })}
                      title={`${index + 1}. ${policy.name}`}
                      key={policy.key}
                    >
                      {index + 1}
                    </button>
                  ))}
                </div>
              ) : null}
              <div className="quality-periods" aria-label={tr("Период статистики")}>
                {(["24h", "7d", "30d"] as const).map((period) => (
                  <button
                    className={historyPeriod === period ? "is-active" : ""}
                    type="button"
                    onClick={() => setHistoryPeriod(period)}
                    aria-pressed={historyPeriod === period}
                    key={period}
                  >
                    {period === "24h" ? tr("24 часа") : period === "7d" ? tr("7 дней") : tr("30 дней")}
                  </button>
                ))}
              </div>
              <button
                className={`quality-window-reset${qualityWindowResetActive ? " is-active" : ""}`}
                type="button"
                onClick={toggleQualityWindow}
                aria-pressed={qualityWindowResetActive}
                aria-label={qualityWindowResetActive
                  ? tr("Вернуть полную статистику за 24 часа")
                  : tr("Начать новый отсчёт статистики за 24 часа")}
                title={qualityWindowResetActive
                  ? tr("Вернуть полные 24 часа")
                  : tr("Новый отсчёт за 24 часа")}
                disabled={!selectedQualityKey}
              >
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M4.8 9.2A7.5 7.5 0 1 1 4.5 14" />
                  <path d="M4.8 4.8v4.4h4.4" />
                  <path d="M12 8v4.3l2.8 1.7" />
                </svg>
                {qualityWindowResetActive ? <span aria-hidden="true" /> : null}
              </button>
            </div>
          </div>
          {quality.rows.length ? (
            <div className="policy-quality-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{quality.policy?.mode === "priority" ? tr("Приоритет") : tr("Рейтинг")}</th>
                    <th>{tr("Маршрут и узел")}</th>
                    <th>{tr("Доступность / потери")}</th>
                    <th>{tr("Медиана")}</th>
                    <th>{tr("Скорость")}</th>
                    <th>p95 HTTPS</th>
                    <th>{tr("К активному")}</th>
                    <th>{tr("Замеры")}</th>
                  </tr>
                </thead>
                <tbody>
                  {quality.rows.map((node) => (
                    <tr key={`${selectedQualityKey}:${node.id}`} className={node.selected ? "is-active" : ""}>
                      <td className="quality-rank">{node.rank}</td>
                      <td className="quality-node-cell">
                        <span className="quality-marker-slot">
                          {node.selected ? (
                            <span className="quality-active-marker" aria-label={tr("Активный узел")}>A</span>
                          ) : (
                            <span className={`quality-state ${node.available ? "is-up" : node.availabilityKnown ? "is-down" : "is-unknown"}`} aria-label={node.available ? tr("Доступен") : node.availabilityKnown ? tr("Недоступен") : tr("Нет проверки")} />
                          )}
                        </span>
                        <span className="quality-node-label">
                          <strong><NodeName label={node.label} country={node.country} provider={node.provider} /></strong>
                          <small>({quality.policy?.name})</small>
                        </span>
                      </td>
                      <td className="quality-inline-value">
                        <span className="quality-availability-value">
                          <strong>{node.availability == null ? tr("Нет замера") : `${node.availability.toFixed(1)}%`}</strong>
                          {node.loss == null ? null : <small>({node.loss.toFixed(1)}{tr("% потерь)")}</small>}
                        </span>
                      </td>
                      <td><strong>{node.median == null ? "—" : tr("{value1} мс", { value1: node.median })}</strong></td>
                      <td><strong>{node.speedBps == null ? "—" : tr("{value1} Мбит/с", { value1: (node.speedBps / 1_000_000).toFixed(1) })}</strong></td>
                      <td>{node.p95 == null ? "—" : tr("{value1} мс", { value1: node.p95 })}</td>
                      <td>
                        {!node.selected && node.deltaPercent != null ? (
                          <span className="quality-delta">
                            {node.deltaPercent > 0 ? "▲" : node.deltaPercent < 0 ? "▼" : "="} {Math.abs(node.deltaPercent).toFixed(1)}%
                          </span>
                        ) : "—"}
                      </td>
                      <td>{node.samples || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="quality-dashboard-empty">
               {tr("Первая проверка ещё не завершена.")} </p>
          )}
        </section>
      </section>

      <RoutingInfrastructureSettings
        config={config}
        runtime={runtime}
        routeros={routeros}
        onDraftChanged={onDraftChanged}
      />
    </>
  );
}

const ROUTING_MONITOR_DEFAULTS = {
  active_liveness_interval_seconds: 3,
  failure_retry_interval_seconds: 2,
  block_recovery_interval_seconds: 15,
  active_quality_interval_seconds: 60,
  reserve_check_interval_seconds: 300,
  full_scan_interval_seconds: 1800,
  probe_batch_size: 0,
} as const;

type RoutingMonitorValues = {
  [Key in keyof typeof ROUTING_MONITOR_DEFAULTS]: number;
};

function routingMonitorValues(config: JsonObject): RoutingMonitorValues {
  const monitor = asObject(asObject(config.system).routing_monitor);
  return Object.fromEntries(
    Object.entries(ROUTING_MONITOR_DEFAULTS).map(([key, fallback]) => {
      const value = Number(monitor[key]);
      return [key, Number.isInteger(value) ? value : fallback];
    }),
  ) as RoutingMonitorValues;
}

function RoutingMonitorSettings({
  values,
  onChange,
  disabled,
}: {
  values: RoutingMonitorValues;
  onChange: (values: RoutingMonitorValues) => void;
  disabled: boolean;
}) {
  const { tr } = useLanguage();

  const update = (key: keyof RoutingMonitorValues, value: string) => {
    onChange({ ...values, [key]: Number(value) });
  };

  const numberField = (
    key: keyof RoutingMonitorValues,
    label: string,
    min: number,
    max: number,
  ) => (
    <label className="field">
      <span>{tr(label as MessageKey)}</span>
      <input
        type="number"
        min={min}
        max={max}
        required
        disabled={disabled}
        value={values[key]}
        onChange={(event) => update(key, event.target.value)}
      />
    </label>
  );

  return (
    <section className="card routing-monitor-card">
      <details>
        <summary>
          <span>
            <strong>{tr("Мониторинг маршрутов")}</strong>
            <small>{tr("Общие настройки всех маршрутных листов")}</small>
          </span>
          <span className="routing-monitor-summary" aria-label={tr("Быстрые интервалы")}>
            {values.active_liveness_interval_seconds} / {values.failure_retry_interval_seconds} / {values.block_recovery_interval_seconds} {tr("сек.")}
          </span>
        </summary>
        <div className="routing-monitor-form">
          <div className="routing-monitor-grid">
            {numberField("active_liveness_interval_seconds", "Доступность активного узла, сек.", 2, 30)}
            {numberField("failure_retry_interval_seconds", "Повтор после ошибки, сек.", 1, 10)}
            {numberField("block_recovery_interval_seconds", "Повтор других узлов, сек.", 5, 60)}
            {numberField("active_quality_interval_seconds", "Качество активного узла, сек.", 10, 3600)}
            {numberField("reserve_check_interval_seconds", "Проверка резервов, сек.", 10, 86400)}
            {numberField("full_scan_interval_seconds", "Полный обход, сек.", 10, 86400)}
            <label className="field">
              <span>{tr("Максимум проверок за цикл")}</span>
              <select
                disabled={disabled}
                value={values.probe_batch_size}
                onChange={(event) => update("probe_batch_size", event.target.value)}
              >
                <option value={0}>{tr("Авто · URLTest: 2, приоритет: 3")}</option>
                <option value={1}>1</option>
                <option value={2}>2</option>
                <option value={3}>3</option>
                <option value={4}>4</option>
                <option value={5}>5</option>
                <option value={6}>6</option>
                <option value={7}>7</option>
                <option value={8}>8</option>
                <option value={9}>9</option>
                <option value={10}>10</option>
              </select>
              <small>{tr("При аварии — одновременно; активный пул не меняется.")}</small>
            </label>
          </div>
          <div className="routing-monitor-actions">
            <button
              className="button button-tertiary"
              type="button"
              disabled={disabled}
              onClick={() => onChange({ ...ROUTING_MONITOR_DEFAULTS })}
            >
              {tr("Рекомендуемые значения")}
            </button>
          </div>
        </div>
      </details>
    </section>
  );
}

function RoutingInfrastructureSettings({
  config,
  runtime,
  routeros,
  onDraftChanged,
}: {
  config: JsonObject;
  runtime?: JsonObject;
  routeros: JsonObject;
  onDraftChanged: () => Promise<void>;
}) {
  const { tr } = useLanguage();
  const system = asObject(config.system);
  const networking = asObject(system.networking);
  const dns = asObject(config.dns);
  const {
    discovery: liveRouteros,
    busy: routerosInventoryBusy,
    error: routerosInventoryError,
    refresh: refreshRouterosInventory,
  } = useRouterClientSources();
  const hasLiveRouteros = Object.keys(liveRouteros).length > 0;
  const displayedRouteros = hasLiveRouteros ? liveRouteros : routeros;
  const liveIpv6 = asObject(displayedRouteros.ipv6);
  const ipv6Live =
    (hasLiveRouteros || displayedRouteros.live_available === true) &&
    liveIpv6.inventory_complete !== false;
  const ipv6Refreshing =
    routerosInventoryBusy || displayedRouteros.summary_source === "refreshing";
  const ipv6Disabled = liveIpv6.disabled === true;
  const ipv6AddressCount = Number(liveIpv6.address_count || 0);
  const ipv6DefaultRouteCount = Number(liveIpv6.active_default_route_count || 0);
  const configuredRemoteIpv6Enabled =
    asText(networking.remote_ipv6_mode, "proxy_only") !== "disabled";
  const directResolver = asObject(dns.direct_resolver);
  const vpnResolver = asObject(dns.vpn_resolver);
  const configuredWireguardExits = asObjectList(networking.wireguard_egress_exits);
  const liveWireguardCandidates = asObjectList(
    displayedRouteros.wireguard_egress_candidates,
  );
  const inventoryComplete =
    !routerosInventoryBusy &&
    !routerosInventoryError &&
    displayedRouteros.wireguard_egress_inventory_complete === true;
  const [wireguardEnabled, setWireguardEnabled] = useState(
    networking.wireguard_egress_enabled === true,
  );
  const [wireguardExits, setWireguardExits] = useState<JsonObject[]>(
    configuredWireguardExits.map((item) => {
      const interfaceName = asText(item.interface, "");
      return {
        id: asText(item.id, wireguardEgressId(interfaceName)),
        interface: interfaceName,
        enabled: item.enabled !== false,
      };
    }),
  );
  const [directDnsProvider, setDirectDnsProvider] = useState(
    asText(directResolver.provider, "yandex") === "routeros"
      ? "yandex"
      : asText(directResolver.provider, "yandex"),
  );
  const [directDnsProtocol, setDirectDnsProtocol] = useState(
    asText(directResolver.provider, "yandex") === "routeros"
      ? "doh"
      : asText(directResolver.protocol, "doh"),
  );
  const [vpnDnsProvider, setVpnDnsProvider] = useState(
    asText(vpnResolver.provider, "cloudflare"),
  );
  const [vpnDnsProtocol, setVpnDnsProtocol] = useState(
    asText(vpnResolver.protocol, "doh"),
  );
  const [remoteIpv6Enabled, setRemoteIpv6Enabled] = useState(
    configuredRemoteIpv6Enabled,
  );
  const [forceTcpForProxyServices, setForceTcpForProxyServices] = useState(
    dns.force_tcp_for_proxy_services === true,
  );
  const [routingMonitor, setRoutingMonitor] = useState<RoutingMonitorValues>(() =>
    routingMonitorValues(config),
  );
  const [routingResetVersion, setRoutingResetVersion] = useState(0);
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveMessage, setSaveMessage] = useState(() => {
    if (typeof window === "undefined") return "";
    return window.sessionStorage.getItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY) ?? "";
  });
  const reverseVlessCollector = useRef<(() => JsonObject[]) | null>(null);
  const registerReverseVlessCollector = useCallback(
    (collector: (() => JsonObject[]) | null) => {
      reverseVlessCollector.current = collector;
    },
    [],
  );
  useEffect(() => {
    if (!saveMessage || typeof window === "undefined") return;
    const timeout = window.setTimeout(() => {
      window.sessionStorage.removeItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY);
      setSaveMessage("");
    }, 12_000);
    return () => window.clearTimeout(timeout);
  }, [saveMessage]);
  useEffect(() => {
    if (typeof window === "undefined") return;
    const persistedMessage = window.sessionStorage.getItem(
      ROUTING_SAVE_MESSAGE_STORAGE_KEY,
    );
    if (persistedMessage && persistedMessage !== saveMessage) {
      const restore = window.setTimeout(
        () => setSaveMessage(persistedMessage),
        0,
      );
      return () => window.clearTimeout(restore);
    }
  }, [config, saveMessage]);
  const selectedInterfaces = new Set(
    wireguardExits
      .filter((item) => item.enabled !== false)
      .map((item) => asText(item.interface, ""))
      .filter(Boolean),
  );
  const wireguardRows = liveWireguardCandidates
    .filter((candidate) => candidate.disabled !== true)
    .sort(
      (left, right) =>
        Number(selectedInterfaces.has(asText(right.interface, ""))) -
        Number(selectedInterfaces.has(asText(left.interface, ""))),
    );
  const wireguardValid =
    !wireguardEnabled ||
    (inventoryComplete &&
      wireguardExits.some((item) => item.enabled !== false) &&
      wireguardExits.every(
        (item) =>
          item.enabled === false ||
          (Boolean(asText(item.interface, "")) &&
            liveWireguardCandidates.some(
              (candidate) =>
                asText(candidate.interface, "") === asText(item.interface, "") &&
                candidate.eligible === true,
            )),
      ));

  function setWireguardSelected(candidate: JsonObject, selected: boolean) {
    const interfaceName = asText(candidate.interface, "");
    if (!interfaceName) return;
    const remaining = wireguardExits.filter(
      (item) => asText(item.interface, "") !== interfaceName,
    );
    setWireguardExits(
      selected
        ? [
            ...remaining,
            {
              id: wireguardEgressId(interfaceName),
              interface: interfaceName,
              enabled: true,
            },
          ]
        : remaining,
    );
  }

  function resetRoutingInfrastructure() {
    setWireguardEnabled(networking.wireguard_egress_enabled === true);
    setWireguardExits(
      configuredWireguardExits.map((item) => {
        const interfaceName = asText(item.interface, "");
        return {
          id: asText(item.id, wireguardEgressId(interfaceName)),
          interface: interfaceName,
          enabled: item.enabled !== false,
        };
      }),
    );
    setDirectDnsProvider(
      asText(directResolver.provider, "yandex") === "routeros"
        ? "yandex"
        : asText(directResolver.provider, "yandex"),
    );
    setDirectDnsProtocol(
      asText(directResolver.provider, "yandex") === "routeros"
        ? "doh"
        : asText(directResolver.protocol, "doh"),
    );
    setVpnDnsProvider(asText(vpnResolver.provider, "cloudflare"));
    setVpnDnsProtocol(asText(vpnResolver.protocol, "doh"));
    setRemoteIpv6Enabled(configuredRemoteIpv6Enabled);
    setForceTcpForProxyServices(dns.force_tcp_for_proxy_services === true);
    setRoutingMonitor(routingMonitorValues(config));
    setRoutingResetVersion((current) => current + 1);
    setSaveMessage(tr("Изменения формы сброшены."));
  }

  async function saveRoutingInfrastructure() {
    const monitorRanges: Array<[keyof RoutingMonitorValues, number, number]> = [
      ["active_liveness_interval_seconds", 2, 30],
      ["failure_retry_interval_seconds", 1, 10],
      ["block_recovery_interval_seconds", 5, 60],
      ["active_quality_interval_seconds", 10, 3600],
      ["reserve_check_interval_seconds", 10, 86400],
      ["full_scan_interval_seconds", 10, 86400],
      ["probe_batch_size", 0, 10],
    ];
    if (monitorRanges.some(([key, minimum, maximum]) =>
      !Number.isInteger(routingMonitor[key]) || routingMonitor[key] < minimum || routingMonitor[key] > maximum
    )) {
      setSaveMessage(prefixedErrorMessage(new Error(tr("Проверьте значения мониторинга маршрутов."))));
      return;
    }
    if (routingMonitor.failure_retry_interval_seconds > routingMonitor.active_liveness_interval_seconds) {
      setSaveMessage(prefixedErrorMessage(new Error(tr("Интервал повтора после ошибки не может быть больше интервала проверки активного узла."))));
      return;
    }
    if (routingMonitor.reserve_check_interval_seconds < routingMonitor.active_quality_interval_seconds) {
      setSaveMessage(prefixedErrorMessage(new Error(tr("Резервы нельзя проверять чаще активного узла."))));
      return;
    }
    if (routingMonitor.full_scan_interval_seconds < routingMonitor.reserve_check_interval_seconds) {
      setSaveMessage(prefixedErrorMessage(new Error(tr("Полный обход не может выполняться чаще проверки резервов."))));
      return;
    }
    if (!wireguardValid) {
      setSaveMessage(
        tr("Ошибка: выберите хотя бы один доступный WireGuard-интерфейс."),
      );
      return;
    }
    setSaveBusy(true);
    setSaveMessage("");
    window.sessionStorage.removeItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY);
    try {
      const reverseVlessExits =
        reverseVlessCollector.current?.() ??
        asObjectList(config.reverse_vless_exits);
      await saveCurrentDraft({
        config: withDeploymentReadiness(
          {
            ...config,
            reverse_vless_exits: reverseVlessExits,
            system: {
              ...system,
              routing_monitor: routingMonitor,
              networking: {
                ...networking,
                wireguard_egress_enabled: wireguardEnabled,
                wireguard_egress_exits: wireguardExits,
                remote_ipv6_mode: remoteIpv6Enabled ? "proxy_only" : "disabled",
              },
            },
            dns: {
              ...dns,
              force_tcp_for_proxy_services: forceTcpForProxyServices,
              direct_resolver: {
                provider: directDnsProvider,
                protocol: directDnsProtocol,
              },
              vpn_resolver: {
                provider: vpnDnsProvider,
                protocol: vpnDnsProtocol,
              },
            },
          },
          false,
        ),
      });
      const successMessage = tr("Маршрутизация сохранена. Примените изменения.");
      window.sessionStorage.setItem(
        ROUTING_SAVE_MESSAGE_STORAGE_KEY,
        successMessage,
      );
      setSaveMessage(successMessage);
      await onDraftChanged();
      setSaveMessage(successMessage);
    } catch (error) {
      setSaveMessage(prefixedErrorMessage(error));
    } finally {
      setSaveBusy(false);
    }
  }

  const wanDnsResolverOptions = [
    ["yandex", "doh", tr("Яндекс DNS (DoH · HTTPS)")],
    ["cloudflare", "doh", "Cloudflare (DoH · HTTPS)"],
    ["google", "doh", "Google Public DNS (DoH · HTTPS)"],
    ["quad9", "doh", "Quad9 (DoH · HTTPS)"],
  ] as const;
  const vpnDnsResolverOptions = [
    ...wanDnsResolverOptions,
    ["yandex", "dot", tr("Яндекс DNS (DoT · TLS)")],
    ["cloudflare", "dot", "Cloudflare (DoT · TLS)"],
    ["google", "dot", "Google Public DNS (DoT · TLS)"],
    ["quad9", "dot", "Quad9 (DoT · TLS)"],
  ] as const;

  return (
    <section className="routing-infrastructure">
      <div className="routing-infrastructure-grid">
        <ReverseVlessSettings
          key={routingResetVersion}
          config={config}
          runtime={runtime}
          onDraftChanged={onDraftChanged}
          onCollectorChange={registerReverseVlessCollector}
          saving={saveBusy}
        />

        <article className="card settings-card wireguard-egress-settings">
          <div className="panel-heading routing-section-header">
            <div className="routing-section-title">
              <strong>{tr("WireGuard-выходы")}</strong>
              <span>{tr("• Туннельные пиры и шлюзы")}</span>
            </div>
            <label className="routing-master-toggle">
              <span className="sr-only">{tr("Использовать WireGuard MikroTik")}</span>
              <input
                type="checkbox"
                checked={wireguardEnabled}
                onChange={(event) => setWireguardEnabled(event.target.checked)}
              />
              <span className="toggle-control" aria-hidden="true" />
            </label>
          </div>
          <div className="settings-card-body wireguard-egress-body">
            {wireguardEnabled ? (
              routerosInventoryBusy ? (
                <div className="subscription-discovery-empty" role="status">
                   {tr("Читаю WireGuard и маршруты с подключённого MikroTik…")} </div>
              ) : routerosInventoryError ? (
                <div className="inline-result inline-result-error wireguard-inventory-error" role="alert">
                  <span>!</span>
                  <span>{tr("Не удалось получить live-инвентаризацию RouterOS:")} {routerosInventoryError}</span>
                  <button
                    className="button button-secondary button-compact"
                    type="button"
                    onClick={() => void refreshRouterosInventory()}
                  >
                     {tr("Повторить")} </button>
                </div>
              ) : !inventoryComplete ? (
                <div className="inline-result inline-result-error" role="alert">
                  <span>!</span>
                   {tr("MikroTik вернул неполную инвентаризацию WireGuard или маршрутов.")} </div>
              ) : wireguardRows.length ? (
                <div className="wireguard-egress-list">
                  {wireguardRows.map((candidate) => {
                    const interfaceName = asText(candidate.interface, "");
                    const selected = selectedInterfaces.has(interfaceName);
                    const eligible = candidate.eligible === true;
                    const reason = asText(candidate.reason, "not_found");
                    const reasonText: Record<string, string> = {
                      ready: tr("Готов к использованию"),
                      will_prepare: tr("Full-tunnel будет подготовлен при применении"),
                      no_peer: tr("Нет настроенного peer"),
                      no_enabled_peer: tr("Нет включённого peer"),
                      ambiguous_peers: tr("Несколько peer — выбор неоднозначен"),
                    };
                    return (
                      <section
                        className={`wireguard-egress-row ${selected ? "is-selected" : ""}`}
                        key={interfaceName}
                      >
                        <label className="wireguard-egress-choice">
                          <input
                            type="checkbox"
                            checked={selected}
                            disabled={!eligible && !selected}
                            onChange={(event) =>
                              setWireguardSelected(candidate, event.target.checked)
                            }
                          />
                          <span>
                            <strong>WG · {interfaceName}</strong>
                            <small>{reasonText[reason] ?? reason}</small>
                          </span>
                        </label>
                      </section>
                    );
                  })}
                </div>
              ) : (
                <div className="subscription-discovery-empty">
                   {tr("Нет включённых WireGuard-интерфейсов.")} </div>
              )
            ) : (
              <div className="subscription-discovery-empty">
                 {tr("WireGuard-выходы выключены.")} </div>
            )}
          </div>
        </article>

        <article className="card settings-card routing-behavior-settings">
          <div className="panel-heading routing-section-header">
            <div className="routing-section-title">
              <strong>{tr("IPv6 и совместимость")}</strong>
            </div>
          </div>
          <div className="settings-card-body routing-behavior-body">
            <Toggle
              checked={remoteIpv6Enabled}
              onChange={setRemoteIpv6Enabled}
              label={tr("IPv6 удалённых VLESS-клиентов")}
              description={
                remoteIpv6Enabled
                  ? tr("IPv6 идёт через назначенный VPN.")
                  : tr("IPv6 удалённых клиентов заблокирован.")
              }
            />
            <div className="locked-setting">
              <div>
                <strong>{tr("IPv6 подключённого MikroTik")}</strong>
                <small>
                  {!ipv6Live
                    ? ipv6Refreshing
                      ? tr("Получаем состояние RouterOS.")
                      : tr("RouterOS REST не ответил.")
                    : ipv6Disabled
                      ? tr("IPv6 на MikroTik выключен.")
                      : tr("IPv6 включён: адресов {value1}, маршрутов ::/0: {value2}.", { value1: ipv6AddressCount, value2: ipv6DefaultRouteCount })}
                </small>
              </div>
              <StatusPill tone={ipv6Live && ipv6Disabled ? "ok" : ipv6Refreshing ? "muted" : "warn"}>
                {!ipv6Live
                  ? ipv6Refreshing
                    ? tr("Обновляется")
                    : tr("Недоступно")
                  : ipv6Disabled
                    ? "IPv4-only WAN"
                    : tr("IPv6 активен")}
              </StatusPill>
            </div>
            <Toggle
              checked={forceTcpForProxyServices}
              onChange={setForceTcpForProxyServices}
              label={tr("Отключать QUIC для сервисных карточек")}
              description={
                forceTcpForProxyServices
                  ? tr("UDP/443 блокируется только для выбранных карточек.")
                  : tr("QUIC и HTTP/3 разрешены.")
              }
            />
          </div>
        </article>

        <article className="card settings-card dns-path-settings">
          <div className="panel-heading routing-section-header">
            <div className="routing-section-title">
              <strong>{tr("DNS по маршруту")}</strong>
            </div>
          </div>
          <div className="settings-card-body dns-path-body">
            <label className="dns-path-row">
              <span className="dns-path-label">
                <strong>{tr("WAN DNS (локальные запросы)")}</strong>
                <small>{directDnsProtocol === "doh" ? "HTTPS · DoH" : "TLS · DoT"}</small>
              </span>
              <select
                aria-label={tr("Провайдер DNS для WAN")}
                value={`${directDnsProvider}:${directDnsProtocol}`}
                onChange={(event) => {
                  const [provider, protocol] = event.target.value.split(":");
                  setDirectDnsProvider(provider);
                  setDirectDnsProtocol(protocol);
                }}
              >
                {wanDnsResolverOptions.map(([provider, protocol, label]) => (
                  <option value={`${provider}:${protocol}`} key={`wan:${provider}:${protocol}`}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
            <label className="dns-path-row">
              <span className="dns-path-label">
                <strong>{tr("VPN DNS (запросы через туннель)")}</strong>
                <small>{vpnDnsProtocol === "doh" ? "HTTPS · DoH" : "TLS · DoT"}</small>
              </span>
              <select
                aria-label={tr("Провайдер DNS для VPN")}
                value={`${vpnDnsProvider}:${vpnDnsProtocol}`}
                onChange={(event) => {
                  const [provider, protocol] = event.target.value.split(":");
                  setVpnDnsProvider(provider);
                  setVpnDnsProtocol(protocol);
                }}
              >
                {vpnDnsResolverOptions.map(([provider, protocol, label]) => (
                  <option value={`${provider}:${protocol}`} key={`vpn:${provider}:${protocol}`}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
          </div>
        </article>
      </div>
      <RoutingMonitorSettings
        values={routingMonitor}
        onChange={setRoutingMonitor}
        disabled={saveBusy}
      />
      <div className="routing-save-bar">
        <button
          className="button button-ghost"
          type="button"
          onClick={resetRoutingInfrastructure}
          disabled={saveBusy}
        >
           {tr("Сбросить")} </button>
        <button
          className="button button-primary"
          type="button"
          onClick={saveRoutingInfrastructure}
          disabled={saveBusy || !wireguardValid}
        >
          {saveBusy ? tr("Сохраняю…") : tr("Сохранить")}
        </button>
      </div>
      {saveMessage ? (
        <div
          className={`inline-result ${isErrorMessage(saveMessage) ? "inline-result-error" : ""}`}
          role={isErrorMessage(saveMessage) ? "alert" : "status"}
        >
          <span>{isErrorMessage(saveMessage) ? "!" : "✓"}</span>
          {saveMessage}
        </div>
      ) : null}
    </section>
  );
}

function ReverseVlessSettings({
  config,
  runtime,
  onDraftChanged,
  onCollectorChange,
  saving,
}: {
  config: JsonObject;
  runtime?: JsonObject;
  onDraftChanged: () => Promise<void>;
  onCollectorChange: (collector: (() => JsonObject[]) | null) => void;
  saving: boolean;
}) {
  const { tr } = useLanguage();
  const xraySelected = true;
  const [statusNow, setStatusNow] = useState(0);
  useEffect(() => {
    const refresh = () => setStatusNow(Date.now());
    const initial = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 30_000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, []);
  const connectionHostname = useConnectionHostname();
  const supportedKinds = new Set([
    "reality",
    "reality-grpc",
    "xhttp-reality",
  ]);
  const transports = asObjectList(config.transports).filter(
    (item) => item.enabled !== false && supportedKinds.has(asText(item.kind, "")),
  );
  const configuredExits = asObjectList(config.reverse_vless_exits);
  const [exitEnabledOverrides, setExitEnabledOverrides] = useState<
    Record<string, boolean>
  >({});
  const exitEnabledValue = useCallback(
    (exit: JsonObject) => {
      const id = asText(exit.id, "");
      return id in exitEnabledOverrides
        ? exitEnabledOverrides[id]
        : exit.enabled !== false;
    },
    [exitEnabledOverrides],
  );
  const exits = [...configuredExits].sort(
    (left, right) =>
      Number(exitEnabledValue(right)) - Number(exitEnabledValue(left)),
  );
  const [busyId, setBusyId] = useState("");
  const [message, setMessage] = useState("");
  const formRef = useRef<HTMLFormElement>(null);

  const collectExits = useCallback(() => {
    if (!formRef.current) return exits;
    const data = new FormData(formRef.current);
    return exits.map((existing) => {
      const exitId = asText(existing.id, "");
      const displayName = String(
        data.get(`display_name:${exitId}`) ?? "",
      ).trim();
      const transportIds = data
        .getAll(`transport_ids:${exitId}`)
        .map(String);
      const enabled = data.get(`enabled:${exitId}`) === "on";
      if (!displayName) {
        throw new Error(tr("Укажите имя каждого Reverse VLESS-клиента."));
      }
      if (enabled && !transportIds.length) {
        throw new Error(
          tr("Выберите хотя бы один серверный вход для «{value1}».", { value1: displayName }),
        );
      }
      return {
        ...existing,
        display_name: displayName,
        enabled,
        transport_ids: transportIds,
        transport_id: transportIds[0] ?? "",
        country: undefined,
        city: undefined,
      };
    });
  }, [exits, tr]);

  useEffect(() => {
    onCollectorChange(collectExits);
    return () => onCollectorChange(null);
  }, [collectExits, onCollectorChange]);

  async function addExit() {
    if (!xraySelected || !transports.length) return;
    const id = `reverse-${Date.now().toString(36)}`;
    setBusyId("new");
    setMessage("");
    try {
      await createCollectionItem("reverse-vless-exits", {
        id,
        display_name: tr("Reverse VLESS клиент"),
        enabled: true,
        transport_id: asText(transports[0].id, ""),
        transport_ids: [asText(transports[0].id, "")],
        generate_uuid: true,
      });
      await onDraftChanged();
      setMessage(tr("Клиент добавлен."));
    } catch (error) {
      setMessage(prefixedErrorMessage(error));
    } finally {
      setBusyId("");
    }
  }

  async function removeExit(exitId: string) {
    setBusyId(exitId);
    setMessage("");
    try {
      await deleteCollectionItem("reverse-vless-exits", exitId);
      await onDraftChanged();
      setMessage(tr("Клиент удалён."));
    } catch (error) {
      setMessage(prefixedErrorMessage(error));
    } finally {
      setBusyId("");
    }
  }

  async function downloadConfig(exitId: string) {
    setBusyId(exitId);
    setMessage("");
    try {
      const { blob, filename } = await downloadReverseVlessClientConfig(exitId);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setMessage(tr("Конфигурация скачана."));
    } catch (error) {
      setMessage(prefixedErrorMessage(error));
    } finally {
      setBusyId("");
    }
  }

  async function copyClientId(exitId: string) {
    try {
      await navigator.clipboard.writeText(exitId.replace(/^reverse-/, ""));
      setMessage(tr("Идентификатор клиента скопирован."));
    } catch {
      setMessage(tr("Ошибка: браузер не разрешил копирование."));
    }
  }

  return (
    <article className="card settings-card reverse-vless-settings">
      <div className="panel-heading reverse-vless-heading routing-section-header">
        <div className="routing-section-title">
          <strong>{tr("Reverse VLESS-клиенты")}</strong>
          <span>{tr("• Точки обратного подключения")}</span>
        </div>
        <button
          className="button button-primary"
          type="button"
          onClick={() => void addExit()}
          disabled={!xraySelected || !transports.length || Boolean(busyId) || saving}
        >
          {busyId === "new" ? tr("Добавляю…") : tr("+ Добавить клиента")}
        </button>
      </div>
      {!xraySelected ? (
        <div className="inline-result inline-result-error" role="alert">
          <span>!</span>
           {tr("Reverse VLESS доступен только при выбранном ядре Xray-core.")} </div>
      ) : !transports.length ? (
        <div className="subscription-discovery-empty reverse-vless-empty">
           {tr("Включите хотя бы один совместимый VLESS-вход.")} </div>
      ) : null}
      {exits.length ? (
        <form ref={formRef} onSubmit={(event) => event.preventDefault()}>
          <div className="reverse-vless-exit-list">
            {exits.map((exit) => {
              const id = asText(exit.id, "");
              const enabled = exitEnabledValue(exit);
              const availability = reverseAvailability(runtime, id, statusNow);
              return (
                <div
                  className={`reverse-vless-exit ${enabled ? "is-enabled" : ""}`}
                  key={id}
                >
                  <span
                    className={`reverse-vless-availability is-${availability.state}`}
                    role="img"
                    aria-label={availability.label}
                    title={availability.label}
                    tabIndex={0}
                  >
                    <svg viewBox="0 0 20 20" aria-hidden="true">
                      <circle cx="10" cy="10" r="8" />
                      <path d={availability.state === "available" ? "m6 10 3 3 5-6" : availability.state === "unavailable" ? "m7 7 6 6m0-6-6 6" : "M6 10h8"} />
                    </svg>
                  </span>
                  <label className="reverse-vless-client-name">
                    <span className="sr-only">{tr("Имя клиента")}</span>
                    <input
                      aria-label={tr("Имя Reverse VLESS-клиента")}
                      name={`display_name:${id}`}
                      defaultValue={asText(exit.display_name, "")}
                      required
                      maxLength={96}
                    />
                  </label>
                  <button
                    className="reverse-vless-client-id"
                    type="button"
                    title={tr("Скопировать идентификатор клиента")}
                    aria-label={tr("Скопировать идентификатор клиента")}
                    onClick={() => void copyClientId(id)}
                  >
                    <code>{id.replace(/^reverse-/, "")}</code>
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M8 8h10v10H8zM6 16H4V4h12v2" />
                    </svg>
                  </button>
                  <fieldset className="field reverse-vless-transport-picker">
                    <legend className="sr-only">{tr("Выбор серверных входов")}</legend>
                    <div className="reverse-vless-transport-options">
                      {transports.map((transport) => {
                        const transportId = asText(transport.id, "");
                        const transportKind = asText(transport.kind, "");
                        const endpoint = `${connectionHostname(transport)}:${asText(transport.listen_port, "443")}`;
                        return (
                          <label
                            key={transportId}
                            title={endpoint}
                            aria-label={`${reverseTransportKindLabel(transportKind)}, ${endpoint}`}
                          >
                            <input
                              type="checkbox"
                              name={`transport_ids:${id}`}
                              value={transportId}
                              defaultChecked={(asStringList(exit.transport_ids).length
                                ? asStringList(exit.transport_ids)
                                : [asText(exit.transport_id, "")]
                              ).includes(transportId)}
                            />
                            <span>{reverseTransportKindLabel(transportKind)}</span>
                          </label>
                        );
                      })}
                    </div>
                  </fieldset>
                  <span className="reverse-vless-row-tools">
                    <label className="reverse-vless-use" title={tr("Использовать в маршрутных листах")}>
                      <input
                        aria-label={tr("Использовать {value1} в маршрутных листах", { value1: asText(exit.display_name, tr("Reverse VLESS-клиент")) })}
                        name={`enabled:${id}`}
                        type="checkbox"
                        checked={enabled}
                        onChange={(event) => setExitEnabledOverrides((current) => ({ ...current, [id]: event.target.checked }))}
                      />
                    </label>
                    <button
                      className="reverse-vless-icon-action"
                      type="button"
                      onClick={() => void downloadConfig(id)}
                      disabled={Boolean(busyId) || saving || exit.enabled === false}
                      aria-label={tr("Скачать конфигурацию клиента")}
                      title={tr("Скачать конфигурацию клиента")}
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M12 3v11m0 0 4-4m-4 4-4-4M5 15v4h14v-4" />
                      </svg>
                      <span>{tr("Конфиг")}</span>
                    </button>
                    <button
                      className="reverse-vless-icon-action reverse-vless-icon-action-danger"
                      type="button"
                      onClick={() => void removeExit(id)}
                      disabled={Boolean(busyId) || saving}
                      aria-label={tr("Удалить клиента")}
                      title={tr("Удалить клиента")}
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M4 7h16M9 7V4h6v3m-8 0 1 13h8l1-13M10 11v5m4-5v5" />
                      </svg>
                    </button>
                  </span>
                </div>
              );
            })}
          </div>
        </form>
      ) : (
        <div className="subscription-discovery-empty reverse-vless-empty">
           {tr("Клиентов пока нет.")} </div>
      )}
      {message ? (
        <div className={`inline-result ${isErrorMessage(message) ? "inline-result-error" : ""}`} role={isErrorMessage(message) ? "alert" : "status"}>
          <span>{isErrorMessage(message) ? "!" : "✓"}</span>{message}
        </div>
      ) : null}
    </article>
  );
}

function Connections({
  certificateStatus,
  subscriptionMetadata,
  setSubscriptionMetadata,
  onAddSubscription,
  onEditSubscription,
  onConfigureTransport,
  onAddTlsProfile,
  onEditTlsProfile,
  onDraftChanged,
  config,
  revisionState,
}: {
  certificateStatus: JsonObject;
  subscriptionMetadata: Record<string, JsonObject>;
  setSubscriptionMetadata: (update: (current: Record<string, JsonObject>) => Record<string, JsonObject>) => void;
  onAddSubscription: () => void;
  onEditSubscription: (id: string) => void;
  onConfigureTransport: (id: string) => void;
  onAddTlsProfile: () => void;
  onEditTlsProfile: (id: string) => void;
  onDraftChanged: () => Promise<void>;
  config: JsonObject;
  revisionState: RevisionState;
}) {
  const { locale, t, tr } = useLanguage();
  const [subscriptionBusy, setSubscriptionBusy] = useState("");
  const connectionHostname = useConnectionHostname();
  const [subscriptionMessage, setSubscriptionMessage] = useState("");
  const [nodeSubscriptionId, setNodeSubscriptionId] = useState("");
  const [nodeRows, setNodeRows] = useState<JsonObject[]>([]);
  const [nodeCities, setNodeCities] = useState<Record<string, string>>({});
  const [initialNodeCities, setInitialNodeCities] = useState<Record<string, string>>({});
  const [nodeBusy, setNodeBusy] = useState(false);
  const [subscriptionMetadataError, setSubscriptionMetadataError] = useState(false);
  const [reserveName, setReserveName] = useState("");
  const [reserveLink, setReserveLink] = useState("");
  const [editingReserveId, setEditingReserveId] = useState("");
  const [reserveBusy, setReserveBusy] = useState(false);
  const [reserveMessage, setReserveMessage] = useState("");
  const [subscriptionEndpointDialogOpen, setSubscriptionEndpointDialogOpen] =
    useState(false);
  const subscriptionEndpointBodyRef = useRef<HTMLDivElement>(null);
  const [reserveDialogOpen, setReserveDialogOpen] = useState(false);
  const configuredPublicPort = Number(
    asObject(config.ingress).public_listen_port ?? 443,
  );
  const configuredCloudflareTlsProfileId = asText(
    asObject(config.ingress).tls_profile_id,
    "cdn-default",
  );
  const configuredStatusHostname = asText(
    asObject(config.ingress).status_hostname,
    "",
  );
  const configuredSubscriptionHostnameValue = asText(
    asObject(config.ingress).subscription_hostname,
    "",
  );
  const configuredSubscriptionHostname = configuredSubscriptionHostnameValue;
  const configuredSubscriptionCdnHostnameValue = asText(
    asObject(config.ingress).subscription_cdn_hostname,
    "",
  );
  const configuredSubscriptionOriginServerName = asText(
    asObject(config.ingress).subscription_origin_server_name,
    "",
  );
  const configuredSubscriptionTlsProfileId = asText(
    asObject(config.ingress).subscription_tls_profile_id,
    configuredCloudflareTlsProfileId,
  );
  const configuredSubscriptionOriginPort = Number(
    asObject(config.ingress).subscription_listen_port ?? configuredPublicPort,
  );
  const configuredSubscriptionPublicPort = Number(
    asObject(config.ingress).subscription_public_port ?? configuredSubscriptionOriginPort,
  );
  const configuredSubscriptionCdnProvider = asText(
    asObject(config.ingress).subscription_cdn_provider,
    "cloudflare",
  );
  const configuredSubscriptionDisplayName = asText(
    asObject(asObject(config.public_exposure).subscription).display_name,
    "SB Gateway",
  );
  const configuredHappProviderId = asText(
    asObject(asObject(config.public_exposure).subscription).happ_provider_id,
    "",
  );
  const configuredSubscriptionEndpointMode = asText(
    asObject(config.ingress).subscription_endpoint_mode,
    "separate",
  );
  const configuredSubscriptionEndpointEnabled =
    asObject(config.ingress).subscription_endpoint_enabled !== false;
  const configuredSubscriptionTransportId = asText(
    asObject(config.ingress).subscription_transport_id,
    "",
  );
  const configuredSubscriptionDeploymentId = asText(
    asObject(config.ingress).subscription_deployment_id,
    "",
  );
  const configuredSubscriptionPrimaryEndpoint = asText(
    asObject(config.ingress).subscription_primary_endpoint,
    "cdn",
  );
  const configuredSubscriptionOriginProtectionMode = asText(
    asObject(config.ingress).subscription_origin_protection_mode,
    configuredSubscriptionCdnProvider === "cloudflare"
      ? "auto-cidr"
      : "secret-header",
  );
  const configuredSubscriptionOriginHeaderRef = asText(
    asObject(config.ingress).subscription_origin_header_secret_ref,
    "",
  );
  const configuredTlsProfiles = asObjectList(config.tls_profiles).map((profile) => {
    const status = asObject(certificateStatus[asText(profile.id, "")]);
    const metadata = asObject(status.metadata);
    return asText(profile.certificate_secret_ref, "").endsWith("/acme-bundle.pem") && metadata.not_after
      ? { ...profile, certificate_metadata: metadata }
      : profile;
  });
  const configuredSubscriptionTlsProfile = configuredTlsProfiles.find(
    (profile) => asText(profile.id, "") === configuredSubscriptionTlsProfileId,
  );
  const configuredSubscriptionDirectHostname = ["direct", "direct-and-cdn"].includes(
    configuredSubscriptionEndpointMode,
  )
    ? configuredSubscriptionHostname
    : configuredSubscriptionEndpointMode === "separate"
      ? configuredSubscriptionOriginServerName
      : "";
  const configuredSubscriptionCdnHostname = configuredSubscriptionCdnHostnameValue ||
    (configuredSubscriptionEndpointMode === "separate"
      ? configuredSubscriptionHostname
      : "");
  const initialSubscriptionHostname = hostnameForTLSProfileInitialization(
    configuredSubscriptionTlsProfile,
    configuredSubscriptionDirectHostname,
    !configuredSubscriptionDirectHostname,
  );
  const initialSubscriptionOriginServerName = hostnameForTLSProfileInitialization(
    configuredSubscriptionTlsProfile,
    configuredSubscriptionOriginServerName,
    configuredSubscriptionEndpointMode === "separate" &&
      !configuredSubscriptionOriginServerName,
  );
  const [subscriptionOriginPort, setSubscriptionOriginPort] = useState(
    configuredSubscriptionOriginPort,
  );
  const [subscriptionPublicPort, setSubscriptionPublicPort] = useState(
    configuredSubscriptionPublicPort,
  );
  const [subscriptionHostname, setSubscriptionHostname] = useState(
    initialSubscriptionHostname,
  );
  const [subscriptionCdnHostname, setSubscriptionCdnHostname] = useState(
    configuredSubscriptionCdnHostname,
  );
  const [subscriptionOriginServerName, setSubscriptionOriginServerName] =
    useState(initialSubscriptionOriginServerName);
  const [subscriptionTlsProfileId, setSubscriptionTlsProfileId] = useState(
    configuredSubscriptionTlsProfileId,
  );
  const [subscriptionCdnProvider, setSubscriptionCdnProvider] = useState(
    configuredSubscriptionCdnProvider,
  );
  const [subscriptionEndpointMode, setSubscriptionEndpointMode] = useState(
    configuredSubscriptionEndpointMode,
  );
  const [subscriptionEndpointEnabled, setSubscriptionEndpointEnabled] = useState(
    configuredSubscriptionEndpointEnabled,
  );
  const [subscriptionPrimaryEndpoint, setSubscriptionPrimaryEndpoint] = useState(
    configuredSubscriptionPrimaryEndpoint,
  );
  const [subscriptionDeploymentSelection, setSubscriptionDeploymentSelection] =
    useState(
      configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
        ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
        : configuredSubscriptionCdnHostname
          ? "subscription-cdn"
          : "",
    );
  const [subscriptionDisplayName, setSubscriptionDisplayName] = useState(
    configuredSubscriptionDisplayName,
  );
  const [happProviderId, setHappProviderId] = useState(
    configuredHappProviderId,
  );
  const [subscriptionOriginProtectionMode, setSubscriptionOriginProtectionMode] =
    useState(configuredSubscriptionOriginProtectionMode);
  const [subscriptionOriginHeaderValue, setSubscriptionOriginHeaderValue] =
    useState(
      configuredSubscriptionOriginProtectionMode === "secret-header" &&
        !configuredSubscriptionOriginHeaderRef
        ? generateOriginHeaderSecret()
        : "",
    );
  const [cloudflarePortBusy, setCloudflarePortBusy] = useState(false);
  const [cloudflarePortMessage, setCloudflarePortMessage] = useState("");
  const [subscriptionProbeBusy, setSubscriptionProbeBusy] = useState(false);
  const [subscriptionProbeResult, setSubscriptionProbeResult] = useState("");
  function openSubscriptionEndpointDialog() {
    setSubscriptionOriginPort(configuredSubscriptionOriginPort);
    setSubscriptionPublicPort(configuredSubscriptionPublicPort);
    setSubscriptionHostname(initialSubscriptionHostname);
    setSubscriptionCdnHostname(configuredSubscriptionCdnHostname);
    setSubscriptionOriginServerName(initialSubscriptionOriginServerName);
    setSubscriptionTlsProfileId(configuredSubscriptionTlsProfileId);
    setSubscriptionCdnProvider(configuredSubscriptionCdnProvider);
    setSubscriptionEndpointMode(configuredSubscriptionEndpointMode);
    setSubscriptionEndpointEnabled(configuredSubscriptionEndpointEnabled);
    setSubscriptionPrimaryEndpoint(configuredSubscriptionPrimaryEndpoint);
    setSubscriptionDeploymentSelection(
      configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
        ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
        : configuredSubscriptionCdnHostname
          ? "subscription-cdn"
          : "",
    );
    setSubscriptionDisplayName(configuredSubscriptionDisplayName);
    setHappProviderId(configuredHappProviderId);
    setSubscriptionOriginProtectionMode(configuredSubscriptionOriginProtectionMode);
    setSubscriptionOriginHeaderValue(
      configuredSubscriptionOriginProtectionMode === "secret-header" &&
        !configuredSubscriptionOriginHeaderRef
        ? generateOriginHeaderSecret()
        : "",
    );
    setCloudflarePortMessage("");
    setSubscriptionProbeResult("");
    setSubscriptionEndpointDialogOpen(true);
  }
  useEffect(() => {
    if (!subscriptionEndpointDialogOpen) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const frame = window.requestAnimationFrame(() => {
      subscriptionEndpointBodyRef.current?.scrollTo({ top: 0 });
    });
    return () => {
      window.cancelAnimationFrame(frame);
      document.body.style.overflow = previousOverflow;
    };
  }, [subscriptionEndpointDialogOpen]);
  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setSubscriptionOriginPort((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionOriginPort,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionPublicPort((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionPublicPort,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionHostname((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          initialSubscriptionHostname,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionCdnHostname((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionCdnHostname,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionOriginServerName((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          initialSubscriptionOriginServerName,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionTlsProfileId((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionTlsProfileId,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionCdnProvider((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionCdnProvider,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionEndpointMode((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionEndpointMode,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionEndpointEnabled((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionEndpointEnabled,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionPrimaryEndpoint((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionPrimaryEndpoint,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionDeploymentSelection((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
            ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
            : configuredSubscriptionCdnHostname
              ? "subscription-cdn"
              : "",
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionDisplayName((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionDisplayName,
          subscriptionEndpointDialogOpen,
        ),
      );
      setHappProviderId((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredHappProviderId,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionOriginProtectionMode((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionOriginProtectionMode,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionOriginHeaderValue((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          "",
          subscriptionEndpointDialogOpen,
        ),
      );
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [
    initialSubscriptionHostname,
    initialSubscriptionOriginServerName,
    configuredSubscriptionCdnHostname,
    configuredSubscriptionOriginPort,
    configuredSubscriptionPublicPort,
    configuredSubscriptionCdnProvider,
    configuredSubscriptionTlsProfileId,
    configuredSubscriptionEndpointMode,
    configuredSubscriptionEndpointEnabled,
    configuredSubscriptionPrimaryEndpoint,
    configuredSubscriptionTransportId,
    configuredSubscriptionDeploymentId,
    configuredSubscriptionDisplayName,
    configuredHappProviderId,
    configuredSubscriptionOriginProtectionMode,
    subscriptionEndpointDialogOpen,
  ]);
  const subscriptionHostnameCandidates = subscriptionEndpointUsesTLSHostname(
    subscriptionEndpointMode,
  )
    ? tlsConcreteHostnames(
        configuredTlsProfiles.find(
          (profile) => asText(profile.id, "") === subscriptionTlsProfileId,
        ),
      )
    : [];
  const subscriptionHostnameDatalistId = "subscription-endpoint-tls-dns-names";
  const subscriptionOriginDatalistId = "subscription-endpoint-origin-tls-dns-names";
  const subscriptionOriginHostnameCandidates =
    subscriptionEndpointMode === "separate"
      ? tlsConcreteHostnames(
          configuredTlsProfiles.find(
            (profile) => asText(profile.id, "") === subscriptionTlsProfileId,
          ),
        )
      : [];
  function selectSubscriptionTlsProfile(profileId: string) {
    const profile = configuredTlsProfiles.find(
      (item) => asText(item.id, "") === profileId,
    );
    setSubscriptionTlsProfileId(profileId);
    setSubscriptionHostname((current) =>
      hostnameAfterTLSProfileChange(profile, current),
    );
    if (subscriptionEndpointMode === "separate") {
      setSubscriptionOriginServerName((current) =>
        hostnameAfterTLSProfileChange(profile, current),
      );
    }
    setCloudflarePortMessage("");
  }
  const configuredTransports = asObjectList(config.transports);
  const subscriptionDeploymentOptions = configuredTransports.flatMap(
    (transport) =>
      ["ws", "grpc", "httpupgrade", "xhttp"].includes(
        asText(transport.kind, ""),
      )
        ? cdnDeploymentsForTransport(transport)
            .filter(
              (deployment) =>
                deployment.enabled !== false &&
                Boolean(asText(deployment.hostname, "").trim()),
            )
            .map((deployment) => ({
              value: `${asText(transport.id, "")}::${asText(deployment.id, "")}`,
              label: `${transportKindLabel(asText(transport.kind, ""))} · ${asText(deployment.display_name, "CDN")} · ${asText(deployment.hostname, "")}`,
              hostname: asText(deployment.hostname, ""),
              port: Number(deployment.listen_port ?? 443),
              serverName: asText(
                deployment.tls_server_name,
                asText(deployment.hostname, ""),
              ),
              transportId: asText(transport.id, ""),
              deploymentId: asText(deployment.id, ""),
            }))
        : [],
  );
  const selectedSubscriptionDeployment = subscriptionDeploymentOptions.find(
    (option) => option.value === subscriptionDeploymentSelection,
  );
  const subscriptionUsesDedicatedCdn =
    subscriptionEndpointMode === "direct-and-cdn" &&
    subscriptionDeploymentSelection === "subscription-cdn";
  const subscriptionHasEditablePublicCdnPort =
    subscriptionEndpointMode === "separate" || subscriptionUsesDedicatedCdn;
  const subscriptionHasDedicatedHttpsEndpoint = [
    "separate",
    "direct",
    "direct-and-cdn",
  ].includes(subscriptionEndpointMode);
  const subscriptionTcpPortConflicts = configuredTransports
    .filter(
      (transport) =>
        transport.enabled !== false &&
        ["reality", "reality-grpc", "grpc-tls", "xhttp-reality"].includes(
          asText(transport.kind, ""),
        ) &&
        Number(transport.listen_port) === subscriptionOriginPort &&
        !asText(transport.wan_destination_address, "").trim(),
    )
    .map((transport) => transportKindLabel(transport.kind));
  const configuredSubscriptionDeployment = subscriptionDeploymentOptions.find(
    (option) =>
      option.value ===
      (configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
        ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
        : ""),
  );
  const configuredDualCdnHostname = configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
    ? configuredSubscriptionDeployment?.hostname || ""
    : configuredSubscriptionCdnHostname;
  const subscriptionEndpointSummaryHost =
    configuredSubscriptionEndpointMode === "reuse-cdn"
      ? configuredSubscriptionDeployment?.hostname || tr("CDN-домен не выбран")
      : configuredSubscriptionEndpointMode === "direct-and-cdn"
        ? `${configuredSubscriptionHostname || tr("Прямой домен не задан")} + ${configuredDualCdnHostname || tr("CDN-домен не выбран")}`
        : configuredSubscriptionHostname || tr("Домен не настроен");
  const configuredSubscriptions = asObjectList(config.subscriptions);
  const configuredSubscriptionReserves = asObjectList(
    config.subscription_reserves,
  );
  const subscriptionIdsKey = configuredSubscriptions
    .map((subscription) => asText(subscription.id, ""))
    .filter(Boolean)
    .sort()
    .join("|");
  useEffect(() => {
    let active = true;
    const ids = subscriptionIdsKey.split("|").filter(Boolean);
    let inFlight = false;
    const refresh = async () => {
      if (document.visibilityState !== "visible" || inFlight || !ids.length) return;
      inFlight = true;
      try {
        const response = await getSubscriptionMetadata<JsonObject>();
        const entries = asObject(response.subscriptions) as Record<string, JsonObject>;
        if (active) {
          setSubscriptionMetadata((current) => mergeSubscriptionMetadata(current,
            Object.fromEntries(ids.map((id) => [id, entries[id] ?? { provider: {} }])), ids));
          setSubscriptionMetadataError(false);
        }
      } catch {
        if (active) setSubscriptionMetadataError(true);
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const timer = window.setInterval(refresh, 30_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [subscriptionIdsKey, setSubscriptionMetadata]);
  const tlsProfilesById = new Map(
    configuredTlsProfiles.map((profile) => [asText(profile.id, ""), profile]),
  );
  const kindNames: Record<string, string> = {
    ws: "WebSocket + TLS",
    grpc: "gRPC + TLS",
    "grpc-tls": "VLESS + gRPC + TLS Pin",
    httpupgrade: "HTTPUpgrade + TLS",
    xhttp: "XHTTP + TLS",
    "xhttp-reality": "VLESS + XHTTP + REALITY",
    reality: "VLESS + REALITY + Vision",
    "reality-grpc": "VLESS + gRPC + REALITY",
    hysteria2: "Hysteria 2",
  };
  const transportRows = configuredTransports.length
    ? configuredTransports.map((transport) => {
        const kind = asText(transport.kind, "");
        const enabled = transport.enabled !== false;
        const cdnDeployments = ["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)
          ? cdnDeploymentsForTransport(transport).filter(
              (deployment) => deployment.enabled !== false,
            )
          : [];
        const profile = tlsProfilesById.get(
          asText(transport.tls_profile_id, ""),
        );
        const cdnProfiles = cdnDeployments.map((deployment) =>
          tlsProfilesById.get(
            asText(
              deployment.tls_profile_id,
              asText(transport.tls_profile_id, ""),
            ),
          ),
        );
        const cdnProfileNames = [
          ...new Set(
            cdnProfiles
              .filter((item): item is JsonObject => Boolean(item))
              .map((item) => itemName(item)),
          ),
        ];
        const tlsKind = [
          "ws",
          "grpc",
          "grpc-tls",
          "httpupgrade",
          "xhttp",
          "hysteria2",
        ].includes(kind);
        const tlsReady = cdnDeployments.length
          ? cdnProfiles.length > 0 && cdnProfiles.every((item) => Boolean(
              item &&
                asText(item.certificate_secret_ref, "") &&
                asText(item.private_key_secret_ref, ""),
            ))
          : Boolean(
              profile &&
                asText(profile.certificate_secret_ref, "") &&
                asText(profile.private_key_secret_ref, ""),
            );
        const tlsSummary = cdnDeployments.length
          ? cdnProfileNames.length
            ? cdnProfileNames.join(" + ")
            : tr("профиль не выбран")
          : profile
            ? itemName(profile)
            : tr("профиль не выбран");
        const port = asText(
          transport.listen_port,
          kind === "reality"
            ? "2443"
            : kind === "reality-grpc"
              ? "2444"
              : kind === "grpc-tls"
                ? "2445"
                : kind === "xhttp-reality"
                  ? "2446"
                  : String(configuredPublicPort),
        );
        const cdnProvider = cdnDeployments.length
          ? [...new Set(cdnDeployments.map((deployment) => cdnProviderName(deployment.cdn_provider)))].join(" + ")
          : cdnProviderName(transport.cdn_provider);
        const xhttpMode = asText(
          transport.mode,
          kind === "xhttp-reality" ? "auto" : "packet-up",
        );
        const xhttpUplinkMethod = asText(
          transport.uplink_http_method,
          xhttpMode === "packet-up" ? "GET" : "POST",
        ).toUpperCase();
        const xhttpVision = transport.vless_encryption_enabled === true;
        return {
          id: asText(transport.id, kind || "transport"),
          name: kindNames[kind] ?? itemName(transport),
          host: cdnDeployments.length
            ? cdnDeployments
                .map(
                  (deployment) =>
                    `${asText(deployment.hostname, tr("hostname не задан"))}:${asText(deployment.listen_port, "443")}`,
                )
                .join(" · ")
            : `${connectionHostname(transport)}:${port}`,
          status:
            enabled && tlsKind && !tlsReady
              ? tr("Нужен TLS-профиль")
                : configuredItemStatus(
                  enabled,
                  revisionState,
                    tr("Выключен"),
                    locale,
                ),
          detail:
            kind === "reality"
              ? tr("VLESS/TCP · XTLS Vision · REALITY · прямой вход")
              : kind === "reality-grpc"
                ? tr("gRPC/HTTP2 + REALITY · без Vision · прямой вход")
                : kind === "grpc-tls"
                  ? tr("gRPC/HTTP2 · TLS Pin · прямой вход")
                  : kind === "xhttp-reality"
                    ? `XHTTP ${xhttpMode} + REALITY · ${xhttpUplinkMethod} uplink${xhttpVision ? tr(" · Vision с VLESS Encryption") : ""}`
                    : kind === "hysteria2"
                      ? `QUIC/UDP · ${profile ? itemName(profile) : tr("профиль не выбран")}`
                      : kind === "xhttp"
                        ? tr("{value1} · {value2} CDN-развёрт. · TLS · XHTTP {value3} · {value4}", { value1: cdnProvider, value2: cdnDeployments.length, value3: xhttpMode, value4: tlsSummary })
                        : kind === "httpupgrade"
                          ? tr("{value1} · {value2} CDN-развёрт. · TLS · HTTPUpgrade · {value3}", { value1: cdnProvider, value2: cdnDeployments.length, value3: tlsSummary })
                          : kind === "grpc"
                            ? tr("{value1} · {value2} CDN-развёрт. · TLS · HTTP/2 · {value3}", { value1: cdnProvider, value2: cdnDeployments.length, value3: tlsSummary })
                            : kind === "ws"
                              ? tr("{value1} · {value2} CDN-развёрт. · TLS · {value3}", { value1: cdnProvider, value2: cdnDeployments.length, value3: tlsSummary })
                              : tr("Прямое подключение"),
          group: ["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)
            ? "cdn"
            : ["reality", "reality-grpc", "xhttp-reality"].includes(kind)
              ? "reality"
              : "direct-tls",
          tlsProfile: cdnDeployments.length ? tlsSummary : profile ? itemName(profile) : "",
          tlsExpiry:
            cdnProfiles.length === 1 && cdnProfiles[0]
              ? tlsProfileExpiry(cdnProfiles[0], locale)
              : profile
                ? tlsProfileExpiry(profile, locale)
                : "",
          tone:
            enabled && tlsKind && !tlsReady
              ? ("warn" as Tone)
              : configuredItemTone(enabled, revisionState),
        };
      })
    : [];
  const transportGroups = [
    {
      id: "cdn",
      title: tr("Через CDN + TLS"),
    },
    {
      id: "reality",
      title: tr("Прямые + REALITY"),
    },
    {
      id: "direct-tls",
      title: tr("Прямые TLS / QUIC"),
    },
  ];
  const subscriptionRows = configuredSubscriptions.map((subscription) => ({
         id: asText(subscription.id, "unknown"),
         name: itemName(subscription),
         last: subscriptionIntervalText(subscription, locale),
         expiry: subscriptionMetadata[asText(subscription.id, "")]
           ? expiryText(asObject(subscriptionMetadata[asText(subscription.id, "")].provider).expires_at, locale)
           : subscriptionMetadataError ? tr("Повторная загрузка срока…") : tr("Загрузка срока…"),
         enabled: subscription.enabled !== false,
      }));
  const [tlsTransfer, setTlsTransfer] = useState<{ id: string; name: string } | "import" | null>(null);
  const tlsProfileRows = configuredTlsProfiles.map((profile) => {
    const id = asText(profile.id, "");
    const metadata = asObject(profile.certificate_metadata);
    const usedByLabels = configuredTransports.flatMap((transport) => {
      if (transport.enabled === false) return [];
      const kind = asText(transport.kind, "");
      if (["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)) {
        return cdnDeploymentsForTransport(transport)
          .filter((deployment) =>
            deployment.enabled !== false &&
            asText(
              deployment.tls_profile_id,
              asText(transport.tls_profile_id, ""),
            ) === id,
          )
          .map(
            (deployment) =>
              `${transportKindLabel(kind)} / ${asText(deployment.display_name, "CDN")}`,
          );
      }
      return asText(transport.tls_profile_id, "") === id
        ? [transportKindLabel(kind)]
        : [];
    });
    if (configuredCloudflareTlsProfileId === id && configuredStatusHostname) {
      usedByLabels.unshift(tr("Внешний status / health"));
    }
    if (configuredSubscriptionEndpointEnabled && configuredSubscriptionTlsProfileId === id) {
      usedByLabels.unshift(tr("Клиентская подписка"));
    }
    const ready = Boolean(
      asText(profile.certificate_secret_ref, "") &&
        asText(profile.private_key_secret_ref, ""),
    );
    return {
      id,
      name: itemName(profile),
      ready,
      expiry: tlsProfileExpiry(profile, locale),
      renewalFailed: asObject(certificateStatus[id]).enabled === true && asObject(certificateStatus[id]).state === "failed" && asText(profile.certificate_secret_ref, "").endsWith("/acme-bundle.pem"),
      dnsNames: asStringList(metadata.dns_names),
      usedByLabels,
    };
  });

  async function saveSubscriptionEndpoint() {
    if (!subscriptionEndpointEnabled) {
      setCloudflarePortBusy(true);
      setCloudflarePortMessage("");
      try {
        await saveCurrentDraft({
          config: disableSubscriptionPublication(config),
        });
        await onDraftChanged();
        setCloudflarePortMessage(tr("Публикация подписки отключена."));
        setSubscriptionEndpointDialogOpen(false);
      } catch (error) {
        setCloudflarePortMessage(prefixedErrorMessage(error));
      } finally {
        setCloudflarePortBusy(false);
      }
      return;
    }
    const nextSubscriptionDisplayName = subscriptionDisplayName.trim();
    if (!nextSubscriptionDisplayName) {
      setCloudflarePortMessage(tr("Укажите имя подписки для клиентского приложения."));
      return;
    }
    const usesDedicatedSubscriptionCdn = subscriptionUsesDedicatedCdn;
    if (
      subscriptionEndpointMode === "reuse-cdn" ||
      (subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn)
    ) {
      const selected = subscriptionDeploymentOptions.find(
        (option) => option.value === subscriptionDeploymentSelection,
      );
      if (!selected) {
        setCloudflarePortMessage(tr("Выберите включённое CDN-развёртывание."));
        return;
      }
      if (subscriptionEndpointMode === "reuse-cdn") {
        setCloudflarePortBusy(true);
        setCloudflarePortMessage("");
        try {
          await saveCurrentDraft({
            config: withDeploymentReadiness(
              {
                ...config,
                ingress: {
                  ...asObject(config.ingress),
                  status_hostname: "",
                  subscription_endpoint_enabled: true,
                  subscription_endpoint_mode: "reuse-cdn",
                  subscription_cdn_hostname: "",
                  subscription_origin_server_name: "",
                  subscription_primary_endpoint: "cdn",
                  subscription_transport_id: selected.transportId,
                  subscription_deployment_id: selected.deploymentId,
                },
                public_exposure: {
                  ...asObject(config.public_exposure),
                  subscription: {
                    ...asObject(asObject(config.public_exposure).subscription),
                    display_name: nextSubscriptionDisplayName,
                    happ_provider_id: happProviderId.trim(),
                  },
                },
              },
              false,
            ),
          });
          await onDraftChanged();
          setCloudflarePortMessage(tr("Подписка использует выбранный CDN-домен. Секретный путь отделён от пути подключения."));
          setSubscriptionEndpointDialogOpen(false);
        } catch (error) {
          setCloudflarePortMessage(prefixedErrorMessage(error));
        } finally {
          setCloudflarePortBusy(false);
        }
        return;
      }
    }
    if (subscriptionHasEditablePublicCdnPort && subscriptionCdnProvider === "cloudflare" && !CLOUDFLARE_HTTPS_PORTS.includes(
      subscriptionPublicPort as (typeof CLOUDFLARE_HTTPS_PORTS)[number],
    )) {
      setCloudflarePortMessage(tr("Выберите поддерживаемый Cloudflare HTTPS-порт подписки."));
      return;
    }
    if (
      subscriptionHasDedicatedHttpsEndpoint &&
      subscriptionTcpPortConflicts.length
    ) {
      setCloudflarePortMessage(
        tr("TCP/{value1} origin уже занят прямым входом: {value2}. Выберите другой origin-порт или настройте общий TCP 443 с разными SNI.", { value1: subscriptionOriginPort, value2: subscriptionTcpPortConflicts.join(
          ", ",
        ) }),
      );
      return;
    }
    if (!Number.isInteger(subscriptionOriginPort) || subscriptionOriginPort < 1 || subscriptionOriginPort > 65535) {
      setCloudflarePortMessage(tr("TCP-порт origin должен быть целым числом от 1 до 65535."));
      return;
    }
    if (subscriptionHasEditablePublicCdnPort && (!Number.isInteger(subscriptionPublicPort) || subscriptionPublicPort < 1 || subscriptionPublicPort > 65535)) {
      setCloudflarePortMessage(tr("Публичный HTTPS-порт должен быть целым числом от 1 до 65535."));
      return;
    }
    if (!configuredTlsProfiles.some((profile) => asText(profile.id, "") === subscriptionTlsProfileId)) {
      setCloudflarePortMessage(tr("Выберите существующий TLS-профиль клиентской подписки."));
      return;
    }
    const nextSubscriptionDirectHostname = subscriptionHostname.trim().replace(/\.$/, "").toLowerCase();
    const nextSubscriptionCdnHostname = subscriptionCdnHostname.trim().replace(/\.$/, "").toLowerCase();
    const nextSubscriptionHostname = subscriptionEndpointMode === "separate"
      ? nextSubscriptionCdnHostname
      : nextSubscriptionDirectHostname;
    if (!nextSubscriptionHostname) {
      setCloudflarePortMessage(
        subscriptionEndpointMode === "separate"
          ? tr("Укажите домен раздачи CDN.")
          : tr("Укажите прямой домен клиентской подписки."),
      );
      return;
    }
    if (usesDedicatedSubscriptionCdn && !nextSubscriptionCdnHostname) {
      setCloudflarePortMessage(tr("Выберите или укажите CDN-домен клиентской подписки."));
      return;
    }
    const nextSubscriptionOriginServerName = subscriptionOriginServerName
      .trim()
      .replace(/\.$/, "")
      .toLowerCase();
    if ((subscriptionEndpointMode === "separate" || usesDedicatedSubscriptionCdn) && !nextSubscriptionOriginServerName) {
      setCloudflarePortMessage(tr("Укажите DNS-имя origin."));
      return;
    }
    if (usesDedicatedSubscriptionCdn && nextSubscriptionDirectHostname !== nextSubscriptionOriginServerName) {
      setCloudflarePortMessage(tr("Для текущего CDN прямой домен должен совпадать с origin: {value1}.", { value1: nextSubscriptionOriginServerName }));
      return;
    }
    setCloudflarePortBusy(true);
    setCloudflarePortMessage("");
    try {
      await saveCurrentDraft({
        config: withDeploymentReadiness(
          {
            ...config,
            ingress: {
              ...asObject(config.ingress),
              status_hostname: "",
              subscription_endpoint_enabled: true,
              subscription_hostname: nextSubscriptionHostname,
              subscription_cdn_hostname:
                subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn
                  ? ""
                  : nextSubscriptionCdnHostname,
              subscription_origin_server_name:
                subscriptionEndpointMode === "separate" || usesDedicatedSubscriptionCdn
                  ? nextSubscriptionOriginServerName
                  : asText(asObject(config.ingress).subscription_origin_server_name, ""),
              subscription_listen_port: subscriptionOriginPort,
              subscription_public_port: subscriptionHasEditablePublicCdnPort
                ? subscriptionPublicPort
                : subscriptionEndpointMode === "direct"
                  ? subscriptionOriginPort
                  : asObject(config.ingress).subscription_public_port ?? subscriptionOriginPort,
              subscription_tls_profile_id: subscriptionTlsProfileId,
              subscription_cdn_provider: subscriptionCdnProvider,
              subscription_endpoint_mode: subscriptionEndpointMode,
              subscription_primary_endpoint:
                subscriptionEndpointMode === "direct-and-cdn"
                  ? subscriptionPrimaryEndpoint
                  : subscriptionEndpointMode === "direct"
                    ? "direct"
                    : "cdn",
              subscription_transport_id:
                subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn
                  ? subscriptionDeploymentSelection.split("::")[0] ?? ""
                  : "",
              subscription_deployment_id:
                subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn
                  ? subscriptionDeploymentSelection.split("::")[1] ?? ""
                  : "",
              subscription_origin_protection_mode: subscriptionOriginProtectionMode,
              subscription_origin_header_name: "X-SB-Origin",
              subscription_origin_header_value:
                subscriptionEndpointMode === "separate" &&
                subscriptionOriginProtectionMode === "secret-header"
                  ? subscriptionOriginHeaderValue || undefined
                  : undefined,
            },
            public_exposure: {
              ...asObject(config.public_exposure),
              subscription: {
                ...asObject(asObject(config.public_exposure).subscription),
                display_name: nextSubscriptionDisplayName,
                happ_provider_id: happProviderId.trim(),
              },
            },
          },
          false,
        ),
      });
      await onDraftChanged();
      setCloudflarePortMessage(
        subscriptionEndpointMode === "direct"
          ? tr("Прямая HTTPS-ссылка сохранена на порту {value1}.", { value1: subscriptionOriginPort })
          : subscriptionEndpointMode === "direct-and-cdn"
            ? tr("Сохранены два адреса одной подписки: прямой HTTPS и выбранный CDN-домен.")
            : tr("Клиентская подписка сохранена: CDN {value1} → origin {value2}.", { value1: subscriptionPublicPort, value2: subscriptionOriginPort }),
      );
      setSubscriptionEndpointDialogOpen(false);
    } catch (error) {
      setCloudflarePortMessage(prefixedErrorMessage(error));
    } finally {
      setCloudflarePortBusy(false);
    }
  }

  async function checkSubscriptionTls() {
    const targets: Array<{ label: string; hostname: string; port: number; serverName: string }> = [];
    if (
      (subscriptionEndpointMode === "reuse-cdn" ||
        subscriptionEndpointMode === "direct-and-cdn") &&
      selectedSubscriptionDeployment
    ) {
      targets.push({
        label: "CDN",
        hostname: selectedSubscriptionDeployment.hostname,
        port: selectedSubscriptionDeployment.port,
        serverName: selectedSubscriptionDeployment.serverName,
      });
    }
    if (
      subscriptionEndpointMode === "direct-and-cdn" &&
      subscriptionDeploymentSelection === "subscription-cdn"
    ) {
      targets.push({
        label: "CDN",
        hostname: subscriptionCdnHostname.trim(),
        port: subscriptionPublicPort,
        serverName: subscriptionCdnHostname.trim(),
      });
    }
    if (subscriptionHasDedicatedHttpsEndpoint) {
      targets.push({
        label: subscriptionEndpointMode === "separate" ? tr("CDN-домен") : tr("Прямой адрес"),
        hostname: subscriptionEndpointMode === "separate"
          ? subscriptionCdnHostname.trim()
          : subscriptionHostname.trim(),
        port: subscriptionEndpointMode === "separate" ? subscriptionPublicPort : subscriptionOriginPort,
        serverName: subscriptionEndpointMode === "separate"
          ? subscriptionCdnHostname.trim()
          : subscriptionHostname.trim(),
      });
    }
    if (!targets.length || targets.some((target) => !target.hostname)) {
      setSubscriptionProbeResult(tr("Сначала укажите домен или выберите готовое CDN-развёртывание."));
      return;
    }
    setSubscriptionProbeBusy(true);
    setSubscriptionProbeResult("");
    try {
      const results = [];
      for (const target of targets) {
        const probe = await probeTlsEndpoint<JsonObject>(
          target.hostname,
          target.port,
          target.serverName,
        );
        results.push(
          tr("{value1}: {value2} · {value3} · сертификат: {value4}", { value1: target.label, value2: asStringList(probe.addresses).join(", "), value3: asText(probe.tls_version, "TLS"), value4: expiryText(probe.certificate_expires_at) }),
        );
      }
      setSubscriptionProbeResult(tr("{value1} Настройки аккаунта CDN проверяются отдельно через API провайдера.", { value1: results.join(" | ") }));
    } catch (error) {
      setSubscriptionProbeResult(prefixedErrorMessage(error));
    } finally {
      setSubscriptionProbeBusy(false);
    }
  }

  async function openNodeLocations(subscriptionId: string) {
    setNodeBusy(true);
    setSubscriptionMessage("");
    try {
      const result = await getSubscriptionNodes(subscriptionId);
      const rows = asObjectList(result.nodes);
      const values = Object.fromEntries(
        rows.map((node) => [asText(node.location_key, ""), asText(node.city, "")]),
      );
      setNodeSubscriptionId(subscriptionId);
      setNodeRows(rows);
      setNodeCities(values);
      setInitialNodeCities(values);
    } catch (error) {
      setSubscriptionMessage(prefixedErrorMessage(error));
    } finally {
      setNodeBusy(false);
    }
  }

  async function saveNodeLocations() {
    const subscription = configuredSubscriptions.find(
      (item) => asText(item.id, "") === nodeSubscriptionId,
    );
    if (!subscription) return;
    setNodeBusy(true);
    setSubscriptionMessage("");
    try {
      const overrides: JsonObject = { ...asObject(subscription.location_overrides) };
      for (const node of nodeRows) {
        const key = asText(node.location_key, "");
        if (!key || nodeCities[key] === initialNodeCities[key]) continue;
        const city = (nodeCities[key] ?? "").trim().replace(/\s+/g, " ");
        if (city) {
          overrides[key] = { ...asObject(overrides[key]), city };
        } else {
          delete overrides[key];
        }
      }
      await updateCollectionItem("subscriptions", nodeSubscriptionId, {
        ...subscription,
        location_overrides: overrides,
      });
      await onDraftChanged();
      setInitialNodeCities({ ...nodeCities });
      setSubscriptionMessage(tr("Города сохранены. Теперь их можно выбрать в маршрутном листе."));
    } catch (error) {
      setSubscriptionMessage(prefixedErrorMessage(error));
    } finally {
      setNodeBusy(false);
    }
  }

  function resetReserveEditor() {
    setEditingReserveId("");
    setReserveName("");
    setReserveLink("");
    setReserveMessage("");
    setReserveDialogOpen(false);
  }

  async function saveSubscriptionReserve(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const displayName = reserveName.trim();
    const link = reserveLink.trim();
    if (!displayName) {
      setReserveMessage(tr("Ошибка: укажите понятное имя резервного подключения."));
      return;
    }
    if (!editingReserveId && !link) {
      setReserveMessage(tr("Ошибка: вставьте одну ссылку VLESS."));
      return;
    }
    if (link && !link.toLowerCase().startsWith("vless://")) {
      setReserveMessage(tr("Ошибка: резерв должен быть одной ссылкой VLESS."));
      return;
    }
    if (!editingReserveId && configuredSubscriptionReserves.length >= 3) {
      setReserveMessage(tr("Ошибка: можно настроить не более трёх независимых резервов."));
      return;
    }
    const reserveId =
      editingReserveId ||
      entityIdFromName(
        displayName,
        new Set(
          configuredSubscriptionReserves.map((item) => asText(item.id, "")),
        ),
        "subscription-reserve",
      );
    const existing =
      configuredSubscriptionReserves.find(
        (item) => asText(item.id, "") === reserveId,
      ) ?? {};
    const item: JsonObject = {
      ...existing,
      id: reserveId,
      display_name: displayName,
      enabled: true,
      ...(link ? { link } : {}),
    };
    setReserveBusy(true);
    setReserveMessage("");
    try {
      if (editingReserveId) {
        await updateCollectionItem(
          "subscription-reserves",
          reserveId,
          item,
        );
      } else {
        await createCollectionItem("subscription-reserves", item);
      }
      await onDraftChanged();
      setReserveMessage(tr("Резервный VLESS сохранён. Для включения примените изменения."));
      setEditingReserveId("");
      setReserveName("");
      setReserveLink("");
      setReserveDialogOpen(false);
    } catch (error) {
      setReserveMessage(prefixedErrorMessage(error));
    } finally {
      setReserveBusy(false);
    }
  }

  async function removeSubscriptionReserve(reserveId: string) {
    setReserveBusy(true);
    setReserveMessage("");
    try {
      await deleteCollectionItem("subscription-reserves", reserveId);
      await onDraftChanged();
      if (editingReserveId === reserveId) resetReserveEditor();
      setReserveMessage(tr("Резервный VLESS удалён. Для включения примените изменения."));
    } catch (error) {
      setReserveMessage(prefixedErrorMessage(error));
    } finally {
      setReserveBusy(false);
    }
  }

  return (
    <>
      <SectionTitle
        title={tr("Подключения")}
      />

      <div className="transport-groups">
        {!configuredTransports.length ? (
          <aside className="notice notice-neutral">
            <span className="notice-icon">i</span>
            <div>
              <strong>{tr("Транспорты ещё не сохранены")}</strong>
              <p>{tr("Запустите мастер первого запуска, чтобы создать фактический набор серверных протоколов.")}</p>
            </div>
          </aside>
        ) : null}
        {transportGroups.map((group) => {
          const rows = transportRows.filter(
            (transport) => transport.group === group.id,
          );
          if (!rows.length && group.id !== "cdn") return null;
          return (
            <section className="transport-group" key={group.id}>
              <div className="transport-group-heading">
                <h3>{group.title}</h3>
              </div>
              {group.id === "cdn" ? (
                <article className="card transport-card settings-launch-card">
                  <div className="transport-summary">
                    <div className="transport-title">
                      <h3>{tr("HTTPS-ссылка клиентской подписки")}</h3>
                      <code>{subscriptionEndpointSummaryHost}</code>
                    </div>
                    <div className="transport-detail">
                      <span
                        className={`signal-dot signal-${configuredSubscriptionHostname ? "ok" : "warn"}`}
                        aria-hidden="true"
                      />
                      <span>
                        {configuredSubscriptionEndpointMode === "reuse-cdn"
                          ? tr("Домен существующего CDN-развёртывания")
                          : configuredSubscriptionEndpointMode === "direct"
                            ? tr("Прямая HTTPS-ссылка")
                            : configuredSubscriptionEndpointMode === "direct-and-cdn"
                              ? tr("Два адреса · CDN и прямой HTTPS")
                              : tr("Отдельный CDN-домен · {value1}", { value1: cdnProviderName(configuredSubscriptionCdnProvider) })}
                        {` · ${configuredSubscriptionDisplayName}`}
                      </span>
                    </div>
                  </div>
                  <div className="transport-actions">
                    <StatusPill tone={!subscriptionEndpointSummaryHost.includes(tr("не ")) && !subscriptionEndpointSummaryHost.includes(tr("не выбран")) ? "ok" : "warn"}>
                      {!subscriptionEndpointSummaryHost.includes(tr("не ")) && !subscriptionEndpointSummaryHost.includes(tr("не выбран")) ? tr("Настроено") : tr("Не настроено")}
                    </StatusPill>
                    <button
                      className="button button-tertiary"
                      type="button"
                      onClick={openSubscriptionEndpointDialog}
                    >
                       {tr("Настроить")} </button>
                  </div>
                </article>
              ) : null}
              <div className="transport-grid">
                {rows.map((transport) => (
                  <article
                    className="card transport-card"
                    key={transport.id}
                  >
                    <div className="transport-summary">
                      <div className="transport-title">
                        <h3>{transport.name}</h3>
                        <code>{transport.host}</code>
                      </div>
                      <div className="transport-detail">
                        <span
                          className={`signal-dot signal-${transport.tone}`}
                          aria-hidden="true"
                        />
                        <span>{transport.detail}</span>
                      </div>
                    </div>
                    <div className="transport-actions">
                      <StatusPill tone={transport.tone}>
                        {transport.status}
                      </StatusPill>
                      <button
                        className="button button-tertiary"
                        onClick={() => onConfigureTransport(transport.id)}
                      >
                        {transport.status === "Выключен"
                          ? tr("Подготовить")
                          : tr("Настроить")}
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          );
        })}
      </div>

      <section className="tls-profile-panel">
        <div className="entity-section-heading">
          <div>
            <h3>{tr("TLS-профили")}</h3>
          </div>
          <div className="panel-heading-actions">
            <button className="button button-secondary button-compact" type="button" onClick={() => setTlsTransfer("import")}>
               {tr("Импорт")} </button>
            <button className="button button-secondary button-compact" type="button" onClick={onAddTlsProfile}>
               {tr("+ Добавить TLS-профиль")} </button>
          </div>
        </div>
        <div className="transport-grid">
          {tlsProfileRows.map((profile) => (
            <article className="card transport-card settings-launch-card" key={profile.id}>
              <div className="transport-summary">
                <div className="transport-title">
                  <h3>{profile.name}</h3>
                  <code>{profile.dnsNames.length ? profile.dnsNames.join(", ") : tr("Домены не определены")}</code>
                </div>
                <div className="transport-detail">
                  <span className={`signal-dot signal-${profile.ready ? "ok" : "warn"}`} aria-hidden="true" />
                  <span>
                    {profile.usedByLabels.length
                      ? tr("Используется: {value1}", { value1: russianCount(profile.usedByLabels.length, [tr("подключение"), tr("подключения"), tr("подключений")]) })
                      : tr("Не используется")}
                  </span>
                </div>
              </div>
              <div className="transport-actions">
                <StatusPill tone={profile.renewalFailed ? "danger" : profile.ready ? "ok" : "warn"}>
                  {profile.renewalFailed ? tr("Ошибка продления") : profile.ready
                    ? profile.expiry === "срок не определён"
                      ? tr("Срок не определён")
                      : tr("До {value1}", { value1: profile.expiry })
                    : tr("Нужна TLS-пара")}
                </StatusPill>
                <button className="button button-tertiary" type="button" onClick={() => onEditTlsProfile(profile.id)}>
                   {tr("Настроить")} </button>
              </div>
            </article>
          ))}
          {!tlsProfileRows.length ? <div className="empty-result">{tr("TLS-профилей пока нет.")}</div> : null}
        </div>
      </section>

      {tlsTransfer ? <TlsTransferDialog profile={tlsTransfer === "import" ? undefined : tlsTransfer} onClose={() => setTlsTransfer(null)} onImported={onDraftChanged} /> : null}
      <section className="subscriptions-grid">
        <article className="card panel-card">
          <div className="panel-heading">
            <div>
              <h3>{tr("Подписки")}</h3>
            </div>
            <div className="panel-heading-actions">
              <StatusPill tone={configuredSubscriptions.length ? "info" : "muted"}>
                {configuredSubscriptions.length
                  ? russianCount(configuredSubscriptions.length, [tr("подписка"), tr("подписки"), tr("подписок")])
                  : tr("Не настроено")}
              </StatusPill>
              <button
                className="button button-primary button-compact subscription-add-button"
                type="button"
                onClick={onAddSubscription}
              >
                 {tr("+ Добавить")} </button>
            </div>
          </div>
          {subscriptionRows.map((subscription) => (
            <div className="subscription-row" key={subscription.id}>
              <div className="subscription-logo">
                {subscription.name.slice(0, 1).toUpperCase()}
              </div>
              <div className="subscription-summary">
                <strong>{subscription.name}</strong>
                <small>{subscription.expiry}</small>
              </div>
              <div className="subscription-schedule">
                <small>{tr("Автопроверка")}</small>
                <strong>{subscription.last}</strong>
              </div>
              <details className="subscription-action-menu">
                <summary className="button button-secondary button-compact">
                   {tr("Действия")} </summary>
                <div className="subscription-action-popover">
                  <button
                  type="button"
                  disabled={
                    !subscription.enabled ||
                    Boolean(subscriptionBusy)
                  }
                  onClick={async (event) => {
                    event.currentTarget.closest("details")?.removeAttribute("open");
                    setSubscriptionBusy(subscription.id);
                    setSubscriptionMessage(
                      tr("Обновляю {value1}…", { value1: subscription.name }),
                    );
                    try {
                      const result = await refreshSubscription<JsonObject>(subscription.id);
                      setSubscriptionMetadata((current) => mergeSubscriptionMetadata(current, {
                        [subscription.id]: { provider: asObject(result.provider), refreshed_at: result.refreshed_at },
                      }, subscriptionIdsKey.split("|").filter(Boolean)));
                      await onDraftChanged();
                      setSubscriptionMessage(
                        resultMessage(
                          result,
                          tr("Candidate подписки проверен локальным control plane."),
                        ),
                      );
                    } catch (error) {
                      setSubscriptionMessage(prefixedErrorMessage(error));
                    } finally {
                      setSubscriptionBusy("");
                    }
                  }}
                >
                  {subscriptionBusy === subscription.id
                      ? tr("Проверяю…")
                      : subscription.enabled
                        ? tr("Проверить сейчас")
                        : tr("Подписка выключена")}
                  </button>
                  <button
                  type="button"
                  disabled={nodeBusy}
                  onClick={(event) => {
                    event.currentTarget.closest("details")?.removeAttribute("open");
                    openNodeLocations(subscription.id);
                  }}
                >
                   {tr("Узлы и города")} </button>
                  <button
                  type="button"
                  onClick={(event) => {
                    event.currentTarget.closest("details")?.removeAttribute("open");
                    onEditSubscription(subscription.id);
                  }}
                >
                   {tr("Настроить")} </button>
                </div>
              </details>
            </div>
          ))}
          {!subscriptionRows.length ? (
            <div className="empty-result">
               {tr("Подписок пока нет. Добавьте HTTPS-подписку кнопкой выше.")} </div>
          ) : null}
          {nodeSubscriptionId ? (
            <section className="node-location-editor">
              <div className="node-location-heading">
                <div>
                  <strong>{tr("Города узлов ·")} {nodeSubscriptionId}</strong>
                  <small>{tr("Исправьте только неизвестные или неверно определённые города.")}</small>
                </div>
                <button className="button button-tertiary" type="button" onClick={() => setNodeSubscriptionId("")}>{tr("Закрыть")}</button>
              </div>
              {nodeRows.map((node) => {
                const key = asText(node.location_key, "");
                return (
                  <label className="node-location-row" key={asText(node.id, key)}>
                    <span>
                      <strong>{asText(node.label, asText(node.id))}</strong>
                      <small>{asText(node.country, "??")} · {asText(node.transport, "tcp")}  {tr("· ключ")} {key}</small>
                    </span>
                    <input
                      value={nodeCities[key] ?? ""}
                      onChange={(event) => setNodeCities((current) => ({ ...current, [key]: event.target.value }))}
                      placeholder={tr("Город")}
                      maxLength={256}
                    />
                  </label>
                );
              })}
              {!nodeRows.length ? (
                <aside className="notice notice-neutral">
                  <span className="notice-icon">i</span>
                  <div><strong>{tr("Узлов пока нет")}</strong><p>{tr("Сначала нажмите «Проверить сейчас», затем откройте этот список снова.")}</p></div>
                </aside>
              ) : (
                <div className="node-location-actions">
                  <button className="button button-primary" type="button" onClick={saveNodeLocations} disabled={nodeBusy}>
                    {nodeBusy ? tr("Сохраняю…") : tr("Сохранить города")}
                  </button>
                </div>
              )}
            </section>
          ) : null}
          {subscriptionMessage ? (
            <div
              className={`inline-result ${
                isErrorMessage(subscriptionMessage)
                  ? "inline-result-error"
                  : ""
              }`}
              role={isErrorMessage(subscriptionMessage) ? "alert" : "status"}
            >
              <span>
                {subscriptionBusy
                  ? "↻"
                  : isErrorMessage(subscriptionMessage)
                    ? "!"
                    : "✓"}
              </span>
              {subscriptionMessage}
            </div>
          ) : null}
        </article>
        <article className="card panel-card subscription-reserve-panel">
          <div className="panel-heading">
            <div>
              <h3>{tr("Независимые VLESS")}</h3>
            </div>
            <div className="panel-heading-actions">
              <StatusPill tone={configuredSubscriptionReserves.length ? "info" : "muted"}>
                {configuredSubscriptionReserves.length}  {tr("из 3")} </StatusPill>
              <button
                className="button button-secondary button-compact"
                type="button"
                disabled={reserveBusy || configuredSubscriptionReserves.length >= 3}
                onClick={() => {
                  setEditingReserveId("");
                  setReserveName("");
                  setReserveLink("");
                  setReserveMessage("");
                  setReserveDialogOpen(true);
                }}
              >
                 {tr("+ Добавить резерв")} </button>
            </div>
          </div>
          <div className="subscription-reserve-list">
            {configuredSubscriptionReserves.map((reserve) => {
              const reserveId = asText(reserve.id, "");
              const node = asObject(reserve.node);
              const server = asText(node.server, tr("Сервер не определён"));
              const port = asText(node.server_port, "");
              return (
                <article className="card transport-card settings-launch-card" key={reserveId}>
                  <div className="transport-summary">
                    <div className="transport-title">
                      <h3>{itemName(reserve)}</h3>
                      <code>{server}{port ? `:${port}` : ""}</code>
                    </div>
                    <div className="transport-detail">
                      <span className="signal-dot signal-ok" aria-hidden="true" />
                      <span>{tr("Независимый VLESS · UUID скрыт")}</span>
                    </div>
                  </div>
                  <div className="transport-actions">
                    <StatusPill tone="ok">{tr("Настроено")}</StatusPill>
                    <button
                      className="button button-tertiary"
                      type="button"
                      disabled={reserveBusy}
                      onClick={() => {
                        setEditingReserveId(reserveId);
                        setReserveName(itemName(reserve));
                        setReserveLink("");
                        setReserveMessage("");
                        setReserveDialogOpen(true);
                      }}
                    >
                       {tr("Настроить")} </button>
                  </div>
                </article>
              );
            })}
            {!configuredSubscriptionReserves.length ? (
              <div className="empty-result">
                 {tr("Независимые резервные подключения пока не настроены.")} </div>
            ) : null}
          </div>
            {reserveMessage ? (
              <div
                className={`inline-result ${
                  isErrorMessage(reserveMessage) ? "inline-result-error" : ""
                }`}
                role={isErrorMessage(reserveMessage) ? "alert" : "status"}
              >
                <span>{isErrorMessage(reserveMessage) ? "!" : "✓"}</span>
                {reserveMessage}
              </div>
            ) : null}
        </article>
      </section>

      {subscriptionEndpointDialogOpen
        ? createPortal(
            <div className="modal-backdrop subscription-endpoint-backdrop" role="presentation" onMouseDown={() => setSubscriptionEndpointDialogOpen(false)}>
              <section className="modal subscription-endpoint-dialog" role="dialog" aria-modal="true" aria-labelledby="subscription-endpoint-title" onMouseDown={(event) => event.stopPropagation()}>
                <header className="subscription-dialog-header">
                  <h2 id="subscription-endpoint-title">{tr("Ссылка подписки")}</h2>
                  <button className="modal-close" type="button" onClick={() => setSubscriptionEndpointDialogOpen(false)} aria-label={tr("Закрыть")}>×</button>
                </header>

                <div className="subscription-dialog-body" ref={subscriptionEndpointBodyRef}>
                  <Toggle
                    className="subscription-publication-toggle"
                    checked={subscriptionEndpointEnabled}
                    onChange={(enabled) => {
                      setSubscriptionEndpointEnabled(enabled);
                      setCloudflarePortMessage("");
                    }}
                    label={tr("Публикация подписки")}
                  />
                  <fieldset className="subscription-publication-fields" disabled={!subscriptionEndpointEnabled}>
                  <div className="subscription-mode-menu" role="radiogroup" aria-label={tr("Способ публикации подписки")}>
                    {[
                      ["cdn", tr("Через CDN")],
                      ["direct", tr("Напрямую")],
                      ["direct-and-cdn", tr("Два адреса")],
                    ].map(([value, title]) => (
                      <label className={`subscription-mode-option ${value === "cdn" ? ["separate", "reuse-cdn"].includes(subscriptionEndpointMode) ? "is-selected" : "" : subscriptionEndpointMode === value ? "is-selected" : ""}`} key={value}>
                        <input
                          type="radio"
                          name="subscription-endpoint-mode"
                          value={value}
                          checked={value === "cdn" ? ["separate", "reuse-cdn"].includes(subscriptionEndpointMode) : subscriptionEndpointMode === value}
                          onChange={(event) => {
                            const nextMode = event.target.value;
                            if (nextMode === "cdn") {
                              if (subscriptionCdnHostname) {
                                setSubscriptionEndpointMode("separate");
                                setSubscriptionDeploymentSelection("subscription-cdn");
                              } else if (subscriptionDeploymentSelection && subscriptionDeploymentSelection !== "subscription-cdn") {
                                setSubscriptionEndpointMode("reuse-cdn");
                              } else {
                                setSubscriptionEndpointMode("separate");
                              }
                            } else {
                              setSubscriptionEndpointMode(nextMode);
                              if (nextMode === "direct-and-cdn" && !subscriptionDeploymentSelection && subscriptionCdnHostname) {
                                setSubscriptionDeploymentSelection("subscription-cdn");
                              }
                            }
                            setCloudflarePortMessage("");
                          }}
                        />
                        <span><strong>{title}</strong></span>
                      </label>
                    ))}
                  </div>

                  <div className="subscription-essential-grid">
                    <label className="field">
                       {tr("Имя в приложении")} <input value={subscriptionDisplayName} maxLength={96} placeholder="SB Gateway" onChange={(event) => { setSubscriptionDisplayName(event.target.value); setCloudflarePortMessage(""); }} />
                    </label>

                    {subscriptionEndpointMode === "separate" || subscriptionEndpointMode === "reuse-cdn" ? (
                      <label className="field">
                         {tr("CDN-домен")} <select
                          value={subscriptionEndpointMode === "reuse-cdn"
                            ? subscriptionDeploymentSelection
                            : subscriptionCdnHostname
                              ? "subscription-cdn"
                              : "new"}
                          onChange={(event) => {
                            if (event.target.value === "new") {
                              setSubscriptionEndpointMode("separate");
                              setSubscriptionCdnHostname("");
                              setSubscriptionDeploymentSelection("");
                            } else if (event.target.value === "subscription-cdn") {
                              setSubscriptionEndpointMode("separate");
                              setSubscriptionDeploymentSelection("subscription-cdn");
                            } else {
                              setSubscriptionEndpointMode("reuse-cdn");
                              setSubscriptionDeploymentSelection(event.target.value);
                            }
                            setCloudflarePortMessage("");
                          }}
                        >
                          <option value="new">{tr("Новый CDN-домен")}</option>
                          {subscriptionCdnHostname ? <option value="subscription-cdn">{`${cdnProviderName(subscriptionCdnProvider)} · ${subscriptionCdnHostname}`}</option> : null}
                          {subscriptionDeploymentOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
                        </select>
                      </label>
                    ) : null}

                    {subscriptionEndpointMode === "direct-and-cdn" ? (
                      <label className="field">
                         {tr("CDN-домен")} <select value={subscriptionDeploymentSelection} onChange={(event) => { setSubscriptionDeploymentSelection(event.target.value); if (event.target.value === "subscription-cdn" && subscriptionOriginServerName) setSubscriptionHostname(subscriptionOriginServerName); setCloudflarePortMessage(""); }} required>
                          <option value="">{tr("Выберите настроенный домен")}</option>
                          {subscriptionCdnHostname ? <option value="subscription-cdn">{`${cdnProviderName(subscriptionCdnProvider)} · ${subscriptionCdnHostname}`}</option> : null}
                          {subscriptionDeploymentOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
                        </select>
                      </label>
                    ) : null}
                  </div>

                  {subscriptionEndpointMode === "separate" ? (
                    <div className="subscription-address-grid subscription-address-grid-separate">
                      <label className="field">
                        CDN
                        <select value={subscriptionCdnProvider} onChange={(event) => {
                          setSubscriptionCdnProvider(event.target.value);
                          setSubscriptionOriginProtectionMode(supportsAutomaticCidr(event.target.value) ? "auto-cidr" : "secret-header");
                          if (!supportsAutomaticCidr(event.target.value)) setSubscriptionOriginHeaderValue((current) => current || generateOriginHeaderSecret());
                          setCloudflarePortMessage("");
                        }}>
                          {CDN_PROVIDERS.map((provider) => <option value={provider.id} key={provider.id}>{tr(provider.name)}</option>)}
                        </select>
                      </label>
                      <label className="field subscription-domain-field">
                         {tr("Домен раздачи CDN")} <input type="text" inputMode="url" value={subscriptionCdnHostname} placeholder="cdn.example.com" onChange={(event) => { setSubscriptionCdnHostname(event.target.value); setSubscriptionDeploymentSelection("subscription-cdn"); setCloudflarePortMessage(""); }} />
                      </label>
                      <label className="field">
                         {tr("TLS-профиль origin")} <select value={subscriptionTlsProfileId} onChange={(event) => selectSubscriptionTlsProfile(event.target.value)}>
                          {configuredTlsProfiles.map((profile) => <option value={asText(profile.id, "")} key={asText(profile.id, "")}>{itemName(profile)}</option>)}
                        </select>
                      </label>
                      <label className="field">
                         {tr("DNS-имя origin")} <input type="text" inputMode="url" list={subscriptionOriginDatalistId} value={subscriptionOriginServerName} placeholder={subscriptionOriginHostnameCandidates.length ? tr("Выберите или введите домен") : "origin.example.com"} onChange={(event) => { setSubscriptionOriginServerName(event.target.value); setCloudflarePortMessage(""); }} />
                        <datalist id={subscriptionOriginDatalistId}>
                          {subscriptionOriginHostnameCandidates.map((hostname) => <option value={hostname} key={hostname} />)}
                        </datalist>
                      </label>
                    </div>
                  ) : null}

                  {subscriptionEndpointMode === "direct" || subscriptionEndpointMode === "direct-and-cdn" ? (
                    <div className="subscription-address-grid subscription-address-grid-direct">
                      <label className="field subscription-domain-field">
                         {tr("Прямой домен")} <input type="text" inputMode="url" list={subscriptionHostnameDatalistId} value={subscriptionHostname} placeholder={subscriptionHostnameCandidates.length ? tr("Выберите или введите домен") : "sub.example.com"} onChange={(event) => { setSubscriptionHostname(event.target.value); setCloudflarePortMessage(""); }} />
                        <datalist id={subscriptionHostnameDatalistId}>
                          {subscriptionHostnameCandidates.map((hostname) => <option value={hostname} key={hostname} />)}
                        </datalist>
                      </label>
                      <label className="field">
                         {tr("TLS-профиль")} <select value={subscriptionTlsProfileId} onChange={(event) => selectSubscriptionTlsProfile(event.target.value)}>
                          {configuredTlsProfiles.map((profile) => <option value={asText(profile.id, "")} key={asText(profile.id, "")}>{itemName(profile)}</option>)}
                        </select>
                      </label>
                    </div>
                  ) : null}

                  <details className="subscription-advanced-settings">
                    <summary>{t("common.advanced")}</summary>
                    <div className="subscription-advanced-grid">
                      {subscriptionEndpointMode === "separate" ? (
                        <label className="field">
                           {tr("Защита origin")} <select value={subscriptionOriginProtectionMode} onChange={(event) => {
                            setSubscriptionOriginProtectionMode(event.target.value);
                            if (event.target.value === "secret-header") setSubscriptionOriginHeaderValue((current) => current || generateOriginHeaderSecret());
                            setCloudflarePortMessage("");
                          }}>
                            {supportsAutomaticCidr(subscriptionCdnProvider) ? <option value="auto-cidr">{tr("Официальные CIDR · автоматически")}</option> : null}
                            <option value="secret-header">{tr("Секретный HTTP-заголовок")}</option>
                          </select>
                          {subscriptionOriginProtectionMode === "auto-cidr" ? <small>{automaticCidrHint(subscriptionCdnProvider)}</small> : null}
                        </label>
                      ) : null}
                      {subscriptionHasEditablePublicCdnPort ? (
                        <label className="field">
                           {tr("Публичный HTTPS-порт")} {subscriptionCdnProvider === "cloudflare" ? (
                            <select value={subscriptionPublicPort} onChange={(event) => { setSubscriptionPublicPort(Number(event.target.value)); setCloudflarePortMessage(""); }}>
                              {CLOUDFLARE_HTTPS_PORTS.map((port) => <option value={port} key={port}>{port}</option>)}
                            </select>
                          ) : (
                            <input type="number" min="1" max="65535" value={subscriptionPublicPort} onChange={(event) => { setSubscriptionPublicPort(Number(event.target.value)); setCloudflarePortMessage(""); }} />
                          )}
                        </label>
                      ) : null}
                      {subscriptionHasDedicatedHttpsEndpoint ? (
                        <label className="field">
                          {subscriptionHasEditablePublicCdnPort ? tr("TCP-порт origin на MikroTik") : tr("HTTPS-порт")}
                          <input type="number" min="1" max="65535" value={subscriptionOriginPort} onChange={(event) => { setSubscriptionOriginPort(Number(event.target.value)); setCloudflarePortMessage(""); }} />
                        </label>
                      ) : null}
                      {subscriptionEndpointMode === "direct-and-cdn" ? (
                        <label className="field">
                           {tr("Основной адрес")} <select value={subscriptionPrimaryEndpoint} onChange={(event) => { setSubscriptionPrimaryEndpoint(event.target.value); setCloudflarePortMessage(""); }}>
                            <option value="cdn">{tr("CDN-домен")}</option>
                            <option value="direct">{tr("Прямой домен")}</option>
                          </select>
                        </label>
                      ) : null}
                      <label className="field">
                        Happ Provider ID
                        <input
                          value={happProviderId}
                          maxLength={127}
                          placeholder={tr("Не задан")}
                          onChange={(event) => {
                            setHappProviderId(event.target.value);
                            setCloudflarePortMessage("");
                          }}
                        />
                        <small>{tr("Нужен Happ для автоматического включения удалённых LAN-маршрутов на iOS. Без ID настройте Include all networks вручную.")}</small>
                      </label>
                      {subscriptionEndpointMode === "separate" && subscriptionOriginProtectionMode === "secret-header" ? (
                        <div className="field subscription-secret-field">
                           {tr("Секрет origin")} <code>X-SB-Origin</code>
                          <div className="inline-field-actions">
                            <input value={subscriptionOriginHeaderValue} readOnly placeholder={configuredSubscriptionOriginHeaderRef ? tr("Секрет сохранён") : tr("Создайте секрет")} />
                            <button className="button button-secondary" type="button" onClick={() => setSubscriptionOriginHeaderValue(generateOriginHeaderSecret())}>{tr("Создать")}</button>
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </details>

                  {subscriptionHasDedicatedHttpsEndpoint && subscriptionTcpPortConflicts.length ? (
                    <div className="subscription-port-conflict" role="alert">
                      <strong>TCP/{subscriptionOriginPort}  {tr("origin уже занят")}</strong>
                      <span>{subscriptionTcpPortConflicts.join(", ")}</span>
                    </div>
                  ) : null}
                  {subscriptionHasDedicatedHttpsEndpoint && /(^|\.)localhost$|\.local$/i.test((subscriptionEndpointMode === "separate" ? subscriptionCdnHostname : subscriptionHostname).trim()) ? <small className="subscription-host-warning">{tr("Для внешнего доступа нужен публичный DNS и действующий сертификат.")}</small> : null}
                  {subscriptionProbeResult ? <div className={`inline-result ${isErrorMessage(subscriptionProbeResult) ? "inline-result-error" : ""}`} role={isErrorMessage(subscriptionProbeResult) ? "alert" : "status"}><span>{isErrorMessage(subscriptionProbeResult) ? "!" : "✓"}</span>{subscriptionProbeResult}</div> : null}
                  </fieldset>
                  {cloudflarePortMessage ? <div className={`inline-result ${isErrorMessage(cloudflarePortMessage) ? "inline-result-error" : ""}`} role={isErrorMessage(cloudflarePortMessage) ? "alert" : "status"}><span>{isErrorMessage(cloudflarePortMessage) ? "!" : "✓"}</span>{cloudflarePortMessage}</div> : null}
                </div>

                <footer className="subscription-endpoint-actions">
                  <button className="button button-secondary" type="button" disabled={!subscriptionEndpointEnabled || subscriptionProbeBusy} onClick={() => void checkSubscriptionTls()}>{subscriptionProbeBusy ? tr("Проверяю…") : tr("Проверить DNS и TLS")}</button>
                  <div className="modal-actions">
                    <button className="button button-tertiary" type="button" disabled={cloudflarePortBusy} onClick={() => setSubscriptionEndpointDialogOpen(false)}>{tr("Отмена")}</button>
                    <button className="button button-primary" type="button" disabled={cloudflarePortBusy} onClick={saveSubscriptionEndpoint}>{cloudflarePortBusy ? tr("Сохраняю…") : tr("Сохранить")}</button>
                  </div>
                </footer>
              </section>
            </div>,
            document.body,
          )
        : null}

      {reserveDialogOpen ? (
        <div className="modal-backdrop" role="presentation" onMouseDown={resetReserveEditor}>
          <section className="modal" role="dialog" aria-modal="true" aria-labelledby="reserve-vless-title" onMouseDown={(event) => event.stopPropagation()}>
            <button className="modal-close" type="button" onClick={resetReserveEditor} aria-label={tr("Закрыть")}>×</button>
            <form onSubmit={saveSubscriptionReserve}>
              <p className="eyebrow">{tr("Резерв обновления")}</p>
              <h2 id="reserve-vless-title">{editingReserveId ? tr("Настроить резервный VLESS") : tr("Добавить резервный VLESS")}</h2>
              <p className="modal-lead">{tr("Узел используется только для обновления недоступных подписок и не участвует в пользовательском трафике.")}</p>
              <div className="form-grid form-grid-single">
                <label className="field">{tr("Понятное имя")}<input value={reserveName} maxLength={96} placeholder={tr("Резерв · Польша Reality")} onChange={(event) => setReserveName(event.target.value)} /></label>
                <label className="field">{tr("Ссылка VLESS")}<input type="password" autoComplete="off" value={reserveLink} placeholder={editingReserveId ? tr("Оставьте пустым, чтобы сохранить текущую") : "vless://…"} onChange={(event) => setReserveLink(event.target.value)} /><small>{tr("UUID хранится только в SecretStore и не возвращается в браузер.")}</small></label>
              </div>
              {reserveMessage ? <div className={`inline-result ${isErrorMessage(reserveMessage) ? "inline-result-error" : ""}`} role={isErrorMessage(reserveMessage) ? "alert" : "status"}><span>{isErrorMessage(reserveMessage) ? "!" : "✓"}</span>{reserveMessage}</div> : null}
              <div className="modal-actions modal-actions-split">
                {editingReserveId ? <button className="button button-danger" type="button" disabled={reserveBusy} onClick={() => void removeSubscriptionReserve(editingReserveId)}>{tr("Удалить")}</button> : <span />}
                <div><button className="button button-tertiary" type="button" disabled={reserveBusy} onClick={resetReserveEditor}>{tr("Отмена")}</button><button className="button button-primary" type="submit" disabled={reserveBusy || (!editingReserveId && configuredSubscriptionReserves.length >= 3)}>{reserveBusy ? tr("Сохраняю…") : tr("Сохранить")}</button></div>
              </div>
            </form>
          </section>
        </div>
      ) : null}
    </>
  );
}

// Kept as the import/review implementation behind the guided setup flow.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function MikroTik({
  config,
  onDraftChanged,
  onOpenSetup,
}: {
  config: JsonObject;
  onDraftChanged: () => Promise<void>;
  onOpenSetup: () => void;
}) {
  const { tr, locale } = useLanguage();
  const [exportName, setExportName] = useState("");
  const [exportFile, setExportFile] = useState<File | null>(null);
  const [importBusy, setImportBusy] = useState(false);
  const [importMessage, setImportMessage] = useState("");
  const [importResult, setImportResult] = useState<JsonObject>();
  const [liveDiscovery, setLiveDiscovery] = useState<JsonObject>();
  const [planResult, setPlanResult] = useState<JsonObject>();

  const savedRouterOs = asObject(config.routeros);
  const savedImportReview = asObject(savedRouterOs.import_review);
  const importedDiscovery = importResult
    ? asObject(importResult.discovered)
    : savedRouterOs;
  const importedCapabilities = asObject(importedDiscovery.capabilities);
  const importedVersion = asText(importedDiscovery.detected_version, "");
  const importedWarnings = importResult
    ? asStringList(importResult.warnings)
    : asStringList(savedImportReview.posture_warnings);
  const importedNetworks = importResult
    ? asStringList(importResult.network_suggestions)
    : asObjectList(savedImportReview.networks)
        .filter((item) => networkReviewStatus(item.status) === "pending")
        .map((item) => asText(item.cidr, ""))
        .filter(Boolean);
  const importedIngressSuggestions = asStringList(
    importResult?.management_ingress_suggestions ??
      savedImportReview.management_ingress_suggestions ??
      importedDiscovery.management_ingress_suggestions,
  );
  const importedTopologySuggestions = asObject(
    importResult?.topology_suggestions ??
      savedImportReview.topology_suggestions ??
      importedDiscovery.topology_suggestions,
  );
  const hasImportedSnapshot = Boolean(
    importResult ||
      savedImportReview.imported_at ||
      savedImportReview.source_fingerprint,
  );
  const liveRouterOs = asObject(liveDiscovery?.routeros);
  const liveCapabilities = asObject(liveRouterOs.capabilities);
  const liveVersion = asText(liveRouterOs.detected_version, "");
  const displayedVersion = liveVersion || importedVersion;
  const displayedChannel = asText(
    liveRouterOs.channel ?? importedDiscovery.channel,
    tr("канал не обнаружен"),
  );
  const planRows = planResult ? resultRows(planResult, locale) : [];
  const reviewCounts = importReviewCounts(config);

  async function analyzeExport() {
    if (!exportFile) return;
    setImportBusy(true);
    setImportMessage("");
    try {
      const result = await importRouterOsExport(exportFile);
      setImportResult(asObject(result));
      await onDraftChanged();
      setImportMessage(
        resultMessage(
          result,
          tr("Экспорт разобран и сохранён как офлайн-снимок. Это ещё не live preflight."),
        ),
      );
    } catch (error) {
      setImportResult(undefined);
      setImportMessage(prefixedErrorMessage(error));
    } finally {
      setImportBusy(false);
    }
  }

  return (
    <>
      <SectionTitle
        eyebrow="MikroTik"
        title={tr("Сначала читаем, потом предлагаем патч")}
        description={tr("Панель управляет только объектами с комментарием SB-GATEWAY и не меняет существующие VPN, LAN, Wi‑Fi и firewall.")}
        action={
          <button
            className="button button-primary"
            onClick={async () => {
              setImportBusy(true);
              setImportMessage("");
              try {
                const discovery = await discoverRouterOs();
                setLiveDiscovery(asObject(discovery));
                const result = await runDraftOperation("check");
                setImportMessage(
                  resultMessage(result, tr("Live preflight и проверка candidate завершены.")),
                );
              } catch (error) {
                setImportMessage(prefixedErrorMessage(error));
              } finally {
                setImportBusy(false);
              }
            }}
            disabled={importBusy}
          >
            {importBusy ? tr("Проверяю…") : tr("Запустить live preflight")}
          </button>
        }
      />

      <aside className="version-banner">
        <div className="version-mark">{displayedVersion.split(".")[0] || "7"}</div>
        <div>
          <p className="eyebrow">
            {liveVersion ? tr("Обнаружено через live REST") : hasImportedSnapshot ? tr("Из безопасного экспорта") : tr("Ожидает обнаружения")}
          </p>
          <h3>
            {displayedVersion ? `RouterOS ${displayedVersion}` : "RouterOS 7"} · {displayedChannel}
          </h3>
          <p>
             {tr("Совместимость определяется по возможностям, а не по точному номеру. Long-term, stable, testing и development не блокируются сами по себе: панель показывает уровень проверенности и останавливает только новую операцию при отсутствии конкретной обязательной возможности.")} </p>
        </div>
        <StatusPill tone={liveVersion ? "ok" : hasImportedSnapshot ? "info" : "muted"}>
          {liveVersion ? tr("Live REST подтверждён") : tr("Нужен live REST")}
        </StatusPill>
      </aside>

      <section className="mikrotik-grid">
        <article className="card import-card">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{tr("Шаг 1 из 3")}</p>
              <h3>{tr("Загрузите безопасный экспорт")}</h3>
            </div>
          </div>
          <p>
             {tr("Нужен обычный текстовый")} <code>.rsc</code>{tr(", созданный командой")}{" "}
            <code>{tr("/export file=имя")}</code>  {tr("без флага show-sensitive. По умолчанию RouterOS скрывает пароли и приватные ключи.")} </p>
          <label className="drop-zone">
            <input
              type="file"
              accept=".rsc,.txt"
              onChange={(event) => {
                const file = event.target.files?.[0] ?? null;
                setExportFile(file);
                setExportName(file?.name ?? "");
                setImportMessage("");
                setImportResult(undefined);
              }}
            />
            <span className="drop-icon">⇧</span>
            <strong>
              {exportName || "Выберите файл или перетащите его сюда"}
            </strong>
            <small>{tr("Файл анализируется локальным control plane")}</small>
          </label>
          <div className="card-actions">
            <button
              className="button button-primary"
              onClick={analyzeExport}
              disabled={!exportFile || importBusy}
            >
              {importBusy ? tr("Анализирую…") : tr("Проанализировать локально")}
            </button>
            <button
              className="button button-secondary"
              type="button"
              onClick={onOpenSetup}
            >
               {tr("Открыть мастер первого запуска")} </button>
          </div>
          {importMessage ? (
            <div
              className={`inline-result ${
                isErrorMessage(importMessage) ? "inline-result-error" : ""
              }`}
              role={isErrorMessage(importMessage) ? "alert" : "status"}
            >
              <span>{isErrorMessage(importMessage) ? "!" : "✓"}</span>
              {importMessage}
            </div>
          ) : null}
          {hasImportedSnapshot ? (
            <aside className="notice notice-danger">
              <span className="notice-icon">!</span>
              <div>
                <strong>{tr(".rsc разобран офлайн — это не live preflight")}</strong>
                <p>
                  {tr("Файл даёт снимок сохранённой конфигурации, но не подтверждает текущую архитектуру, установленные пакеты, device-mode, доступность REST, kernel TPROXY, auto-restart или scheduler.")} </p>
                <p>
                   {tr("Найдено сетевых подсказок:")} {importedNetworks.length}{tr("; кандидатов на доверенный management ingress:")}{" "}
                  {importedIngressSuggestions.length}{tr(". Каждая подсказка должна получить явный статус «принять» или «игнорировать».")} </p>
                {Object.keys(importedTopologySuggestions).length ? (
                  <p>
                     {tr("Также рассчитан непересекающийся offline-кандидат для bridge/veth/container/TUN. Он заполняет только пустые поля, не подтверждает адреса и требует вашего review плюс live discovery.")} </p>
                ) : null}
                {importedWarnings.length ? (
                  <p>
                     {tr("Предупреждения импорта:")}{" "}
                    {importedWarnings
                      .map((warning) => routerImportWarningText(warning, locale))
                      .join(" ")}
                  </p>
                ) : null}
                <div className="card-actions">
                  <button
                    className="button button-secondary"
                    type="button"
                    onClick={onOpenSetup}
                  >
                     {tr("Открыть мастер и классифицировать")} </button>
                </div>
              </div>
            </aside>
          ) : null}
        </article>

        <article className="card checklist-card">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{tr("Шаг 2 из 3")}</p>
              <h3>{tr("Обязательные возможности RouterOS")}</h3>
            </div>
          </div>
          <ul className="checklist">
            {routerCapabilityLabels.map(([name, label]) => {
              const importedValue = importedCapabilities[name];
              const liveValue = liveCapabilities[name];
              const isVersionMetadata =
                name === "routeros_major_7" && importedVersion.startsWith("7.");
              const status = liveDiscovery
                ? liveValue === true
                  ? tr("Подтверждено live REST")
                  : liveValue === false
                    ? tr("Live REST: обязательная возможность отсутствует")
                    : tr("Live REST не вернул однозначный результат")
                : !hasImportedSnapshot
                ? tr("Ожидает .rsc, затем обязательный live REST")
                : importedValue === true
                  ? tr("Найдено в .rsc · live ещё не подтверждено")
                  : importedValue === false
                    ? tr("Не найдено в .rsc · требуется live-проверка")
                    : isVersionMetadata
                      ? tr("Заголовок .rsc: RouterOS {value1} · не live", { value1: importedVersion })
                      : tr("Неопределённо · требуется live REST");
              return (
                <li key={name}>
                  <span>
                    {liveDiscovery
                      ? liveValue === true
                        ? "✓"
                        : liveValue === false
                          ? "!"
                          : "?"
                      : hasImportedSnapshot
                        ? "?"
                        : "○"}
                  </span>
                  <div>
                    <strong>{label}</strong>
                    <small>{status}</small>
                  </div>
                </li>
              );
            })}
          </ul>
          {hasImportedSnapshot ? (
            <aside className="notice notice-neutral">
              <span className="notice-icon">i</span>
              <div>
                <strong>{tr("Неопределённая capability не считается успешной")}</strong>
                <p>
                   {tr("Кнопка live preflight обращается к текущему RouterOS по HTTPS REST. Только её результат может разрешить новый Apply.")} </p>
                <div>
                   {tr("Review сетей: принято")} {reviewCounts.accepted}{tr(", проигнорировано")}{" "}
                  {reviewCounts.ignored}{tr(", ожидает решения")} {reviewCounts.pending}.
                </div>
              </div>
            </aside>
          ) : null}
        </article>
      </section>

      <article className="card change-plan">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">{tr("Шаг 3 из 3")}</p>
            <h3>{tr("Безопасный план изменений")}</h3>
          </div>
          <div className="card-actions">
            <StatusPill
              tone={
                planResult
                  ? planResult.valid === true
                    ? "ok"
                    : "danger"
                  : "muted"
              }
            >
              {planResult
                ? planResult.valid === true
                  ? tr("План готов · {value1} изменений", { value1: asObjectList(planResult.changes).length })
                  : tr("План содержит ошибки")
                : tr("План ещё не запрашивался")}
            </StatusPill>
            <button
              className="button button-secondary"
              type="button"
              disabled={importBusy}
              onClick={async () => {
                setImportBusy(true);
                setImportMessage("");
                try {
                  const result = await runDraftOperation<JsonObject>("plan");
                  setPlanResult(asObject(result));
                  setImportMessage(
                    resultMessage(result, tr("Безопасный план сформирован из текущего черновика.")),
                  );
                } catch (error) {
                  setPlanResult(undefined);
                  setImportMessage(prefixedErrorMessage(error));
                } finally {
                  setImportBusy(false);
                }
              }}
            >
              {importBusy ? tr("Формирую…") : tr("Сформировать точный план")}
            </button>
          </div>
        </div>
        <div className="plan-flow">
          {[
            [
              "01",
              planResult?.apply_mode === "state_only"
                ? tr("Только состояние")
                : planResult?.apply_mode === "runtime_fast"
                ? tr("Быстрое применение")
                : planResult?.apply_mode === "connectivity_safe_mode"
                  ? tr("Защита связности")
                : planResult?.apply_mode === "unchanged"
                  ? tr("Без изменений")
                  : tr("Защита RouterOS"),
              planResult?.apply_mode === "state_only"
                ? tr("Без RouterOS и перезапуска")
                : planResult?.apply_mode === "runtime_fast"
                ? tr("Без RouterOS и backup")
                : planResult?.apply_mode === "connectivity_safe_mode"
                  ? tr("Runtime LKG и проверки TUN/DNS")
                : planResult?.apply_mode === "unchanged"
                  ? tr("Только live-проверка")
                  : tr("Backup только при изменении RouterOS"),
            ],
            ["02", tr("Точный diff"), tr("Только SB-GATEWAY")],
            ["03", tr("Проверка"), tr("Маршруты и FastTrack")],
            ["04", tr("Применение"), tr("С таймером отката")],
            ["05", "Health-check", tr("Интернет и панель")],
          ].map(([number, title, detail]) => (
            <div key={number}>
              <span>{number}</span>
              <strong>{title}</strong>
              <small>{detail}</small>
            </div>
          ))}
        </div>
        {planRows.length ? (
          <div className="decision-path is-ready" aria-live="polite">
            {planRows.map(([label, value], index) => (
              <div className="decision-step" key={`${label}-${index}`}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <small>{label}</small>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-result">
             {tr("Нажмите «Сформировать точный план»: control plane покажет реальные шаги и diff текущего черновика без изменения маршрутизатора.")} </div>
        )}
        <aside className="notice notice-neutral">
          <span className="notice-icon">i</span>
          <div>
            <strong>{tr("Если существующий FastTrack неоднозначен")}</strong>
            <p>
               {tr("Установка остановится и покажет точную ручную рекомендацию. Панель никогда не удаляет или не переписывает firewall-правила вслепую.")} </p>
          </div>
        </aside>
      </article>
    </>
  );
}

function Operations({
  onRefresh,
  onDraftChanged,
  onNavigate,
  overview,
  runtime,
  config,
}: {
  onRefresh: () => Promise<void>;
  onDraftChanged: () => Promise<void>;
  onNavigate: (screen: Screen) => void;
  overview?: JsonObject;
  runtime?: JsonObject;
  config: JsonObject;
}) {
  const { locale, tr } = useLanguage();
  const [diagnosticsBusy, setDiagnosticsBusy] = useState(false);
  const [diagnosticsMessage, setDiagnosticsMessage] = useState("");
  const [diagnosticsResult, setDiagnosticsResult] = useState<JsonObject>();
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [lifecycleStatus, setLifecycleStatus] = useState<JsonObject>();
  const [uninstallPreview, setUninstallPreview] = useState<JsonObject>();
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  const [lifecycleMessage, setLifecycleMessage] = useState("");
  const [candidateReference, setCandidateReference] = useState("");
  const [candidateVersion, setCandidateVersion] = useState("");
  const [candidateChecksum, setCandidateChecksum] = useState("");
  const [imageUploadBusy, setImageUploadBusy] = useState(false);
  const [imageUploadProgress, setImageUploadProgress] = useState({ loadedBytes: 0, totalBytes: 0, percent: 0 });
  const [updateDialogOpen, setUpdateDialogOpen] = useState(false);
  const [updateProgressOpen, setUpdateProgressOpen] = useState(false);
  const [updateStartedAt, setUpdateStartedAt] = useState(0);
  const [updateElapsed, setUpdateElapsed] = useState(0);
  const [updateConnectionMessage, setUpdateConnectionMessage] = useState("");
  const [uninstallDialogOpen, setUninstallDialogOpen] = useState(false);
  const [recoveryStatus, setRecoveryStatus] = useState<JsonObject>();
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryMessage, setRecoveryMessage] = useState("");
  const [restoreArchive, setRestoreArchive] = useState("");
  const [xrayLogOpen, setXrayLogOpen] = useState(false);
  const [xrayLogSource, setXrayLogSource] = useState<RuntimeLogSource>("error");
  const [xrayLogSnapshot, setXrayLogSnapshot] = useState<JsonObject>();
  const [xrayLogBusy, setXrayLogBusy] = useState(false);
  const [xrayLogMessage, setXrayLogMessage] = useState("");
  const [xrayLogCollapsed, setXrayLogCollapsed] = useState(false);
  const [xrayLogLevel, setXrayLogLevel] = useState(
    asText(asObject(asObject(config.system).logging).xray_level, "warning"),
  );
  const [xrayLogLevelBusy, setXrayLogLevelBusy] = useState(false);
  const xrayLogViewportRef = useRef<HTMLPreElement>(null);
  const xrayLogStickToEndRef = useRef(true);
  const diagnosticsChecks = asObject(diagnosticsResult?.checks_performed);
  const checkLabels: Record<string, string> = {
    config_validation: tr("Проверка структуры черновика"),
    routeros_discovery: "RouterOS live discovery",
    candidate_binary_validation: tr("Активное proxy-ядро и nginx candidate"),
    runtime_network_probes: tr("Внешние сетевые пробы"),
  };
  const diagnosticReasonLabels: Record<string, string> = {
    "No active generation is running under the native process controller.": tr(
      "Активная конфигурация сейчас не запущена.",
    ),
    "Diagnostics does not initiate external Internet traffic; watchdog evidence is reported separately in status.": tr(
      "Диагностика не запускает внешние подключения; результат watchdog показан отдельно.",
    ),
  };
  const auditRows = asObjectList(overview?.recent_audit).slice().reverse();
  const lastApply = asObject(runtime?.last_apply);
  const rollbackAvailable = Boolean(asText(lastApply.previous_revision, ""));
  const watchdogRuntime = asObject(runtime?.watchdog);
  const watchdogConfig = asObject(config.watchdog);
  const liveRouteros = asObject(overview?.routeros);
  const liveContainer = asObject(liveRouteros.container);
  const lifecycleStorageRoot = asText(lifecycleStatus?.storage_root, "");
  const lifecycleOperation = asObject(lifecycleStatus?.operation);
  const lifecycleOperationState = asText(lifecycleOperation.state, "");
  const lifecycleOperationVersion = asText(lifecycleOperation.version, candidateVersion);
  const lifecycleProgressPercent = lifecycleOperationState === "completed" || lifecycleOperationState === "rolled_back" || lifecycleOperationState === "failed"
    ? 100
    : lifecycleOperationState === "probation"
      ? 76
      : 34;
  const xrayLogSelected = xrayLogSource === "error" || xrayLogSource === "process";
  const xrayLogging = asObject(xrayLogSnapshot?.logging);
  const xrayLogLines = Array.isArray(xrayLogSnapshot?.lines)
    ? xrayLogSnapshot.lines.filter((line): line is string => typeof line === "string")
    : [];
  const configuredXrayLogLevel = asText(
    asObject(asObject(config.system).logging).xray_level,
    "warning",
  );
  const effectiveXrayLogLevel = asText(
    xrayLogging.effective_level,
    configuredXrayLogLevel,
  );

  const loadXrayLog = useCallback(async (quiet = false) => {
    if (!quiet) setXrayLogBusy(true);
    try {
      const result = xrayLogSource === "error" || xrayLogSource === "process"
        ? await getXrayLogs<JsonObject>(xrayLogSource, 300)
        : await getSystemLogs<JsonObject>(xrayLogSource, 300);
      setXrayLogSnapshot(asObject(result));
      if (!quiet) setXrayLogMessage("");
      if (xrayLogStickToEndRef.current) {
        window.requestAnimationFrame(() => {
          const viewport = xrayLogViewportRef.current;
          if (viewport) viewport.scrollTop = viewport.scrollHeight;
        });
      }
    } catch (error) {
      setXrayLogMessage(prefixedErrorMessage(error));
    } finally {
      if (!quiet) setXrayLogBusy(false);
    }
  }, [xrayLogSource]);

  const refreshLifecycleStatus = useCallback(async () => {
    const result = await getLifecycleStatus<JsonObject>();
    setLifecycleStatus(asObject(result));
    return asObject(result);
  }, []);

  useEffect(() => {
    if (!updateProgressOpen) return;
    let active = true;
    const refresh = async () => {
      try {
        await refreshLifecycleStatus();
        if (active) setUpdateConnectionMessage("");
      } catch {
        if (active) setUpdateConnectionMessage(tr("Панель перезапускается. Ожидаю восстановления связи…"));
      }
    };
    const initial = window.setTimeout(() => void refresh(), 0);
    const poll = window.setInterval(() => void refresh(), 2_000);
    const timer = window.setInterval(() => {
      if (active && updateStartedAt > 0) {
        setUpdateElapsed(Math.max(0, Math.floor((Date.now() - updateStartedAt) / 1000)));
      }
    }, 1_000);
    return () => {
      active = false;
      window.clearTimeout(initial);
      window.clearInterval(poll);
      window.clearInterval(timer);
    };
  }, [refreshLifecycleStatus, tr, updateProgressOpen, updateStartedAt]);

  useEffect(() => {
    if (!xrayLogOpen) return;
    const initial = window.setTimeout(() => void loadXrayLog(), 0);
    const timer = window.setInterval(() => void loadXrayLog(true), 3_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [loadXrayLog, xrayLogOpen]);

  useEffect(() => {
    if (!xrayLogOpen) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setXrayLogOpen(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [xrayLogOpen]);

  async function saveXrayLogLevel() {
    setXrayLogLevelBusy(true);
    setXrayLogMessage("");
    try {
      const system = asObject(config.system);
      const logging = asObject(system.logging);
      await saveCurrentDraft({
        config: {
          ...config,
          system: {
            ...system,
            logging: {
              ...logging,
              xray_level: xrayLogLevel,
              xray_debug_timeout_minutes: 15,
            },
          },
        },
      });
      await onDraftChanged();
      setXrayLogMessage(
        xrayLogLevel === "debug"
          ? tr("Debug сохранён в черновик. После применения он выключится автоматически через 15 минут.")
          : tr("Уровень сохранён в черновик и вступит в силу после применения."),
      );
    } catch (error) {
      setXrayLogMessage(prefixedErrorMessage(error));
    } finally {
      setXrayLogLevelBusy(false);
    }
  }

  async function copyXrayLog() {
    try {
      const text = xrayLogLines.join("\n");
      if (window.isSecureContext && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const field = document.createElement("textarea");
        field.value = text;
        field.setAttribute("readonly", "");
        field.style.position = "fixed";
        field.style.opacity = "0";
        document.body.appendChild(field);
        field.select();
        const copied = document.execCommand("copy");
        field.remove();
        if (!copied) throw new Error("copy unavailable");
      }
      setXrayLogMessage(tr("Видимые строки скопированы."));
    } catch (error) {
      setXrayLogMessage(prefixedErrorMessage(error));
    }
  }

  useEffect(() => {
    let active = true;
    Promise.allSettled([
      getLifecycleStatus<JsonObject>(),
      getUninstallPreview<JsonObject>(),
      getRecoveryBackups<JsonObject>(),
    ])
      .then(([status, preview, recovery]) => {
        if (active) {
          const nextLifecycle = status.status === "fulfilled" ? asObject(status.value) : undefined;
          setLifecycleStatus(nextLifecycle);
          const operation = asObject(nextLifecycle?.operation);
          if (["preparing", "scheduled", "probation"].includes(asText(operation.state, ""))) {
            const started = Date.parse(asText(operation.scheduled_at, asText(operation.preparing_at, "")));
            setUpdateStartedAt(Number.isFinite(started) ? started : Date.now());
            setUpdateProgressOpen(true);
          }
          setUninstallPreview(preview.status === "fulfilled" ? asObject(preview.value) : undefined);
          setRecoveryStatus(recovery.status === "fulfilled" ? asObject(recovery.value) : undefined);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  async function refreshRecovery() {
    const result = await getRecoveryBackups<JsonObject>();
    setRecoveryStatus(asObject(result));
  }

  async function createRecovery() {
    setRecoveryBusy(true);
    setRecoveryMessage("");
    try {
      await createRecoveryBackup<JsonObject>();
      await refreshRecovery();
      setRecoveryMessage(tr("Зашифрованная копия сохранена на SSD и в RouterOS Files."));
    } catch (error) {
      setRecoveryMessage(prefixedErrorMessage(error));
    } finally {
      setRecoveryBusy(false);
    }
  }

  async function uploadRecovery(file: File | undefined) {
    if (!file) return;
    setRecoveryBusy(true);
    setRecoveryMessage("");
    try {
      await uploadRecoveryBackup<JsonObject>(file);
      await refreshRecovery();
      setRecoveryMessage(tr("Архив проверен и добавлен в список восстановления."));
    } catch (error) {
      setRecoveryMessage(prefixedErrorMessage(error));
    } finally {
      setRecoveryBusy(false);
    }
  }

  async function saveRecoveryArchive(name: string) {
    setRecoveryBusy(true);
    setRecoveryMessage("");
    try {
      const { blob, filename } = await downloadRecoveryBackup(name);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setRecoveryMessage(tr("Зашифрованный архив скачан."));
    } catch (error) {
      setRecoveryMessage(prefixedErrorMessage(error));
    } finally {
      setRecoveryBusy(false);
    }
  }

  async function restoreRecovery(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setRecoveryBusy(true);
    setRecoveryMessage("");
    try {
      await restoreRecoveryBackup<JsonObject>({
        name: restoreArchive,
        source: "auto",
        password: String(data.get("password") ?? ""),
      });
      setRecoveryMessage(
        tr("Архив проверен. RouterOS перезапускает контейнер для восстановления."),
      );
    } catch (error) {
      setRecoveryMessage(prefixedErrorMessage(error));
    } finally {
      setRecoveryBusy(false);
    }
  }

  async function startImageUpdate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLifecycleBusy(true);
    setLifecycleMessage("");
    const data = new FormData(event.currentTarget);
    try {
      const result = await scheduleImageUpdate<JsonObject>({
        candidate_source: "local-file",
        candidate_reference: candidateReference.trim(),
        confirmation: data.get("confirmed") === "on" ? tr("ОБНОВИТЬ") : "",
      });
      setLifecycleMessage(
        resultMessage(
          result,
          tr("Обновление поставлено в автономную очередь RouterOS. Панель временно отключится."),
        ),
      );
      setLifecycleStatus((current) => ({
        ...asObject(current),
        operation: { kind: "image-update", state: "scheduled", version: candidateVersion },
      }));
      setUpdateStartedAt(Date.now());
      setUpdateElapsed(0);
      setUpdateConnectionMessage("");
      setUpdateDialogOpen(false);
      setUpdateProgressOpen(true);
    } catch (error) {
      if (isUncertainOperationError(error)) {
        setUpdateStartedAt(Date.now());
        setUpdateElapsed(0);
        setUpdateConnectionMessage(tr("Проверяю, была ли задача принята RouterOS…"));
        setUpdateDialogOpen(false);
        setUpdateProgressOpen(true);
      } else {
        setLifecycleMessage(prefixedErrorMessage(error));
      }
    } finally {
      setLifecycleBusy(false);
    }
  }

  async function uploadImageFromBrowser(file: File | undefined) {
    if (!file) return;
    setImageUploadBusy(true);
    setImageUploadProgress({ loadedBytes: 0, totalBytes: file.size, percent: 0 });
    setCandidateReference("");
    setCandidateVersion("");
    setCandidateChecksum("");
    setLifecycleMessage(tr("Загружаю образ прямо на SSD; после записи проверю arm64 и SHA-256…"));
    try {
      await preflightContainerImageUpload(file);
      const result = await uploadContainerImage<JsonObject>(file, setImageUploadProgress);
      const routerosPath = asText(result.routeros_path, "");
      setCandidateReference(routerosPath);
      setCandidateVersion(asText(result.version, ""));
      setCandidateChecksum(asText(result.sha256, ""));
      setLifecycleMessage(
        tr("Образ проверен: arm64, SHA-256 {value1}… Путь RouterOS подставлен автоматически.", { value1: asText(result.sha256, "").slice(0, 16) }),
      );
    } catch (error) {
      setLifecycleMessage(prefixedErrorMessage(error));
    } finally {
      setImageUploadBusy(false);
    }
  }

  async function startFullUninstall(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLifecycleBusy(true);
    setLifecycleMessage("");
    const data = new FormData(event.currentTarget);
    try {
      const result = await scheduleFullUninstall<JsonObject>({
        storage_root: lifecycleStorageRoot,
        confirmation: data.get("confirmed") === "on" ? tr("УДАЛИТЬ SB-GATEWAY") : "",
      });
      setLifecycleMessage(
        resultMessage(
          result,
          tr("Полное удаление поставлено в автономную очередь RouterOS."),
        ),
      );
    } catch (error) {
      setLifecycleMessage(prefixedErrorMessage(error));
    } finally {
      setLifecycleBusy(false);
    }
  }

  async function startDiagnostics() {
    setDiagnosticsBusy(true);
    setDiagnosticsMessage(
      tr("Проверяю черновик, RouterOS discovery, state/LKG и статус watchdog…"),
    );
    try {
      const result = await runDiagnostics();
      setDiagnosticsResult(asObject(result));
      setDiagnosticsMessage(
        resultMessage(result, tr("Диагностика завершена локальным control plane.")),
      );
    } catch (error) {
      setDiagnosticsResult(undefined);
      setDiagnosticsMessage(prefixedErrorMessage(error));
    } finally {
      setDiagnosticsBusy(false);
    }
  }

  return (
    <>
      <SectionTitle
        eyebrow={tr("Эксплуатация")}
        title={tr("Проверки, версии и восстановление")}
        description={tr("Любая операция оставляет проверяемую историю без UUID, URL подписок и других секретов.")}
        action={
          <button
            className="button button-primary"
            onClick={startDiagnostics}
            disabled={diagnosticsBusy}
          >
            {diagnosticsBusy ? tr("Диагностика…") : tr("Запустить диагностику")}
          </button>
        }
      />

      {diagnosticsMessage ? (
        <div
          className={`operation-progress ${
            isErrorMessage(diagnosticsMessage) ? "operation-error" : ""
          }`}
          role={isErrorMessage(diagnosticsMessage) ? "alert" : "status"}
          aria-live="polite"
        >
          <span className={diagnosticsBusy ? "spinner" : ""}>
            {diagnosticsBusy
              ? ""
              : isErrorMessage(diagnosticsMessage)
                ? "!"
                : "✓"}
          </span>
          <div>
            <strong>
              {diagnosticsBusy ? tr("Диагностика запущена") : tr("Ответ control plane")}
            </strong>
            <small>{diagnosticsMessage}</small>
          </div>
          <button
            className="text-button"
            onClick={() => setDiagnosticsMessage("")}
          >
             {tr("Скрыть")} </button>
        </div>
      ) : null}

      <section className="operations-grid">
        <article className="card watchdog-card">
          <div className="card-topline">
            <span className="icon-box icon-safe">W</span>
            <StatusPill
              tone={
                watchdogRuntime.state === "healthy"
                  ? "ok"
                  : watchdogRuntime.state
                    ? "warn"
                    : "muted"
              }
            >
              {asText(watchdogRuntime.state, tr("Нет runtime-данных"))}
            </StatusPill>
          </div>
          <p className="eyebrow">{tr("Фактическая настройка черновика")}</p>
          <h3>{tr("Watchdog контейнера")}</h3>
          <p>
             {tr("Проверка каждые")} {asText(watchdogConfig.interval_seconds, "—")}  {tr("сек.; порог отказа —")} {asText(watchdogConfig.failure_threshold, "—")}{tr(", восстановления —")} {asText(watchdogConfig.recovery_threshold, "—")}.
          </p>
          <div className="watchdog-chain">
            <span>{tr("Сбой")}</span>
            <i>→</i>
            <span>{tr("Локальные:")} {asText(runtime?.routing && asObject(runtime.routing).local_on_outage, "wan-direct")}</span>
            <i>→</i>
            <span>{tr("Удалённые:")} {asText(runtime?.routing && asObject(runtime.routing).remote_on_outage, "drop")}</span>
            <i>→</i>
            <span>{asText(watchdogConfig.max_restarts_per_hour, "—")}  {tr("рестартов/ч")}</span>
          </div>
          <button
            className="button button-tertiary"
            onClick={() => onNavigate("settings")}
          >
             {tr("Настроить пороги")} </button>
        </article>

        <article className="card validation-card">
          <div className="card-topline">
            <span className="icon-box icon-info">V</span>
            <StatusPill
              tone={
                diagnosticsResult
                  ? diagnosticsResult.ok === true
                    ? "ok"
                    : "danger"
                  : "muted"
              }
            >
              {diagnosticsResult
                ? diagnosticsResult.ok === true
                  ? tr("Проверки пройдены")
                  : tr("Есть ошибки")
                : tr("Диагностика не запускалась")}
            </StatusPill>
          </div>
          <p className="eyebrow">{tr("Фактическое состояние")}</p>
          <h3>{tr("Результат локального control plane")}</h3>
          {Object.keys(diagnosticsChecks).length ? (
            <ul className="validation-list">
              {Object.entries(diagnosticsChecks).map(([id, raw]) => {
                const check = asObject(raw);
                const performed = check.performed === true;
                const passed = check.passed === true;
                const rawReason = asText(check.reason, tr("не выполнялась"));
                return (
                  <li key={id}>
                    <span>{!performed ? "○" : passed ? "✓" : "!"}</span>
                    <div className="validation-check-copy">
                      <span>{checkLabels[id] ?? id}</span>
                      {!performed ? (
                        <small>{diagnosticReasonLabels[rawReason] ?? rawReason}</small>
                      ) : null}
                    </div>
                    {performed ? (
                      <small className="validation-check-outcome">
                        {passed ? tr("пройдена") : tr("не пройдена")}
                      </small>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          ) : (
            <div className="empty-result">
               {tr("Нажмите «Запустить диагностику», чтобы получить реальные результаты.")} </div>
          )}
        </article>
      </section>

      <article className="card xray-log-launcher">
        <div>
          <div className="xray-log-title-line">
            <h3>{tr("Журналы SB Gateway")}</h3>
            <StatusPill tone={configuredXrayLogLevel === "none" ? "muted" : configuredXrayLogLevel === "debug" ? "warn" : "info"}>
              {tr("В черновике:")} {configuredXrayLogLevel}
            </StatusPill>
          </div>
          <p>{tr("Xray, control plane, nginx и обновления — без входа в shell контейнера.")}</p>
        </div>
        <button className="button button-secondary" type="button" onClick={() => {
          setXrayLogLevel(configuredXrayLogLevel);
          setXrayLogCollapsed(false);
          setXrayLogOpen(true);
        }}>
          {tr("Открыть журнал")}
        </button>
      </article>

      <article className="card versions-card">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">{tr("История конфигурации")}</p>
            <h3>{tr("Резервные копии и откат")}</h3>
          </div>
          <button
            className="button button-secondary"
            onClick={() => setRollbackOpen(true)}
            disabled={!rollbackAvailable}
            title={
              rollbackAvailable
                ? tr("Вернуть предыдущую проверенную ревизию")
                : tr("Предыдущая проверенная ревизия пока отсутствует")
            }
          >
             {tr("Откатить к предыдущей проверенной версии")} </button>
        </div>
        <div className="responsive-table">
          <table>
            <thead>
              <tr>
                <th>{tr("Ревизия")}</th>
                <th>{tr("Время")}</th>
                <th>{tr("Операция")}</th>
                <th>{tr("Инициатор")}</th>
                <th>{tr("Результат")}</th>
                <th>{tr("Запрос")}</th>
              </tr>
            </thead>
            <tbody>
              {auditRows.map((event, index) => {
                const details = asObject(event.details);
                const revision =
                  shortRevision(details.revision ?? details.draft_revision) ||
                  shortRevision(overview?.draft_revision) ||
                  "—";
                return (
                  <tr key={`${asText(event.timestamp, "event")}-${index}`}>
                    <td><code>{revision}</code></td>
                    <td>{formatTimestamp(event.timestamp, locale)}</td>
                    <td>{asText(event.action, tr("операция"))}</td>
                    <td>{asText(event.actor, tr("локально"))}</td>
                    <td>
                      <StatusPill tone={event.outcome === "ok" ? "ok" : "danger"}>
                        {asText(event.outcome, tr("неизвестно"))}
                      </StatusPill>
                    </td>
                    <td><code>{asText(event.request_id, "—")}</code></td>
                  </tr>
                );
              })}
              {!auditRows.length ? (
                <tr>
                  <td colSpan={6}>
                     {tr("Событий пока нет. Первая сохранённая операция появится здесь автоматически.")} </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </article>

      <article className="card recovery-card">
        <div className="panel-heading recovery-heading">
          <div>
            <h3>{tr("Резервные копии SB Gateway")}</h3>
            <p>
               {tr("Три последние копии хранятся на SSD и в RouterOS Files. Архив зашифрован паролем администратора панели и не содержит образ, журнал или кэш.")} </p>
          </div>
          <div className="recovery-toolbar">
            <label className="button button-secondary recovery-upload-button">
               {tr("Загрузить архив")} <input
                type="file"
                accept=".sbgw,application/octet-stream"
                disabled={recoveryBusy}
                onChange={(event) => {
                  void uploadRecovery(event.target.files?.[0]);
                  event.currentTarget.value = "";
                }}
              />
            </label>
            <button
              className="button button-primary"
              type="button"
              disabled={recoveryBusy}
              onClick={() => void createRecovery()}
            >
              {recoveryBusy ? tr("Проверяю…") : tr("Создать копию")}
            </button>
          </div>
        </div>
        <div className="recovery-list">
          {asObjectList(recoveryStatus?.items).map((archive) => {
            const name = asText(archive.name, "");
            return (
              <div className="recovery-row" key={name}>
                <div className="recovery-file">
                  <strong>{formatTimestamp(archive.created_at, locale)}</strong>
                  <small>
                    SB Gateway {asText(archive.application_version, "—")} · {formatBytes(archive.size_bytes, locale)}
                  </small>
                </div>
                <div className="recovery-locations" aria-label={tr("Места хранения")}>
                  <StatusPill tone={archive.ssd === true ? "ok" : "warn"}>
                    SSD
                  </StatusPill>
                  <StatusPill tone={archive.routeros_files === true ? "ok" : "warn"}>
                    RouterOS Files
                  </StatusPill>
                </div>
                <div className="recovery-row-actions">
                  <button
                    className="button button-tertiary"
                    type="button"
                    disabled={recoveryBusy}
                    onClick={() => void saveRecoveryArchive(name)}
                  >
                     {tr("Скачать")} </button>
                  <button
                    className="button button-secondary"
                    type="button"
                    disabled={recoveryBusy}
                    onClick={() => setRestoreArchive(name)}
                  >
                     {tr("Восстановить")} </button>
                </div>
              </div>
            );
          })}
          {!asObjectList(recoveryStatus?.items).length ? (
            <div className="empty-result">
               {tr("Копий пока нет. Нажмите «Создать копию» — панель проверит обе точки хранения и настроит ротацию до трёх архивов.")} </div>
          ) : null}
        </div>
        {restoreArchive ? (
          <form className="recovery-restore-form" onSubmit={restoreRecovery}>
            <input className="sr-only" name="username" autoComplete="username" value="admin" readOnly tabIndex={-1} aria-hidden="true" />
            <div>
              <strong>{tr("Восстановить выбранную копию")}</strong>
              <small>{tr("После проверки RouterOS один раз перезапустит контейнер.")}</small>
            </div>
            <label className="field">
               {tr("Пароль администратора панели")} <input name="password" type="password" required autoComplete="current-password" />
            </label>
            <div className="recovery-confirm-actions">
              <button
                className="button button-tertiary"
                type="button"
                onClick={() => setRestoreArchive("")}
              >
                 {tr("Отмена")} </button>
              <button className="button button-danger" type="submit" disabled={recoveryBusy}>
                 {tr("Проверить и восстановить")} </button>
            </div>
          </form>
        ) : null}
        {recoveryMessage ? (
          <div
            className={`inline-result recovery-result ${isErrorMessage(recoveryMessage) ? "inline-result-error" : ""}`}
            role={isErrorMessage(recoveryMessage) ? "alert" : "status"}
          >
            <span>{isErrorMessage(recoveryMessage) ? "!" : "i"}</span>
            {recoveryMessage}
          </div>
        ) : null}
      </article>

      <section className="lifecycle-grid">
        <article className="card transport-card settings-launch-card">
          <div className="transport-summary">
            <div className="transport-title">
              <h3>{tr("Обновление контейнера")}</h3>
              <code>{asText(liveContainer.tag, tr("Тег не определён"))}</code>
            </div>
            <div className="transport-detail">
              <span className={`signal-dot signal-${liveContainer.healthy === true ? "ok" : "warn"}`} aria-hidden="true" />
              <span>{tr("Один .tar · проверка arm64 и SHA-256 · автоматический откат")}</span>
            </div>
          </div>
          <div className="transport-actions">
            <StatusPill tone={liveContainer.healthy === true ? "ok" : "warn"}>{liveContainer.healthy === true ? tr("Контейнер работает") : tr("Нужна проверка")}</StatusPill>
            <button className="button button-tertiary" type="button" onClick={() => setUpdateDialogOpen(true)}>{tr("Настроить")}</button>
          </div>
        </article>

        <article className="card transport-card settings-launch-card lifecycle-danger-row">
          <div className="transport-summary">
            <div className="transport-title">
              <h3>{tr("Полное удаление SB Gateway")}</h3>
              <code>{lifecycleStorageRoot || "Каталог проекта не определён"}</code>
            </div>
            <div className="transport-detail">
              <span className="signal-dot signal-warn" aria-hidden="true" />
              <span>{tr("Только контейнер, файлы и RouterOS-объекты с точной меткой SB-GATEWAY")}</span>
            </div>
          </div>
          <div className="transport-actions">
            <StatusPill tone="danger">{tr("Опасная операция")}</StatusPill>
            <button className="button button-tertiary" type="button" onClick={() => setUninstallDialogOpen(true)}>{tr("Настроить")}</button>
          </div>
        </article>
      </section>

      {updateDialogOpen ? (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setUpdateDialogOpen(false)}>
          <section className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="image-update-title" onMouseDown={(event) => event.stopPropagation()}>
            <button className="modal-close" type="button" onClick={() => setUpdateDialogOpen(false)} aria-label={tr("Закрыть")}>×</button>
            <form onSubmit={startImageUpdate}>
              <p className="eyebrow">{tr("Образ шлюза")}</p>
              <h2 id="image-update-title">{tr("Безопасное обновление контейнера")}</h2>
              <p className="modal-lead">{tr("RouterOS сохранит прежний контейнер остановленным и запустит его снова, если новый образ не пройдёт health-check.")}</p>
              <label className="field browser-image-upload" htmlFor="container-image-archive">
                 {tr("Новый образ SB Gateway · один .tar")} <input id="container-image-archive" type="file" accept=".tar,application/x-tar,application/octet-stream" aria-describedby="container-image-upload-help" disabled={imageUploadBusy || lifecycleBusy} onChange={(event) => { void uploadImageFromBrowser(event.target.files?.[0]); event.currentTarget.value = ""; }} />
                <small id="container-image-upload-help">{imageUploadBusy ? tr("Записываю прямо на SSD…") : tr("После записи панель проверит SB Gateway, linux/arm64 и SHA-256. Второй архив и файл .sha256 не нужны.")}</small>
              </label>
              {imageUploadBusy ? (
                <div className="image-upload-progress" aria-live="polite">
                  <div><strong>{imageUploadProgress.percent}%</strong><span>{formatBytes(imageUploadProgress.loadedBytes, locale)} / {formatBytes(imageUploadProgress.totalBytes, locale)}</span></div>
                  <div className="progress-track" role="progressbar" aria-label={tr("Загрузка образа на SSD")} aria-valuemin={0} aria-valuemax={100} aria-valuenow={imageUploadProgress.percent}>
                    <span style={{ width: `${imageUploadProgress.percent}%` }} />
                  </div>
                </div>
              ) : null}
              {candidateReference ? <div className="notice notice-success lifecycle-candidate-notice"><span className="notice-icon">✓</span><div><strong>{tr("Образ")} {candidateVersion}  {tr("проверен и готов")}</strong><p>SHA-256: {candidateChecksum.slice(0, 16)}{tr("… Проверен за один потоковый проход.")}</p></div></div> : null}
              {updateDialogOpen && lifecycleMessage ? <div className={`inline-result ${isErrorMessage(lifecycleMessage) ? "inline-result-error" : ""}`} role={isErrorMessage(lifecycleMessage) ? "alert" : "status"}><span>{isErrorMessage(lifecycleMessage) ? "!" : "i"}</span>{lifecycleMessage}</div> : null}
              <label className="checkbox-field lifecycle-confirmation"><input name="confirmed" type="checkbox" required /><span><strong>{tr("Обновить контейнер с автоматическим откатом")}</strong><small>{tr("Панель временно перезапустится; маршрутизация заранее перейдёт в fail-open.")}</small></span></label>
              <aside className="notice notice-neutral"><span className="notice-icon">i</span><div><strong>{tr("Перед остановкой запускается автоматическая проверка")}</strong><p>{tr("RouterOS проверяет project-owned объекты, отключает diversion и сохраняет прежний контейнер для отката.")}</p></div></aside>
              <div className="modal-actions"><button className="button button-tertiary" type="button" disabled={lifecycleBusy} onClick={() => setUpdateDialogOpen(false)}>{tr("Отмена")}</button><button className="button button-primary" type="submit" disabled={lifecycleBusy || imageUploadBusy || !candidateReference}>{lifecycleBusy ? tr("Ставлю в очередь…") : tr("Подготовить обновление")}</button></div>
            </form>
          </section>
        </div>
      ) : null}
      {updateProgressOpen ? createPortal(
        <LifecycleUpdateProgressDialog
          state={lifecycleOperationState || "scheduled"}
          version={lifecycleOperationVersion}
          elapsed={updateElapsed}
          progress={lifecycleProgressPercent}
          connectionMessage={updateConnectionMessage}
          onClose={() => setUpdateProgressOpen(false)}
        />,
        document.body,
      ) : null}

      {uninstallDialogOpen ? (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setUninstallDialogOpen(false)}>
          <section className="modal modal-wide modal-danger" role="dialog" aria-modal="true" aria-labelledby="full-uninstall-title" onMouseDown={(event) => event.stopPropagation()}>
            <button className="modal-close" type="button" onClick={() => setUninstallDialogOpen(false)} aria-label={tr("Закрыть")}>×</button>
            <form onSubmit={startFullUninstall}>
              <p className="eyebrow">{tr("Опасная операция")}</p>
              <h2 id="full-uninstall-title">{tr("Полностью удалить SB Gateway")}</h2>
              <p className="modal-lead">{tr("Удаляются только подтверждённый каталог проекта и RouterOS-объекты с точной меткой SB-GATEWAY.")}</p>
              {uninstallPreview ? <div className="lifecycle-preview"><div><strong>{tr("Будет удалено")}</strong><ul>{asStringList(uninstallPreview.removes).map((item) => <li key={item}>{item}</li>)}</ul></div><div><strong>{tr("Будет сохранено")}</strong><ul>{asStringList(uninstallPreview.preserves).map((item) => <li key={item}>{item}</li>)}</ul></div></div> : null}
              <label className="checkbox-field lifecycle-confirmation"><input name="confirmed" type="checkbox" required /><span><strong>{tr("Удалить SB Gateway полностью")}</strong><small>{tr("Каталог")} {lifecycleStorageRoot || "проекта"}  {tr("и только объекты с меткой SB-GATEWAY.")}</small></span></label>
              <div className="modal-actions"><button className="button button-tertiary" type="button" disabled={lifecycleBusy} onClick={() => setUninstallDialogOpen(false)}>{tr("Отмена")}</button><button className="button button-danger" type="submit" disabled={lifecycleBusy || !lifecycleStorageRoot}>{lifecycleBusy ? tr("Проверяю…") : tr("Проверить и удалить")}</button></div>
            </form>
          </section>
        </div>
      ) : null}

      {!updateDialogOpen && !updateProgressOpen && lifecycleMessage ? (
        <div
          className={`inline-result ${isErrorMessage(lifecycleMessage) ? "inline-result-error" : ""}`}
          role={isErrorMessage(lifecycleMessage) ? "alert" : "status"}
        >
          <span>{isErrorMessage(lifecycleMessage) ? "!" : "i"}</span>
          {lifecycleMessage}
        </div>
      ) : null}
      {lifecycleStatus && asObject(lifecycleStatus.operation).state ? (
        <aside className="mini-notice">
           {tr("Последняя lifecycle-операция:")} {asText(asObject(lifecycleStatus.operation).state, tr("неизвестно"))} · {asText(asObject(lifecycleStatus.operation).version, tr("без версии"))}
        </aside>
      ) : null}
      {rollbackOpen ? (
        <RollbackDialog
          onClose={() => setRollbackOpen(false)}
          onCompleted={onRefresh}
        />
      ) : null}
      {xrayLogOpen ? createPortal(
        <div className="modal-backdrop xray-log-backdrop" role="presentation" onMouseDown={() => setXrayLogOpen(false)}>
          <section className="modal modal-wide xray-log-dialog" role="dialog" aria-modal="true" aria-labelledby="xray-log-title" onMouseDown={(event) => event.stopPropagation()}>
            <header className="xray-log-dialog-header">
              <div>
                <h2 id="xray-log-title">{tr("Журналы SB Gateway")}</h2>
                <p>{tr("Последние 300 строк · обновление каждые 3 секунды")}</p>
              </div>
              <button className="modal-close" type="button" onClick={() => setXrayLogOpen(false)} aria-label={tr("Закрыть")}>×</button>
            </header>

            <div className="xray-log-toolbar">
              <div className="xray-log-tabs" role="tablist" aria-label={tr("Источник журнала")}>
                <button id="xray-log-tab-error" type="button" role="tab" aria-controls="xray-log-panel" aria-selected={xrayLogSource === "error"} className={xrayLogSource === "error" ? "is-active" : ""} onClick={() => setXrayLogSource("error")}>
                  {tr("Ошибки Xray")}
                </button>
                <button id="xray-log-tab-process" type="button" role="tab" aria-controls="xray-log-panel" aria-selected={xrayLogSource === "process"} className={xrayLogSource === "process" ? "is-active" : ""} onClick={() => setXrayLogSource("process")}>
                  {tr("Процесс и panic")}
                </button>
                <button id="gateway-log-tab-system" type="button" role="tab" aria-controls="xray-log-panel" aria-selected={xrayLogSource === "system"} className={xrayLogSource === "system" ? "is-active" : ""} onClick={() => setXrayLogSource("system")}>
                  {tr("Control plane")}
                </button>
                <button id="gateway-log-tab-routing" type="button" role="tab" aria-controls="xray-log-panel" aria-selected={xrayLogSource === "routing"} className={xrayLogSource === "routing" ? "is-active" : ""} onClick={() => setXrayLogSource("routing")}>
                  {tr("Маршруты")}
                </button>
                <button id="gateway-log-tab-nginx" type="button" role="tab" aria-controls="xray-log-panel" aria-selected={xrayLogSource === "nginx"} className={xrayLogSource === "nginx" ? "is-active" : ""} onClick={() => setXrayLogSource("nginx")}>
                  nginx
                </button>
                <button id="gateway-log-tab-lifecycle" type="button" role="tab" aria-controls="xray-log-panel" aria-selected={xrayLogSource === "lifecycle"} className={xrayLogSource === "lifecycle" ? "is-active" : ""} onClick={() => setXrayLogSource("lifecycle")}>
                  {tr("Обновления")}
                </button>
              </div>
              <div className="xray-log-toolbar-actions">
                <button
                  className="button button-tertiary xray-log-collapse"
                  type="button"
                  aria-controls="xray-log-panel"
                  aria-expanded={!xrayLogCollapsed}
                  aria-label={xrayLogCollapsed ? tr("Развернуть журнал") : tr("Свернуть журнал")}
                  title={xrayLogCollapsed ? tr("Развернуть журнал") : tr("Свернуть журнал")}
                  onClick={() => setXrayLogCollapsed((current) => !current)}
                >
                  {xrayLogCollapsed ? "⌄" : "⌃"}
                </button>
                <button className="button button-tertiary" type="button" disabled={!xrayLogLines.length} onClick={() => void copyXrayLog()}>{tr("Копировать")}</button>
                <button className="button button-tertiary" type="button" disabled={xrayLogBusy} onClick={() => void loadXrayLog()}>
                  {xrayLogBusy ? tr("Обновляю…") : tr("Обновить")}
                </button>
              </div>
            </div>

            <pre id="xray-log-panel" className="xray-log-viewport" ref={xrayLogViewportRef} role="tabpanel" aria-labelledby={xrayLogSource === "error" ? "xray-log-tab-error" : xrayLogSource === "process" ? "xray-log-tab-process" : runtimeLogTabId(xrayLogSource)} tabIndex={xrayLogCollapsed ? -1 : 0} hidden={xrayLogCollapsed} onScroll={(event) => {
              const viewport = event.currentTarget;
              xrayLogStickToEndRef.current = viewport.scrollHeight - viewport.scrollTop - viewport.clientHeight < 48;
            }}>
              {xrayLogBusy && !xrayLogSnapshot
                ? tr("Читаю журнал…")
                : xrayLogSnapshot?.available === false
                  ? tr("Файл журнала пока не создан.")
                  : xrayLogLines.length
                    ? xrayLogLines.join("\n")
                    : tr("Новых записей нет.")}
            </pre>
            {!xrayLogCollapsed && xrayLogSnapshot?.truncated === true ? <p className="xray-log-caption">{tr("Показан конец файла. Старые строки скрыты.")}</p> : null}

            {xrayLogSelected ? <div className="xray-log-settings">
              <label className="field" htmlFor="xray-log-level">
                {tr("Уровень логирования")}
                <select id="xray-log-level" value={xrayLogLevel} onChange={(event) => setXrayLogLevel(event.target.value)}>
                  <option value="error">Error</option>
                  <option value="warning">Warning · {tr("рекомендуется")}</option>
                  <option value="info">Info</option>
                  <option value="debug">Debug · 15 {tr("минут")}</option>
                  <option value="none">None</option>
                </select>
                <small>{tr("Access-log подключений остаётся выключенным. Изменение ядра выполняется только после общего применения конфигурации.")}</small>
                <small>{tr("Сейчас работает:")} {effectiveXrayLogLevel}{xrayLogging.debug_expires_at ? ` · ${tr("до")} ${formatTimestamp(xrayLogging.debug_expires_at, locale)}` : ""}</small>
              </label>
              <button className="button button-primary" type="button" disabled={xrayLogLevelBusy || xrayLogLevel === configuredXrayLogLevel} onClick={() => void saveXrayLogLevel()}>
                {xrayLogLevelBusy ? tr("Сохраняю…") : tr("Сохранить уровень")}
              </button>
            </div> : null}
            {xrayLogSelected && xrayLogLevel === "debug" ? (
              <aside className="notice notice-warning xray-log-warning">
                <span className="notice-icon">!</span>
                <div><strong>{tr("Debug временный")}</strong><p>{tr("Через 15 минут шлюз автоматически вернёт Warning и перезапустит только Xray.")}</p></div>
              </aside>
            ) : null}
            {xrayLogMessage ? <div className={`inline-result ${isErrorMessage(xrayLogMessage) ? "inline-result-error" : ""}`} role={isErrorMessage(xrayLogMessage) ? "alert" : "status"}><span>{isErrorMessage(xrayLogMessage) ? "!" : "i"}</span>{xrayLogMessage}</div> : null}
          </section>
        </div>,
        document.body,
      ) : null}
    </>
  );
}

function LifecycleUpdateProgressDialog({
  state,
  version,
  elapsed,
  progress,
  connectionMessage,
  onClose,
}: {
  state: string;
  version: string;
  elapsed: number;
  progress: number;
  connectionMessage: string;
  onClose: () => void;
}) {
  const { tr } = useLanguage();
  const completed = state === "completed";
  const rolledBack = state === "rolled_back";
  const failed = rolledBack || state === "failed";
  const probation = state === "probation";
  const switched = probation || completed || failed;
  const statusLabel = completed
    ? tr("Обновление завершено")
    : state === "rolled_back"
      ? tr("Выполнен автоматический откат")
      : state === "failed"
        ? tr("Обновление остановлено")
        : probation
          ? tr("Проверяю новую версию")
          : tr("RouterOS готовит переключение");
  const stepState = (done: boolean, active: boolean) => done ? "done" : active ? "active" : "pending";

  return (
    <div className="modal-backdrop lifecycle-progress-backdrop" role="presentation">
      <section className="modal lifecycle-progress-dialog" role="dialog" aria-modal="true" aria-labelledby="lifecycle-progress-title">
        <button className="modal-close" type="button" onClick={onClose} aria-label={tr("Закрыть")}>×</button>
        <h2 id="lifecycle-progress-title">{tr("Обновление контейнера")}</h2>
        <p className="modal-lead">SB Gateway {version || "—"} · {tr("прошло")} <strong className="tabular-numbers">{formatElapsed(elapsed)}</strong></p>

        <div className={`lifecycle-progress-status ${failed ? "is-failed" : completed ? "is-complete" : ""}`} aria-live="polite">
          <div><strong>{statusLabel}</strong><span>{progress}%</span></div>
          <div className="progress-track" role="progressbar" aria-label={statusLabel} aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}>
            <span style={{ width: `${progress}%` }} />
          </div>
        </div>

        <ol className="lifecycle-progress-steps">
          <li data-state={stepState(true, false)}><span>1</span><div><strong>{tr("Архив проверен")}</strong><small>{tr("ARM64, версия и SHA-256 подтверждены.")}</small></div></li>
          <li data-state={stepState(switched, !switched)}><span>2</span><div><strong>{tr("Распаковка и переключение")}</strong><small>{tr("RouterOS сохраняет рабочий контейнер для автоматического возврата.")}</small></div></li>
          <li data-state={stepState(completed, probation)}><span>3</span><div><strong>{rolledBack ? tr("Предыдущая версия восстановлена") : state === "failed" ? tr("Рабочая версия не изменена") : tr("Health-check и контрольный период")}</strong><small>{failed ? tr("Рабочая конфигурация сохранена; откройте журнал обновления.") : tr("После подтверждения новая версия станет рабочей.")}</small></div></li>
        </ol>

        {connectionMessage ? <div className="mini-notice lifecycle-reconnect" role="status">{connectionMessage}</div> : null}
        {completed ? <div className="inline-result" role="status"><span>✓</span>{tr("Новая версия принята. Автоматический откат больше не требуется.")}</div> : null}
        {failed ? <div className="inline-result inline-result-error" role="alert"><span>!</span>{rolledBack ? tr("Новая версия не прошла проверку. Шлюз вернул предыдущий контейнер.") : tr("RouterOS не начал переключение. Рабочий контейнер сохранён.")}</div> : null}

        <div className="modal-actions">
          <button className={completed ? "button button-primary" : "button button-secondary"} type="button" onClick={onClose}>
            {completed || failed ? tr("Готово") : tr("Скрыть")}
          </button>
        </div>
      </section>
    </div>
  );
}

function Settings({
  config,
  routeros,
  onDraftChanged,
}: {
  config: JsonObject;
  routeros: JsonObject;
  onDraftChanged: () => Promise<void>;
}) {
  const { locale, tr } = useLanguage();
  const systemFromDraft = asObject(config.system);
  const managementFromDraft = asObject(systemFromDraft.management);
  const networkingFromDraft = asObject(systemFromDraft.networking);
  const watchdogFromDraft = asObject(config.watchdog);
  const exposureFromDraft = asObject(config.public_exposure);
  const guardFromDraft = asObject(exposureFromDraft.connection_guard);
  const configuredManagementSources = asStringList(
    managementFromDraft.allowed_source_cidrs,
  );
  const configuredManagementIngress = asStringList(
    managementFromDraft.allowed_ingress_interfaces,
  );
  const [managementSourcesOverride, setManagementSourcesOverride] = useState<
    string | null
  >(null);
  const [managementIngressOverride, setManagementIngressOverride] = useState<
    string | null
  >(null);
  const [panelPortOverride, setPanelPortOverride] = useState<string | null>(null);
  const [selectedPanelHost, setSelectedPanelHost] = useState("");
  const connectionSnapshot = useContext(ConnectionAddressContext);
  const panelPortText = panelPortOverride ?? String(managementFromDraft.routeros_panel_port ?? 17443);
  const panelPort = Number(panelPortText);
  const panelPortValid = Number.isInteger(panelPort) && panelPort >= 1024 && panelPort <= 65535 && panelPort !== 9443;
  const [watchdogIntervalOverride, setWatchdogIntervalOverride] = useState<
    number | null
  >(null);
  const [failureThresholdOverride, setFailureThresholdOverride] = useState<
    number | null
  >(null);
  const [recoveryThresholdOverride, setRecoveryThresholdOverride] = useState<
    number | null
  >(null);
  const [recoveryCooldownOverride, setRecoveryCooldownOverride] = useState<
    number | null
  >(null);
  const [restartBudgetOverride, setRestartBudgetOverride] = useState<
    number | null
  >(null);
  const [guardEnabled, setGuardEnabled] = useState(guardFromDraft.enabled !== false);
  const [sharedTcp443, setSharedTcp443] = useState(exposureFromDraft.shared_tcp_443 === true);
  const [guardRate, setGuardRate] = useState(Number(guardFromDraft.new_connection_rate ?? 40));
  const [guardBurst, setGuardBurst] = useState(Number(guardFromDraft.burst ?? 80));
  const [guardTimeout, setGuardTimeout] = useState(Number(guardFromDraft.quarantine_seconds ?? 600));
  const [storageRoot, setStorageRoot] = useState(asText(asObject(config.storage).root, ""));
  const [keepPreviousVersion, setKeepPreviousVersion] = useState(Number(asObject(config.updates).retain_previous_images ?? 0) === 1);
  const managementSourcesText =
    managementSourcesOverride ?? configuredManagementSources.join("\n");
  const managementIngressText =
    managementIngressOverride ?? configuredManagementIngress.join("\n");
  const managementSources = uniqueListInput(managementSourcesText);
  const managementIngressInterfaces = uniqueListInput(managementIngressText);
  const invalidManagementSources = managementSources.filter(
    (value) => !isIpv4Cidr(value, false),
  );
  const invalidManagementIngress = managementIngressInterfaces.filter(
    (value) => !isRouterOsInterfaceName(value),
  );
  const containerBridgeName = asText(networkingFromDraft.bridge_name, "");
  const containerBridgeSelected = Boolean(
    containerBridgeName && managementIngressInterfaces.includes(containerBridgeName),
  );
  const managementAccessValid =
    managementSources.length > 0 &&
    managementIngressInterfaces.length > 0 &&
    invalidManagementSources.length === 0 &&
    invalidManagementIngress.length === 0 &&
    !containerBridgeSelected;
  const watchdogInterval =
    watchdogIntervalOverride ?? Number(watchdogFromDraft.interval_seconds || 5);
  const failureThreshold =
    failureThresholdOverride ??
    Number(watchdogFromDraft.failure_threshold || 3);
  const recoveryThreshold =
    recoveryThresholdOverride ??
    Number(watchdogFromDraft.recovery_threshold || 3);
  const recoveryCooldown =
    recoveryCooldownOverride ??
    Number(watchdogFromDraft.recovery_cooldown_seconds ?? 0);
  const restartBudget =
    restartBudgetOverride ??
    Number(watchdogFromDraft.max_restarts_per_hour || 6);
  const watchdogSettingsValid =
    Number.isInteger(watchdogInterval) &&
    watchdogInterval >= 5 &&
    watchdogInterval <= 300 &&
    Number.isInteger(failureThreshold) &&
    failureThreshold >= 1 &&
    failureThreshold <= 20 &&
    Number.isInteger(recoveryThreshold) &&
    recoveryThreshold >= 1 &&
    recoveryThreshold <= 20 &&
    Number.isInteger(recoveryCooldown) &&
    recoveryCooldown >= 10 &&
    recoveryCooldown <= 3600 &&
    Number.isInteger(restartBudget) &&
    restartBudget >= 1 &&
    restartBudget <= 60;
  const publicExposureValid =
    Number.isInteger(guardRate) &&
    guardRate >= 5 &&
    guardRate <= 1000 &&
    Number.isInteger(guardBurst) &&
    guardBurst >= 10 &&
    guardBurst <= 5000 &&
    Number.isInteger(guardTimeout) &&
    guardTimeout >= 60 &&
    guardTimeout <= 86400;
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [passwordMessage, setPasswordMessage] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPasswordConfirmation, setNewPasswordConfirmation] = useState("");
  const currentSystem = asObject(config.system);
  const currentStorage = asObject(config.storage);
  const currentContainer = asObject(currentSystem.container);
  const liveContainer = asObject(routeros.container);
  const usbPath = asText(
    liveContainer.root_dir,
    asText(currentStorage.root, tr("Live REST недоступен")),
  );
  const liveMemoryLimit = asText(
    liveContainer.memory_max,
    asText(liveContainer.memory_high, ""),
  );
  const configuredMemoryMb = asText(currentContainer.memory_limit_mb, "");
  const memoryLimitLabel =
    liveMemoryLimit.toLowerCase() === "unlimited"
      ? tr("Без ограничения")
      : liveMemoryLimit
        ? formatBytes(liveMemoryLimit, locale)
        : configuredMemoryMb
          ? tr("{value1} МБ (из черновика)", { value1: configuredMemoryMb })
          : tr("Live REST недоступен");
  const panelHosts = Array.from(new Set(asObjectList(connectionSnapshot.local_addresses)
    .filter((row) => managementIngressInterfaces.includes(asText(row.interface, "")) && row.interface !== containerBridgeName)
    .map((row) => asText(row.address, ""))))
    .sort((left, right) => right.localeCompare(left, undefined, { numeric: true }));
  const panelHost = panelHosts.includes(selectedPanelHost) ? selectedPanelHost : panelHosts[0] ?? "";

  async function saveSettings() {
    setSaveBusy(true);
    setSaveMessage("");
    if (!managementAccessValid || !panelPortValid) {
      setSaveMessage(
        tr("Ошибка: проверьте IP/CIDR, интерфейсы и порт доступа к панели."),
      );
      setSaveBusy(false);
      return;
    }
    try {
      const system = asObject(config.system);
      const management = asObject(system.management);
      const networking = asObject(system.networking);
      const watchdog = asObject(config.watchdog);
      const security = asObject(config.security);
      const publicExposure = asObject(config.public_exposure);
      const storage = asObject(config.storage);

      await saveCurrentDraft({
        config: withDeploymentReadiness({
          ...config,
          system: {
            ...system,
            management: {
              ...management,
              allowed_source_cidrs: managementSources,
              allowed_ingress_interfaces: managementIngressInterfaces,
              routeros_panel_port: panelPort,
            },
            networking,
          },
          watchdog: {
            ...watchdog,
            interval_seconds: watchdogInterval,
            failure_threshold: failureThreshold,
            recovery_threshold: recoveryThreshold,
            recovery_cooldown_seconds: recoveryCooldown,
            max_restarts_per_hour: restartBudget,
            enabled: undefined,
            routeros_auto_restart_seconds: undefined,
            local_fail_mode: undefined,
            remote_fail_mode: undefined,
          },
          security: {
            ...security,
            allow_router_management: false,
            redact_logs: undefined,
            csrf_protection: undefined,
            block_management_from_wan: undefined,
          },
          public_exposure: {
            ...publicExposure,
            shared_tcp_443: sharedTcp443,
            decoy: undefined,
            connection_guard: {
              ...asObject(publicExposure.connection_guard),
              enabled: guardEnabled,
              new_connection_rate: guardRate,
              burst: guardBurst,
              quarantine_seconds: guardTimeout,
            },
            subscription: asObject(publicExposure.subscription),
          },
          storage: {
            ...storage,
            root: storageRoot.trim().replace(/^\/+|\/+$/g, ""),
          },
          updates: {
            ...asObject(config.updates),
            retain_previous_images: keepPreviousVersion ? 1 : 0,
          },
        }, false),
      });
      await onDraftChanged();
      setManagementSourcesOverride(managementSources.join("\n"));
      setManagementIngressOverride(managementIngressInterfaces.join("\n"));
      setSaveMessage(
        tr("Настройки сохранены: {value1} IP/CIDR, {value2} входных интерфейсов. Для включения примените изменения.", { value1: managementSources.length, value2: managementIngressInterfaces.length }),
      );
    } catch (error) {
      setSaveMessage(prefixedErrorMessage(error));
    } finally {
      setSaveBusy(false);
    }
  }

  async function changePanelPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPasswordMessage("");
    if (newPassword.length < 12) {
      setPasswordMessage(tr("Ошибка: новый пароль должен содержать минимум 12 символов."));
      return;
    }
    if (newPassword !== newPasswordConfirmation) {
      setPasswordMessage(tr("Ошибка: подтверждение нового пароля не совпадает."));
      return;
    }
    setPasswordBusy(true);
    try {
      await changeAdministratorPassword(
        currentPassword,
        newPassword,
        newPasswordConfirmation,
      );
      setCurrentPassword("");
      setNewPassword("");
      setNewPasswordConfirmation("");
      setPasswordMessage(tr("Пароль изменён. Остальные сеансы панели завершены."));
    } catch (error) {
      setPasswordMessage(prefixedErrorMessage(error));
    } finally {
      setPasswordBusy(false);
    }
  }

  return (
    <>
      <SectionTitle
        eyebrow={tr("Настройки")}
        title={tr("Доступ и системные параметры")}
      />

      {saveMessage ? (
        <div
          className={`inline-result ${
            isErrorMessage(saveMessage) ? "inline-result-error" : ""
          }`}
          role={isErrorMessage(saveMessage) ? "alert" : "status"}
        >
          <span>{isErrorMessage(saveMessage) ? "!" : "✓"}</span>
          {saveMessage}
        </div>
      ) : null}

      <section className="settings-grid">
        <article className="card settings-card">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{tr("Веб-интерфейс")}</p>
              <h3>{tr("Доступ к панели")}</h3>
            </div>
          </div>
          <label className="field">
             {tr("Разрешённые IP/CIDR")} <textarea
              value={managementSourcesText}
              onChange={(event) =>
                setManagementSourcesOverride(event.target.value)
              }
              placeholder={tr("Заполняется мастером первого запуска")}
              rows={5}
              aria-invalid={invalidManagementSources.length > 0}
            />
            <small>{tr("Один IP/CIDR на строку.")}</small>
          </label>
          {invalidManagementSources.length ? (
            <div className="field-error" role="alert">
               {tr("Неверный IPv4 CIDR:")} {invalidManagementSources.join(", ")}{tr(". Маршрут 0.0.0.0/0 запрещён.")} </div>
          ) : null}
          <label className="field">
             {tr("Доверенные входные интерфейсы RouterOS")} <textarea
              value={managementIngressText}
              onChange={(event) =>
                setManagementIngressOverride(event.target.value)
              }
              placeholder={tr("Заполняется мастером первого запуска")}
              rows={4}
              aria-invalid={
                invalidManagementIngress.length > 0 || containerBridgeSelected
              }
            />
            <small>{tr("Один интерфейс на строку. WireGuard добавляется автоматически.")}</small>
          </label>
          {invalidManagementIngress.length ? (
            <div className="field-error" role="alert">
               {tr("Недопустимое имя интерфейса:")} {invalidManagementIngress.join(", ")}.
            </div>
          ) : null}
          {containerBridgeSelected ? (
            <div className="field-error" role="alert">
              {containerBridgeName}  {tr("— внутренний bridge контейнера, а не место входа LAN/VPN-клиента.")} </div>
          ) : null}
          <div className="locked-setting">
            <div>
              <strong>{tr("LAN и OpenVPN · IP/CIDR + интерфейс")}</strong>
            </div>
            <StatusPill tone={managementAccessValid ? "ok" : "danger"}>
              {managementSources.length} IP · {managementIngressInterfaces.length}  {tr("входа")} </StatusPill>
          </div>
          <div className="locked-setting">
            <div>
              <strong>WireGuard</strong>
            </div>
            <StatusPill tone="ok">{tr("Автоматически")}</StatusPill>
          </div>
          <div className="panel-address-fields">
            <label className="field">
               {tr("Адрес панели")} <select aria-label={tr("Адрес панели")} value={panelHost} onChange={(event) => setSelectedPanelHost(event.target.value)} disabled={!panelHosts.length}>
                {!panelHosts.length ? <option value="">{tr("Сначала выполните первичную настройку")}</option> : null}
                {panelHosts.map((address) => <option key={address} value={address}>{`https://${address}:${panelPortValid ? panelPort : "—"}`}</option>)}
              </select>
            </label>
            <label className="field">
               {tr("Порт панели")} <input type="number" min={1024} max={65535} step={1} value={panelPortText} aria-invalid={!panelPortValid} onChange={(event) => setPanelPortOverride(event.target.value)} />
            </label>
          </div>
          {!panelPortValid ? <div className="field-error" role="alert">{tr("Порт: 1024–65535, кроме 9443.")}</div> : null}
          <details className="compact-disclosure">
            <summary>{tr("Сменить пароль")}</summary>
            <form className="compact-password-form" onSubmit={changePanelPassword}>
              <label className="field">
                 {tr("Текущий пароль")} <input
                  type="password"
                  autoComplete="current-password"
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.target.value)}
                  required
                />
              </label>
              <label className="field">
                 {tr("Новый пароль")} <input
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  required
                />
                <small>{tr("Минимум 12 символов, без обязательных правил состава.")}</small>
              </label>
              <label className="field">
                 {tr("Повторите новый пароль")} <input
                  type="password"
                  autoComplete="new-password"
                  minLength={12}
                  value={newPasswordConfirmation}
                  onChange={(event) => setNewPasswordConfirmation(event.target.value)}
                  required
                />
              </label>
              <div className="compact-password-actions">
                <small className={isErrorMessage(passwordMessage) ? "field-error" : "field-success"} role="status">
                  {passwordMessage}
                </small>
                <button className="button button-primary" type="submit" disabled={passwordBusy}>
                  {passwordBusy ? tr("Сохраняю…") : tr("Сохранить новый пароль")}
                </button>
              </div>
            </form>
          </details>
          <Toggle
            checked
            disabled
            label={tr("Всегда блокировать доступ с WAN")}
          />
          <Toggle
            checked
            disabled
            label={tr("CSRF-защита")}
          />
          <Toggle
            checked
            disabled
            label={tr("Маскировать секреты")}
          />
        </article>

        <article className="card settings-card">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Watchdog</p>
              <h3>{tr("Проверки и восстановление")}</h3>
            </div>
          </div>
          <div className="form-grid compact-form-grid">
            <label className="field">
               {tr("Интервал проверки · сек.")} <input
                type="number"
                min="5"
                max="300"
                value={watchdogInterval}
                onChange={(event) =>
                  setWatchdogIntervalOverride(Number(event.target.value))
                }
              />
            </label>
            <label className="field">
               {tr("Ошибок до fail-open")} <input
                type="number"
                min="1"
                max="20"
                value={failureThreshold}
                onChange={(event) =>
                  setFailureThresholdOverride(Number(event.target.value))
                }
              />
            </label>
            <label className="field">
               {tr("Успехов до возврата")} <input
                type="number"
                min="1"
                max="20"
                value={recoveryThreshold}
                onChange={(event) =>
                  setRecoveryThresholdOverride(Number(event.target.value))
                }
              />
            </label>
            <label className="field">
               {tr("Cooldown возврата · сек.")} <input
                type="number"
                min="0"
                max="3600"
                value={recoveryCooldown}
                onChange={(event) =>
                  setRecoveryCooldownOverride(Number(event.target.value))
                }
              />
            </label>
            <label className="field form-span">
               {tr("Принудительных рестартов за 60 минут")} <input
                type="number"
                min="1"
                max="60"
                value={restartBudget}
                onChange={(event) =>
                  setRestartBudgetOverride(Number(event.target.value))
                }
              />
              <small>
                 {tr("После исчерпания бюджета контейнер остаётся доступным для диагностики, а локальный трафик продолжает идти через обычный WAN.")} </small>
            </label>
          </div>
        </article>

        <article className="card settings-card">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{tr("Ресурсы")}</p>
              <h3>{tr("Контейнер и накопитель")}</h3>
            </div>
          </div>
          <Toggle
            checked={keepPreviousVersion}
            onChange={setKeepPreviousVersion}
            label={tr("Хранить предыдущую версию")}
          />
          <label className="field">
             {tr("Root-dir контейнера")} <input value={usbPath} readOnly />
          </label>
          <label className="field">
             {tr("Лимит памяти контейнера")} <input value={memoryLimitLabel} readOnly />
          </label>
        </article>

        <article className="card settings-card">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">{tr("Защита портов")}</p>
              <h3>{tr("Входящие подключения")}</h3>
            </div>
          </div>
          <Toggle
            checked={sharedTcp443}
            onChange={setSharedTcp443}
            label={tr("Общий TCP 443 для Reality и HTTPS")}
          />
          <Toggle
            checked={guardEnabled}
            onChange={setGuardEnabled}
            label={tr("Включить connection guard")}
          />
          <div className="form-grid compact-form-grid">
            <label className="field">
               {tr("Новых соединений/сек. на IP")} <input type="number" min="5" max="1000" value={guardRate} onChange={(event) => setGuardRate(Number(event.target.value))} />
            </label>
            <label className="field">
               {tr("Допустимый burst")} <input type="number" min="10" max="5000" value={guardBurst} onChange={(event) => setGuardBurst(Number(event.target.value))} />
            </label>
            <label className="field form-span">
               {tr("Карантин · сек.")} <input type="number" min="60" max="86400" value={guardTimeout} onChange={(event) => setGuardTimeout(Number(event.target.value))} />
            </label>
          </div>
          <label className="field">
             {tr("Каталог проекта на внешнем SSD")} <input value={storageRoot} onChange={(event) => setStorageRoot(event.target.value)} placeholder="usb1/sb-gateway" />
          </label>
        </article>
      </section>
      <div className="settings-save-actions">
        <button
          className="button button-primary"
          onClick={saveSettings}
          disabled={
            saveBusy ||
            !watchdogSettingsValid ||
            !managementAccessValid ||
            !panelPortValid ||
            !publicExposureValid
          }
        >
          {saveBusy ? tr("Сохраняю…") : tr("Сохранить изменения")}
        </button>
      </div>
    </>
  );
}

function ResetDraftDialog({
  changeCount,
  onClose,
  onReset,
}: {
  changeCount: number;
  onClose: () => void;
  onReset: () => Promise<unknown>;
}) {
  const { tr } = useLanguage();
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState("");

  async function reset() {
    setBusy(true);
    setOperationError("");
    try {
      await onReset();
      onClose();
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={() => {
        if (!busy) onClose();
      }}
    >
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="reset-draft-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          onClick={onClose}
          aria-label={tr("Закрыть")}
          disabled={busy}
        >
          ×
        </button>
        <h2 id="reset-draft-title">{tr("Сбросить изменения?")}</h2>
        <p className="modal-lead">
           {tr("Черновик вернётся к последней применённой конфигурации. Работающий маршрут и соединения не изменятся.")} </p>
        <aside className="notice notice-neutral">
          <span className="notice-icon">i</span>
          <div>
            <strong>{tr("Будет отброшено изменений:")} {changeCount}</strong>
            <p>{tr("Повторно восстанавливать значения вручную не потребуется.")}</p>
          </div>
        </aside>
        {operationError ? (
          <div className="inline-result inline-result-error" role="alert">
            <span>!</span>
            {operationError}
          </div>
        ) : null}
        <div className="modal-actions">
          <button className="button button-secondary" onClick={onClose} disabled={busy}>
             {tr("Оставить черновик")} </button>
          <button className="button button-danger" onClick={reset} disabled={busy}>
            {busy ? tr("Сбрасываю…") : tr("Сбросить изменения")}
          </button>
        </div>
      </section>
    </div>
  );
}

function ApplyDialog({
  mode,
  onClose,
  onRun,
  onPlan,
  publicTlsReady,
  networkReviewPending,
  managementIngressReady,
}: {
  mode: "check" | "apply";
  onClose: () => void;
  onRun: (mode: "check" | "apply") => Promise<unknown>;
  onPlan: () => Promise<unknown>;
  publicTlsReady: boolean;
  networkReviewPending: number;
  managementIngressReady: boolean;
}) {
  const { locale, tr } = useLanguage();
  const [reviewConfirmed, setReviewConfirmed] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [completed, setCompleted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [operationError, setOperationError] = useState("");
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [applyPlan, setApplyPlan] = useState<JsonObject>({});
  const [planBusy, setPlanBusy] = useState(mode === "apply");
  const [planError, setPlanError] = useState("");
  const planRequestRef = useRef(onPlan);

  useEffect(() => {
    if (mode !== "apply") return;
    let cancelled = false;
    void planRequestRef.current()
      .then((value) => {
        if (cancelled) return;
        const plan = asObject(value);
        setApplyPlan(plan);
        if (plan.valid !== true) {
          setPlanError(tr("Точный план не прошёл проверку. Исправьте ошибки черновика."));
        }
      })
      .catch((error) => {
        if (!cancelled) setPlanError(errorMessage(error));
      })
      .finally(() => {
        if (!cancelled) setPlanBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [mode, tr]);

  useEffect(() => {
    if (!busy) return;
    const startedAt = Date.now();
    const timer = window.setInterval(() => {
      setElapsedSeconds(Math.floor((Date.now() - startedAt) / 1000));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [busy]);

  async function execute() {
    setElapsedSeconds(0);
    setBusy(true);
    setOperationError("");
    try {
      setResult(await onRun(mode));
      setCompleted(true);
    } catch (error) {
      setOperationError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  const plannedMode = asText(applyPlan.apply_mode, "");
  const isStateOnly = plannedMode === "state_only";
  const isRuntimeFast = plannedMode === "runtime_fast";
  const isConnectivitySafeMode = plannedMode === "connectivity_safe_mode";
  const isRouterOsSafeMode = plannedMode === "routeros_safe_mode";
  const isUnchanged = plannedMode === "unchanged";
  const planValidationErrors = asObjectList(asObject(applyPlan.check).errors);
  const applyPlanReady =
    mode !== "apply" ||
    (!planBusy &&
      !planError &&
      applyPlan.valid === true &&
      (isStateOnly || isRuntimeFast || isConnectivitySafeMode || isRouterOsSafeMode || isUnchanged));

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={() => {
        if (!busy) onClose();
      }}
    >
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="apply-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          onClick={onClose}
          aria-label={tr("Закрыть")}
          disabled={busy}
          title={busy ? tr("Дождитесь подтверждённого результата операции") : undefined}
        >
          ×
        </button>
        {completed ? (
          <div className="modal-success" role="status">
            <span>✓</span>
            <h2 id="apply-title">
              {mode === "check"
                ? tr("Проверка пройдена")
                : isStateOnly
                  ? tr("Название сохранено")
                : isRuntimeFast
                  ? tr("Runtime обновлён")
                  : isConnectivitySafeMode
                    ? tr("Связность безопасно обновлена")
                  : tr("Изменения применены")}
            </h2>
            <p>
              {resultMessage(
                result,
                mode === "check"
                  ? tr("Control plane завершил проверку candidate. Рабочая конфигурация не менялась.")
                  : tr("Control plane подтвердил завершение безопасного применения."),
              )}
            </p>
            <button className="button button-primary" onClick={onClose}>
               {tr("Готово")} </button>
          </div>
        ) : (
          <>
            <p className="eyebrow">
              {mode === "check"
                ? tr("Без изменений")
                : isStateOnly
                  ? tr("Только метаданные")
                : isRuntimeFast
                  ? tr("Быстрое применение")
                  : isConnectivitySafeMode
                    ? tr("Защита связности")
                  : isUnchanged
                    ? tr("Конфигурация совпадает")
                    : tr("Безопасное применение")}
            </p>
            <h2 id="apply-title">
              {mode === "check"
                ? tr("Проверить черновик")
                : isStateOnly
                  ? tr("Сохранить изменения")
                : isRuntimeFast
                  ? tr("Обновить runtime")
                  : isConnectivitySafeMode
                    ? tr("Безопасно обновить связность")
                  : tr("Применить проверенный черновик")}
            </h2>
            <p className="modal-lead">
              {mode === "check"
                ? tr("Панель сгенерирует candidate и запустит все проверки, но ничего не перезапустит.")
                : planBusy
                  ? tr("Панель сравнивает фактический RouterOS-кандидат с активным и выбирает необходимый уровень защиты.")
                  : isStateOnly
                    ? tr("Рендер уже доказал, что runtime и RouterOS побайтно не меняются. Панель обновит только сохранённые названия и указатели состояния — без сети, backup и перезапуска.")
                  : isRuntimeFast
                    ? tr("RouterOS не меняется. Панель проверит и атомарно обновит только контейнер, сохранив предыдущий runtime как last-known-good.")
                    : isConnectivitySafeMode
                      ? tr("RouterOS не меняется, но затронуты TUN, DNS, ядро или правила управляемого трафика. Панель вооружит runtime LKG, проверит связность и автоматически вернёт предыдущую версию при ошибке.")
                    : isUnchanged
                      ? tr("RouterOS и контейнер уже соответствуют черновику; останется только повторная live-проверка.")
                      : tr("Изменения затрагивают RouterOS. Панель создаст backup, вооружит локальный автооткат и сохранит патч только после проверки связи.")}
            </p>
            {mode === "apply" ? (
              planBusy ? (
                <aside className="notice notice-neutral" aria-live="polite">
                  <span className="spinner" />
                  <div>
                    <strong>{tr("Определяю режим применения")}</strong>
                    <p>{tr("Сравниваю точный RouterOS-скрипт без изменения роутера.")}</p>
                  </div>
                </aside>
              ) : planError ? (
                <aside className="notice notice-danger" role="alert">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>{tr("Apply пока недоступен")}</strong>
                    <p>{planError}</p>
                    {planValidationErrors.length ? (
                      <ul className="apply-plan-errors" aria-label={tr("Ошибки проверки черновика")}>
                        {planValidationErrors.map((issue, index) => {
                          const path = asText(issue.path, "");
                          return (
                            <li key={`${path}:${asText(issue.code, "")}:${index}`}>
                              <span>{planValidationIssueLabel(path, locale)}</span>
                              <p>{planValidationIssueMessage(issue, locale)}</p>
                              {path ? <code>{path}</code> : null}
                            </li>
                          );
                        })}
                      </ul>
                    ) : null}
                  </div>
                </aside>
              ) : isStateOnly ? (
                <aside className="notice notice-safe">
                  <span className="notice-icon">✓</span>
                  <div>
                    <strong>{tr("Только метаданные — трафик не затрагивается")}</strong>
                    <p>{tr("Live RouterOS, backup, Safe Mode, runtime reload и health-check не требуются.")}</p>
                  </div>
                </aside>
              ) : isRuntimeFast ? (
                <aside className="notice notice-safe">
                  <span className="notice-icon">✓</span>
                  <div>
                    <strong>{tr("Только контейнер — RouterOS не изменяется")}</strong>
                    <p>{tr("Новый backup и Safe Mode не нужны. При ошибке runtime автоматически вернётся к предыдущей рабочей версии.")}</p>
                  </div>
                </aside>
              ) : isConnectivitySafeMode ? (
                <aside className="notice notice-lock">
                  <span className="notice-icon">↺</span>
                  <div>
                    <strong>{tr("RouterOS не меняется — защищаем связность контейнера")}</strong>
                    <p>{tr("Runtime LKG будет сохранён до проверки TUN, DNS и управляемых маршрутов. RouterOS backup и SSH Safe Mode не требуются.")}</p>
                  </div>
                </aside>
              ) : isUnchanged ? (
                <aside className="notice notice-neutral">
                  <span className="notice-icon">i</span>
                  <div>
                    <strong>{tr("Изменений для применения нет")}</strong>
                    <p>{tr("Backup, Safe Mode и перезапуск контейнера выполняться не будут.")}</p>
                  </div>
                </aside>
              ) : isRouterOsSafeMode ? (
                <aside className="notice notice-lock">
                  <span className="notice-icon">↺</span>
                  <div>
                    <strong>{tr("RouterOS изменяется — включена полная защита")}</strong>
                    <p>{tr("Будут созданы export и зашифрованный backup. Планировщик вернёт прежнюю проверенную конфигурацию, а при первом применении оставит маршрутизацию напрямую через WAN.")}</p>
                  </div>
                </aside>
              ) : null
            ) : null}
            <ol className="modal-steps">
              <li>
                <span>1</span>
                {isStateOnly ? tr("Схема и локальный diff") : tr("Схема и секреты")}
                <StatusPill tone="muted">{tr("Будет выполнено")}</StatusPill>
              </li>
              <li>
                <span>2</span>
                {isStateOnly ? tr("Побайтовый runtime proof") : tr("Проверка выбранного ядра")}
                <StatusPill tone="muted">{isStateOnly ? tr("Выполнено в плане") : tr("Будет выполнено")}</StatusPill>
              </li>
              <li>
                <span>3</span>
                {isStateOnly ? "RouterOS candidate proof" : "nginx -t"}
                <StatusPill tone="muted">{isStateOnly ? tr("Выполнено в плане") : tr("Будет выполнено")}</StatusPill>
              </li>
              <li>
                <span>4</span>
                {isStateOnly ? tr("Коммит метаданных") : "Live RouterOS preflight"}
                <StatusPill tone="muted">{isStateOnly ? tr("Будет выполнено") : tr("Будет выполнено")}</StatusPill>
              </li>
            </ol>
            {busy ? (
              <div className="operation-progress" role="status" aria-live="polite">
                <span className="spinner" />
                <div>
                  <strong>
                    {mode === "apply"
                      ? tr("{value1} выполняется · {value2}", { value1: isStateOnly ? tr("Сохранение метаданных") : isRuntimeFast ? tr("Быстрое применение") : isConnectivitySafeMode ? tr("Защита связности") : isUnchanged ? tr("Live-проверка") : "Safe Mode", value2: formatElapsed(elapsedSeconds) })
                      : tr("Проверка выполняется · {value1}", { value1: formatElapsed(elapsedSeconds) })}
                  </strong>
                  <small>
                    {mode === "apply"
                      ? isStateOnly
                        ? tr("Панель коммитит только локальное состояние без обращения к RouterOS и без перезапуска контейнера.")
                        : isRuntimeFast
                        ? tr("Панель обновляет только runtime контейнера и проверяет его готовность.")
                        : isConnectivitySafeMode
                          ? tr("Панель активирует кандидат под защитой runtime LKG и проверяет TUN, DNS и маршруты.")
                        : isUnchanged
                          ? tr("Панель подтверждает актуальное состояние без перезапуска и backup.")
                          : tr("Панель остаётся доступной и ждёт backup, применение, health-check и подтверждение RouterOS.")
                      : tr("Control plane проверяет RouterOS и сгенерированные конфигурации.")}
                  </small>
                </div>
              </div>
            ) : null}
            {mode === "apply" ? (
              <>
                {!publicTlsReady ? (
                  <aside className="notice notice-danger">
                    <span className="notice-icon">!</span>
                    <div>
                      <strong>{tr("Apply заблокирован: TLS-профили не готовы")}</strong>
                      <p>
                         {tr("В разделе «Подключения» выберите или создайте TLS-профиль для каждого включённого TLS-транспорта. Настройку можно выполнить из любой подходящей карточки.")} </p>
                    </div>
                  </aside>
                ) : null}
                {networkReviewPending > 0 ? (
                  <aside className="notice notice-danger">
                    <span className="notice-icon">!</span>
                    <div>
                      <strong>
                         {tr("Apply заблокирован: сетевые подсказки не классифицированы")} </strong>
                      <p>
                         {tr("Ожидают явного решения:")} {networkReviewPending}{tr(". Закройте окно и в мастере выберите для каждой сети «принять» или «игнорировать».")} </p>
                    </div>
                  </aside>
                ) : null}
                {!managementIngressReady ? (
                  <aside className="notice notice-danger">
                    <span className="notice-icon">!</span>
                    <div>
                      <strong>
                         {tr("Apply заблокирован: не выбран доверенный ingress")} </strong>
                      <p>
                         {tr("В мастере выберите фактический локальный bridge, с которого разрешено управление Web UI.")} </p>
                    </div>
                  </aside>
                ) : null}
                <label className="checkbox-field">
                  <input
                    type="checkbox"
                    checked={reviewConfirmed}
                    onChange={(event) =>
                      setReviewConfirmed(event.target.checked)
                    }
                  />
                  <span>
                    <strong>
                      {isRuntimeFast
                        ? tr("Разрешаю обновить runtime контейнера")
                        : isStateOnly
                          ? tr("Разрешаю сохранить только метаданные")
                        : isConnectivitySafeMode
                          ? tr("Разрешаю безопасно обновить связность контейнера")
                        : tr("Разрешаю применить этот проверенный черновик")}
                    </strong>
                    <small>
                      {isStateOnly
                        ? tr("Ни RouterOS, ни runtime-файлы изменены не будут.")
                        : isRuntimeFast
                        ? tr("Будет изменён только контейнер; при ошибке вернётся предыдущий runtime.")
                        : isConnectivitySafeMode
                          ? tr("Будут проверены TUN, DNS и управляемые маршруты; при ошибке вернётся runtime LKG.")
                        : isUnchanged
                          ? tr("Будет выполнена только повторная live-проверка.")
                          : tr("Для изменений RouterOS используются backup, SSH Safe Mode и автоматический откат.")}  {tr("Галочка действует только для этой попытки Apply.")} </small>
                  </span>
                </label>
              </>
            ) : null}
            {operationError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {operationError}
              </div>
            ) : null}
            <div className="modal-actions">
              <button
                className="button button-tertiary"
                onClick={onClose}
                disabled={busy}
              >
                 {tr("Отмена")} </button>
              <button
                className="button button-primary"
                disabled={
                  busy ||
                  (mode === "apply" &&
                    (!applyPlanReady ||
                      !publicTlsReady ||
                      networkReviewPending > 0 ||
                      !managementIngressReady ||
                      !reviewConfirmed))
                }
                onClick={execute}
              >
                {busy
                  ? tr("Выполняется · {value1}", { value1: formatElapsed(elapsedSeconds) })
                  : mode === "check"
                    ? tr("Начать проверку")
                    : isRuntimeFast
                      ? tr("Обновить runtime")
                      : isStateOnly
                        ? tr("Сохранить метаданные")
                      : isConnectivitySafeMode
                        ? tr("Обновить под защитой LKG")
                      : isUnchanged
                        ? tr("Подтвердить состояние")
                        : tr("Применить с автооткатом")}
              </button>
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function RollbackDialog({
  onClose,
  onCompleted,
}: {
  onClose: () => void;
  onCompleted: () => Promise<void>;
}) {
  const { tr } = useLanguage();
  const passwordRef = useRef<HTMLInputElement>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [completed, setCompleted] = useState(false);
  const [operationError, setOperationError] = useState("");

  async function execute(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = passwordRef.current?.value ?? "";
    if (passwordRef.current) passwordRef.current.value = "";
    setBusy(true);
    setOperationError("");
    try {
      const response = await runDraftOperation("rollback", {
        password,
        confirmation: tr("ОТКАТИТЬ"),
      });
      await onCompleted();
      setResult(response);
      setCompleted(true);
    } catch (error) {
      setOperationError(errorMessage(error));
      passwordRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="rollback-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button
          className="modal-close"
          onClick={onClose}
          aria-label={tr("Закрыть")}
          disabled={busy}
        >
          ×
        </button>
        {completed ? (
          <div className="modal-success" role="status">
            <span>✓</span>
            <h2 id="rollback-title">{tr("Откат завершён")}</h2>
            <p>
              {resultMessage(
                result,
                tr("Control plane восстановил предыдущую проверенную LKG-версию."),
              )}
            </p>
            <button className="button button-primary" onClick={onClose}>
               {tr("Готово")} </button>
          </div>
        ) : (
          <form onSubmit={execute}>
            <p className="eyebrow">{tr("Повторная аутентификация")}</p>
            <h2 id="rollback-title">
               {tr("Откатить к предыдущей проверенной версии?")} </h2>
            <p className="modal-lead">
               {tr("Control plane проверит сохранённую LKG-конфигурацию и выполнит управляемый rollback. Локальный fail-open остаётся отдельной защитой интернета при сбое контейнера.")} </p>
            <label className="field">
               {tr("Текущий пароль администратора")} <input
                ref={passwordRef}
                type="password"
                autoComplete="current-password"
                minLength={12}
                required
              />
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
                required
              />
              <span>
                <strong>{tr("Подтверждаю откат к предыдущей проверенной версии")}</strong>
                <small>{tr("Произвольный backup выбран не будет.")}</small>
              </span>
            </label>
            <aside className="notice notice-neutral">
              <span className="notice-icon">i</span>
              <div>
                <strong>{tr("Операция не выбирает произвольный backup")}</strong>
                <p>
                   {tr("Восстанавливается только предыдущая проверенная генерация, известная локальному control plane.")} </p>
              </div>
            </aside>
            {operationError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {operationError}
              </div>
            ) : null}
            <div className="modal-actions">
              <button
                className="button button-tertiary"
                type="button"
                onClick={onClose}
                disabled={busy}
              >
                 {tr("Отмена")} </button>
              <button
                className="button button-primary"
                type="submit"
                disabled={busy || !confirmed}
              >
                {busy ? tr("Выполняется…") : tr("Подтвердить откат")}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}

function AddDialog({
  kind,
  onClose,
  onSave,
  onDelete,
  existingItem,
  config,
}: {
  kind: "local" | "remote";
  onClose: () => void;
  onSave: (
    kind: "local" | "remote",
    item: JsonObject,
    servicePacks: JsonObject[],
  ) => Promise<unknown>;
  onDelete?: () => Promise<void>;
  existingItem?: JsonObject;
  config: JsonObject;
}) {
  const { tr, locale } = useLanguage();
  const editing = Boolean(existingItem && asText(existingItem.id, ""));
  const connectionHostname = useConnectionHostname();
  const configuredInternalNetworks = asObjectList(config.networks)
    .filter(
      (network) =>
        network.enabled !== false &&
        ["internal", "management"].includes(
          asText(network.kind, "internal"),
        ),
    )
    .map((network) => {
      const id = asText(network.id, "");
      const name = itemName(network);
      const kind = asText(network.kind, "internal");
      const imported = id.startsWith("imported-") || network.imported === true;
      const displayName = imported
        ? kind === "management"
          ? tr("Сеть управления MikroTik")
          : tr("Внутренние маршрутизируемые сети")
        : name;
      return {
        id,
        name,
        displayName,
        kind,
        interfaceName: asText(
          network.interface ?? network.source_interface,
          "",
        ),
        cidrs: asStringList(network.cidrs),
      };
    })
    .filter((network) => network.id && network.cidrs.length);
  const [saved, setSaved] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [remoteRole, setRemoteRole] = useState(() => {
    const role = asText(existingItem?.role, "trusted-full");
    return role === "disabled" ? "internet-only" : role;
  });
  const [savedSubscription, setSavedSubscription] =
    useState<RemoteUserSubscriptionLink | null>(null);
  const [savedSubscriptionError, setSavedSubscriptionError] = useState("");
  const [subscriptionCopied, setSubscriptionCopied] = useState(false);
  const [selectedAllowedCidrs, setSelectedAllowedCidrs] = useState<string[]>(
    () => {
      const selected = new Set(asStringList(existingItem?.allowed_cidrs));
      const legacyNetworkIds = new Set(
        asStringList(existingItem?.allowed_network_ids),
      );
      for (const network of configuredInternalNetworks) {
        if (legacyNetworkIds.has(network.id)) {
          network.cidrs.forEach((cidr) => selected.add(cidr));
        }
      }
      return [...selected];
    },
  );
  const [allowedNetworkQuery, setAllowedNetworkQuery] = useState("");
  const [savedName, setSavedName] = useState("");
  const [remoteConnectionName, setRemoteConnectionName] = useState(
    asText(existingItem?.display_name, ""),
  );
  const [localDeviceName, setLocalDeviceName] = useState(
    asText(existingItem?.name, ""),
  );
  const [remoteTunAddress, setRemoteTunAddress] = useState(
    asText(existingItem?.client_tun_address, ""),
  );
  const [sourceKind, setSourceKind] = useState<RouterSourceKind>(
    normalizeRouterSourceKind(existingItem?.source_kind),
  );
  const [allLanDevices, setAllLanDevices] = useState(
    asText(existingItem?.source_scope, "") === "lan-all",
  );
  const [selectedSourceCidrs, setSelectedSourceCidrs] = useState<string[]>(
    asStringList(existingItem?.source_cidrs),
  );
  const [selectedSourcePeerRefs, setSelectedSourcePeerRefs] = useState<string[]>(
    asStringList(existingItem?.source_peer_refs),
  );
  const [excludedTransportIds, setExcludedTransportIds] = useState<string[]>(
    asStringList(existingItem?.excluded_transports),
  );
  const [happIncludeAllNetworks, setHappIncludeAllNetworks] = useState(
    existingItem?.happ_include_all_networks !== false,
  );
  const [happExcludeLocalNetworks, setHappExcludeLocalNetworks] = useState(
    existingItem?.happ_exclude_local_networks !== false,
  );
  const [happExcludeAPNs, setHappExcludeAPNs] = useState(
    existingItem?.happ_exclude_apns !== false,
  );
  const happProviderConfigured = Boolean(
    asText(
      asObject(asObject(config.public_exposure).subscription).happ_provider_id,
      "",
    ).trim(),
  );
  const routerSources = useRouterClientSources();
  const existingId = asText(existingItem?.id, "");
  const tunSuggestion = suggestedClientTunAddress(
    config,
    routerSources.discovery,
    existingId,
  );
  const remoteNameError =
    kind === "remote"
      ? remoteConnectionNameError(config, existingId, remoteConnectionName, locale)
      : "";
  const remoteTunError =
    kind === "remote"
      ? clientTunAddressError(
          config,
          routerSources.discovery,
          existingId,
          remoteTunAddress,
          locale,
        )
      : "";
  const sourceRows = useMemo(() => {
    const sourceInventory = asObject(routerSources.discovery.client_sources);
    return asObjectList(sourceInventory[sourceKind]);
  }, [routerSources.discovery, sourceKind]);
  const sourceInventoryComplete =
    asObject(routerSources.discovery.client_source_inventory_complete)[sourceKind] ===
    true;
  const allLANInventoryComplete =
    routerSources.discovery.lan_source_inventory_complete === true;
  const discoveredAllLANCidrs = asStringList(
    routerSources.discovery.lan_source_cidrs,
  );
  const availableSourceCidrs = useMemo(
    () => new Set(sourceRows.flatMap(sourceCidrsForRow)),
    [sourceRows],
  );
  const sourceRowsByCidr = useMemo(
    () => new Map(
      sourceRows.flatMap((row) =>
        sourceCidrsForRow(row).map((cidr) => [cidr, row] as const),
      ),
    ),
    [sourceRows],
  );
  const effectiveSourceCidrs = allLanDevices
    ? allLANInventoryComplete
      ? discoveredAllLANCidrs
      : selectedSourceCidrs
    : sourceInventoryComplete
      ? selectedSourceCidrs.filter((cidr) => availableSourceCidrs.has(cidr))
      : selectedSourceCidrs;
  const invalidSelectedSource = selectedSourceCidrs.find((cidr) => {
    const row = sourceRowsByCidr.get(cidr);
    return sourceInventoryComplete && (!row || row.valid === false);
  });
  useEffect(() => {
    if (
      sourceKind !== "wireguard" ||
      !sourceInventoryComplete ||
      !selectedSourcePeerRefs.length
    ) {
      return;
    }
    const currentCidrs = sourceRows
      .filter((row) =>
        selectedSourcePeerRefs.includes(asText(row.peer_ref, "")),
      )
      .flatMap(sourceCidrsForRow);
    if (!currentCidrs.length) return;
    const currentKey = [...new Set(currentCidrs)].sort().join("|");
    const selectedKey = [...new Set(selectedSourceCidrs)].sort().join("|");
    if (currentKey !== selectedKey) {
      const timer = window.setTimeout(
        () => setSelectedSourceCidrs([...new Set(currentCidrs)]),
        0,
      );
      return () => window.clearTimeout(timer);
    }
  }, [
    selectedSourceCidrs,
    selectedSourcePeerRefs,
    sourceInventoryComplete,
    sourceKind,
    sourceRows,
  ]);
  useEffect(() => {
    if (
      kind !== "local" ||
      !editing ||
      sourceKind !== "wireguard" ||
      !sourceRows.length ||
      selectedSourcePeerRefs.length ||
      selectedSourceCidrs.length !== 1
    ) {
      return;
    }
    const legacyCidr = selectedSourceCidrs[0];
    if (availableSourceCidrs.has(legacyCidr)) return;
    const matchingPeers = sourceRows.filter((row) =>
      Boolean(asText(row.peer_ref, "")) &&
      wireGuardPeerMatchesDevice(row.peer_name, localDeviceName),
    );
    if (matchingPeers.length !== 1) return;
    const peer = matchingPeers[0];
    const peerRef = asText(peer.peer_ref, "");
    const peerCidrs = sourceCidrsForRow(peer);
    if (!peerRef || !peerCidrs.length) return;
    const timer = window.setTimeout(() => {
      setSelectedSourcePeerRefs([peerRef]);
      setSelectedSourceCidrs(peerCidrs);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [
    availableSourceCidrs,
    editing,
    kind,
    localDeviceName,
    selectedSourceCidrs,
    selectedSourcePeerRefs,
    sourceKind,
    sourceRows,
  ]);
  const directClientDns = clientDnsAddress(config);
  const anotherAllLANClient = asObjectList(config.local_clients).find(
    (client) =>
      asText(client.id, "") !== existingId &&
      asText(client.source_kind, "lan") === "lan" &&
      asText(client.source_scope, "") === "lan-all",
  );
  const policyOptions = asObjectList(config.policies)
    .filter(
      (policy) =>
        policy.enabled !== false &&
        typeof policy.id === "string",
    )
    .map((policy) => ({
      id: asText(policy.id),
      name: itemName(policy),
    }));
  const remoteTransportOptions = asObjectList(config.transports)
    .filter(
      (transport) =>
        transport.enabled !== false &&
        typeof transport.id === "string",
    )
    .map((transport) => ({
      id: asText(transport.id, ""),
      name: itemName(transport),
      kind: asText(transport.kind, ""),
      kindLabel: transportKindLabel(transport.kind),
      hostname: connectionHostname(transport, tr("Адрес ещё не настроен")),
      port: Number(
        transport.listen_port ??
          asObject(config.ingress).public_listen_port ??
          443,
      ),
    }))
    .filter((transport) => transport.id);
  const configuredNetworkByCidr = new Map(
    configuredInternalNetworks.flatMap((network) =>
      network.cidrs.map((cidr) => [cidr, network] as const),
    ),
  );
  const runtimeNetworking = asObject(asObject(config.system).networking);
  const runtimeLinkRanges = [
    asText(runtimeNetworking.container_address, ""),
    asText(runtimeNetworking.tun_address, ""),
  ]
    .map(ipv4CidrRange)
    .filter((range): range is [number, number] => range !== null);
  const discoveredAccessDestinations = asObjectList(
    routerSources.discovery.access_destinations,
  ).filter((destination) => {
    const cidr = asText(destination.cidr, "");
    if (configuredNetworkByCidr.has(cidr)) return true;
    const range = ipv4CidrRange(cidr);
    return Boolean(
      range &&
        isPrivateIpv4Cidr(cidr) &&
        !runtimeLinkRanges.some((reserved) => ipv4RangesOverlap(range, reserved)),
    );
  });
  const liveUnconfiguredGroupId = "routeros-live-unconfigured";
  const hasLiveUnconfiguredDestinations = discoveredAccessDestinations.some(
    (destination) => {
      const cidr = asText(destination.cidr, "");
      return Boolean(cidr && !configuredNetworkByCidr.has(cidr));
    },
  );
  const destinationGroupDefinitions = [
    ...configuredInternalNetworks.map((network) => ({
      id: network.id,
      displayName: network.displayName,
      description:
        network.kind === "management"
          ? tr("Доступ к самому роутеру и его служебной сети")
          : tr("Сети назначения, уже настроенные в маршрутизации MikroTik"),
    })),
    ...(hasLiveUnconfiguredDestinations
      ? [{
          id: liveUnconfiguredGroupId,
          displayName: tr("Новые маршруты MikroTik"),
          description: tr("Автоматически обнаружены в актуальной таблице маршрутов"),
        }]
      : []),
  ];
  const liveDestinationEntries = discoveredAccessDestinations
    .map((destination) => {
      const cidr = asText(destination.cidr, "");
      const configuredNetwork = configuredNetworkByCidr.get(cidr);
      if (!cidr) return null;
      const groupId = configuredNetwork?.id ?? liveUnconfiguredGroupId;
      const comment = asText(destination.comment, "");
      const title =
        configuredNetwork?.kind === "management"
          ? tr("Сеть управления")
          : !configuredNetwork
            ? tr("Новый внутренний маршрут")
          : /\/(32|128)$/.test(cidr)
            ? tr("Маршрутизируемый внутренний адрес")
            : tr("Внутренняя подсеть");
      return {
        cidr,
        groupId,
        title,
        detail: [
          configuredNetwork
            ? tr("Маршрут уже настроен в MikroTik")
            : tr("Обнаружен автоматически; полный доступ использует live-набор"),
          comment,
        ]
          .filter(Boolean)
          .join(" · "),
      };
    })
    .filter(
      (
        entry,
      ): entry is {
        cidr: string;
        groupId: string;
        title: string;
        detail: string;
      } => entry !== null,
    );
  const fallbackDestinationEntries = configuredInternalNetworks.flatMap(
    (network) =>
      network.cidrs
        .filter((cidr) => !/\/(32|128)$/.test(cidr))
        .map((cidr) => ({
          cidr,
          groupId: network.id,
          title:
            network.kind === "management"
              ? tr("Сеть управления")
              : tr("Внутренняя подсеть"),
          detail: tr("Подсеть из группы «{value1}»; live-маршрут временно недоступен", { value1: network.displayName }),
        })),
  );
  const destinationEntries =
    discoveredAccessDestinations.length ||
    routerSources.discovery.access_destination_inventory_complete === true
      ? liveDestinationEntries
      : fallbackDestinationEntries;
  const networkOptions = destinationGroupDefinitions
    .map((group) => ({
      ...group,
      entries: destinationEntries
        .filter((entry) => entry.groupId === group.id)
        .sort((left, right) => left.cidr.localeCompare(right.cidr, "en")),
    }))
    .filter((group) => group.entries.length);
  const normalizedNetworkQuery = allowedNetworkQuery.trim().toLocaleLowerCase("ru");
  const visibleNetworkOptions = networkOptions
    .map((network) => ({
      ...network,
      entries: network.entries.filter((entry) =>
        !normalizedNetworkQuery ||
        `${network.displayName} ${network.description} ${entry.cidr} ${entry.title} ${entry.detail}`
          .toLocaleLowerCase("ru")
          .includes(normalizedNetworkQuery),
      ),
    }))
    .filter((network) => network.entries.length);
  const availableAllowedCidrs = networkOptions.flatMap((network) =>
    network.entries.map((entry) => entry.cidr),
  );
  const effectiveSelectedAllowedCidrs = selectedAllowedCidrs.filter((cidr) =>
    availableAllowedCidrs.includes(cidr),
  );

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    setSaveBusy(true);
    setSaveError("");
    const data = new FormData(form);
    const name = String(data.get("name") ?? "").trim();
    if (kind === "remote" && remoteNameError) {
      setSaveError(remoteNameError);
      setSaveBusy(false);
      return;
    }
    if (kind === "remote" && remoteTunError) {
      setSaveError(remoteTunError);
      setSaveBusy(false);
      return;
    }
    const collection = kind === "local" ? config.local_clients : config.remote_users;
    const occupiedIds = new Set(
      asObjectList(collection)
        .map((item) => asText(item.id, ""))
        .filter((id) => id && id !== existingId),
    );
    const id = editing
      ? existingId
      : entityIdFromName(
          name,
          occupiedIds,
          kind === "local" ? "device" : "user",
        );
    const allowedPortTokens = String(data.get("allowed_ports") ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    const allowedPorts = allowedPortTokens.map(Number);
    if (
      kind === "remote" &&
      allowedPorts.some(
        (value) => !Number.isInteger(value) || value < 1 || value > 65535,
      )
    ) {
      setSaveError(tr("Порты должны быть целыми числами от 1 до 65535 через запятую."));
      setSaveBusy(false);
      return;
    }
    if (kind === "local" && !allLanDevices && invalidSelectedSource) {
      const row = sourceRowsByCidr.get(invalidSelectedSource);
      setSaveError(
        asText(
          row?.validation_message,
          tr("Адрес WireGuard {value1} отсутствует или конфликтует с адресом RouterOS.", { value1: invalidSelectedSource }),
        ),
      );
      setSaveBusy(false);
      return;
    }
    if (kind === "local" && !effectiveSourceCidrs.length) {
      setSaveError(
        allLanDevices
          ? tr("MikroTik не вернул ни одной IPv4-подсети из списка интерфейсов LAN. Проверьте список LAN и обновите инвентарь.")
          : tr("Выберите хотя бы один статический адрес с MikroTik."),
      );
      setSaveBusy(false);
      return;
    }
    if (
      kind === "remote" &&
      remoteRole === "trusted-limited" &&
      !effectiveSelectedAllowedCidrs.length
    ) {
      setSaveError(
        tr("Для ограниченного доступа выберите хотя бы одну внутреннюю сеть."),
      );
      setSaveBusy(false);
      return;
    }
    const item: JsonObject =
      kind === "local"
        ? {
            ...existingItem,
            id,
            name,
            source_kind: sourceKind,
            source_scope: allLanDevices ? "lan-all" : undefined,
            source_cidrs: effectiveSourceCidrs,
            source_peer_refs:
              sourceKind === "wireguard" ? selectedSourcePeerRefs : [],
            policy_id: String(data.get("policy") ?? ""),
            container_outage: String(data.get("container_outage") ?? "direct"),
            direct_domains: undefined,
            direct_services: undefined,
            service_routes: undefined,
            final: undefined,
            enabled: data.get("enabled") === "on",
          }
        : {
            ...existingItem,
            id,
            display_name: name,
            role: String(data.get("role") ?? ""),
            policy_id: String(data.get("policy") ?? ""),
            client_tun_address: String(
              data.get("client_tun_address") ?? "",
            ),
            subscription_format: String(
              data.get("subscription_format") ?? "auto",
            ),
            client_fingerprint: String(
              data.get("client_fingerprint") ?? "chrome",
            ),
            client_tun_stack: String(
              data.get("client_tun_stack") ?? "auto",
            ),
            client_individual_routing:
              data.get("client_individual_routing") === "on",
            client_auto_fallback:
              data.get("client_auto_fallback") === "on",
            client_adblock: data.get("client_adblock") === "on",
            happ_include_all_networks: happIncludeAllNetworks,
            happ_exclude_local_networks: happExcludeLocalNetworks,
            happ_exclude_apns: happExcludeAPNs,
            excluded_transports: [...new Set(excludedTransportIds)],
            allowed_network_ids: [],
            allowed_cidrs:
              remoteRole === "trusted-limited"
                ? effectiveSelectedAllowedCidrs
                : [],
            allowed_ports: allowedPorts,
            direct_domains: undefined,
            direct_services: undefined,
            generate_uuid: !editing,
            enabled: data.get("enabled") === "on",
          };
    try {
      await onSave(kind, item, asObjectList(config.service_packs));
      if (kind === "remote") {
        try {
          setSavedSubscription(await getRemoteUserSubscriptionLink(id));
          setSavedSubscriptionError("");
        } catch (error) {
          setSavedSubscriptionError(errorMessage(error));
        }
      }
      setSavedName(name);
      setSaved(true);
    } catch (error) {
      setSaveError(errorMessage(error));
    } finally {
      setSaveBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="modal modal-wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="add-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        {saved ? (
          <div className="modal-success">
            <span>✓</span>
            <h2 id="add-title">
              {kind === "remote"
                ? editing
                  ? tr("Профиль пользователя обновлён")
                  : tr("Профиль «{value1}» создан", { value1: savedName })
                : editing
                  ? tr("Изменения сохранены")
                  : tr("Устройство добавлено")}
            </h2>
            <p>
              {kind === "remote"
                ? tr("Одна постоянная подписка автоматически включает все серверные транспорты, кроме снятых вами. До успешного Apply она не отдаёт черновые или нерабочие изменения.")
                : allLanDevices
                  ? tr("Все устройства из выбранных LAN-подсетей получат этот маршрут после Apply. Отдельные карточки устройств сохраняют приоритет.")
                  : tr("Сеть пока не менялась. Для включения примените сохранённые изменения.")}
            </p>
            {kind === "remote" && savedSubscription ? (
              <div className="saved-subscription">
                <label className="field">
                   {tr("URL подписки")} <input
                    type="text"
                    value={savedSubscription.url}
                    readOnly
                    onFocus={(event) => event.currentTarget.select()}
                  />
                </label>
                <button
                  className="button button-secondary"
                  type="button"
                  onClick={async () => {
                    try {
                      await copyText(savedSubscription.url);
                      setSubscriptionCopied(true);
                      setSavedSubscriptionError("");
                    } catch (error) {
                      setSavedSubscriptionError(errorMessage(error));
                    }
                  }}
                >
                  {subscriptionCopied ? tr("Скопировано") : tr("Скопировать ссылку")}
                </button>
                <small>
                  {savedSubscription.active
                    ? tr("Ссылка уже активна; изменения транспортов появятся после следующего Apply.")
                    : tr("Ссылка начнёт отдавать профиль после первого успешного Apply.")}
                </small>
              </div>
            ) : null}
            {kind === "remote" && savedSubscriptionError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {savedSubscriptionError}
              </div>
            ) : null}
            <button className="button button-primary" onClick={onClose}>
              {kind === "remote" ? tr("Перейти к карточке профиля") : tr("Вернуться к устройствам")}
            </button>
          </div>
        ) : (
          <form onSubmit={submit}>
            <p className="eyebrow">
              {kind === "local" ? tr("Локальное или VPN") : tr("Удалённый VPN")}
            </p>
            <h2 id="add-title">
              {kind === "local"
                ? editing
                  ? tr("Настроить устройство")
                  : tr("Добавить устройство")
                : editing
                  ? tr("Настроить пользователя")
                  : tr("Добавить пользователя")}
            </h2>
            <p className="modal-lead">
              {kind === "local"
                ? tr("Выберите отдельные адреса или назначьте один маршрут всем устройствам LAN / Wi‑Fi. Отдельная карточка устройства всегда имеет приоритет.")
                : tr("Технический идентификатор и UUID создаются автоматически. Пользователь подключается через любой включённый серверный транспорт по одной обновляемой подписке.")}
            </p>
            <div className="form-grid">
              <label className="field">
                {kind === "remote" ? tr("Имя подключения") : tr("Имя устройства")}
                {kind === "remote" ? (
                  <>
                    <input
                      required
                      name="name"
                      value={remoteConnectionName}
                      onChange={(event) => setRemoteConnectionName(event.target.value)}
                      aria-invalid={remoteNameError ? "true" : undefined}
                      aria-describedby={remoteNameError ? "remote-name-error" : undefined}
                    />
                    {remoteNameError ? (
                      <small className="field-inline-error" id="remote-name-error" role="alert">
                        {remoteNameError}
                      </small>
                    ) : null}
                  </>
                ) : (
                  <input
                    required
                    name="name"
                    value={localDeviceName}
                    onChange={(event) => setLocalDeviceName(event.target.value)}
                  />
                )}
              </label>
              {kind === "local" ? (
                <>
                  <label className="field">
                     {tr("Откуда подключён клиент")} <select
                      value={sourceKind}
                      onChange={(event) => {
                        setSourceKind(event.target.value as RouterSourceKind);
                        setAllLanDevices(false);
                        setSelectedSourceCidrs([]);
                        setSelectedSourcePeerRefs([]);
                      }}
                    >
                      <option value="lan">LAN / Wi‑Fi MikroTik</option>
                      <option value="wireguard">WireGuard</option>
                      <option value="ppp-vpn">{tr("PPP / OpenVPN / другой VPN")}</option>
                    </select>
                    <small>
                      {sourceKind === "lan"
                        ? tr("Для одного устройства используется статическая аренда; общий режим охватывает и динамические адреса.")
                        : tr("Показываются только фактические статические адреса выбранного типа.")}
                    </small>
                  </label>
                  <label className="field">
                     {tr("Маршрутный лист")} <select
                      name="policy"
                      defaultValue={asText(existingItem?.policy_id, "") || policyOptions[0]?.id}
                      disabled={!policyOptions.length}
                      required
                    >
                      {!policyOptions.length ? <option value="">{tr("Сначала создайте маршрутный лист")}</option> : null}
                      {policyOptions.map((policy) => <option value={policy.id} key={policy.id}>{policy.name}</option>)}
                    </select>
                    <small>{tr("Режим WAN/VLESS, расположения и карточки настраиваются в разделе «Маршрутизация».")}</small>
                  </label>
                  {sourceKind === "lan" ? (
                    <Toggle
                      className="form-span"
                      checked={allLanDevices}
                      disabled={Boolean(anotherAllLANClient)}
                      onChange={(checked) => {
                        setAllLanDevices(checked);
                        if (checked && discoveredAllLANCidrs.length) {
                          setSelectedSourceCidrs(discoveredAllLANCidrs);
                        }
                      }}
                      tone="state"
                      label={tr("Все устройства LAN / Wi‑Fi")}
                      description={
                        anotherAllLANClient
                          ? tr("Общий маршрут уже задан записью «{value1}». Откройте её для изменения.", { value1: itemName(anotherAllLANClient) })
                          : tr("Работает для статических и динамических адресов во всех подсетях интерфейсов RouterOS LAN. Отдельные устройства исключаются автоматически и используют свой маршрутный лист и DNS.")
                      }
                    />
                  ) : null}
                  {allLanDevices ? (
                    <fieldset className="field form-span router-source-picker">
                      <legend className="sr-only">{tr("Подсети общего маршрута LAN / Wi‑Fi")}</legend>
                      <div className="router-source-picker-heading">
                        <strong>{tr("Подсети интерфейсов LAN")}</strong>
                        <button
                          type="button"
                          className="text-button"
                          disabled={routerSources.busy}
                          onClick={() => void routerSources.refresh()}
                        >
                          {routerSources.busy ? tr("Обновляю…") : tr("Обновить список")}
                        </button>
                      </div>
                      {routerSources.error ? (
                        <div className="inline-result inline-result-error" role="alert">
                          <span>!</span>{routerSources.error}
                        </div>
                      ) : effectiveSourceCidrs.length ? (
                        <div className="all-lan-cidr-list">
                          {effectiveSourceCidrs.map((cidr) => <code key={cidr}>{cidr}</code>)}
                        </div>
                      ) : (
                        <div className="subscription-discovery-empty">
                          {allLANInventoryComplete
                            ? tr("В списке RouterOS LAN нет интерфейсов с IPv4-подсетями.")
                            : tr("Читаю подсети интерфейсов LAN с MikroTik…")}
                        </div>
                      )}
                      <small>
                         {tr("Изменение DHCP-адреса устройства не требует редактирования карточки. Новую LAN-подсеть нужно сохранить и применить после обновления списка.")} </small>
                    </fieldset>
                  ) : (
                    <RouterSourcePicker
                      kind={sourceKind}
                      selectedCidrs={selectedSourceCidrs}
                      selectedPeerRefs={selectedSourcePeerRefs}
                      onChange={setSelectedSourceCidrs}
                      onPeerRefsChange={setSelectedSourcePeerRefs}
                      discovery={routerSources.discovery}
                      busy={routerSources.busy}
                      error={routerSources.error}
                      onRefresh={routerSources.refresh}
                    />
                  )}
                  {sourceKind === "wireguard" ? (
                    <div className="wireguard-client-hint form-span">
                      <strong>{tr("На устройстве WireGuard при")}</strong>
                      <span>AllowedIPs 0.0.0.0/0 · DNS {directClientDns}</span>
                      <small>{tr("DNS перехватывается шлюзом и следует выбранному маршруту.")}</small>
                    </div>
                  ) : null}
                  <label className="field form-span">
                     {tr("Если контейнер на MikroTik остановился")} <select name="container_outage" defaultValue={asText(existingItem?.container_outage, "direct")}>
                      <option value="direct">{tr("Полный доступ через обычный WAN")}</option>
                      <option value="lan_only">{tr("Только LAN + списки исключений маршрутного листа")}</option>
                    </select>
                    <small>
                       {tr("Это аварийное поведение только выбранных IP. Другие устройства сохраняют собственный режим.")} </small>
                  </label>
                  <Toggle
                    className="form-span"
                    name="enabled"
                    defaultChecked={existingItem?.enabled !== false}
                    tone="state"
                    label={tr("Устройство включено")}
                    description={tr("Выключенная запись сохраняется и не участвует в маршрутизации.")}
                  />
                </>
              ) : (
                <>
                  <label className="field">
                     {tr("Доступ к LAN")} <select
                      name="role"
                      value={remoteRole}
                      onChange={(event) => setRemoteRole(event.target.value)}
                    >
                      <option value="trusted-full">
                         {tr("Полный доступ к LAN")} </option>
                      <option value="trusted-limited">
                         {tr("Ограниченный доступ к LAN")} </option>
                      <option value="internet-only">{tr("Без доступа к LAN")}</option>
                    </select>
                  </label>
                  <label className="field">
                     {tr("Политика интернета")} <select
                      name="policy"
                      defaultValue={
                        asText(existingItem?.policy_id, "") || policyOptions[0]?.id
                      }
                      disabled={!policyOptions.length}
                    >
                      {!policyOptions.length ? (
                        <option value="">{tr("Сначала создайте политику")}</option>
                      ) : null}
                      {policyOptions.map((policy) => (
                        <option value={policy.id} key={policy.id}>
                          {policy.name}
                        </option>
                      ))}
                    </select>
                    <small>{tr("Страны, города, режим WAN/VLESS и исключения настраиваются только в этом маршрутном листе.")}</small>
                  </label>
                  <label className="field remote-tun-field">
                     {tr("TUN-адрес")} <input
                      required
                      name="client_tun_address"
                      value={remoteTunAddress}
                      onChange={(event) => setRemoteTunAddress(event.target.value)}
                      autoCapitalize="none"
                      spellCheck={false}
                      placeholder={tunSuggestion || "IPv4/CIDR"}
                      aria-invalid={remoteTunError ? "true" : undefined}
                      aria-describedby={remoteTunError ? "remote-tun-error" : "remote-tun-hint"}
                    />
                    {remoteTunError ? (
                      <small className="field-inline-error" id="remote-tun-error" role="alert">
                        {remoteTunError}
                      </small>
                    ) : (
                      <small id="remote-tun-hint">
                        {routerSources.busy
                          ? tr("Проверяю сети…")
                          : tunSuggestion
                            ? <>{tr("Свободный:")} <code>{tunSuggestion}</code></>
                            : tr("Укажите свободный IPv4/CIDR.")}
                      </small>
                    )}
                  </label>
                  {remoteRole === "trusted-limited" ? (
                    <fieldset className="field form-span lan-access-picker">
                      <legend>{tr("К каким внутренним сетям разрешить доступ")}</legend>
                      <p className="lan-access-explanation">
                         {tr("Выберите сети назначения. MikroTik уже знает, через какой маршрут их передавать; адреса VPN-транспорта здесь не показываются.")} </p>
                      <div className="lan-access-toolbar">
                        <label className="lan-access-search">
                          <span>{tr("Найти внутреннюю сеть")}</span>
                          <input
                            type="search"
                            value={allowedNetworkQuery}
                            onChange={(event) =>
                              setAllowedNetworkQuery(event.target.value)
                            }
                            placeholder={tr("Например: 192.168.55.0/24")}
                          />
                        </label>
                        <div className="lan-access-actions">
                          <span aria-live="polite">
                             {tr("Выбрано:")} <strong>{effectiveSelectedAllowedCidrs.length}</strong>
                          </span>
                          <button
                            className="text-button"
                            type="button"
                            onClick={() =>
                              setSelectedAllowedCidrs(availableAllowedCidrs)
                            }
                            disabled={!availableAllowedCidrs.length}
                          >
                             {tr("Выбрать все сети")} </button>
                          <button
                            className="text-button"
                            type="button"
                            onClick={() => setSelectedAllowedCidrs([])}
                            disabled={!effectiveSelectedAllowedCidrs.length}
                          >
                             {tr("Снять выбор")} </button>
                        </div>
                      </div>
                      {routerSources.busy ? (
                        <div className="lan-access-source-status" role="status">
                           {tr("Читаю сети назначения из таблицы маршрутов MikroTik…")} </div>
                      ) : routerSources.error ? (
                        <div className="lan-access-source-status lan-access-source-status-warn">
                           {tr("Live RouterOS сейчас недоступен. Показаны только подсети из черновика; транспортные адреса /32 скрыты.")} </div>
                      ) : null}
                      <div className="lan-network-list">
                        {visibleNetworkOptions.length ? (
                          visibleNetworkOptions.map((network) => {
                            const networkCidrs = network.entries.map(
                              (entry) => entry.cidr,
                            );
                            const selectedInNetwork = networkCidrs.filter((cidr) =>
                              effectiveSelectedAllowedCidrs.includes(cidr),
                            ).length;
                            const wholeNetworkSelected =
                              selectedInNetwork === networkCidrs.length;
                            return (
                              <section className="lan-network-group" key={network.id}>
                                <header className="lan-network-group-header">
                                  <span>
                                    <strong>{network.displayName}</strong>
                                    <small>
                                      {network.description}
                                      {tr(" · выбрано {value1} из {value2}", { value1: selectedInNetwork, value2: networkCidrs.length })}
                                    </small>
                                  </span>
                                  <button
                                    className="text-button"
                                    type="button"
                                    onClick={() =>
                                      setSelectedAllowedCidrs(() => {
                                        const next = new Set(
                                          effectiveSelectedAllowedCidrs,
                                        );
                                        networkCidrs.forEach((cidr) =>
                                          wholeNetworkSelected
                                            ? next.delete(cidr)
                                            : next.add(cidr),
                                        );
                                        return [...next];
                                      })
                                    }
                                  >
                                    {wholeNetworkSelected
                                      ? normalizedNetworkQuery
                                        ? tr("Снять найденные")
                                        : tr("Снять группу")
                                      : normalizedNetworkQuery
                                        ? tr("Выбрать найденные")
                                        : tr("Выбрать группу")}
                                  </button>
                                </header>
                                <div className="lan-cidr-options">
                                  {network.entries.map((entry) => {
                                    const checked =
                                      effectiveSelectedAllowedCidrs.includes(
                                        entry.cidr,
                                      );
                                    return (
                                      <label className="lan-cidr-option" key={entry.cidr}>
                                        <input
                                          name="allowed_cidrs"
                                          type="checkbox"
                                          value={entry.cidr}
                                          checked={checked}
                                          onChange={() =>
                                            setSelectedAllowedCidrs((current) =>
                                              checked
                                                ? current.filter(
                                                    (cidr) => cidr !== entry.cidr,
                                                  )
                                                : [...current, entry.cidr],
                                            )
                                          }
                                        />
                                        <span className="lan-cidr-copy">
                                          <code>{entry.cidr}</code>
                                          <span>
                                            <strong>{entry.title}</strong>
                                            <small>{entry.detail}</small>
                                          </span>
                                        </span>
                                      </label>
                                    );
                                  })}
                                </div>
                              </section>
                            );
                          })
                        ) : (
                          <div className="subscription-discovery-empty">
                            {networkOptions.length
                              ? tr("По этому запросу ничего не найдено.")
                              : tr("В черновике нет включённых внутренних сетей. Сначала импортируйте и классифицируйте сети MikroTik.")}
                          </div>
                        )}
                      </div>
                      <label className="field lan-access-ports">
                         {tr("Разрешённые TCP/UDP-порты")} <input
                          name="allowed_ports"
                          inputMode="numeric"
                          defaultValue={
                            Array.isArray(existingItem?.allowed_ports)
                              ? existingItem.allowed_ports.map(String).join(", ")
                              : ""
                          }
                          placeholder={tr("Например: 22, 80, 443")}
                        />
                        <small>
                           {tr("Пустое поле разрешает все порты только у отмеченных выше назначений.")} </small>
                      </label>
                    </fieldset>
                  ) : null}
                  <label className="field">
                     {tr("Формат подписки")} <select
                      name="subscription_format"
                      defaultValue={asText(
                        existingItem?.subscription_format,
                        "auto",
                      )}
                    >
                      <option value="auto">{tr("Совместимый список · рекомендуется")}</option>
                      <option value="array">{tr("JSON-массив · узлы и автовыбор")}</option>
                      <option value="xray">{tr("Xray JSON · только Xray-клиенты")}</option>
                      <option value="singbox">Sing-box JSON · Hiddify/Karing</option>
                      <option value="mihomo">{tr("Mihomo YAML · только Mihomo/Clash")}</option>
                      <option value="links">{tr("Список ссылок · только узлы")}</option>
                    </select>
                  </label>
                  <label className="field">
                    uTLS fingerprint
                    <select
                      name="client_fingerprint"
                      defaultValue={asText(existingItem?.client_fingerprint, "chrome")}
                    >
                      <option value="chrome">{tr("Chrome · по умолчанию")}</option>
                      <option value="firefox">Firefox</option>
                      <option value="safari">Safari</option>
                      <option value="ios">iOS</option>
                      <option value="android">Android</option>
                      <option value="edge">Edge</option>
                      <option value="360">360 Secure Browser</option>
                      <option value="qq">QQ Browser</option>
                      <option value="random">{tr("Random из известных профилей")}</option>
                    </select>
                  </label>
                  <fieldset className="client-profile-options form-span">
                    <legend>{tr("Полный профиль · Xray / Sing-box / Mihomo")}</legend>
                    <label className="field client-tun-stack-field">
                       {tr("Стек TUN")} <select
                        name="client_tun_stack"
                        defaultValue={asText(existingItem?.client_tun_stack, "auto")}
                      >
                        <option value="auto">{tr("Автоматически · рекомендуется")}</option>
                        <option value="mixed">Mixed · TCP system, UDP gVisor</option>
                        <option value="system">{tr("System · меньше нагрузки")}</option>
                        <option value="gvisor">{tr("gVisor · максимальная изоляция")}</option>
                      </select>
                      <small>
                         {tr("Авто не добавляет чужое поле в Xray/Happ/Streisand; sing-box выбирает стек ядра, Mihomo получает mixed.")} </small>
                    </label>
                    <div className="client-profile-option-grid">
                      <label className="client-profile-option">
                        <input
                          name="client_individual_routing"
                          type="checkbox"
                          defaultChecked={
                            existingItem?.client_individual_routing === true
                          }
                        />
                        <span>
                          <strong>{tr("Индивидуальная маршрутизация")}</strong>
                          <small>
                             {tr("Правила WAN/VLESS выполняются на устройстве.")} </small>
                        </span>
                      </label>
                      <label className="client-profile-option">
                        <input
                          name="client_auto_fallback"
                          type="checkbox"
                          defaultChecked={
                            existingItem?.client_auto_fallback === true
                          }
                        />
                        <span>
                          <strong>{tr("Автоматический выбор узла")}</strong>
                          <small>
                             {tr("Клиент проверяет доступность и переключается на рабочий транспорт без смены подписки.")} </small>
                        </span>
                      </label>
                      <label className="client-profile-option">
                        <input
                          name="client_adblock"
                          type="checkbox"
                          defaultChecked={existingItem?.client_adblock === true}
                        />
                        <span>
                          <strong>{tr("Блокировка рекламы")}</strong>
                          <small>
                             {tr("Консервативный список рекламных сетей добавляется прямо в клиентский профиль.")} </small>
                        </span>
                      </label>
                    </div>
                  </fieldset>
                  <details className="happ-tunnel-disclosure form-span">
                    <summary>
                      <span>
                        <strong>{tr("Happ на iOS · системный туннель")}</strong>
                        <small>
                          {happProviderConfigured
                            ? tr("3 параметра приложения")
                            : tr("Нужен Happ Provider ID")
                          }
                        </small>
                      </span>
                    </summary>
                    <fieldset
                      className="client-profile-options happ-tunnel-options"
                      disabled={!happProviderConfigured}
                    >
                      <legend className="sr-only">{tr("Параметры системного туннеля Happ")}</legend>
                      <p className="happ-tunnel-help">
                        {happProviderConfigured
                          ? tr("Значения передаются по ссылке этого пользователя. В самом Happ это общие настройки приложения: последняя обновившаяся подписка имеет приоритет.")
                          : tr("Доступно только после настройки Happ Provider ID в общей ссылке подписки.")
                        }
                      </p>
                      <div className="client-profile-option-grid">
                        <label className="client-profile-option">
                          <input
                            type="checkbox"
                            checked={happIncludeAllNetworks}
                            onChange={(event) =>
                              setHappIncludeAllNetworks(event.target.checked)
                            }
                          />
                          <span>
                            <strong>{tr("Весь трафик через VPN")}</strong>
                            <small>
                               {tr("Включает Include all networks в NetworkExtension.")} </small>
                          </span>
                        </label>
                        <label className="client-profile-option">
                          <input
                            type="checkbox"
                            checked={happExcludeLocalNetworks}
                            disabled={!happIncludeAllNetworks}
                            onChange={(event) =>
                              setHappExcludeLocalNetworks(event.target.checked)
                            }
                          />
                          <span>
                            <strong>{tr("Текущая локальная сеть напрямую")}</strong>
                            <small>
                               {tr("Сохраняет AirPlay, AirDrop и CarPlay в локальной сети iPhone.")} </small>
                          </span>
                        </label>
                        <label className="client-profile-option">
                          <input
                            type="checkbox"
                            checked={happExcludeAPNs}
                            disabled={!happIncludeAllNetworks}
                            onChange={(event) => setHappExcludeAPNs(event.target.checked)}
                          />
                          <span>
                            <strong>{tr("Уведомления Apple напрямую")}</strong>
                            <small>
                               {tr("Исключает APNs из туннеля для надёжной доставки в фоне.")} </small>
                          </span>
                        </label>
                      </div>
                    </fieldset>
                  </details>
                  <section className="automatic-transport-summary form-span">
                    <div className="automatic-transport-head">
                      <div>
                        <span>{tr("Подписка и транспорты")}</span>
                        <strong>
                          {remoteTransportOptions.length
                            ? tr("Выбрано: {value1} из {value2}", { value1: remoteTransportOptions.filter((transport) => !excludedTransportIds.includes(transport.id)).length, value2: remoteTransportOptions.length })
                            : tr("Транспортов в подписке пока нет")}
                        </strong>
                      </div>
                      <span className="automatic-badge">{tr("Новые — автоматически")}</span>
                    </div>
                    {remoteTransportOptions.length ? (
                      <ul className="automatic-transport-list">
                        {remoteTransportOptions.map((transport) => {
                          const checked = !excludedTransportIds.includes(transport.id);
                          return (
                            <li key={transport.id}>
                              <label>
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() =>
                                    setExcludedTransportIds((current) =>
                                      checked
                                        ? [...new Set([...current, transport.id])]
                                        : current.filter((id) => id !== transport.id),
                                    )
                                  }
                                />
                                <span>
                                  <strong>{transport.kindLabel}</strong>
                                  <small>{transport.hostname}:{transport.port}</small>
                                </span>
                              </label>
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <p>
                         {tr("Клиента и постоянную ссылку можно создать уже сейчас. Добавьте транспорт позже и нажмите Apply — URL менять не придётся.")} </p>
                    )}
                    <small>
                       {tr("По умолчанию отмечены все включённые транспорты. Снимите галочки с ненужных; новые транспорты появятся отмеченными автоматически после Apply.")} </small>
                  </section>
                  <Toggle
                    className="form-span"
                    name="enabled"
                    defaultChecked={existingItem?.enabled !== false}
                    tone="state"
                    label={tr("Пользователь включён")}
                    description={tr("Выключенный пользователь сохраняется, но не получает inbound-профили после Apply.")}
                  />
                </>
              )}
            </div>
            {!policyOptions.length ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                 {tr("Сначала создайте фактическую политику выхода в разделе «Маршрутизация». Демонстрационные варианты здесь не подставляются.")} </div>
            ) : null}
            {saveError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {saveError}
              </div>
            ) : null}
            <div className="modal-actions">
              {editing && onDelete ? (
                <button
                  className="button button-danger"
                  type="button"
                  disabled={saveBusy}
                  onClick={async () => {
                    if (!deleteArmed) {
                      setDeleteArmed(true);
                      setSaveError(
                        tr("Нажмите «Удалить пользователя» ещё раз. Секреты сохранятся для восстановления."),
                      );
                      return;
                    }
                    setSaveBusy(true);
                    setSaveError("");
                    try {
                      await onDelete();
                    } catch (error) {
                      setSaveError(errorMessage(error));
                      setSaveBusy(false);
                    }
                  }}
                >
                  {deleteArmed ? tr("Удалить пользователя") : tr("Подготовить удаление")}
                </button>
              ) : null}
              <button
                className="button button-tertiary"
                type="button"
                onClick={onClose}
                disabled={saveBusy}
              >
                 {tr("Отмена")} </button>
              <button
                className="button button-primary"
                type="submit"
                disabled={
                  saveBusy ||
                  !policyOptions.length ||
                  Boolean(remoteNameError) ||
                  Boolean(remoteTunError) ||
                  (kind === "local" && !allLanDevices && Boolean(invalidSelectedSource)) ||
                  (kind === "remote" &&
                    (!remoteConnectionName.trim() || !remoteTunAddress.trim()))
                }
              >
                {saveBusy
                  ? tr("Сохраняю…")
                  : editing
                    ? tr("Сохранить изменения")
                    : tr("Добавить")}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}

function PolicyDialog({
  policyId,
  onClose,
  onSaved,
  config,
}: {
  policyId?: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
  config: JsonObject;
}) {
  const { tr } = useLanguage();
  const existingPolicy =
    asObjectList(config.policies).find(
      (item) => asText(item.id, "") === policyId,
    ) ?? {};
  const editing = Boolean(policyId && existingPolicy.id);
  const initialSelectionOrderKey = initialPolicySelectionOrder(existingPolicy).join("\n");
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [mode, setMode] = useState<PolicySelectionMode>(
    normalizePolicySelectionMode(existingPolicy.mode),
  );
  const [trafficMode, setTrafficMode] = useState(
    asText(
      existingPolicy.traffic_mode,
      asText(existingPolicy.final, "direct") === "direct"
        ? "wan_with_vless_exceptions"
        : "vless_with_wan_exceptions",
    ),
  );
  const [policyEnabled, setPolicyEnabled] = useState(existingPolicy.enabled !== false);
  const [torrentDirect, setTorrentDirect] = useState(
    existingPolicy.torrent_direct !== false,
  );
  const [domainStrategyEnabled, setDomainStrategyEnabled] = useState(
    asText(existingPolicy.domain_strategy, "IPIfNonMatch") === "IPIfNonMatch",
  );
  const [selectedCountries, setSelectedCountries] = useState<string[]>(
    asStringList(existingPolicy.countries),
  );
  const [selectedLocations, setSelectedLocations] = useState<string[]>(
    asStringList(existingPolicy.locations),
  );
  const [selectionOrder, setSelectionOrder] = useState<string[]>(
    () => initialSelectionOrderKey.split("\n").filter(Boolean),
  );
  const [candidateLimit, setCandidateLimit] = useState(() => {
    const saved = Number(existingPolicy.max_active_candidates);
    if (Number.isFinite(saved) && saved >= 1) {
      return Math.max(1, Math.min(10, Math.trunc(saved)));
    }
    const selected = initialSelectionOrderKey.split("\n").filter(Boolean).length;
    return Math.max(1, Math.min(10, selected || 3));
  });
  const [candidateServiceIds, setCandidateServiceIds] = useState<string[]>(() => {
    const saved = asStringList(existingPolicy.candidate_service_ids);
    return saved.length ? saved : ["claude", "antigravity"];
  });
  const [candidateServiceAccess, setCandidateServiceAccess] = useState<Record<string, string[]>>(() => {
    const saved = asObject(existingPolicy.candidate_service_access);
    if (Object.keys(saved).length) {
      const selectedTokens = initialSelectionOrderKey.split("\n").filter(Boolean);
      const normalized = Object.fromEntries(
        Object.entries(saved).map(([token, values]) => [token, asStringList(values)]),
      );
      selectedTokens.forEach((token) => {
        if (!Object.prototype.hasOwnProperty.call(normalized, token)) normalized[token] = [];
      });
      return normalized;
    }
    const serviceIds = asStringList(existingPolicy.candidate_service_ids);
    const defaults = serviceIds.length ? serviceIds : ["claude", "antigravity"];
    return Object.fromEntries(
      initialSelectionOrderKey.split("\n").filter(Boolean).map((token) => [token, defaults]),
    );
  });
  const networking = asObject(asObject(config.system).networking);
  const wireguardExits = networking.wireguard_egress_enabled === true
    ? asObjectList(networking.wireguard_egress_exits).filter(
        (item) => item.enabled !== false,
      )
    : [];
  const [selectedWireguardExits, setSelectedWireguardExits] = useState<string[]>(
    initialSelectionOrderKey.split("\n").filter(Boolean)
      .filter((token) => token.startsWith("wireguard:"))
      .map((token) => token.slice("wireguard:".length)),
  );
  const reverseVlessExits = asObjectList(config.reverse_vless_exits).filter(
    (item) => item.enabled !== false,
  );
  const selectedReverseVlessExits = selectionOrder
    .filter((token) => token.startsWith("reverse:"))
    .map((token) => token.slice("reverse:".length));
  const [subscriptionNodes, setSubscriptionNodes] = useState<JsonObject[]>([]);
  const [nodesBusy, setNodesBusy] = useState(true);
  const [nodesError, setNodesError] = useState("");
  const [customPacks, setCustomPacks] = useState(
    asObjectList(config.service_packs),
  );
  const [hiddenServicePacks, setHiddenServicePacks] = useState<string[]>(
    asStringList(existingPolicy.hidden_service_packs),
  );
  const [exceptionServices, setExceptionServices] = useState<string[]>(() => [
    ...new Set([
      ...asStringList(existingPolicy.direct_services),
      ...Object.keys(asObject(existingPolicy.service_routes)),
    ]),
  ]);
  const legacyExceptionDomains = asStringList(existingPolicy.direct_domains);
  const [pinpointDomainsEnabled, setPinpointDomainsEnabled] = useState(
    existingPolicy.pinpoint_domains_enabled === true || legacyExceptionDomains.length > 0,
  );
  const [pinpointDomainsText, setPinpointDomainsText] = useState(
    legacyExceptionDomains.join(", "),
  );
  const automaticPinpointDomainsRef = useRef<Set<string> | null>(null);
  useEffect(() => {
    let cancelled = false;
    const subscriptionIds = asObjectList(config.subscriptions)
      .filter((item) => item.enabled !== false)
      .map((item) => asText(item.id, ""))
      .filter(Boolean);
    Promise.all(subscriptionIds.map((id) => getSubscriptionNodes<JsonObject>(id)))
      .then((results) => {
        if (cancelled) return;
        const liveNodes = results.flatMap((result) => asObjectList(result.nodes));
        setSubscriptionNodes(liveNodes);
        const savedOrder = initialSelectionOrderKey.split("\n").filter(Boolean);
        if (savedOrder.length && liveNodes.length) {
          const mirrors = policySelectionMirrorsFromOrder(savedOrder, liveNodes);
          setSelectedCountries(mirrors.countries);
          setSelectedLocations(mirrors.locations);
          setSelectionOrder(savedOrder);
        }
        if (!subscriptionIds.length) {
          setNodesError(tr("Сначала добавьте и обновите хотя бы одну подписку."));
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setSubscriptionNodes([]);
          setNodesError(errorMessage(error));
        }
      })
      .finally(() => {
        if (!cancelled) setNodesBusy(false);
      });
    return () => {
      cancelled = true;
    };
  }, [config.subscriptions, initialSelectionOrderKey, tr]);

  const selectedExceptionServices = [
    ...new Set([
      ...exceptionServices,
      ...(torrentDirect ? ["torrent"] : []),
    ]),
  ].filter(
    (service) =>
      service !== "torrent" ||
      torrentDirect ||
      trafficMode === "wan_with_vless_exceptions",
  );
  const recommendedPinpointDomains = [...new Set(
    selectedExceptionServices.flatMap(
      (service) => PINPOINT_DOMAINS_BY_PACK[service] ?? [],
    ),
  )];
  const recommendedPinpointDomainsKey = recommendedPinpointDomains.join("\n");

  useEffect(() => {
    if (!pinpointDomainsEnabled) {
      automaticPinpointDomainsRef.current = null;
      return;
    }
    const recommended = recommendedPinpointDomainsKey
      ? recommendedPinpointDomainsKey.split("\n")
      : [];
    const previousAutomatic = automaticPinpointDomainsRef.current;
    setPinpointDomainsText((current) => {
      const currentDomains = parsePinpointDomains(current);
      const automatic = previousAutomatic ?? new Set(
        recommended.filter((domain) => currentDomains.includes(domain)),
      );
      const manual = currentDomains.filter((domain) => !automatic.has(domain));
      return mergePinpointDomains(manual.join(", "), recommended);
    });
    automaticPinpointDomainsRef.current = new Set(recommended);
  }, [pinpointDomainsEnabled, recommendedPinpointDomainsKey]);

  function removeServicePack(packId: string, custom: boolean) {
    setExceptionServices((current) => current.filter((id) => id !== packId));
    setCandidateServiceIds((current) => current.filter((id) => id !== packId));
    setCandidateServiceAccess((current) => Object.fromEntries(
      Object.entries(current).map(([token, ids]) => [
        token,
        ids.filter((id) => id !== packId),
      ]),
    ));
    if (custom) {
      setCustomPacks((current) => current.filter(
        (pack) => asText(pack.id, "") !== packId,
      ));
      return;
    }
    setHiddenServicePacks((current) => [...new Set([...current, packId])]);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setSaveError("");
    const data = new FormData(event.currentTarget);
    try {
      if (
        !selectedCountries.length &&
        !selectedLocations.length &&
        !selectedWireguardExits.length &&
        !selectedReverseVlessExits.length
      ) {
        throw new Error(tr("Выберите хотя бы одну группу, страну, город или WireGuard-выход."));
      }
      const displayName = String(data.get("display_name") ?? "").trim();
      if (!displayName) throw new Error(tr("Введите название маршрута."));
      const id = editing
        ? asText(existingPolicy.id, "")
        : entityIdFromName(
            displayName,
            new Set(asObjectList(config.policies).map((policy) => asText(policy.id, ""))),
            "route",
          );
      const exceptionServices = selectedExceptionServices.filter(
        (service) =>
          service !== "torrent" ||
          torrentDirect ||
          trafficMode === "wan_with_vless_exceptions",
      );
      const pinpointDomains = pinpointDomainsEnabled
        ? [...new Set(
            pinpointDomainsText
              .split(/[\n,]/)
              .map((value) => value.trim().toLowerCase().replace(/^\.+/, ""))
              .filter(Boolean),
          )]
        : [];
      const retainedCustomIds = new Set(
        customPacks.map((pack) => asText(pack.id, "")).filter(Boolean),
      );
      const removedCustomIds = new Set(
        asObjectList(config.service_packs)
          .map((pack) => asText(pack.id, ""))
          .filter((id) => id && !retainedCustomIds.has(id)),
      );
      const item: JsonObject = {
        ...existingPolicy,
        id,
        display_name: displayName,
        enabled: policyEnabled,
        mode,
        traffic_mode: trafficMode,
        hidden_service_packs: hiddenServicePacks,
        torrent_direct: torrentDirect,
        domain_strategy: domainStrategyEnabled ? "IPIfNonMatch" : "AsIs",
        kind: undefined,
        countries: selectedCountries,
        locations: selectedLocations,
        selection_order: selectionOrder,
        candidate_service_ids: mode === "priority" ? candidateServiceIds : [],
        candidate_service_access: mode === "priority"
          ? Object.fromEntries(
              selectionOrder.map((token) => [
                token,
                (Object.prototype.hasOwnProperty.call(candidateServiceAccess, token)
                  ? candidateServiceAccess[token]
                  : candidateServiceIds
                ).filter((service) =>
                  candidateServiceIds.includes(service),
                ),
              ]),
            )
          : {},
        cities: [],
        outbounds: [
          ...selectedWireguardExits.map((id) => `wg-egress-${id}`),
          ...selectedReverseVlessExits.map((id) => `reverse-vless-${id}`),
        ],
        final: "direct",
        // The historical key is retained for configuration compatibility, but
        // its destination is determined by traffic_mode: WAN in VLESS+WAN,
        // and the selected VLESS policy in WAN+VLESS.
        direct_domains: pinpointDomains,
        pinpoint_domains_enabled: pinpointDomainsEnabled,
        direct_services:
          trafficMode === "vless_with_wan_exceptions"
            ? exceptionServices
            : [],
        service_routes:
          trafficMode === "wan_with_vless_exceptions"
            ? Object.fromEntries(exceptionServices.map((service) => [service, id]))
            : {},
        container_outage: undefined,
        on_all_unavailable: "block",
        failure_threshold: Number(data.get("failure_threshold") ?? existingPolicy.failure_threshold ?? 3),
        recovery_threshold: Number(data.get("recovery_threshold") ?? existingPolicy.recovery_threshold ?? 3),
        quality_window: Number(data.get("quality_window") ?? existingPolicy.quality_window ?? 5),
        max_packet_loss_percent: Number(data.get("max_packet_loss_percent") ?? existingPolicy.max_packet_loss_percent ?? 40),
        max_latency_ms: Number(data.get("max_latency_ms") ?? existingPolicy.max_latency_ms ?? 2000),
        switch_cooldown_seconds: Number(data.get("switch_cooldown_seconds") ?? existingPolicy.switch_cooldown_seconds ?? 600),
        switch_improvement_percent: undefined,
        switch_improvement_ms: Number(data.get("switch_improvement_ms") ?? existingPolicy.switch_improvement_ms ?? 50),
        speed_check_enabled: mode === "best",
        speed_improvement_percent: Number(data.get("speed_improvement_percent") ?? existingPolicy.speed_improvement_percent ?? 25),
        speed_check_interval_seconds: 10800,
        speed_probe_bytes: 2097152,
        speed_candidate_count: 2,
        max_active_candidates: candidateLimit,
        max_probe_candidates: candidateLimit,
        return_to_primary: true,
        interrupt_exist_connections: false,
      };
      await saveCurrentDraft({
        config: withDeploymentReadiness(
          {
            ...config,
            service_packs: customPacks,
            local_clients: asObjectList(config.local_clients).map((client) =>
              withoutServicePackReferences(client, removedCustomIds),
            ),
            remote_users: asObjectList(config.remote_users).map((user) =>
              withoutServicePackReferences(user, removedCustomIds),
            ),
            policies: editing
              ? asObjectList(config.policies).map((policy) =>
                  policy.id === policyId
                    ? item
                    : withoutServicePackReferences(policy, removedCustomIds),
                )
              : [
                  ...asObjectList(config.policies).map((policy) =>
                    withoutServicePackReferences(policy, removedCustomIds),
                  ),
                  item,
                ],
          },
          false,
        ),
      });
      await onSaved();
      setSaved(true);
    } catch (error) {
      setSaveError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop policy-editor-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="policy-title"
        className="modal modal-wide policy-editor-modal"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        {saved ? (
          <div className="modal-success" role="status">
            <span>✓</span>
            <h2 id="policy-title">
              {editing ? tr("Маршрутный лист обновлён") : tr("Маршрутный лист создан")}
            </h2>
            <p>{tr("Сохранено. Изменения вступят в силу после применения.")}</p>
            <button className="button button-primary" onClick={onClose}>
               {tr("Готово")} </button>
          </div>
        ) : (
          <form className="policy-editor-form" onSubmit={submit}>
            <header className="policy-editor-header">
              <span>{tr("Конфигурация листа")}</span>
              <h2 id="policy-title">
                {editing ? tr("Маршрутный лист · {value1}", { value1: itemName(existingPolicy) }) : tr("Новый маршрутный лист")}
              </h2>
            </header>
            <div className="policy-editor-body">
              <p className="policy-editor-notice">
                 {tr("Здесь выбираются расположения подписки, основной путь трафика и сервисы-исключения. Устройство только подключается к готовому листу.")} </p>
              <div className="form-grid policy-editor-grid">
              <label className="field">
                 {tr("Название маршрута")} <input
                  name="display_name"
                  required
                  defaultValue={asText(existingPolicy.display_name, "")}
                />
              </label>
              <label className="field">
                 {tr("Основной маршрут")} <select value={trafficMode} onChange={(event) => setTrafficMode(event.target.value)}>
                  <option value="vless_with_wan_exceptions">{tr("VLESS + исключения через WAN")}</option>
                  <option value="wan_with_vless_exceptions">{tr("WAN + исключения через VLESS")}</option>
                </select>
                <small>{tr("Отмеченные ниже карточки идут по противоположному пути.")}</small>
              </label>
              <fieldset className="field form-span policy-strategy-picker">
                <legend>{tr("Как выбирать узел")}</legend>
                <div>
                  <label>
                    <input
                      type="radio"
                      name="mode"
                      value="best"
                      checked={mode === "best"}
                      onChange={() => setMode("best")}
                    />
                    <span>
                      <strong>{tr("URLTest с резервированием")}</strong>
                      <small>{tr("Распределяет HTTPS- и ограниченные тесты скорости по всему выбранному набору. Планово переключается только на заметно лучший канал.")}</small>
                    </span>
                  </label>
                  <label>
                    <input
                      type="radio"
                      name="mode"
                      value="priority"
                      checked={mode === "priority"}
                      onChange={() => setMode("priority")}
                    />
                    <span>
                      <strong>{tr("Приоритет с резервированием")}</strong>
                      <small>{tr("Меняет узел только при подтверждённой нестабильности или недоступности и возвращается к восстановившемуся более приоритетному пункту.")}</small>
                    </span>
                  </label>
                </div>
              </fieldset>
              <section className="subscription-location-picker form-span">
                {nodesBusy ? (
                  <div className="subscription-discovery-empty">{tr("Загружаю расположения из подписок…")}</div>
                ) : nodesError ? (
                  <div className="inline-result inline-result-error" role="alert"><span>!</span>{nodesError}</div>
                ) : (
                  <SubscriptionLocationPicker
                    nodes={subscriptionNodes}
                    wireguardExits={wireguardExits}
                    reverseVlessExits={reverseVlessExits}
                    mode={mode}
                    selectedCountries={selectedCountries}
                    selectedLocations={selectedLocations}
                    selectedWireguardExits={selectedWireguardExits}
                    selectedReverseVlessExits={selectedReverseVlessExits}
                    selectionOrder={selectionOrder}
                    candidateLimit={candidateLimit}
                    candidateServiceIds={candidateServiceIds}
                    candidateServiceAccess={candidateServiceAccess}
                    customPacks={customPacks}
                    onCountriesChange={setSelectedCountries}
                    onLocationsChange={setSelectedLocations}
                    onWireguardExitsChange={setSelectedWireguardExits}
                    onSelectionOrderChange={setSelectionOrder}
                    onCandidateServiceIdsChange={setCandidateServiceIds}
                    onCandidateServiceAccessChange={setCandidateServiceAccess}
                    onCustomPackAdded={(pack) => {
                      if (pack.builtin) return;
                      const id = asText(pack.id, "");
                      setCustomPacks((current) => current.some((item) => asText(item.id, "") === id)
                        ? current
                        : [...current, pack]);
                    }}
                  />
                )}
              </section>
              <DirectServicePackPicker
                selectedValues={selectedExceptionServices}
                onSelectedValuesChange={setExceptionServices}
                customPacks={customPacks}
                inputName="exception_services"
                legend={trafficMode === "vless_with_wan_exceptions" ? tr("Исключения через обычный WAN") : tr("Исключения через VLESS")}
                lockedValues={torrentDirect ? ["torrent"] : []}
                excludedValues={
                  torrentDirect || trafficMode === "vless_with_wan_exceptions"
                    ? ["torrent"]
                    : []
                }
                hiddenValues={hiddenServicePacks}
                onRemovePack={removeServicePack}
                onRestoreHidden={() => setHiddenServicePacks([])}
                description={trafficMode === "vless_with_wan_exceptions"
                  ? tr("Карточки применяются ко всем устройствам маршрутного листа и отправляются через обычный WAN.")
                  : tr("Карточки применяются ко всем устройствам, подключённым к этому маршрутному листу.")}
              />
              <CatalogServiceAdder
                knownPacks={customPacks}
                destinationLabel={trafficMode === "vless_with_wan_exceptions" ? tr("обычный WAN MikroTik") : "VLESS"}
                onResolved={(pack) => {
                  const id = asText(pack.id, "");
                  if (!pack.builtin) {
                    setCustomPacks((current) => current.some((item) => asText(item.id, "") === id)
                      ? current
                      : [...current, pack]);
                  }
                  setExceptionServices((current) => current.includes(id) ? current : [...current, id]);
                }}
              />
              <div className="form-span">
                <div className="policy-route-toggles">
                  <Toggle
                    checked={torrentDirect}
                    onChange={setTorrentDirect}
                    label={tr("Torrent через WAN")}
                    description={tr("BitTorrent идёт напрямую и не нагружает VPN.")}
                  />
                  <Toggle
                    checked={domainStrategyEnabled}
                    onChange={setDomainStrategyEnabled}
                    label={tr("Стратегия домена")}
                    description={domainStrategyEnabled
                      ? tr("Если доменное правило не найдено, клиент дополнительно проверяет IP-адрес.")
                      : tr("Маршрутизация выполняется только по явно совпавшим доменным правилам.")}
                  />
                  <Toggle
                    checked={pinpointDomainsEnabled}
                    onChange={setPinpointDomainsEnabled}
                    label={tr("Точечные домены")}
                    description={pinpointDomainsEnabled
                      ? tr("{value1} доменов добавлены к выбранным карточкам.", { value1: parsePinpointDomains(pinpointDomainsText).length })
                      : recommendedPinpointDomains.length
                        ? tr("Не используются. Включите вручную, чтобы дополнить выбранные карточки.")
                        : tr("Не используются.")}
                  />
                </div>
                {pinpointDomainsEnabled ? (
                  <details className="pinpoint-domains" open={!editing || !legacyExceptionDomains.length}>
                    <summary>
                       {tr("Точечные домены ·")} {parsePinpointDomains(pinpointDomainsText).length}
                    </summary>
                    <label className="field">
                      <span className="sr-only">{tr("Точечные домены")}</span>
                      <textarea
                        rows={3}
                        value={pinpointDomainsText}
                        onChange={(event) => setPinpointDomainsText(event.target.value)}
                        placeholder="example.ru, api.example.ru"
                      />
                      <small>{tr("Через запятую. Эти имена дополняют выбранные обновляемые карточки, а не заменяют их.")}</small>
                    </label>
                  </details>
                ) : null}
              </div>
              <aside className="adaptive-checks-note form-span">
                <strong>{tr("Проверки распределены по времени")}</strong>
                <p>{mode === "priority"
                  ? tr("Вся выбранная очередь проверяется малыми партиями. Доступность активного пути контролируется отдельно.")
                  : tr("Все выбранные серверы проверяются малыми партиями. Замеры скорости чередуются: до 2 МиБ на узел, не чаще раза в 3 часа для каждого.")}</p>
              </aside>
              <details className="policy-check-advanced form-span">
                <summary>{tr("Дополнительные параметры переключения")}</summary>
                <div className="policy-check-grid">
                  {mode === "best" ? <label className="field">
                    <span className="policy-check-label">{tr("Узлов в активном пуле")}</span>
                    <select name="max_active_candidates" value={candidateLimit} onChange={(event) => setCandidateLimit(Number(event.target.value))}>
                      {Array.from({ length: 10 }, (_, index) => index + 1).map((count) => <option key={count} value={count}>{count}</option>)}
                    </select>
                    <small>{tr("Активный узел и лучшие резервы. Все выбранные серверы проверяются в фоне.")}</small>
                  </label> : null}
                  <label className="field">
                    <span className="policy-check-label">{tr("Окно оценки качества")}</span>
                    <input name="quality_window" type="number" min="3" max="60" defaultValue={asText(existingPolicy.quality_window, "5")} />
                    <small>{tr("Количество последних HTTPS-проверок.")}</small>
                  </label>
                  <label className="field">
                    <span className="policy-check-label">{tr("Допустимая доля потерь, %")}</span>
                    <input name="max_packet_loss_percent" type="number" min="0" max="100" defaultValue={asText(existingPolicy.max_packet_loss_percent, "40")} />
                  </label>
                  <label className="field">
                    <span className="policy-check-label">{tr("Максимальный p95 HTTPS, мс")}</span>
                    <input name="max_latency_ms" type="number" min="0" max="30000" defaultValue={asText(existingPolicy.max_latency_ms, "2000")} />
                    <small>{tr("0 отключает порог задержки.")}</small>
                  </label>
                  <label className="field">
                    <span className="policy-check-label">{tr("Подтверждений обычной ошибки")}</span>
                    <input name="failure_threshold" type="number" min="1" max="20" defaultValue={asText(existingPolicy.failure_threshold, "3")} />
                    <small>{tr("Сетевой отказ или TLS-ошибка — сразу; тайм-аут — после двух запросов.")}</small>
                  </label>
                  <label className="field">
                    <span className="policy-check-label">{tr("Подтверждений восстановления")}</span>
                    <input name="recovery_threshold" type="number" min="1" max="20" defaultValue={asText(existingPolicy.recovery_threshold, "3")} />
                  </label>
                  {mode === "best" ? (
                    <>
                      <label className="field">
                        <span className="policy-check-label">{tr("Порог переключения URLTest, мс")}</span>
                        <input name="switch_improvement_ms" type="number" min="0" max="30000" defaultValue={asText(existingPolicy.switch_improvement_ms, "50")} />
                        <small>{tr("Переключение выполняется, только если стабильная HTTPS-задержка ниже хотя бы на это значение.")}</small>
                      </label>
                      <label className="field">
                        <span className="policy-check-label">{tr("Порог приоритета скорости, %")}</span>
                        <input name="speed_improvement_percent" type="number" min="0" max="100" defaultValue={asText(existingPolicy.speed_improvement_percent, "25")} />
                        <small>{tr("Сначала — узлы с таким приростом. Иначе — лучший отклик, если его выигрыш больше потери скорости; предел потери — 35%.")}</small>
                      </label>
                    </>
                  ) : null}
                  <label className="field">
                    <span className="policy-check-label">{tr("Защита от обратного переключения, сек.")}</span>
                    <input name="switch_cooldown_seconds" type="number" min="0" max="86400" defaultValue={asText(existingPolicy.switch_cooldown_seconds, "600")} />
                    <small>{tr("Только для планового выбора лучшего узла. Отказ, деградация и выход из блокировки выполняются без этой паузы.")}</small>
                  </label>
                </div>
              </details>
              <div className="form-span policy-enabled-toggle">
                <Toggle
                  checked={policyEnabled}
                  onChange={setPolicyEnabled}
                  tone="state"
                  label={tr("Маршрутный лист включён")}
                  description={tr("Выключенный лист сохраняется, но не назначается устройствам.")}
                />
              </div>
              </div>
              {saveError ? (
                <div className="inline-result inline-result-error policy-editor-error" role="alert">
                  <span>!</span>
                  {saveError}
                </div>
              ) : null}
            </div>
            <footer className="modal-actions policy-editor-footer">
              {editing ? (
                <button
                  className="button button-danger"
                  type="button"
                  disabled={busy}
                  onClick={async () => {
                    if (!deleteArmed) {
                      setDeleteArmed(true);
                      setSaveError(
                        tr("Нажмите «Удалить маршрутный лист» ещё раз. Удаление будет отклонено, если он назначен устройству."),
                      );
                      return;
                    }
                    setBusy(true);
                    setSaveError("");
                    try {
                      await deleteCollectionItem("policies", policyId!);
                      await onSaved();
                      onClose();
                    } catch (error) {
                      setSaveError(errorMessage(error));
                      setBusy(false);
                    }
                  }}
                >
                  {deleteArmed ? tr("Удалить маршрутный лист") : tr("Подготовить удаление")}
                </button>
              ) : null}
              <button
                className="button button-tertiary"
                type="button"
                onClick={onClose}
                disabled={busy}
              >
                 {tr("Отмена")} </button>
              <button
                className="button button-primary"
                type="submit"
                disabled={busy}
              >
                {busy
                  ? tr("Сохраняю…")
                  : editing
                    ? tr("Сохранить изменения")
                    : tr("Добавить")}
              </button>
            </footer>
          </form>
        )}
      </section>
    </div>
  );
}

function TlsProfileDialog({
  profileId,
  onClose,
  onSaved,
  config,
}: {
  profileId?: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
  config: JsonObject;
}) {
  const { locale, tr } = useLanguage();
  const certificateRef = useRef<HTMLInputElement>(null);
  const privateKeyRef = useRef<HTMLInputElement>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [workingId, setWorkingId] = useState(profileId);
  const profiles = asObjectList(config.tls_profiles);
  const existing = profiles.find((profile) => asText(profile.id, "") === workingId) ?? {};
  const savedCertificateMode = asText(existing.certificate_source, "") ||
    (asText(existing.certificate_secret_ref, "").endsWith("/acme-bundle.pem") ? "acme" : "manual");
  const [localCAServerName, setLocalCAServerName] = useState(asText(existing.local_ca_server_name, ""));
  const acme = useAcmeProfile(workingId, savedCertificateMode);
  const refreshedCertificate = useRef("");
  const issuedFingerprint = asText(asObject(acme.status.metadata).fingerprint_sha256, "") || asText(asObject(acme.status.metadata).not_after, "");
  useEffect(() => {
    if (acme.status.state !== "issued" || !issuedFingerprint || refreshedCertificate.current === issuedFingerprint) return;
    refreshedCertificate.current = issuedFingerprint;
    void onSaved().catch(() => { refreshedCertificate.current = ""; });
  }, [acme.status.state, issuedFingerprint, onSaved]);
  const editing = Boolean(profileId);
  const usedByLabels = asObjectList(config.transports).flatMap((transport) => {
    const kind = asText(transport.kind, "");
    if (["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)) {
      return cdnDeploymentsForTransport(transport)
        .filter((deployment) =>
          asText(
            deployment.tls_profile_id,
            asText(transport.tls_profile_id, ""),
          ) === profileId,
        )
        .map(
          (deployment) =>
            `${transportKindLabel(kind)} / ${asText(deployment.display_name, "CDN")}`,
        );
    }
    return asText(transport.tls_profile_id, "") === profileId
      ? [transportKindLabel(kind)]
      : [];
  });
  const usedByPublicIngress =
    asText(asObject(config.ingress).tls_profile_id, "") === profileId;
  if (usedByPublicIngress) usedByLabels.unshift("Status / health");
  const usedBySubscriptionIngress =
    asText(asObject(config.ingress).subscription_tls_profile_id, "") === profileId;
  if (usedBySubscriptionIngress) usedByLabels.unshift(tr("Клиентская подписка"));
  const pairReady = Boolean(
    asText(existing.certificate_secret_ref, "") &&
      asText(existing.private_key_secret_ref, ""),
  );
  const normalizedLocalCAServerName = localCAServerName.trim().toLowerCase().replace(/\.+$/, "");
  const localCAPairReady = pairReady && savedCertificateMode === "local-ca" &&
    normalizedLocalCAServerName === asText(existing.local_ca_server_name, "").toLowerCase().replace(/\.+$/, "");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const data = new FormData(event.currentTarget);
      const displayName = String(data.get("display_name") ?? "").trim();
      if (!displayName) throw new Error(tr("Введите название TLS-профиля."));
      const id = workingId ?? entityIdFromName(
        displayName,
        new Set(profiles.map((profile) => asText(profile.id, ""))),
        "tls-profile",
      );
      const certificateFile = acme.mode === "manual" ? certificateRef.current?.files?.[0] ?? null : null;
      const privateKeyFile = acme.mode === "manual" ? privateKeyRef.current?.files?.[0] ?? null : null;
      const certificate = certificateFile ? (await certificateFile.text()).trim() : "";
      const privateKey = privateKeyFile ? (await privateKeyFile.text()).trim() : "";
      if (Boolean(certificate) !== Boolean(privateKey)) {
        throw new Error(tr("Сертификат и private key нужно загрузить одной парой."));
      }
      if (certificate && !certificate.includes("BEGIN CERTIFICATE")) {
        throw new Error(tr("Сертификат должен быть в формате PEM."));
      }
      if (privateKey && !privateKey.includes("PRIVATE KEY")) {
        throw new Error(tr("Private key должен быть в формате PEM."));
      }
      const submitter = (event.nativeEvent as SubmitEvent).submitter;
      const regenerateLocalCA = submitter?.getAttribute("data-generate-local-ca") === "true";
      const generateLocalCA = acme.mode === "local-ca" && (
        regenerateLocalCA || !localCAPairReady
      );
      const item: JsonObject = {
        ...existing,
        id,
        display_name: displayName,
        enabled: data.get("enabled") === "on",
        certificate_source: acme.mode,
        ...(acme.mode === "local-ca"
          ? { local_ca_server_name: normalizedLocalCAServerName, generate_local_ca: generateLocalCA }
          : {}),
        ...(certificate
          ? { secret_values: { certificate, private_key: privateKey } }
          : {}),
      };
      // The server retains the latest pair atomically, including a certificate
      // issued after this form was opened. A manual upload still replaces it.
      delete item.certificate_secret_ref;
      delete item.private_key_secret_ref;
      delete item.certificate_metadata;
      if (workingId) {
        await updateCollectionItem("tls-profiles", id, item);
      } else {
        await createCollectionItem("tls-profiles", item);
        setWorkingId(id);
      }
      const issue = submitter?.getAttribute("data-issue") === "true";
      await acme.save(id, issue);
      await onSaved();
      setSaved(acme.mode !== "acme");
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={() => { if (!exportOpen) onClose(); }}>
      <section className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="tls-profile-title" onMouseDown={(event) => event.stopPropagation()}>
        <button className="modal-close" type="button" onClick={onClose} aria-label={tr("Закрыть")}>×</button>
        {saved ? (
          <div className="modal-success" role="status">
            <span>✓</span>
            <h2 id="tls-profile-title">{tr("TLS-профиль сохранён")}</h2>
            <p>{tr("Пара хранится в SecretStore. Связанные транспорты получат изменения после Apply.")}</p>
            <button className="button button-primary" type="button" onClick={onClose}>{tr("Готово")}</button>
          </div>
        ) : (
          <form onSubmit={submit}>
            <p className="eyebrow">{tr("Сертификат подключений")}</p>
            <h2 id="tls-profile-title">{editing ? tr("Настроить · {value1}", { value1: itemName(existing) }) : tr("Добавить TLS-профиль")}</h2>
            <div className="form-grid">
              <label className="field">
                 {tr("Имя профиля")} <input name="display_name" defaultValue={asText(existing.display_name, "")} placeholder={tr("Основной")} maxLength={96} required />
              </label>
              <label className="field">{tr("Сертификат")} <select value={acme.mode} disabled={!acme.loaded} onChange={(event) => acme.setMode(event.target.value)}>
                  <option value="manual">{tr("Загрузить файлы")}</option>
                  <option value="acme">{tr("Автоматически · ACME")}</option>
                  <option value="local-ca">{tr("Локальный CA · TLS Pin")}</option>
                </select>
              </label>
              {acme.mode === "acme" ? <AcmeFields model={acme} /> : acme.mode === "local-ca" ? <>
              <label className="field form-span">
                {tr("SNI сертификата")}
                <input
                  name="local_ca_server_name"
                  type="text"
                  inputMode="url"
                  value={localCAServerName}
                  onChange={(event) => setLocalCAServerName(event.target.value)}
                  placeholder="www.example.com"
                  maxLength={253}
                  autoComplete="off"
                  required
                />
                <small>{tr("Root CA и leaf создаются на шлюзе. Срок действия leaf — 10 лет.")}</small>
              </label>
              <aside className="notice notice-neutral form-span">
                <span className="notice-icon">{localCAPairReady ? "✓" : "!"}</span>
                <div>
                  <strong>{localCAPairReady ? tr("Локальный сертификат настроен") : tr("Сертификат будет создан при сохранении")}</strong>
                  {localCAPairReady ? <small>{tr("Действует до:")} {tlsProfileExpiry(existing, locale)}</small> : null}
                </div>
              </aside>
              </> : <>
              <label className="field">
                 {tr("TLS-сертификат · PEM")} <input ref={certificateRef} name="certificate" type="file" accept=".pem,.crt,.cer,application/x-pem-file" />
              </label>
              <label className="field">
                 {tr("Соответствующий private key · PEM")} <input ref={privateKeyRef} name="private_key" type="file" accept=".pem,.key,application/x-pem-file" />
              </label>
              <aside className="notice notice-neutral form-span">
                <span className="notice-icon">{pairReady ? "✓" : "!"}</span>
                <div>
                  <strong>{pairReady ? tr("TLS-пара настроена") : tr("TLS-пара ещё не загружена")}</strong>
                  <p>{tr("Private key не возвращается в браузер. Чтобы заменить пару, выберите оба файла одновременно.")}</p>
                  {pairReady ? <small>{tr("Действует до:")} {tlsProfileExpiry(existing, locale)}</small> : null}
                </div>
              </aside>
              </>}
              {acme.loadError ? <div className="inline-result inline-result-error form-span" role="alert">{acme.loadError}<button className="button button-tertiary" type="button" onClick={acme.retry}>{tr("Повторить")}</button></div> : null}
              {acme.mode === "acme" ? <p className="field-hint form-span">{tr("Первое подключение сертификата — после Apply. Последующие продления выполняются автоматически.")}</p> : null}
              {editing ? (
                <div className="tls-profile-usage-strip form-span">
                  <small>{tr("Используют")}</small>
                  <span className="tls-profile-uses">
                    {usedByLabels.length
                      ? usedByLabels.map((label) => <span key={label}>{label}</span>)
                      : <em>{tr("Не используется")}</em>}
                  </span>
                </div>
              ) : null}
            </div>
            {error ? <div className="inline-result inline-result-error" role="alert"><span>!</span>{error}</div> : null}
            <div className="tls-profile-footer">
              <Toggle
                name="enabled"
                defaultChecked={existing.enabled !== false}
                tone="state"
                label={tr("Профиль включён")}
                description={tr("Выключенный профиль сохраняется, но не используется подключениями.")}
                title={tr("Связанный профиль можно выключить после переназначения использующих его транспортов.")}
              />
              <div className="modal-actions">
                {editing ? (
                  <button
                    className="button button-danger"
                    type="button"
                    disabled={busy || usedByLabels.length > 0}
                    title={usedByLabels.length ? tr("Сначала выберите другой TLS-профиль во всех связанных транспортах, status / health и клиентской подписке") : tr("Удалить TLS-профиль")}
                    onClick={async () => {
                      if (!deleteArmed) {
                        setDeleteArmed(true);
                        setError(tr("Нажмите «Удалить TLS-профиль» ещё раз. Секреты останутся в хранилище для восстановления."));
                        return;
                      }
                      setBusy(true);
                      setError("");
                      try {
                        await deleteCollectionItem("tls-profiles", profileId!);
                        await onSaved();
                        onClose();
                      } catch (caught) {
                        setError(errorMessage(caught));
                        setBusy(false);
                      }
                    }}
                  >
                    {deleteArmed ? tr("Удалить TLS-профиль") : tr("Подготовить удаление")}
                  </button>
                ) : null}
                {workingId ? <button className="button button-tertiary" type="button" disabled={busy || !pairReady} onClick={() => setExportOpen(true)}>{tr("Экспорт")}</button> : null}
                <button className="button button-tertiary" type="button" onClick={onClose} disabled={busy}>{tr("Отмена")}</button>
                {acme.mode === "acme" && acme.issueAvailable ? <button className="button button-secondary" type="submit" data-issue="true" disabled={busy || ["queued", "running"].includes(String(acme.status.state))}>{tr("Выпустить сертификат")}</button> : null}
                {acme.mode === "local-ca" && localCAPairReady ? <button className="button button-secondary" type="submit" data-generate-local-ca="true" disabled={busy}>{tr("Пересоздать сертификат")}</button> : null}
                <button className="button button-primary" type="submit" disabled={busy || !acme.loaded}>{busy ? tr("Сохраняю…") : tr("Сохранить изменения")}</button>
              </div>
            </div>
          </form>
        )}
      </section>
      {exportOpen && workingId ? <TlsTransferDialog profile={{ id: workingId, name: itemName(existing) }} onClose={() => setExportOpen(false)} onImported={onSaved} /> : null}
    </div>
  );
}

function ConnectionDialog({
  kind,
  transportId,
  subscriptionId,
  onClose,
  onSaved,
  config,
  certificateStatus,
}: {
  kind: "subscription" | "transport";
  transportId?: string;
  subscriptionId?: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
  config: JsonObject;
  certificateStatus: JsonObject;
}) {
  const { locale, t, tr } = useLanguage();
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [revealedHttpPath, setRevealedHttpPath] = useState("");
  const [httpPathBusy, setHttpPathBusy] = useState(false);
  const [httpPathMessage, setHttpPathMessage] = useState("");
  const [realityProbeBusy, setRealityProbeBusy] = useState(false);
  const [realityProbeResult, setRealityProbeResult] = useState("");
  const [realityProbeTone, setRealityProbeTone] = useState<
    "idle" | "success" | "warning" | "error"
  >("idle");
  const [realityProbeSignature, setRealityProbeSignature] = useState("");
  const [realityProbeEndpoints, setRealityProbeEndpoints] = useState<JsonObject[]>([]);
  const [realityProbeWildcards, setRealityProbeWildcards] = useState<string[]>([]);
  const [cdnProbeBusyId, setCdnProbeBusyId] = useState("");
  const [cdnProbeResults, setCdnProbeResults] = useState<Record<string, string>>({});
  const [pendingTransportActions, setPendingTransportActions] = useState<string[]>([]);
  const formRef = useRef<HTMLFormElement>(null);
  const transportParameterSnapshotRef = useRef<
    Record<string, { value: string; checked?: boolean }> | null
  >(null);
  const transportActionMenuRef = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    function closeTransportActionMenu(event: PointerEvent) {
      const menu = transportActionMenuRef.current;
      if (!menu?.open || menu.contains(event.target as Node)) return;
      menu.open = false;
    }
    function closeTransportActionMenuWithKeyboard(event: KeyboardEvent) {
      if (event.key !== "Escape" || !transportActionMenuRef.current?.open) return;
      transportActionMenuRef.current.open = false;
      transportActionMenuRef.current.querySelector<HTMLElement>("summary")?.focus();
    }
    document.addEventListener("pointerdown", closeTransportActionMenu);
    document.addEventListener("keydown", closeTransportActionMenuWithKeyboard);
    return () => {
      document.removeEventListener("pointerdown", closeTransportActionMenu);
      document.removeEventListener("keydown", closeTransportActionMenuWithKeyboard);
    };
  }, []);
  const [workingSubscriptionId, setWorkingSubscriptionId] = useState(
    subscriptionId ?? "",
  );
  const [subscriptionNodes, setSubscriptionNodes] = useState<JsonObject[]>([]);
  const [discoveryReady, setDiscoveryReady] = useState(false);
  const [discoveryMessage, setDiscoveryMessage] = useState("");
  const [subscriptionProvider, setSubscriptionProvider] = useState<JsonObject>({});
  const [persistedSubscription, setPersistedSubscription] = useState<JsonObject>({});
  const [subscriptionUrl, setSubscriptionUrl] = useState("");
  const [subscriptionUrlBusy, setSubscriptionUrlBusy] = useState(false);

  useEffect(() => {
    if (kind !== "subscription" || !subscriptionId) {
      setSubscriptionUrl("");
      setSubscriptionUrlBusy(false);
      return;
    }
    let active = true;
    setSubscriptionUrlBusy(true);
    getSubscriptionUrl<JsonObject>(subscriptionId)
      .then((result) => {
        if (active) setSubscriptionUrl(asText(result.url, ""));
      })
      .catch((error) => {
        if (active) {
          setSaveError(tr("Не удалось загрузить сохранённый URL: {value1}", { value1: errorMessage(error) }));
        }
      })
      .finally(() => {
        if (active) setSubscriptionUrlBusy(false);
      });
    return () => {
      active = false;
    };
  }, [kind, subscriptionId, tr]);

  const existingTransport =
    asObjectList(config.transports).find((item) => item.id === transportId) ?? {};
  const [transportEnabled, setTransportEnabled] = useState(
    existingTransport.enabled !== false,
  );
  const savedTransportKind = asText(existingTransport.kind, "").trim();
  const transportKind = savedTransportKind ||
    (transportId === "websocket"
      ? "ws"
      : transportId === "direct-reality"
        ? "reality"
        : transportId === "grpc-reality"
          ? "reality-grpc"
          : transportId === "grpc-tls-pin"
            ? "grpc-tls"
            : transportId === "xhttp-reality"
              ? "xhttp-reality"
              : transportId === "hysteria2"
                ? "hysteria2"
                : transportId ?? "ws");
  const transportRecommendation = TRANSPORT_RECOMMENDATIONS[transportKind];
  const directGRPCKind = ["reality-grpc", "grpc-tls"].includes(transportKind);
  const grpcIdleTimeoutDefault = directGRPCKind ? "60" : "0";
  const hostnamePlaceholder =
    ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(
      transportKind,
    )
      ? tr("IP-адрес или DNS-имя")
      : transportKind === "grpc"
      ? tr("Фактический gRPC hostname")
      : transportKind === "httpupgrade"
        ? tr("Фактический HTTPUpgrade hostname")
        : transportKind === "xhttp"
          ? tr("Фактический XHTTP hostname")
          : tr("Фактический WebSocket hostname");
  const connectionAddress = useContext(ConnectionAddressContext);
  const [hostnameMode, setHostnameMode] = useState(
    asText(existingTransport.hostname_mode, asText(existingTransport.hostname, "") ? "manual" : "auto"),
  );
  const [manualHostname, setManualHostname] = useState(asText(existingTransport.hostname, ""));
  const initialXHTTPMode = asText(
    existingTransport.mode,
    transportKind === "xhttp-reality" ? "auto" : "packet-up",
  );
  const [xhttpMode, setXHTTPMode] = useState(initialXHTTPMode);
  const [xhttpUplinkMethod, setXHTTPUplinkMethod] = useState(() => {
    const value = asText(existingTransport.uplink_http_method, initialXHTTPMode === "packet-up" ? "GET" : "POST").toUpperCase();
    return initialXHTTPMode !== "packet-up" && value === "GET" ? "POST" : value;
  });
  const [xhttpUplinkPlacement, setXHTTPUplinkPlacement] = useState(() => {
    const value = asText(existingTransport.uplink_data_placement, initialXHTTPMode === "packet-up" ? "header" : "auto");
    return initialXHTTPMode !== "packet-up" && ["header", "cookie"].includes(value) ? "auto" : value;
  });
  const [realityServerName, setRealityServerName] = useState(
    asText(existingTransport.server_name, ""),
  );
  const [realityCoverMode, setRealityCoverMode] = useState(
    asText(existingTransport.cover_mode, "external"),
  );
  const [realityHandshakeServer, setRealityHandshakeServer] = useState(
    asText(
      existingTransport.handshake_server,
      asText(existingTransport.server_name, ""),
    ),
  );
  const [realityHandshakeServerEdited, setRealityHandshakeServerEdited] =
    useState(false);
  const directInboundKind = [
    "reality",
    "reality-grpc",
    "grpc-tls",
    "xhttp-reality",
    "hysteria2",
  ].includes(transportKind);
  const directInboundProtocol = transportKind === "hysteria2" ? "UDP" : "TCP";
  const directInboundDefaultPort =
    transportKind === "hysteria2"
      ? "443"
      : transportKind === "reality-grpc"
        ? "2444"
        : transportKind === "grpc-tls"
          ? "2445"
          : transportKind === "xhttp-reality"
            ? "2446"
            : "2443";
  const [directListenPort, setDirectListenPort] = useState(
    asText(existingTransport.listen_port, directInboundDefaultPort),
  );
  const ownedWanAddresses = asObjectList(connectionAddress.wan_addresses);
  const selectedWanAddress = hostnameMode === "manual"
    ? ownedWanAddresses.find((row) => asText(row.address, "") === manualHostname.trim())
    : undefined;
  const wanDestinationAddress = selectedWanAddress ? manualHostname.trim() : "";
  const directPortConflict = directInboundKind
    ? asObjectList(config.transports).find((transport) => {
        const otherKind = asText(transport.kind, "");
        const otherProtocol = otherKind === "hysteria2" ? "UDP" : "TCP";
        const otherDestination = asText(
          transport.wan_destination_address,
          "",
        ).trim();
        return (
          asText(transport.id, "") !== asText(existingTransport.id, transportId ?? "") &&
          transport.enabled !== false &&
          ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(
            otherKind,
          ) &&
          otherProtocol === directInboundProtocol &&
          Number(transport.listen_port) === Number(directListenPort) &&
          (!wanDestinationAddress.trim() ||
            !otherDestination ||
            otherDestination === wanDestinationAddress.trim())
        );
      })
    : undefined;
  const savedRealityServerNames = asStringList(existingTransport.server_names)
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const [realitySniInput, setRealitySniInput] = useState(
    savedRealityServerNames.join(", "),
  );
  const [realitySniChecks, setRealitySniChecks] = useState<
    Array<{
      name: string;
      status: "pending" | "confirmed" | "certificate" | "rejected" | "failed";
      detail: string;
    }>
  >(
    savedRealityServerNames.map((name) => ({
      name,
      status: "pending",
      detail: tr("Сохранено · требуется повторная проверка"),
    })),
  );
  const [selectedRealitySnis, setSelectedRealitySnis] = useState<string[]>(
    savedRealityServerNames,
  );
  const [realitySniCheckPerformed, setRealitySniCheckPerformed] = useState(false);
  const existingXrayHysteria = asObject(existingTransport.xray_hysteria);
  const existingXrayMasquerade = asObject(existingXrayHysteria.masquerade);
  const existingXrayQuic = asObject(existingXrayHysteria.quic_params);
  const existingXrayUDPHop = asObject(existingXrayHysteria.udp_hop);
  const [hysteriaMasqueradeType, setHysteriaMasqueradeType] = useState(
    asText(existingXrayMasquerade.type, ""),
  );
  const [hysteriaWebsiteURL, setHysteriaWebsiteURL] = useState(
    asText(existingXrayMasquerade.type, "") === "website"
      ? asText(existingXrayMasquerade.url, "")
      : "",
  );
  const [hysteriaWebsiteBandwidth, setHysteriaWebsiteBandwidth] = useState(() => {
    if (asText(existingXrayMasquerade.type, "") !== "website") return "1";
    const value = Number(existingXrayMasquerade.bandwidth_mbps ?? 1);
    return Number.isFinite(value) && value >= 0.1 && value <= 100
      ? String(value)
      : "1";
  });
  const [hysteriaObfsEnabled, setHysteriaObfsEnabled] = useState(
    existingTransport.obfs_enabled === true,
  );
  const [hysteriaCongestion, setHysteriaCongestion] = useState(
    asText(existingXrayQuic.congestion, ""),
  );
  const [hysteriaUDPHopEnabled, setHysteriaUDPHopEnabled] = useState(
    existingXrayUDPHop.enabled === true,
  );
  const tlsProfiles = asObjectList(config.tls_profiles).map((profile) => {
    const status = asObject(certificateStatus[asText(profile.id, "")]);
    const certificateMetadata = asObject(status.metadata);
    return asStringList(certificateMetadata.dns_names).length
      ? { ...profile, certificate_metadata: certificateMetadata }
      : profile;
  });
  const [cdnDeployments, setCdnDeployments] = useState<JsonObject[]>(
    () =>
      cdnDeploymentsForTransport(existingTransport).map((deployment) => {
        const prepared =
          deployment.origin_protection_mode === "secret-header" &&
          !asText(deployment.origin_header_secret_ref, "")
            ? {
                ...deployment,
                origin_header_value: generateOriginHeaderSecret(),
              }
            : deployment;
        const profile = tlsProfiles.find(
          (item) =>
            asText(item.id, "") === asText(prepared.tls_profile_id, ""),
        );
        return cdnDeploymentForTLSInitialization(prepared, profile);
      }),
  );
  function updateCdnDeployment(index: number, patch: JsonObject) {
    setCdnDeployments((current) =>
      current.map((item, itemIndex) =>
        itemIndex === index ? { ...item, ...patch } : item,
      ),
    );
  }

  function syncRecommendedFieldState(
    name: string,
    value: string,
    checked?: boolean,
  ) {
    if (name === "mode") setXHTTPMode(value);
    if (name === "uplink_http_method") setXHTTPUplinkMethod(value);
    if (name === "uplink_data_placement") setXHTTPUplinkPlacement(value);
    if (name === "hysteria_congestion") setHysteriaCongestion(value);
    if (name === "hysteria_masquerade_type") setHysteriaMasqueradeType(value);
    if (name === "obfs_enabled") setHysteriaObfsEnabled(checked === true);
    if (name === "hysteria_udp_hop_enabled") {
      setHysteriaUDPHopEnabled(checked === true);
    }
  }

  function setRecommendedField(
    control: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
    value: string | boolean,
  ) {
    if (typeof value === "boolean" && control instanceof HTMLInputElement) {
      control.checked = value;
      syncRecommendedFieldState(control.name, control.value, value);
    } else if (typeof value === "string") {
      control.value = value;
      syncRecommendedFieldState(
        control.name,
        value,
        control instanceof HTMLInputElement ? control.checked : undefined,
      );
    }
    control.dispatchEvent(new Event("input", { bubbles: true }));
    control.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function applyTransportParameterDefaults() {
    const form = formRef.current;
    if (!form || !transportRecommendation) return;
    const snapshot: Record<string, { value: string; checked?: boolean }> = {};
    for (const field of transportRecommendation.fields) {
      const control = form.elements.namedItem(field.name);
      if (
        !(control instanceof HTMLInputElement) &&
        !(control instanceof HTMLSelectElement) &&
        !(control instanceof HTMLTextAreaElement)
      ) {
        continue;
      }
      snapshot[field.name] = {
        value: control.value,
        ...(control instanceof HTMLInputElement &&
        ["checkbox", "radio"].includes(control.type)
          ? { checked: control.checked }
          : {}),
      };
      setRecommendedField(control, field.value);
    }
    transportParameterSnapshotRef.current = snapshot;
  }

  function restoreTransportParameters() {
    const form = formRef.current;
    const snapshot = transportParameterSnapshotRef.current;
    if (!form || !snapshot) return;
    for (const [name, previous] of Object.entries(snapshot)) {
      const control = form.elements.namedItem(name);
      if (
        !(control instanceof HTMLInputElement) &&
        !(control instanceof HTMLSelectElement) &&
        !(control instanceof HTMLTextAreaElement)
      ) {
        continue;
      }
      setRecommendedField(
        control,
        typeof previous.checked === "boolean"
          ? previous.checked
          : previous.value,
      );
    }
    transportParameterSnapshotRef.current = null;
  }

  function cloneCdnDeployment(index: number, duplicate = true) {
    setCdnDeployments((current) => {
      const source = current[index] ?? current[0] ?? {};
      const usedIds = new Set(current.map((item) => asText(item.id, "")));
      let sequence = current.length + 1;
      let id = `cdn-${sequence}`;
      while (usedIds.has(id)) {
        sequence += 1;
        id = `cdn-${sequence}`;
      }
      const clone = {
        ...source,
        id,
        display_name: duplicate
          ? tr("{value1} · копия", { value1: asText(source.display_name, "CDN") })
          : `CDN ${sequence}`,
        hostname: "",
        tls_server_name: "",
        enabled: false,
        origin_header_secret_ref: undefined,
        origin_header_value:
          asText(source.origin_protection_mode, "") === "secret-header"
            ? generateOriginHeaderSecret()
            : undefined,
      };
      return [...current.slice(0, index + 1), clone, ...current.slice(index + 1)];
    });
  }
  async function showHttpPath() {
    if (!transportId) return;
    setHttpPathBusy(true);
    setHttpPathMessage("");
    try {
      const result = await revealTransportHttpPath<JsonObject>(transportId);
      setRevealedHttpPath(asText(result.path, ""));
    } catch (error) {
      setHttpPathMessage(errorMessage(error));
    } finally {
      setHttpPathBusy(false);
    }
  }

  async function copyHttpPath() {
    if (!revealedHttpPath) return;
    try {
      await navigator.clipboard.writeText(revealedHttpPath);
      setHttpPathMessage(tr("HTTP-путь скопирован."));
    } catch {
      setHttpPathMessage(tr("Браузер запретил копирование. Выделите путь вручную."));
    }
  }

  function invalidateRealityProbe() {
    setRealityProbeTone("idle");
    setRealityProbeSignature("");
    setRealityProbeResult("");
    setRealityProbeEndpoints([]);
    setRealityProbeWildcards([]);
    setRealitySniCheckPerformed(false);
  }

  function realityProbeFacts(probe: JsonObject): JsonObject[] {
    const endpoints = asObjectList(probe.endpoint_results);
    if (endpoints.length) return endpoints;
    return asStringList(probe.addresses).map((address) => ({
      address,
      ok: true,
      tls_version: asText(probe.tls_version, ""),
      alpn: asText(probe.alpn, ""),
    }));
  }

  function realityProbeProblem(probe: JsonObject): string {
    const endpoints = realityProbeFacts(probe);
    const failed = endpoints.filter((item) => item.ok !== true);
    const incompatible = failed.filter(
      (item) => asText(item.error_code, "") !== "tls_probe_handshake_failed",
    );
    if (incompatible.length) {
      return tr("Не все доступные адреса target принимают SNI: {value1}.", { value1: incompatible.map((item) => asText(item.address, tr("неизвестный IP"))).join(", ") });
    }
    const successful = endpoints.filter((item) => item.ok === true);
    const legacyTls = successful.filter(
      (item) => asText(item.tls_version, "") !== "TLSv1.3",
    );
    if (legacyTls.length) {
      return tr("REALITY требует TLS 1.3; несовместимые адреса: {value1}.", { value1: legacyTls.map((item) => asText(item.address, tr("неизвестный IP"))).join(", ") });
    }
    if (transportKind === "reality-grpc") {
      const withoutH2 = successful.filter((item) => asText(item.alpn, "") !== "h2");
      if (withoutH2.length) {
        return tr("Для gRPC нужен HTTP/2 (ALPN h2); несовместимые адреса: {value1}.", { value1: withoutH2.map((item) => `${asText(item.address, tr("неизвестный IP"))} — ${asText(item.alpn, tr("ALPN не согласован"))}`).join(", ") });
      }
    }
    return "";
  }

  function currentRealityProbeSignature() {
    const form = formRef.current;
    if (!form) return "";
    const serverNameInput = form.elements.namedItem("server_name");
    const handshakeServerInput = form.elements.namedItem("handshake_server");
    const handshakePortInput = form.elements.namedItem("handshake_port");
    const serverName =
      serverNameInput instanceof HTMLInputElement
        ? serverNameInput.value.trim().toLowerCase()
        : "";
    const handshakeServer =
      handshakeServerInput instanceof HTMLInputElement
        ? handshakeServerInput.value.trim().toLowerCase()
        : "";
    const handshakePort =
      handshakePortInput instanceof HTMLInputElement
        ? Number(handshakePortInput.value)
        : 443;
    const names = realitySniInput.split(/[\n,]/).map((value) => value.trim().toLowerCase()).filter(Boolean).sort();
    return `${transportKind}|${serverName}|${handshakeServer}|${handshakePort}|${names.join(",")}`;
  }

  async function checkRealityTarget(): Promise<boolean> {
    const form = formRef.current;
    if (!form) return false;
    const serverNameInput = form.elements.namedItem("server_name");
    const handshakeServerInput = form.elements.namedItem("handshake_server");
    const handshakePortInput = form.elements.namedItem("handshake_port");
    const serverName =
      serverNameInput instanceof HTMLInputElement
        ? serverNameInput.value.trim()
        : "";
    const handshakeServer =
      handshakeServerInput instanceof HTMLInputElement
        ? handshakeServerInput.value.trim()
        : "";
    const handshakePort =
      handshakePortInput instanceof HTMLInputElement
        ? Number(handshakePortInput.value)
        : 443;
    if (!serverName || !handshakeServer) {
      setRealityProbeResult(tr("Укажите SNI и сервер рукопожатия."));
      setRealityProbeTone("error");
      setRealityProbeSignature("");
      return false;
    }
    const manualNames = realitySniInput
      .split(/[\n,]/)
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    const wildcardNames = manualNames.filter((value) => value.includes("*"));
    if (wildcardNames.length) {
      setRealityProbeResult(
        tr("Wildcard SAN нельзя сохранять напрямую: {value1}. Укажите конкретное имя хоста и проверьте его отдельно.", { value1: wildcardNames.join(", ") }),
      );
      setRealityProbeTone("error");
      setRealityProbeSignature(currentRealityProbeSignature());
      setRealityProbeEndpoints([]);
      setRealityProbeWildcards(wildcardNames);
      setRealitySniCheckPerformed(false);
      return false;
    }
    setRealityProbeBusy(true);
    setRealityProbeResult("");
    setRealityProbeTone("idle");
    setRealityProbeEndpoints([]);
    setRealityProbeWildcards([]);
    setRealitySniCheckPerformed(false);
    try {
      const probe = await probeTlsEndpoint<JsonObject>(
        handshakeServer,
        handshakePort,
        serverName,
        true,
      );
      const endpoints = realityProbeFacts(probe);
      setRealityProbeEndpoints(endpoints);
      const certificateNames = asStringList(probe.certificate_dns_names);
      const wildcardNames = certificateNames.filter((name) => name.includes("*"));
      setRealityProbeWildcards(wildcardNames);
      const mainProblem = realityProbeProblem(probe);
      if (mainProblem) {
        setRealityProbeTone("error");
        setRealityProbeSignature(currentRealityProbeSignature());
        setRealityProbeResult(mainProblem);
        return false;
      }
      const candidates = [...new Set([
        ...manualNames,
        ...certificateNames
          .map((value) => value.trim().toLowerCase())
          .filter((value) => value && !value.includes("*")),
      ])].filter((value) => value !== serverName.toLowerCase());
      const checks = await Promise.all(
        candidates.map(async (candidate) => {
          try {
            const candidateProbe = await probeTlsEndpoint<JsonObject>(
              handshakeServer,
              handshakePort,
              candidate,
              true,
            );
            const candidateProblem = realityProbeProblem(candidateProbe);
            if (candidateProblem) {
              return {
                name: candidate,
                status: "rejected" as const,
                detail: candidateProblem,
              };
            }
            return {
              name: candidate,
              status: "confirmed" as const,
              detail: `${asText(candidateProbe.tls_version, "TLS")} · ALPN ${asText(candidateProbe.alpn, tr("не согласован"))}`,
            };
          } catch (error) {
            const code = error instanceof GatewayApiError ? error.code : "";
            if (code === "tls_probe_certificate_mismatch") {
              return {
                name: candidate,
                status: "certificate" as const,
                detail: tr("Сертификат не подходит"),
              };
            }
            if (code === "tls_probe_sni_rejected" || code === "tls_probe_handshake_failed") {
              return {
                name: candidate,
                status: "rejected" as const,
                detail: tr("Target отклонил SNI"),
              };
            }
            return {
              name: candidate,
              status: "failed" as const,
              detail: errorMessage(error),
            };
          }
        }),
      );
      const confirmed = new Set(
        checks.filter((item) => item.status === "confirmed").map((item) => item.name),
      );
      setRealitySniChecks(checks);
      setSelectedRealitySnis((current) =>
        current.filter((name) => confirmed.has(name.toLowerCase())),
      );
      setRealitySniCheckPerformed(true);
      const successfulEndpoints = endpoints.filter((item) => item.ok === true);
      const unavailableEndpoints = endpoints.filter(
        (item) =>
          item.ok !== true &&
          asText(item.error_code, "") === "tls_probe_handshake_failed",
      );
      const nonH2 = successfulEndpoints.filter((item) => asText(item.alpn, "") !== "h2");
      const warnings: string[] = [];
      if (unavailableEndpoints.length) {
        warnings.push(
          tr("Часть DNS-адресов недоступна из контейнера ({value1}); успешный TLS через доступные адреса подтверждён.", { value1: unavailableEndpoints.map((item) => asText(item.address, tr("неизвестный IP"))).join(", ") }),
        );
      }
      if (transportKind === "reality" && nonH2.length > 0) {
        warnings.push(tr("Не все доступные адреса согласуют HTTP/2. Для Vision это допустимо; для gRPC такой target использовать нельзя."));
      }
      const warning = warnings.length > 0;
      setRealityProbeTone(warning ? "warning" : "success");
      setRealityProbeSignature(currentRealityProbeSignature());
      setRealityProbeResult(
        warning
          ? tr("SNI и target совместимы. {value1}", { value1: warnings.join(" ") })
          : tr("SNI и target совместимы с {value1}. Успешно проверено адресов: {value2}. Сертификат: {value3}.", { value1: transportKind === "reality-grpc" ? "gRPC + Reality" : transportKind === "xhttp-reality" ? "XHTTP + Reality" : "VLESS Reality", value2: successfulEndpoints.length, value3: expiryText(probe.certificate_expires_at) }),
      );
      return true;
    } catch (error) {
      setRealityProbeResult(prefixedErrorMessage(error));
      setRealityProbeTone("error");
      setRealityProbeSignature(currentRealityProbeSignature());
      setRealityProbeEndpoints([]);
      return false;
    } finally {
      setRealityProbeBusy(false);
    }
  }

  async function checkCdnDeployment(deploymentIndex: number) {
    const deployment = cdnDeployments[deploymentIndex] ?? {};
    const deploymentId = asText(
      deployment.id,
      `cdn-${deploymentIndex + 1}`,
    );
    const publicHostname = asText(deployment.hostname, "").trim();
    const publicPort = Number(deployment.listen_port ?? 443);
    const publicServerName =
      asText(deployment.tls_server_name, "").trim() || publicHostname;
    const originHostname = asText(deployment.origin_server_name, "").trim();
    const originPort = Number(
      deployment.origin_port ??
        existingTransport.origin_port ??
        existingTransport.listen_port ??
        legacyCloudflarePort,
    );
    if (!publicHostname || !originHostname) {
      setCdnProbeResults((current) => ({
        ...current,
        [deploymentId]: tr("Укажите домен раздачи CDN и DNS-имя origin."),
      }));
      return;
    }
    setCdnProbeBusyId(deploymentId);
    setCdnProbeResults((current) => ({ ...current, [deploymentId]: "" }));
    try {
      const publicProbe = await probeTlsEndpoint<JsonObject>(
        publicHostname,
        publicPort,
        publicServerName,
      );
      const originProbe = await probeTlsEndpoint<JsonObject>(
        originHostname,
        originPort,
        originHostname,
      );
      setCdnProbeResults((current) => ({
        ...current,
        [deploymentId]:
          tr("Домен CDN: {value1} · {value2} · {value3} | ", { value1: asStringList(publicProbe.addresses).join(", "), value2: asText(publicProbe.tls_version, "TLS"), value3: expiryText(publicProbe.certificate_expires_at) }) +
          `origin: ${asStringList(originProbe.addresses).join(", ")} · ${asText(originProbe.tls_version, "TLS")} · ${expiryText(originProbe.certificate_expires_at)} ` +
          "Proxy/CDN, Full strict и правила origin проверяются в аккаунте провайдера.",
      }));
    } catch (error) {
      setCdnProbeResults((current) => ({
        ...current,
        [deploymentId]: prefixedErrorMessage(error),
      }));
    } finally {
      setCdnProbeBusyId("");
    }
  }
  function selectCdnDeploymentTlsProfile(index: number, profileId: string) {
    const profile = tlsProfiles.find(
      (item) => asText(item.id, "") === profileId,
    );
    setCdnDeployments((current) =>
      current.map((deployment, deploymentIndex) =>
        deploymentIndex === index
          ? cdnDeploymentAfterTLSProfileChange(
              deployment,
              profileId,
              profile,
            )
          : deployment,
      ),
    );
  }
  const tlsManagedKind = [
    "ws",
    "grpc",
    "httpupgrade",
    "xhttp",
    "grpc-tls",
    "hysteria2",
  ].includes(transportKind);
  const cdnTransportKind = [
    "ws",
    "grpc",
    "httpupgrade",
    "xhttp",
  ].includes(transportKind);
  const realityKind = ["reality", "reality-grpc", "xhttp-reality"].includes(
    transportKind,
  );
  const realityAPICoverProfiles = realityKind
    ? tlsProfiles.filter((profile) =>
        certificateCoversHostname(profile, realityServerName),
      )
    : [];
  const realityAPICoverAvailable = realityAPICoverProfiles.length > 0;
  const effectiveRealityCoverMode =
    realityCoverMode === "api" && realityAPICoverAvailable ? "api" : "external";
  const sharedTlsManagedKind =
    (tlsManagedKind && !cdnTransportKind) ||
    (realityKind && effectiveRealityCoverMode === "api");
  const xhttpKind = ["xhttp", "xhttp-reality"].includes(transportKind);
  const tcpStabilityKind = realityKind || ["grpc", "grpc-tls"].includes(transportKind);
  const legacyCloudflarePort = Number(
    asObject(config.ingress).public_listen_port ?? 443,
  );
  const persistedDirectTlsServerName = asText(
    existingTransport.tls_server_name,
    asText(existingTransport.hostname, ""),
  );
  const savedTlsProfileId = asText(existingTransport.tls_profile_id, "");
  const initialTlsProfileId = savedTlsProfileId ||
    (["hysteria2", "grpc-tls"].includes(transportKind)
      ? tlsProfileIdForHostname(tlsProfiles, persistedDirectTlsServerName, "")
      : "");
  const [tlsProfileChoice, setTlsProfileChoice] = useState(
    initialTlsProfileId,
  );
  const selectedTlsProfile =
    tlsProfiles.find(
      (profile) => asText(profile.id, "") === tlsProfileChoice,
    ) ?? {};
  const [directTlsServerName, setDirectTlsServerName] = useState(() =>
    hostnameForTLSProfileInitialization(
      selectedTlsProfile,
      persistedDirectTlsServerName,
      ["hysteria2", "grpc-tls"].includes(transportKind),
    ),
  );
  const directTlsHostnameCandidates = tlsConcreteHostnames(selectedTlsProfile);
  function selectTransportTlsProfile(profileId: string) {
    setTlsProfileChoice(profileId);
    if (!["hysteria2", "grpc-tls"].includes(transportKind)) return;
    const profile =
      tlsProfiles.find((item) => asText(item.id, "") === profileId) ?? {};
    setDirectTlsServerName((current) =>
      hostnameAfterTLSProfileChange(profile, current),
    );
  }
  const existingSubscription =
    asObjectList(config.subscriptions).find(
      (item) => asText(item.id, "") === workingSubscriptionId,
    ) ?? persistedSubscription;
  const configuredSubscriptionReserves = asObjectList(
    config.subscription_reserves,
  ).filter((item) => item.enabled !== false);
  const editingSubscription = Boolean(
    kind === "subscription" && workingSubscriptionId,
  );
  const [refreshViaDirect, setRefreshViaDirect] = useState(
    existingSubscription.refresh_via_direct !== false,
  );
  const [refreshViaVpn, setRefreshViaVpn] = useState(
    existingSubscription.refresh_via_vpn !== false,
  );
  const [refreshViaActiveOutbounds, setRefreshViaActiveOutbounds] = useState(
    existingSubscription.refresh_via_active_outbounds !== false,
  );
  const [refreshViaIndependentReserves, setRefreshViaIndependentReserves] =
    useState(existingSubscription.refresh_via_independent_reserves === true);
  const configuredRefreshMinutes = Math.max(
    1,
    Number(
      existingSubscription.refresh_minutes ??
        Number(existingSubscription.refresh_hours ?? 6) * 60,
    ),
  );
  const defaultRefreshUnit =
    configuredRefreshMinutes % 60 === 0 ? "hours" : "minutes";
  const defaultRefreshValue =
    defaultRefreshUnit === "hours"
      ? configuredRefreshMinutes / 60
      : configuredRefreshMinutes;
  const existingSecretRefs = asObject(existingTransport.secret_refs);
  const selectedTlsProfileComplete = Boolean(
    asText(selectedTlsProfile.certificate_secret_ref, "") &&
      asText(selectedTlsProfile.private_key_secret_ref, ""),
  );

  function subscriptionItemFromForm(data: FormData): JsonObject {
    const displayName = String(data.get("display_name") ?? "").trim();
    const id =
      workingSubscriptionId ||
      entityIdFromName(
        displayName,
        new Set(
          asObjectList(config.subscriptions).map((item) => asText(item.id, "")),
        ),
        "provider",
      );
    if (!id || !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(id)) {
      throw new Error(
        tr("Идентификатор должен состоять из строчных латинских букв, цифр, точки, дефиса или подчёркивания."),
      );
    }
    const url = String(data.get("url") ?? "").trim();
    if (!workingSubscriptionId && !url) {
      throw new Error(tr("Введите HTTPS URL подписки."));
    }
    if (url && !url.startsWith("https://")) {
      throw new Error(tr("Подписка должна использовать HTTPS."));
    }
    const intervalValue = Number(data.get("refresh_value") ?? 6);
    const intervalUnit = String(data.get("refresh_unit") ?? "hours");
    const refreshMinutes =
      intervalUnit === "minutes" ? intervalValue : intervalValue * 60;
    if (
      !Number.isInteger(refreshMinutes) ||
      refreshMinutes < 1 ||
      refreshMinutes > 7 * 24 * 60
    ) {
      throw new Error(tr("Интервал проверки должен быть от 1 минуты до 7 суток."));
    }
    const vpnRouteReady =
      refreshViaVpn &&
      (refreshViaActiveOutbounds || refreshViaIndependentReserves);
    if (!refreshViaDirect && !vpnRouteReady) {
      throw new Error(
        tr("Оставьте хотя бы один путь обновления: прямой WAN или VPN-резерв."),
      );
    }
    if (
      !refreshViaDirect &&
      refreshViaVpn &&
      !refreshViaActiveOutbounds &&
      refreshViaIndependentReserves &&
      configuredSubscriptionReserves.length === 0
    ) {
      throw new Error(
        tr("Добавьте хотя бы один независимый резервный VLESS или включите рабочие VPN-каналы."),
      );
    }
    return {
      ...existingSubscription,
      ...persistedSubscription,
      id,
      display_name: displayName,
      ...(url ? { url } : {}),
      refresh_hours: undefined,
      refresh_minutes: refreshMinutes,
      // Location selection belongs to routing lists.  Keeping subscription
      // filters empty makes the complete provider catalogue available to
      // every independently configured list.
      allowed_countries: [],
      allowed_locations: [],
      enabled: data.get("enabled") === "on",
      refresh_via_direct: refreshViaDirect,
      refresh_via_vpn: refreshViaVpn,
      refresh_via_active_outbounds: refreshViaActiveOutbounds,
      refresh_via_independent_reserves: refreshViaIndependentReserves,
    };
  }

  async function persistAndDiscover(data: FormData) {
    const item = subscriptionItemFromForm(data);
    const id = asText(item.id, "");
    const savedItem = workingSubscriptionId
      ? await updateCollectionItem<JsonObject>(
          "subscriptions",
          workingSubscriptionId,
          item,
        )
      : await createCollectionItem<JsonObject>("subscriptions", item);
    const persisted = asObject(savedItem.item);
    const safeItem = { ...item };
    delete safeItem.url;
    setWorkingSubscriptionId(id);
    setPersistedSubscription({ ...safeItem, ...persisted, id });
    await onSaved();
    setDiscoveryMessage(tr("Подписка сохранена. Загружаю страны и города…"));
    const refreshed = await refreshSubscription<JsonObject>(id);
    const response = await getSubscriptionNodes<JsonObject>(id);
    const rows = asObjectList(response.nodes);
    const provider = asObject(response.provider);
    setSubscriptionNodes(rows);
    setSubscriptionProvider(provider);
    setDiscoveryReady(true);
    const refreshedNodeCount =
      typeof refreshed.nodes === "number" ? refreshed.nodes : rows.length;
    setDiscoveryMessage(
      tr("{value1} узл. загружено. Расположения доступны в маршрутных листах.", { value1: refreshedNodeCount }),
    );
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedForm = event.currentTarget;
    if (kind === "transport" && directPortConflict) {
      setSaveError(
        tr("Этот WAN IP и {value1}-порт уже использует «{value2}».", { value1: directInboundProtocol, value2: transportKindLabel(directPortConflict.kind) }),
      );
      return;
    }
    if (kind === "transport" && realityKind && effectiveRealityCoverMode !== "api") {
      const signature = currentRealityProbeSignature();
      const savedSignature = `${transportKind}|${asText(existingTransport.server_name, "").trim().toLowerCase()}|${asText(existingTransport.handshake_server, "").trim().toLowerCase()}|${Number(existingTransport.handshake_port ?? 443)}|${[...savedRealityServerNames].sort().join(",")}`;
      const savedTargetUnchanged = existingTransport.enabled === true &&
        existingTransport.kind === transportKind && signature === savedSignature;
      const currentProbeAccepted =
        signature === realityProbeSignature &&
        ["success", "warning"].includes(realityProbeTone);
      if (!savedTargetUnchanged && !currentProbeAccepted) {
        const compatible = await checkRealityTarget();
        if (!compatible) {
          setSaveError(
            tr("Сохранение остановлено: исправьте SNI или target и повторите проверку."),
          );
          return;
        }
      }
    }
    setBusy(true);
    setSaveError("");
    const data = new FormData(submittedForm);
    try {
      if (kind === "subscription") {
        if (!discoveryReady) {
          await persistAndDiscover(data);
        } else {
          const item = subscriptionItemFromForm(data);
          await updateCollectionItem(
            "subscriptions",
            workingSubscriptionId,
            item,
          );
          await onSaved();
          setSaved(true);
        }
      } else {
        const id = transportId ?? "websocket";
        let tlsProfileId = "";
        if (sharedTlsManagedKind) {
          tlsProfileId = tlsProfileChoice;
          if (!tlsProfileId) {
            throw new Error(tr("Выберите TLS-профиль в форме транспорта."));
          }
        }
        const parseHttpHeaders = (fieldName: string, label: string): Record<string, string> => {
          const parsed: Record<string, string> = {};
          for (const rawLine of String(data.get(fieldName) ?? "").split("\n")) {
            const line = rawLine.trim();
            if (!line) continue;
            const separator = line.indexOf(":");
            if (separator <= 0) {
              throw new Error(tr("Каждый {value1}-заголовок задаётся как «Имя: значение».", { value1: label }));
            }
            const name = line.slice(0, separator).trim();
            const value = line.slice(separator + 1).trim();
            if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || !value) {
              throw new Error(tr("Некорректный {value1}-заголовок: {value2}", { value1: label, value2: line }));
            }
            parsed[name] = value;
          }
          return parsed;
        };
        const xhttpHeaders: Record<string, string> = {};
        const clientHttpHeaders = ["ws", "httpupgrade"].includes(transportKind)
          ? parseHttpHeaders("client_http_headers", "HTTP")
          : {};
        let xhttpDownloadSettings: JsonObject | undefined;
        if (xhttpKind) {
          Object.assign(xhttpHeaders, parseHttpHeaders("xhttp_headers", "XHTTP"));
          const rawDownloadSettings = String(
            data.get("download_settings_json") ?? "",
          ).trim();
          if (rawDownloadSettings) {
            const parsed = JSON.parse(rawDownloadSettings) as unknown;
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
              throw new Error(tr("downloadSettings должен быть JSON-объектом Xray StreamConfig."));
            }
            xhttpDownloadSettings = parsed as JsonObject;
          }
        }
        const submittedXHTTPMode = String(data.get("mode") ?? xhttpMode);
        const submittedXHTTPUplinkMethod = String(
          data.get("uplink_http_method") ?? xhttpUplinkMethod,
        ).toUpperCase();
        const submittedXHTTPUplinkPlacement = String(
          data.get("uplink_data_placement") ?? xhttpUplinkPlacement,
        );
        const submittedHysteriaMasqueradeType = String(
          data.get("hysteria_masquerade_type") ?? hysteriaMasqueradeType,
        );
        const submittedHysteriaCongestion = String(
          data.get("hysteria_congestion") ?? hysteriaCongestion,
        );
        const submittedHysteriaUDPHopEnabled =
          data.get("hysteria_udp_hop_enabled") === "on";
        let xrayHysteria: JsonObject | undefined;
        if (transportKind === "hysteria2") {
          const masqueradeHeaders: Record<string, string> = {};
          if (submittedHysteriaMasqueradeType === "string") {
            for (const rawLine of String(
              data.get("hysteria_masquerade_headers") ?? "",
            ).split("\n")) {
              const line = rawLine.trim();
              if (!line) continue;
              const separator = line.indexOf(":");
              if (separator <= 0) {
                throw new Error(
                  tr("Каждый заголовок ответа Hysteria задаётся как «Имя: значение»."),
                );
              }
              const name = line.slice(0, separator).trim();
              const value = line.slice(separator + 1).trim();
              if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || !value) {
                throw new Error(tr("Некорректный заголовок Hysteria: {value1}", { value1: line }));
              }
              masqueradeHeaders[name] = value;
            }
          }
          const optionalInteger = (name: string): number => {
            const raw = String(data.get(name) ?? "").trim();
            return raw ? Number(raw) : 0;
          };
          const websiteBandwidth = Number(
            String(data.get("hysteria_masquerade_bandwidth_mbps") ?? "").trim(),
          );
          if (
            submittedHysteriaMasqueradeType === "website" &&
            (!Number.isFinite(websiteBandwidth) ||
              websiteBandwidth < 0.1 ||
              websiteBandwidth > 100)
          ) {
            throw new Error(tr("Лимит сайта должен быть числом от 0.1 до 100 Мбит/с."));
          }
          xrayHysteria = {
            udp_idle_timeout: Number(data.get("hysteria_udp_idle_timeout") ?? 60),
            ...(submittedHysteriaUDPHopEnabled
              ? {
                  udp_hop: {
                    enabled: true,
                    port_start: Number(data.get("hysteria_udp_hop_port_start")),
                    port_end: Number(data.get("hysteria_udp_hop_port_end")),
                    interval_min: Number(data.get("hysteria_udp_hop_interval_min")),
                    interval_max: Number(data.get("hysteria_udp_hop_interval_max")),
                    excluded_ports: String(data.get("hysteria_udp_hop_excluded_ports") ?? "").trim(),
                  },
                }
              : {}),
            masquerade:
              submittedHysteriaMasqueradeType === "string"
                ? {
                    type: "string",
                    content: String(data.get("hysteria_masquerade_content") ?? ""),
                    status_code: Number(
                      data.get("hysteria_masquerade_status_code") ?? 200,
                    ),
                    headers: masqueradeHeaders,
                  }
                  : submittedHysteriaMasqueradeType === "api"
                    ? { type: "api" }
                  : submittedHysteriaMasqueradeType === "proxy" ||
                    submittedHysteriaMasqueradeType === "website"
                    ? {
                        type: submittedHysteriaMasqueradeType,
                        url: String(data.get("hysteria_masquerade_url") ?? "").trim(),
                        ...(submittedHysteriaMasqueradeType === "website"
                          ? { bandwidth_mbps: websiteBandwidth }
                          : {}),
                        rewrite_host:
                          data.get("hysteria_masquerade_rewrite_host") === "on",
                        ...(submittedHysteriaMasqueradeType === "proxy" &&
                        data.get("hysteria_masquerade_x_forwarded") === "on"
                          ? { x_forwarded: true }
                          : {}),
                    }
                  : { type: "" },
            quic_params: {
              congestion: submittedHysteriaCongestion,
              brutal_up_mbps: optionalInteger("hysteria_brutal_up_mbps"),
              brutal_down_mbps: optionalInteger("hysteria_brutal_down_mbps"),
              init_stream_receive_window: optionalInteger(
                "hysteria_init_stream_receive_window",
              ),
              max_stream_receive_window: optionalInteger(
                "hysteria_max_stream_receive_window",
              ),
              init_connection_receive_window: optionalInteger(
                "hysteria_init_connection_receive_window",
              ),
              max_connection_receive_window: optionalInteger(
                "hysteria_max_connection_receive_window",
              ),
              max_idle_timeout: optionalInteger("hysteria_max_idle_timeout"),
              keep_alive_period: optionalInteger("hysteria_keep_alive_period"),
              max_incoming_streams: optionalInteger(
                "hysteria_max_incoming_streams",
              ),
              disable_path_mtu_discovery:
                data.get("hysteria_disable_path_mtu_discovery") === "on",
              ...(submittedHysteriaCongestion === "brutal" &&
              data.get("hysteria_brutal_disable_loss_compensation") === "on"
                ? { brutal_disable_loss_compensation: true }
                : {}),
              ...(data.get("hysteria_disable_gso") === "on"
                ? { disable_gso: true }
                : {}),
              ...(data.get("hysteria_disable_stateless_reset") === "on"
                ? { disable_stateless_reset: true }
                : {}),
            },
          };
        }
        const normalizedCdnDeployments = cdnTransportKind
          ? cdnDeployments.map((deployment, deploymentIndex) => ({
              id: asText(deployment.id, `cdn-${deploymentIndex + 1}`)
                .trim()
                .toLowerCase(),
              display_name: asText(
                deployment.display_name,
                `CDN ${deploymentIndex + 1}`,
              ).trim(),
              enabled: deployment.enabled !== false,
              cdn_provider: asText(deployment.cdn_provider, "cloudflare"),
              hostname: asText(deployment.hostname, "").trim(),
              listen_port: Number(deployment.listen_port ?? 443),
              tls_server_name: asText(
                deployment.tls_server_name,
                asText(deployment.hostname, ""),
              ).trim(),
              http_host: asText(deployment.http_host, "").trim(),
              grpc_authority: asText(deployment.grpc_authority, "").trim(),
              origin_port: Number(
                deployment.origin_port ??
                  existingTransport.origin_port ??
                  existingTransport.listen_port ??
                  legacyCloudflarePort,
              ),
              origin_server_name: asText(
                deployment.origin_server_name,
                asText(existingTransport.origin_server_name, ""),
              ).trim(),
              tls_profile_id: asText(
                deployment.tls_profile_id,
                asText(existingTransport.tls_profile_id, ""),
              ),
              origin_allowed_cidrs: asStringList(
                deployment.origin_allowed_cidrs,
              ),
              origin_protection_mode: asText(
                deployment.origin_protection_mode,
                asText(deployment.cdn_provider, "cloudflare") === "cloudflare"
                  ? "auto-cidr"
                  : "secret-header",
              ),
              origin_header_name: asText(
                deployment.origin_header_name,
                "X-SB-Origin",
              ),
              origin_header_secret_ref: asText(
                deployment.origin_header_secret_ref,
                "",
              ) || undefined,
              origin_header_value: asText(
                deployment.origin_header_value,
                "",
              ) || undefined,
            }))
          : [];
        const primaryCdnDeployment =
          normalizedCdnDeployments.find((deployment) => deployment.enabled) ??
          normalizedCdnDeployments[0];
        const backend =
          id === "grpc"
            ? "127.0.0.1:11002"
            : id === "httpupgrade"
              ? "127.0.0.1:11003"
              : id === "xhttp"
                ? "127.0.0.1:11004"
              : ["direct-reality", "grpc-reality", "grpc-tls-pin", "xhttp-reality", "hysteria2"].includes(id)
                ? undefined
                : "127.0.0.1:11001";
        await updateCollectionItem("transports", id, {
          ...existingTransport,
          wan_destination_address: undefined,
          id,
          kind: transportKind,
          cdn_deployments: cdnTransportKind
            ? normalizedCdnDeployments
            : undefined,
          cdn_provider: cdnTransportKind
            ? asText(primaryCdnDeployment?.cdn_provider, "cloudflare")
            : undefined,
          tls_profile_id: tlsManagedKind
            ? cdnTransportKind
              ? asText(primaryCdnDeployment?.tls_profile_id, "")
              : tlsProfileId
            : realityKind && effectiveRealityCoverMode === "api"
              ? tlsProfileId
              : undefined,
          enabled: data.get("enabled") === "on",
          recommended: existingTransport.recommended === true,
          hostname: cdnTransportKind
            ? asText(primaryCdnDeployment?.hostname, "")
            : directInboundKind ? manualHostname : String(data.get("hostname") ?? ""),
          hostname_mode: directInboundKind ? hostnameMode : undefined,
          backend,
          listen_port:
            cdnTransportKind
              ? Number(primaryCdnDeployment?.listen_port ?? legacyCloudflarePort)
              : ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(transportKind)
              ? Number(
                  data.get("listen_port") ??
                    (transportKind === "reality" ? 2443 : transportKind === "reality-grpc" ? 2444 : transportKind === "grpc-tls" ? 2445 : transportKind === "xhttp-reality" ? 2446 : 443),
                )
                : undefined,
          origin_port: cdnTransportKind
            ? Number(primaryCdnDeployment?.origin_port ?? legacyCloudflarePort)
            : undefined,
          origin_server_name: cdnTransportKind
            ? asText(primaryCdnDeployment?.origin_server_name, "")
            : undefined,
          origin_allowed_cidrs:
            cdnTransportKind
              ? normalizedCdnDeployments.flatMap((deployment) =>
                  asStringList(deployment.origin_allowed_cidrs),
                )
              : [],
          handshake_server:
            realityKind
              ? String(data.get("handshake_server") ?? "")
              : undefined,
          handshake_port:
            realityKind
              ? Number(data.get("handshake_port") ?? 443)
              : undefined,
          server_name:
            realityKind
              ? String(data.get("server_name") ?? "")
              : undefined,
          cover_mode: realityKind ? effectiveRealityCoverMode : undefined,
          fingerprint:
            undefined,
          up_mbps:
            undefined,
          down_mbps:
            undefined,
          ignore_client_bandwidth:
            undefined,
          xray_hysteria:
            transportKind === "hysteria2" ? xrayHysteria : undefined,
          obfs_enabled:
            transportKind === "hysteria2"
              ? data.get("obfs_enabled") === "on"
              : undefined,
          tls_server_name:
            ["hysteria2", "grpc-tls"].includes(transportKind)
              ? String(data.get("tls_server_name") ?? "").trim()
              : undefined,
          tls_pin_certificate:
            transportKind === "hysteria2"
              ? data.get("tls_pin_certificate") === "on"
              : undefined,
          tcp_keep_alive_enabled: tcpStabilityKind
            ? data.get("tcp_keep_alive_enabled") === "on"
            : undefined,
          tcp_keep_alive_idle: tcpStabilityKind
            ? Number(data.get("tcp_keep_alive_idle") ?? 30)
            : undefined,
          tcp_keep_alive_interval: tcpStabilityKind
            ? Number(data.get("tcp_keep_alive_interval") ?? 10)
            : undefined,
          tcp_user_timeout: tcpStabilityKind
            ? Number(data.get("tcp_user_timeout") ?? 60000)
            : undefined,
          client_http_headers: ["ws", "httpupgrade"].includes(transportKind)
            ? clientHttpHeaders
            : undefined,
          early_data: ["ws", "httpupgrade"].includes(transportKind)
            ? Number(data.get("early_data") ?? 0)
            : undefined,
          ws_heartbeat_period: transportKind === "ws"
            ? Number(data.get("ws_heartbeat_period") ?? 0)
            : undefined,
          grpc_multi_mode: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? data.get("grpc_multi_mode") === "on"
            : undefined,
          grpc_user_agent: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? String(data.get("grpc_user_agent") ?? "").trim()
            : undefined,
          grpc_idle_timeout: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? Number(data.get("grpc_idle_timeout") ?? grpcIdleTimeoutDefault)
            : undefined,
          grpc_health_check_timeout: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? Number(data.get("grpc_health_check_timeout") ?? 20)
            : undefined,
          grpc_permit_without_stream: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? data.get("grpc_permit_without_stream") === "on"
            : undefined,
          grpc_initial_windows_size: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? Number(data.get("grpc_initial_windows_size") ?? 0)
            : undefined,
          mode:
            xhttpKind
              ? submittedXHTTPMode
              : undefined,
          x_padding_bytes:
            xhttpKind
              ? String(data.get("x_padding_bytes") ?? "100-1000")
              : undefined,
          vless_encryption_enabled: xhttpKind
            ? data.get("vless_encryption_enabled") === "on"
            : undefined,
          vless_encryption_authentication: xhttpKind
            ? String(data.get("vless_encryption_authentication") ?? "mlkem768")
            : undefined,
          x_padding_obfs_mode: xhttpKind
            ? data.get("x_padding_obfs_mode") === "on"
            : undefined,
          x_padding_placement: xhttpKind
            ? String(data.get("x_padding_placement") ?? "query")
            : undefined,
          x_padding_key: xhttpKind
            ? String(data.get("x_padding_key") ?? "_v").trim()
            : undefined,
          x_padding_header: xhttpKind
            ? String(data.get("x_padding_header") ?? "X-Padding").trim()
            : undefined,
          x_padding_method: xhttpKind
            ? String(data.get("x_padding_method") ?? "tokenish")
            : undefined,
          uplink_http_method: xhttpKind
            ? submittedXHTTPMode !== "packet-up" && submittedXHTTPUplinkMethod === "GET"
              ? "POST"
              : submittedXHTTPUplinkMethod
            : undefined,
          uplink_data_placement: xhttpKind
            ? submittedXHTTPMode !== "packet-up" && ["header", "cookie"].includes(submittedXHTTPUplinkPlacement)
              ? "auto"
              : submittedXHTTPUplinkPlacement
            : undefined,
          uplink_data_key: xhttpKind
            ? String(data.get("uplink_data_key") ?? "X-Data").trim()
            : undefined,
          uplink_chunk_size: xhttpKind
            ? String(data.get("uplink_chunk_size") ?? "2048-3072").trim()
            : undefined,
          session_id_placement: xhttpKind
            ? String(data.get("session_id_placement") ?? "cookie")
            : undefined,
          session_id_key: xhttpKind
            ? String(data.get("session_id_key") ?? "_sid").trim()
            : undefined,
          session_id_table: xhttpKind
            ? String(data.get("session_id_table") ?? "").trim()
            : undefined,
          session_id_length:
            xhttpKind && String(data.get("session_id_length") ?? "").trim()
              ? Number(data.get("session_id_length"))
              : undefined,
          seq_placement: xhttpKind
            ? String(data.get("seq_placement") ?? "query")
            : undefined,
          seq_key: xhttpKind
            ? String(data.get("seq_key") ?? "_seq").trim()
            : undefined,
          server_max_header_bytes: xhttpKind
            ? Number(data.get("server_max_header_bytes") ?? 16384)
            : undefined,
          no_grpc_header: xhttpKind
            ? data.get("no_grpc_header") === "on"
            : undefined,
          no_sse_header: xhttpKind
            ? data.get("no_sse_header") === "on"
            : undefined,
          sc_max_each_post_bytes: xhttpKind
            ? String(data.get("sc_max_each_post_bytes") ?? "").trim()
            : undefined,
          sc_min_posts_interval_ms: xhttpKind
            ? String(data.get("sc_min_posts_interval_ms") ?? "").trim()
            : undefined,
          sc_max_buffered_posts:
            xhttpKind && String(data.get("sc_max_buffered_posts") ?? "").trim()
              ? Number(data.get("sc_max_buffered_posts"))
              : undefined,
          sc_stream_up_server_secs: xhttpKind
            ? String(data.get("sc_stream_up_server_secs") ?? "").trim()
            : undefined,
          headers: xhttpKind ? xhttpHeaders : undefined,
          download_settings: xhttpKind ? xhttpDownloadSettings : undefined,
          xmux_max_connections: xhttpKind
            ? String(data.get("xmux_max_connections") ?? "").trim()
            : undefined,
          xmux_max_concurrency: xhttpKind
            ? String(data.get("xmux_max_concurrency") ?? "").trim()
            : undefined,
          xmux_h_max_request_times: xhttpKind
            ? String(data.get("xmux_h_max_request_times") ?? "").trim()
            : undefined,
          xmux_h_max_reusable_secs: xhttpKind
            ? String(data.get("xmux_h_max_reusable_secs") ?? "").trim()
            : undefined,
          xmux_c_max_reuse_times: xhttpKind
            ? String(data.get("xmux_c_max_reuse_times") ?? "").trim()
            : undefined,
          xmux_h_keep_alive_period: xhttpKind
            ? String(data.get("xmux_h_keep_alive_period") ?? "").trim()
            : undefined,
          server_names: realityKind
            ? String(data.get("server_names") ?? "")
                .split(/[\n,]/)
                .map((value) => value.trim())
                .filter(Boolean)
            : undefined,
          min_client_ver: realityKind
            ? String(data.get("min_client_ver") ?? "").trim()
            : undefined,
          max_client_ver: realityKind
            ? String(data.get("max_client_ver") ?? "").trim()
            : undefined,
          max_time_diff: realityKind
            ? Number(data.get("max_time_diff") ?? 0)
            : undefined,
          xver: realityKind ? Number(data.get("xver") ?? 0) : undefined,
          reality_show: realityKind
            ? data.get("reality_show") === "on"
            : undefined,
          reality_fallback_upload_after_bytes: realityKind
            ? Number(data.get("reality_fallback_upload_after_bytes") ?? 0)
            : undefined,
          reality_fallback_upload_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_upload_bytes_per_sec") ?? 0)
            : undefined,
          reality_fallback_upload_burst_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_upload_burst_bytes_per_sec") ?? 0)
            : undefined,
          reality_fallback_download_after_bytes: realityKind
            ? Number(data.get("reality_fallback_download_after_bytes") ?? 0)
            : undefined,
          reality_fallback_download_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_download_bytes_per_sec") ?? 0)
            : undefined,
          reality_fallback_download_burst_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_download_burst_bytes_per_sec") ?? 0)
            : undefined,
          spider_x: realityKind
            ? String(data.get("spider_x") ?? "").trim()
            : undefined,
          reality_mldsa65_enabled: realityKind
            ? data.get("reality_mldsa65_enabled") === "on"
            : undefined,
          require_public_address: ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(transportKind),
          grpc_service_name:
            ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind) &&
            String(data.get("grpc_service_name") ?? "").trim()
              ? String(data.get("grpc_service_name") ?? "").trim()
              : undefined,
          generate_http_path:
            ["ws", "httpupgrade", "xhttp", "xhttp-reality"].includes(transportKind) &&
            (!existingTransport.path_secret_ref || data.get("regenerate_http_path") === "on"),
          generate_grpc_service_name:
            ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind) &&
            (!existingTransport.service_name_secret_ref || data.get("regenerate_grpc_service_name") === "on"),
          generate_reality_keys:
            realityKind &&
            (!existingSecretRefs.reality_private_key ||
              !existingTransport.public_key ||
              data.get("regenerate_reality_keys") === "on"),
          generate_vless_encryption:
            xhttpKind &&
            data.get("vless_encryption_enabled") === "on" &&
            (!existingSecretRefs.vless_decryption ||
              !existingSecretRefs.vless_encryption ||
              data.get("regenerate_vless_encryption") === "on"),
          generate_reality_mldsa65:
            realityKind &&
            data.get("reality_mldsa65_enabled") === "on" &&
            (!existingSecretRefs.reality_mldsa65_seed ||
              !existingTransport.mldsa65_verify ||
              data.get("regenerate_reality_mldsa65") === "on"),
          generate_hysteria2_obfs:
            transportKind === "hysteria2" &&
            data.get("obfs_enabled") === "on" &&
            (!existingSecretRefs.hysteria2_obfs_password ||
              data.get("regenerate_hysteria2_obfs") === "on"),
        });
      }
      if (kind !== "subscription") {
        await onSaved();
        setSaved(true);
      }
    } catch (error) {
      setSaveError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  const grpcClientTuningFields = (
    <>
      <div className="transport-client-profile-scope form-span">
        <strong>{tr("Только клиентский профиль")}</strong>
        <span>{tr("Попадает в Xray/Reverse; совместимые поля — в Mihomo.")}</span>
      </div>
      <label className="checkbox-field">
        <input name="grpc_multi_mode" type="checkbox" defaultChecked={existingTransport.grpc_multi_mode === true} />
        <span><strong>{tr("gRPC multiMode · экспериментально")}</strong><small>{tr("Только клиентский профиль. Может повысить скорость, но совместимость между версиями Xray не гарантируется.")}</small></span>
      </label>
      <label className="field">
         {tr("User-Agent выдаваемого gRPC-клиента · необязательно")} <input name="grpc_user_agent" defaultValue={asText(existingTransport.grpc_user_agent, "")} placeholder={tr("Пусто · стандарт Xray")} />
      </label>
      <label className="field">
         {tr("Проверка простоя, сек.")} <input name="grpc_idle_timeout" type="number" min="0" max="86400" defaultValue={asText(existingTransport.grpc_idle_timeout, grpcIdleTimeoutDefault)} />
        <small>{directGRPCKind ? tr("60 — для прямого подключения; 0 отключает проверку.") : tr("0 отключает health-check; Xray применяет минимум 10 секунд.")}</small>
      </label>
      <label className="field">
         {tr("Таймаут health-check, сек.")} <input name="grpc_health_check_timeout" type="number" min="1" max="86400" defaultValue={asText(existingTransport.grpc_health_check_timeout, "20")} />
      </label>
      <label className="checkbox-field">
        <input
          name="grpc_permit_without_stream"
          type="checkbox"
          defaultChecked={
            existingTransport.grpc_permit_without_stream === true ||
            (directGRPCKind && !("grpc_permit_without_stream" in existingTransport))
          }
        />
        <span><strong>{tr("Проверять без активных stream")}</strong><small>{tr("Только клиент: разрешает gRPC health-check без дочерних соединений.")}</small></span>
      </label>
      <label className="field">
         {tr("Начальное окно HTTP/2")} <input name="grpc_initial_windows_size" type="number" min="0" max="2147483647" defaultValue={asText(existingTransport.grpc_initial_windows_size, "0")} />
        <small>
          {directGRPCKind
            ? tr("0 — автоматический размер. Большее окно может повысить скорость на канале с высокой задержкой, но требует больше памяти.")
            : tr("0 — авто. Для Cloudflare обычно проверяют 65536 и выше.")}
        </small>
      </label>
    </>
  );

  const tcpStabilityFields = (
    <>
      <label className="checkbox-field form-span">
        <input
          name="tcp_keep_alive_enabled"
          type="checkbox"
          defaultChecked={existingTransport.tcp_keep_alive_enabled !== false}
        />
        <span>
          <strong>TCP Keep-Alive</strong>
          <small>
            {transportKind === "grpc"
              ? tr("Xray JSON · клиент → CDN.")
              : tr("Сервер и Xray JSON, включая Reverse VLESS.")}
          </small>
        </span>
      </label>
      <label className="field">
         {tr("Начать проверку после простоя · сек.")} <input name="tcp_keep_alive_idle" type="number" min="1" max="86400" defaultValue={asText(existingTransport.tcp_keep_alive_idle, "30")} required />
      </label>
      <label className="field">
         {tr("Интервал проверок · сек.")} <input name="tcp_keep_alive_interval" type="number" min="1" max="86400" defaultValue={asText(existingTransport.tcp_keep_alive_interval, "10")} required />
      </label>
      <label className="field">
         {tr("Таймаут TCP · мс · Linux")} <input name="tcp_user_timeout" type="number" min="0" max="2147483647" defaultValue={asText(existingTransport.tcp_user_timeout, "60000")} required />
        <small>{tr("0 — без принудительного таймаута. Не зависит от Keep-Alive.")}</small>
      </label>
    </>
  );

  const regenerationOptions = [
    {
      name: "regenerate_http_path",
      label: t("regenerate.httpPath"),
      visible:
        ["ws", "httpupgrade", "xhttp", "xhttp-reality"].includes(
          transportKind,
        ) && Boolean(existingTransport.path_secret_ref),
    },
    {
      name: "regenerate_vless_encryption",
      label: "VLESS Encryption",
      visible:
        xhttpKind &&
        (Boolean(existingSecretRefs.vless_decryption) ||
          Boolean(existingSecretRefs.vless_encryption)),
    },
    {
      name: "regenerate_grpc_service_name",
      label: t("regenerate.grpc"),
      visible:
        ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind) &&
        Boolean(existingTransport.service_name_secret_ref),
    },
    {
      name: "regenerate_reality_keys",
      label: tr("X25519 и Short ID"),
      visible: realityKind && Boolean(existingTransport.public_key),
    },
    {
      name: "regenerate_reality_mldsa65",
      label: "ML-DSA-65",
      visible:
        realityKind &&
        (Boolean(existingSecretRefs.reality_mldsa65_seed) ||
          Boolean(existingTransport.mldsa65_verify)),
    },
    {
      name: "regenerate_hysteria2_obfs",
      label: t("regenerate.salamander"),
      visible:
        transportKind === "hysteria2" &&
        Boolean(existingSecretRefs.hysteria2_obfs_password),
    },
  ].filter((option) => option.visible);

  const transportActionOptions = [
    {
      name: "reset_transport_parameters",
      label: t("transport.reset"),
    },
    ...regenerationOptions,
  ];
  const selectedTransportActionLabels = transportActionOptions
    .filter((option) => pendingTransportActions.includes(option.name))
    .map((option) => option.label);
  const transportActionCount = selectedTransportActionLabels.length;
  function selectTransportAction(name: string, selected: boolean) {
    if (name === "reset_transport_parameters") {
      if (selected) applyTransportParameterDefaults();
      else restoreTransportParameters();
    }
    setPendingTransportActions((current) =>
      selected
        ? current.includes(name)
          ? current
          : [...current, name]
        : current.filter((value) => value !== name),
    );
  }

  const transportActionMenu = transportActionOptions.length ? (
    <details ref={transportActionMenuRef} className="transport-regeneration-menu">
      <summary
        className={`button button-compact ${transportActionCount ? "button-primary" : "button-tertiary"}`}
        title={t("regenerate.title")}
      >
        {t("regenerate.action")}
        {transportActionCount ? ` (${transportActionCount})` : ""}
      </summary>
      <div
        className="transport-regeneration-options"
        role="group"
        aria-label={t("regenerate.group")}
      >
        {transportActionOptions.map((option) => (
          <label key={option.name}>
            <input
              name={option.name}
              type="checkbox"
              checked={pendingTransportActions.includes(option.name)}
              onChange={(event) =>
                selectTransportAction(option.name, event.target.checked)
              }
            />
            <span>{option.label}</span>
          </label>
        ))}
      </div>
    </details>
  ) : null;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className={`modal modal-wide ${kind === "subscription" ? "subscription-editor-modal" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="connection-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        {saved ? (
          <div className="modal-success" role="status">
            <span>✓</span>
            <h2 id="connection-title">{tr("Настройки сохранены")}</h2>
            <p>
              {kind === "subscription"
                ? tr("Подписка сохранена. URL доступен авторизованному администратору в настройках.")
                : tr("Секретное значение записано отдельно и не возвращается в браузер.")}{" "}
               {tr("Рабочая конфигурация изменится только после применения.")} </p>
            <button className="button button-primary" onClick={onClose}>
               {tr("Готово")} </button>
          </div>
        ) : (
          <form ref={formRef} onSubmit={submit}>
            {kind === "transport" ? <p className="eyebrow">{tr("Удалённый вход")}</p> : null}
            <h2 id="connection-title">
              {kind === "subscription"
                ? editingSubscription
                  ? tr("Настроить · {value1}", { value1: itemName(existingSubscription) })
                  : tr("Добавить подписку")
                : tr("Настроить {value1}", { value1: transportKindLabel(transportKind) })}
            </h2>
            {kind !== "subscription" ? (
              <p className="modal-lead">{tr(transportChangeLead(transportKind))}</p>
            ) : null}
            {kind === "subscription" ? (
              <div className="form-grid">
                <label className="field">
                   {tr("Имя подписки")} <input
                    name="display_name"
                    required
                    defaultValue={asText(existingSubscription.display_name, "")}
                    placeholder={tr("Основной провайдер")}
                  />
                </label>
                <label className="field">
                   {tr("Проверять каждые")} <div className="field-with-unit field-with-select">
                    <input name="refresh_value" type="number" min="1" max="10080" defaultValue={defaultRefreshValue} required />
                    <select name="refresh_unit" defaultValue={defaultRefreshUnit} aria-label={tr("Единица интервала проверки")}>
                      <option value="minutes">{tr("минут")}</option>
                      <option value="hours">{tr("часов")}</option>
                    </select>
                  </div>
                </label>
                <label className="field form-span">
                   {tr("URL подписки")} <textarea
                    name="url"
                    required
                    autoComplete="url"
                    rows={1}
                    wrap="off"
                    spellCheck={false}
                    className="subscription-url-input"
                    value={subscriptionUrl}
                    placeholder={subscriptionUrlBusy ? tr("Загружаю сохранённый URL…") : "https://…"}
                    onChange={(event) => {
                      setSubscriptionUrl(event.target.value);
                      if (workingSubscriptionId) {
                        setDiscoveryReady(false);
                        setDiscoveryMessage(
                          tr("URL изменён. Загрузите список заново перед сохранением выбора."),
                        );
                      }
                    }}
                  />
                  {subscriptionUrlBusy ? <small role="status">{tr("Загрузка ссылки…")}</small> : null}
                </label>
                <fieldset className="subscription-refresh-routing form-span">
                  <legend>{tr("Пути обновления")}</legend>
                  <div className="subscription-refresh-modes">
                    {[
                      { id: "wan", label: "WAN", direct: true, vpn: false, title: tr("Только прямой WAN") },
                      { id: "wan-vpn", label: "WAN → VPN", direct: true, vpn: true, title: tr("Прямой WAN, затем VPN-резерв") },
                      { id: "vpn", label: "VPN", direct: false, vpn: true, title: tr("Только VPN") },
                    ].map((mode) => (
                      <label key={mode.id} title={mode.title}>
                        <input
                          type="radio"
                          name="refresh_route_mode"
                          value={mode.id}
                          checked={refreshViaDirect === mode.direct && refreshViaVpn === mode.vpn}
                          onChange={() => {
                            setRefreshViaDirect(mode.direct);
                            setRefreshViaVpn(mode.vpn);
                          }}
                        />
                        <span>{mode.label}</span>
                      </label>
                    ))}
                  </div>
                  {refreshViaVpn ? (
                    <div className="subscription-refresh-children">
                      <Toggle className="subscription-refresh-toggle" label={tr("Рабочие каналы")} checked={refreshViaActiveOutbounds} onChange={setRefreshViaActiveOutbounds} />
                      <Toggle className="subscription-refresh-toggle" label={tr("Резервные VLESS")} description={tr("{value1} из 3 настроено", { value1: configuredSubscriptionReserves.length })} checked={refreshViaIndependentReserves} onChange={setRefreshViaIndependentReserves} />
                    </div>
                  ) : null}
                </fieldset>
                 <section className="subscription-location-picker form-span" aria-live="polite">
                   <div className="subscription-location-heading">
                     <div>
                       <strong>{tr("Данные подписки")}</strong>
                     </div>
                     {workingSubscriptionId ? (
                       <button
                         type="button"
                         className="button button-tertiary"
                         disabled={busy}
                         onClick={async () => {
                           if (!formRef.current) return;
                           setBusy(true);
                           setSaveError("");
                           try {
                             setDiscoveryReady(false);
                             await persistAndDiscover(new FormData(formRef.current));
                           } catch (error) {
                             setSaveError(errorMessage(error));
                           } finally {
                             setBusy(false);
                           }
                         }}
                       >
                          {tr("Обновить список")} </button>
                     ) : null}
                   </div>
                   {discoveryMessage ? (
                     <p className="subscription-discovery-message">{discoveryMessage}</p>
                   ) : null}
                   {discoveryReady ? (
                     <div className="subscription-provider-meta">
                       <span>
                         <strong>{tr("Срок")}</strong>
                         <small>{expiryText(subscriptionProvider.expires_at, locale)}</small>
                       </span>
                       <span>
                         <strong>{tr("Трафик")}</strong>
                         <small>
                           {Object.keys(asObject(subscriptionProvider.usage)).length
                             ? locale === "en"
                               ? `${formatBytes(asObject(subscriptionProvider.usage).used_bytes, locale)} of ${formatBytes(asObject(subscriptionProvider.usage).total_bytes, locale)} · ${formatBytes(asObject(subscriptionProvider.usage).remaining_bytes, locale)} remaining`
                               : tr("{value1} из {value2} · осталось {value3}", { value1: formatBytes(asObject(subscriptionProvider.usage).used_bytes, locale), value2: formatBytes(asObject(subscriptionProvider.usage).total_bytes, locale), value3: formatBytes(asObject(subscriptionProvider.usage).remaining_bytes, locale) })
                             : tr("Лимит не указан провайдером")}
                         </small>
                       </span>
                     </div>
                   ) : null}
                   {discoveryReady ? (
                     <div className="subscription-discovery-ready">
                       <strong>{subscriptionNodes.length}  {tr("узл. готовы к использованию")}</strong>
                     </div>
                   ) : (
                     <div className="subscription-discovery-empty">
                        {tr("Список узлов ещё не загружен.")} </div>
                   )}
                 </section>
                 <Toggle
                   className="form-span subscription-enabled-toggle"
                   name="enabled"
                   defaultChecked={existingSubscription.enabled !== false}
                   tone="state"
                   label={tr("Подписка включена")}
                 />
               </div>
            ) : (
              <div className="form-grid">
                {!cdnTransportKind ? (
                  <div className={directInboundKind ? "field form-span" : "field"}>
                    <label htmlFor="transport-hostname">{tr("Адрес подключения")}</label>
                    <div className={directInboundKind ? "connection-address-row" : undefined}>
                    <input
                      id="transport-hostname"
                      name="hostname"
                      required={!directInboundKind || hostnameMode === "manual"}
                      readOnly={directInboundKind && hostnameMode === "auto"}
                      value={directInboundKind && hostnameMode === "auto" ? asText(connectionAddress.address, "") : manualHostname}
                      onChange={(event) => setManualHostname(event.target.value)}
                      placeholder={hostnamePlaceholder}
                      list={directInboundKind && hostnameMode === "manual" ? "connection-wan-addresses" : undefined}
                    />
                    {directInboundKind ? (
                      <select aria-label={tr("Режим адреса подключения")} name="hostname_mode" value={hostnameMode} onChange={(event) => setHostnameMode(event.target.value)}>
                        <option value="auto">{tr("Автоматически")}</option>
                        <option value="manual">{tr("Вручную")}</option>
                      </select>
                    ) : null}
                    </div>
                    {directInboundKind && hostnameMode === "manual" ? (
                      <>
                        <datalist id="connection-wan-addresses">
                          {ownedWanAddresses.map((row) => <option key={asText(row.address, "")} value={asText(row.address, "")}>{asText(row.interface, "")}</option>)}
                        </datalist>
                      </>
                    ) : null}
                    {directInboundKind && hostnameMode === "auto" ? (
                      <small role="status">{connectionAddress.state === "ready"
                        ? `WAN: ${asText(connectionAddress.interface, "")}`
                        : connectionAddress.state === "ambiguous" ? tr("Несколько WAN-адресов — выберите адрес вручную.")
                        : tr("Адрес WAN пока недоступен.")}</small>
                    ) : null}
                  </div>
                ) : null}
                {cdnTransportKind ? (
                  <>
                    <section className="cdn-deployments-editor form-span" aria-labelledby="cdn-deployments-title">
                      <div className="cdn-deployments-heading">
                        <span>
                          <strong id="cdn-deployments-title">{tr("CDN-развёртывания")}</strong>
                          <small>{tr(cdnDeploymentScopeNote(transportKind))}</small>
                        </span>
                        <button
                          className="button button-secondary cdn-add-button"
                          type="button"
                          onClick={() => cloneCdnDeployment(Math.max(0, cdnDeployments.length - 1), false)}
                        >
                           {tr("+ Ещё один CDN")} </button>
                      </div>
                      <div className="cdn-deployments-list">
                        {cdnDeployments.map((deployment, deploymentIndex) => {
                          const deploymentProvider = asText(
                            deployment.cdn_provider,
                            "cloudflare",
                          );
                          const deploymentId = asText(
                            deployment.id,
                            `cdn-${deploymentIndex + 1}`,
                          );
                          const deploymentHostname = asText(
                            deployment.hostname,
                            "",
                          );
                          const configuredTlsServerName = asText(
                            deployment.tls_server_name,
                            "",
                          );
                          const customTlsServerName =
                            configuredTlsServerName &&
                            configuredTlsServerName.toLowerCase() !==
                              deploymentHostname.toLowerCase()
                              ? configuredTlsServerName
                              : "";
                          const hasClientHostOverride = Boolean(
                            customTlsServerName ||
                              asText(deployment.http_host, "") ||
                              asText(deployment.grpc_authority, ""),
                          );
                          const originHostnameCandidates = tlsConcreteHostnames(
                            tlsProfiles.find(
                              (profile) =>
                                asText(profile.id, "") ===
                                asText(deployment.tls_profile_id, ""),
                            ),
                          );
                          const originHostnameDatalistId = `cdn-origin-dns-${deploymentIndex}`;
                          return (
                            <fieldset className="cdn-deployment-row" key={deploymentId}>
                              <legend>{asText(deployment.display_name, `CDN ${deploymentIndex + 1}`)}</legend>
                              <div className="form-grid">
                                <label className="field">
                                   {tr("Название")} <input
                                    value={asText(deployment.display_name, "")}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        display_name: event.target.value,
                                      })
                                    }
                                    required
                                  />
                                  <small>ID: {deploymentId}</small>
                                </label>
                                <label className="field">
                                  CDN
                                  <select
                                    value={deploymentProvider}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        cdn_provider: event.target.value,
                                        listen_port:
                                          event.target.value === "cloudflare" && transportKind === "grpc"
                                            ? 443
                                            : deployment.listen_port ?? 443,
                                        origin_protection_mode:
                                          supportsAutomaticCidr(event.target.value)
                                            ? "auto-cidr"
                                            : "secret-header",
                                        origin_header_value:
                                          supportsAutomaticCidr(event.target.value)
                                            ? undefined
                                            : asText(deployment.origin_header_value, "") ||
                                              generateOriginHeaderSecret(),
                                      })
                                    }
                                  >
                                    {CDN_PROVIDERS.map((provider) => (
                                      <option value={provider.id} key={provider.id}>{tr(provider.name)}</option>
                                    ))}
                                  </select>
                                  <small>{tr(subscriptionCdnProviderNote(deploymentProvider))}</small>
                                </label>
                                <label className="field">
                                   {tr("Домен раздачи CDN")} <input
                                    value={asText(deployment.hostname, "")}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        hostname: event.target.value,
                                        ...(customTlsServerName
                                          ? {}
                                          : { tls_server_name: "" }),
                                      })
                                    }
                                    placeholder="edge.example.com"
                                    required={transportEnabled && deployment.enabled !== false}
                                  />
                                  <small>{tr("Собственный CNAME или технический домен именно этого CDN-ресурса.")}</small>
                                </label>
                                <details className="cdn-client-overrides form-span" open={hasClientHostOverride}>
                                  <summary>
                                    <span><strong>{tr("SNI и Host клиента")}</strong><small>{hasClientHostOverride ? tr("Переопределено") : tr("Автоматически · домен раздачи CDN")}</small></span>
                                  </summary>
                                  <div className="form-grid">
                                    <label className="field">
                                       {tr("TLS SNI клиента")} <input
                                        value={customTlsServerName}
                                        onChange={(event) =>
                                          updateCdnDeployment(deploymentIndex, {
                                            tls_server_name: event.target.value,
                                          })
                                        }
                                        placeholder={tr("Авто: {value1}", { value1: deploymentHostname || "edge.example.com" })}
                                      />
                                      <small>{tr("Оставьте пустым, чтобы использовать публичный домен CDN.")}</small>
                                    </label>
                                    {["ws", "httpupgrade"].includes(transportKind) ? (
                                      <label className="field">
                                         {tr("HTTP Host клиента")} <input
                                          value={asText(deployment.http_host, "")}
                                          onChange={(event) => updateCdnDeployment(deploymentIndex, { http_host: event.target.value })}
                                          placeholder={tr("Авто: {value1}", { value1: deploymentHostname || "edge.example.com" })}
                                        />
                                        <small>{tr("Меняйте только если CDN требует отдельный Host.")}</small>
                                      </label>
                                    ) : null}
                                    {transportKind === "grpc" ? (
                                      <label className="field">
                                        gRPC authority
                                        <input
                                          value={asText(deployment.grpc_authority, "")}
                                          onChange={(event) => updateCdnDeployment(deploymentIndex, { grpc_authority: event.target.value })}
                                          placeholder={tr("Авто: не добавляется")}
                                        />
                                        <small>{tr("Меняйте только если CDN требует отдельный :authority.")}</small>
                                      </label>
                                    ) : null}
                                  </div>
                                </details>
                                <label className="field">
                                   {tr("Публичный HTTPS-порт")} {deploymentProvider === "cloudflare" ? (
                                    <select
                                      value={Number(deployment.listen_port ?? 443)}
                                      onChange={(event) =>
                                        updateCdnDeployment(deploymentIndex, {
                                          listen_port: Number(event.target.value),
                                        })
                                      }
                                    >
                                      {(transportKind === "grpc" ? [443] : CLOUDFLARE_HTTPS_PORTS).map((port) => (
                                        <option value={port} key={port}>{port}</option>
                                      ))}
                                    </select>
                                  ) : (
                                    <input
                                      type="number"
                                      min="1"
                                      max="65535"
                                      value={Number(deployment.listen_port ?? 443)}
                                      onChange={(event) =>
                                        updateCdnDeployment(deploymentIndex, {
                                          listen_port: Number(event.target.value),
                                        })
                                      }
                                      required
                                    />
                                  )}
                                  <small>{deploymentProvider === "cloudflare" && transportKind === "grpc" ? tr("Cloudflare gRPC использует TCP 443.") : tr("Проверьте поддержку порта у выбранного CDN.")}</small>
                                </label>
                                <label className="field">
                                   {tr("TCP-порт origin на MikroTik")} <input
                                    type="number"
                                    min="1"
                                    max="65535"
                                    value={Number(
                                      deployment.origin_port ??
                                        existingTransport.origin_port ??
                                        existingTransport.listen_port ??
                                        legacyCloudflarePort,
                                    )}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        origin_port: Number(event.target.value),
                                      })
                                    }
                                    required={transportEnabled && deployment.enabled !== false}
                                  />
                                  <small>{tr("Порт, на который этот CDN обращается к origin шлюза. Разные классы защиты, например Cloudflare CIDR и Yandex secret-header, используют разные origin-порты.")}</small>
                                </label>
                                <label className="field">
                                   {tr("DNS-имя origin")} <input
                                    value={asText(deployment.origin_server_name, "")}
                                    list={originHostnameDatalistId}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        origin_server_name: event.target.value,
                                      })
                                    }
                                    placeholder={originHostnameCandidates.length ? tr("Выберите или введите домен") : "origin.example.com"}
                                    required={transportEnabled && deployment.enabled !== false}
                                  />
                                  <datalist id={originHostnameDatalistId}>
                                    {originHostnameCandidates.map((hostname) => <option value={hostname} key={hostname} />)}
                                  </datalist>
                                  <small>{tr(cdnOriginNameNote(transportKind))}</small>
                                </label>
                                <label className="field">
                                   {tr("TLS-профиль origin")} <select
                                    value={asText(deployment.tls_profile_id, "")}
                                    onChange={(event) =>
                                      selectCdnDeploymentTlsProfile(
                                        deploymentIndex,
                                        event.target.value,
                                      )
                                    }
                                    required={transportEnabled && deployment.enabled !== false}
                                  >
                                    <option value="">{tr("Выберите сертификат origin")}</option>
                                    {tlsProfiles.map((profile) => (
                                      <option
                                        value={asText(profile.id, "")}
                                        key={asText(profile.id, "")}
                                      >
                                        {itemName(profile)}
                                        {asText(profile.certificate_secret_ref, "")
                                          ? tr(" · настроен")
                                          : tr(" · нужна пара")}
                                      </option>
                                    ))}
                                  </select>
                                  <small>{tr("Сертификат соединения CDN → origin.")}</small>
                                </label>
                                <label className="field">
                                   {tr("Защита origin")} <select
                                    value={asText(
                                      deployment.origin_protection_mode,
                                      deploymentProvider === "cloudflare"
                                        ? "auto-cidr"
                                        : "secret-header",
                                    )}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        origin_protection_mode: event.target.value,
                                        origin_header_value:
                                          event.target.value === "secret-header"
                                            ? asText(deployment.origin_header_value, "") ||
                                              generateOriginHeaderSecret()
                                            : undefined,
                                      })
                                    }
                                  >
                                    {supportsAutomaticCidr(deploymentProvider) ? (
                                      <option value="auto-cidr">{tr("Официальные CIDR · авто")}</option>
                                    ) : null}
                                    <option value="secret-header">{tr("Секретный HTTP-заголовок")}</option>
                                    <option value="manual-cidr">{tr("IPv4 CIDR · вручную")}</option>
                                  </select>
                                  <small>
                                    {asText(deployment.origin_protection_mode, "") === "auto-cidr"
                                      ? automaticCidrHint(deploymentProvider)
                                      : asText(deployment.origin_protection_mode, "") === "manual-cidr"
                                        ? tr("Расширенный fallback, если провайдер не умеет добавлять секретный header и не публикует машинный feed.")
                                        : tr("Добавьте этот header в настройках CDN-запроса к origin. Прямой запрос без секрета получит 404.")}
                                  </small>
                                </label>
                                {asText(deployment.origin_protection_mode, "") === "secret-header" ? (
                                  <div className="field">
                                     {tr("Секрет origin-header")} <div className="inline-field-actions">
                                      <input
                                        value={asText(deployment.origin_header_value, "")}
                                        readOnly
                                        placeholder={
                                          asText(deployment.origin_header_secret_ref, "")
                                            ? tr("Секрет уже сохранён и скрыт")
                                            : tr("Нажмите «Создать новый»")
                                        }
                                        aria-label={tr("Секрет origin-header")}
                                      />
                                      <button
                                        className="button button-secondary"
                                        type="button"
                                        onClick={() =>
                                          updateCdnDeployment(deploymentIndex, {
                                            origin_header_value: generateOriginHeaderSecret(),
                                          })
                                        }
                                      >
                                         {tr("Создать новый")} </button>
                                    </div>
                                    <small>
                                       {tr("Имя заголовка:")} <code>{asText(deployment.origin_header_name, "X-SB-Origin")}</code>{tr(". Новый секрет покажется до сохранения — скопируйте его в CDN.")} </small>
                                  </div>
                                ) : null}
                                {asText(deployment.origin_protection_mode, "") === "manual-cidr" ? (
                                  <label className="field">
                                     {tr("Разрешённые IPv4-сети CDN")} <textarea
                                      value={asStringList(deployment.origin_allowed_cidrs).join("\n")}
                                      onChange={(event) =>
                                        updateCdnDeployment(deploymentIndex, {
                                          origin_allowed_cidrs: event.target.value
                                            .split(/[\n,]/)
                                            .map((value) => value.trim())
                                            .filter(Boolean),
                                        })
                                      }
                                      placeholder={"203.0.113.0/24\n198.51.100.0/24"}
                                      rows={3}
                                    />
                                    <small>{tr("Панель валидирует список; меняйте его только по официальным данным CDN.")}</small>
                                  </label>
                                ) : null}
                                <label className="checkbox-field">
                                  <input
                                    type="checkbox"
                                    checked={deployment.enabled !== false}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        enabled: event.target.checked,
                                      })
                                    }
                                  />
                                  <span><strong>{tr("Отдавать клиентам")}</strong><small>{tr("Выключенное развёртывание сохраняется, но не попадает в подписку.")}</small></span>
                                </label>
                                <div className="cdn-deployment-actions">
                                  <button className="button button-tertiary" type="button" onClick={() => cloneCdnDeployment(deploymentIndex)}>{tr("Дублировать")}</button>
                                  <button
                                    className="button button-tertiary"
                                    type="button"
                                    disabled={cdnDeployments.length <= 1}
                                    onClick={() => setCdnDeployments((current) => current.filter((_, itemIndex) => itemIndex !== deploymentIndex))}
                                  >
                                     {tr("Удалить")} </button>
                                </div>
                                <div className="reality-target-check form-span">
                                  <div>
                                    <strong>{tr("Проверка домена CDN и origin")}</strong>
                                    <small>{tr("Проверяет DNS, TLS/SNI и срок сертификатов без сохранения и Apply.")}</small>
                                  </div>
                                  <button
                                    className="button button-secondary button-compact"
                                    type="button"
                                    disabled={cdnProbeBusyId === deploymentId}
                                    onClick={() => void checkCdnDeployment(deploymentIndex)}
                                  >
                                    {cdnProbeBusyId === deploymentId ? tr("Проверяю…") : tr("Проверить")}
                                  </button>
                                  {cdnProbeResults[deploymentId] ? (
                                    <small
                                      className={isErrorMessage(cdnProbeResults[deploymentId]) ? "field-error" : ""}
                                      role={isErrorMessage(cdnProbeResults[deploymentId]) ? "alert" : "status"}
                                    >
                                      {cdnProbeResults[deploymentId]}
                                    </small>
                                  ) : null}
                                </div>
                              </div>
                            </fieldset>
                          );
                        })}
                      </div>
                    </section>
                  </>
                ) : null}
                {!directInboundKind && !cdnTransportKind ? (
                  <Toggle
                    className="form-span"
                    name="enabled"
                    checked={transportEnabled}
                    onChange={setTransportEnabled}
                    tone="state"
                    label={tr("Транспорт включён")}
                    description={tr("Изменение вступит в силу только после проверки и Apply.")}
                  />
                ) : null}
                {directInboundKind ? (
                  <>
                    <label className="field direct-inbound-port">
                      {directInboundProtocol}{tr("-порт прямого входа")} <input
                        name="listen_port"
                        type="number"
                        min="1"
                        max="65535"
                        value={directListenPort}
                        onChange={(event) => setDirectListenPort(event.target.value)}
                        required
                      />
                    </label>
                    {["hysteria2", "grpc-tls"].includes(transportKind) ? (
                      <label className="field">
                        TLS SNI
                        <input
                          name="tls_server_name"
                          list="direct-tls-server-names"
                          value={directTlsServerName}
                          onChange={(event) => {
                            const nextServerName = event.target.value;
                            setDirectTlsServerName(nextServerName);
                            const matchingProfileId = tlsProfileIdForHostname(
                              tlsProfiles,
                              nextServerName,
                              tlsProfileChoice,
                            );
                            if (matchingProfileId !== tlsProfileChoice) {
                              setTlsProfileChoice(matchingProfileId);
                            }
                          }}
                          placeholder="www.example.com"
                          required
                        />
                        <datalist id="direct-tls-server-names">
                          {directTlsHostnameCandidates.map((hostname) => (
                            <option value={hostname} key={hostname} />
                          ))}
                        </datalist>
                      </label>
                    ) : null}
                    {directPortConflict ? (
                      <div className="direct-inbound-conflict form-span" role="alert">
                         {tr("Порт")} {directListenPort}  {tr("уже используется входом «")} {transportKindLabel(directPortConflict.kind)}{tr("». Выберите другой WAN IP или порт.")} </div>
                    ) : null}
                  </>
                ) : null}
                {["ws", "httpupgrade"].includes(transportKind) ? (
                  <details className="policy-check-advanced form-span">
                    <summary>{tr("Дополнительно")}</summary>
                    <div className="form-grid">
                      <div className="transport-http-path form-span">
                        <div className="transport-http-path-heading">
                          <span>
                            <strong>{tr("HTTP-путь транспорта")}</strong>
                            <small>{existingTransport.path_secret_ref ? tr("Хранится в SecretStore и показывается только по запросу.") : tr("Будет создан автоматически при сохранении.")}</small>
                          </span>
                          {existingTransport.path_secret_ref ? (
                            <div className="transport-http-path-actions">
                              <button className="button button-tertiary button-compact" type="button" disabled={httpPathBusy} onClick={() => void showHttpPath()}>{httpPathBusy ? tr("Открываю…") : revealedHttpPath ? tr("Обновить") : tr("Показать")}</button>
                              <button className="button button-tertiary button-compact" type="button" disabled={!revealedHttpPath} onClick={() => void copyHttpPath()}>{tr("Скопировать")}</button>
                            </div>
                          ) : null}
                        </div>
                        {revealedHttpPath ? <input className="transport-http-path-value" value={revealedHttpPath} readOnly aria-label={tr("Текущий HTTP-путь")} /> : null}
                        {httpPathMessage ? <small className="transport-http-path-message" role="status">{httpPathMessage}</small> : null}
                      </div>
                      <label className="field">
                         {tr("Early Data, байт")} <input name="early_data" type="number" min="0" max="8192" defaultValue={asText(existingTransport.early_data, "0")} />
                        <small>{tr("0 — выключено; рекомендуемый порог Xray — 2560.")}</small>
                      </label>
                      {transportKind === "ws" ? (
                        <label className="field">
                           {tr("WebSocket heartbeat, сек.")} <input name="ws_heartbeat_period" type="number" min="0" max="86400" defaultValue={asText(existingTransport.ws_heartbeat_period, "0")} />
                          <small>{tr("0 — Ping keepalive отключён.")}</small>
                        </label>
                      ) : null}
                      <label className="field form-span">
                         {tr("Заголовки клиентского запроса · необязательно")} <textarea
                          name="client_http_headers"
                          rows={3}
                          defaultValue={Object.entries(asObject(existingTransport.client_http_headers)).map(([name, value]) => `${name}: ${asText(value, "")}`).join("\n")}
                          placeholder={tr("Оставьте пустым, если CDN не требует специальных заголовков")}
                        />
                        <small>{tr("Только Xray / Sing-box / Mihomo. Обычная VLESS-ссылка недоступна с дополнительными заголовками.")}</small>
                      </label>
                    </div>
                  </details>
                ) : null}
                {xhttpKind ? (
                  <>
                    <label className="field">
                       {tr("Режим XHTTP")} <select
                        name="mode"
                        value={xhttpMode}
                        onChange={(event) => {
                          const nextMode = event.target.value;
                          setXHTTPMode(nextMode);
                          if (nextMode !== "packet-up") {
                            if (xhttpUplinkMethod === "GET") setXHTTPUplinkMethod("POST");
                            if (["header", "cookie"].includes(xhttpUplinkPlacement)) setXHTTPUplinkPlacement("auto");
                          }
                        }}
                      >
                        <option value="packet-up">
                          {transportKind === "xhttp"
                            ? tr("packet-up · основной режим через CDN")
                            : tr("packet-up · принудительный пакетный uplink")}
                        </option>
                        <option value="stream-up">stream-up</option>
                        <option value="stream-one">stream-one</option>
                        <option value="auto">
                          {transportKind === "xhttp-reality"
                            ? tr("auto · рекомендуется для Reality")
                            : tr("auto · клиент выбирает")}
                        </option>
                      </select>
                      <small>{tr("Vision для XHTTP включается только вместе с VLESS Encryption в расширенном профиле Xray.")}</small>
                    </label>
                    <label className="field">
                       {tr("XHTTP padding, байты")} <input
                        name="x_padding_bytes"
                        pattern="[1-9][0-9]{0,5}(-[1-9][0-9]{0,5})?"
                        defaultValue={asText(existingTransport.x_padding_bytes, "100-1000")}
                        required
                      />
                      <small>{tr("Обязательный диапазон форка; безопасное значение по умолчанию — 100-1000.")}</small>
                    </label>
                    <details className="policy-check-advanced form-span">
                      <summary>{t("common.advanced")} · XHTTP</summary>
                      <div className="form-grid">
                        <label className="checkbox-field form-span">
                          <input name="vless_encryption_enabled" type="checkbox" defaultChecked={existingTransport.vless_encryption_enabled !== false} />
                          <span><strong>VLESS Encryption + XTLS Vision</strong><small>{tr("Серверный decryption и клиентский encryption генерируются парой через `xray vlessenc` и хранятся в SecretStore.")}</small></span>
                        </label>
                        <label className="field">
                           {tr("Аутентификация VLESS Encryption")} <select name="vless_encryption_authentication" defaultValue={asText(existingTransport.vless_encryption_authentication, "mlkem768")}>
                            <option value="mlkem768">{tr("ML-KEM-768 · постквантовая")}</option>
                            <option value="x25519">X25519</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Метод uplink")} <select name="uplink_http_method" value={xhttpUplinkMethod} onChange={(event) => setXHTTPUplinkMethod(event.target.value)}>
                            <option value="GET">{tr("GET · только packet-up")}</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="PATCH">PATCH</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Где передавать uplink data")} <select name="uplink_data_placement" value={xhttpUplinkPlacement} onChange={(event) => setXHTTPUplinkPlacement(event.target.value)}>
                            <option value="header">{tr("header · для GET packet-up")}</option>
                            <option value="cookie">{tr("cookie · для GET packet-up")}</option>
                            <option value="body">body</option>
                            <option value="auto">auto</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ uplink data")} <input name="uplink_data_key" defaultValue={asText(existingTransport.uplink_data_key, "X-Data")} required />
                        </label>
                        <label className="field">
                           {tr("Размер чанка uplink")} <input name="uplink_chunk_size" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.uplink_chunk_size, "2048-3072")} required />
                          <small>
                             {tr("Для header/cookie учитывайте Base64 и")} {transportKind === "xhttp"
                              ? tr(" лимит заголовков выбранного CDN.")
                              : tr(" заданный максимум HTTP-заголовков.")}
                          </small>
                        </label>
                        <label className="checkbox-field form-span">
                          <input name="x_padding_obfs_mode" type="checkbox" defaultChecked={existingTransport.x_padding_obfs_mode !== false} />
                          <span><strong>{tr("Новый padding obfs mode")}</strong><small>{tr("Включает управляемые placement, key, header и method.")}</small></span>
                        </label>
                        <label className="field">
                           {tr("Размещение padding")} <select name="x_padding_placement" defaultValue={asText(existingTransport.x_padding_placement, "query")}>
                            <option value="query">query</option>
                            <option value="queryInHeader">queryInHeader</option>
                            <option value="header">header</option>
                            <option value="cookie">cookie</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Вид padding")} <select name="x_padding_method" defaultValue={asText(existingTransport.x_padding_method, "tokenish")}>
                            <option value="tokenish">tokenish</option>
                            <option value="repeat-x">repeat-x</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ padding")} <input name="x_padding_key" defaultValue={asText(existingTransport.x_padding_key, "_v")} required />
                        </label>
                        <label className="field">
                           {tr("Заголовок padding")} <input name="x_padding_header" defaultValue={asText(existingTransport.x_padding_header, "X-Padding")} required />
                        </label>
                        <label className="field">
                           {tr("Размещение session ID")} <select name="session_id_placement" defaultValue={asText(existingTransport.session_id_placement, "cookie")}>
                            <option value="path">path</option><option value="cookie">cookie</option><option value="header">header</option><option value="query">query</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ session ID")} <input name="session_id_key" defaultValue={asText(existingTransport.session_id_key, "_sid")} required />
                        </label>
                        <label className="field">
                           {tr("Таблица символов session ID")} <input name="session_id_table" defaultValue={asText(existingTransport.session_id_table, "")} placeholder={tr("Пусто · таблица Xray")} />
                        </label>
                        <label className="field">
                           {tr("Длина session ID")} <input name="session_id_length" type="number" min="1" max="1048576" defaultValue={asText(existingTransport.session_id_length, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                           {tr("Размещение seq")} <select name="seq_placement" defaultValue={asText(existingTransport.seq_placement, "query")}>
                            <option value="path">path</option><option value="cookie">cookie</option><option value="header">header</option><option value="query">query</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ seq")} <input name="seq_key" defaultValue={asText(existingTransport.seq_key, "_seq")} required />
                        </label>
                        <label className="field">
                           {tr("Максимум заголовков сервера, байт")} <input name="server_max_header_bytes" type="number" min="1024" max="1048576" defaultValue={asText(existingTransport.server_max_header_bytes, "16384")} required />
                        </label>
                        <label className="field form-span">
                           {tr("Дополнительные HTTP-заголовки")} <textarea
                            name="xhttp_headers"
                            rows={4}
                            defaultValue={Object.entries(asObject(existingTransport.headers)).map(([name, value]) => `${name}: ${asText(value, "")}`).join("\n")}
                            placeholder={"Accept: */*\nCache-Control: no-cache"}
                          />
                          <small>{tr("По одному «Имя: значение» на строке. Не копируйте чужой фиксированный User-Agent без причины.")}</small>
                        </label>
                        <label className="field form-span">
                           {tr("downloadSettings · JSON StreamConfig клиента")} <textarea
                            name="download_settings_json"
                            rows={6}
                            defaultValue={Object.keys(asObject(existingTransport.download_settings)).length ? JSON.stringify(asObject(existingTransport.download_settings), null, 2) : ""}
                            placeholder={'{"address":"download.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.example.com"},"xhttpSettings":{"path":"/down"}}'}
                            spellCheck={false}
                          />
                          <small>{tr("Отдельный downlink Xray. Сохраняется в JSON и ссылке XHTTP; экспорт Mihomo недоступен.")}</small>
                        </label>
                        <label className="checkbox-field">
                          <input name="no_grpc_header" type="checkbox" defaultChecked={existingTransport.no_grpc_header === true} />
                          <span><strong>noGRPCHeader</strong><small>{tr("Не добавлять gRPC-подобный заголовок.")}</small></span>
                        </label>
                        <label className="checkbox-field">
                          <input name="no_sse_header" type="checkbox" defaultChecked={existingTransport.no_sse_header === true} />
                          <span><strong>noSSEHeader</strong><small>{tr("Не добавлять SSE-заголовок downlink.")}</small></span>
                        </label>
                        <label className="field">
                          scMaxEachPostBytes
                          <input name="sc_max_each_post_bytes" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.sc_max_each_post_bytes, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          scMinPostsIntervalMs
                          <input name="sc_min_posts_interval_ms" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.sc_min_posts_interval_ms, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          scMaxBufferedPosts
                          <input name="sc_max_buffered_posts" type="number" min="1" max="1048576" defaultValue={asText(existingTransport.sc_max_buffered_posts, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          scStreamUpServerSecs
                          <input name="sc_stream_up_server_secs" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.sc_stream_up_server_secs, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          XMUX maxConnections
                          <input name="xmux_max_connections" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_max_connections, "3")} />
                        </label>
                        <label className="field">
                          XMUX maxConcurrency
                          <input name="xmux_max_concurrency" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_max_concurrency, "0")} />
                          <small>{tr("Для стабильной работы на мобильных сетях: maxConnections 3, maxConcurrency 0.")}</small>
                        </label>
                        <label className="field">
                          XMUX hMaxRequestTimes
                          <input name="xmux_h_max_request_times" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_h_max_request_times, "600-900")} />
                        </label>
                        <label className="field">
                          XMUX hMaxReusableSecs
                          <input name="xmux_h_max_reusable_secs" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_h_max_reusable_secs, "1800-3000")} />
                        </label>
                        <label className="field">
                          XMUX cMaxReuseTimes
                          <input name="xmux_c_max_reuse_times" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_c_max_reuse_times, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          XMUX hKeepAlivePeriod
                          <input name="xmux_h_keep_alive_period" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_h_keep_alive_period, "")} placeholder={tr("Авто")} />
                        </label>
                      </div>
                    </details>
                  </>
                ) : null}
                {["grpc", "grpc-tls"].includes(transportKind) ? (
                  <details className="policy-check-advanced form-span">
                    <summary>{t("common.advanced")} · gRPC</summary>
                    <div className="form-grid">
                      {grpcClientTuningFields}
                      {tcpStabilityFields}
                    </div>
                  </details>
                ) : null}
                {realityKind ? (
                  <>
                    <label className="field">
                       {tr("SNI для маскировки")} <input
                        name="server_name"
                        value={realityServerName}
                        onChange={(event) => {
                          const nextServerName = event.target.value;
                          setRealityServerName(nextServerName);
                          if (
                            realityCoverMode === "api" &&
                            !tlsProfiles.some((profile) =>
                              certificateCoversHostname(profile, nextServerName),
                            )
                          ) {
                            setRealityCoverMode("external");
                          }
                          invalidateRealityProbe();
                          if (!realityHandshakeServerEdited) {
                            setRealityHandshakeServer(nextServerName);
                          }
                        }}
                        placeholder="www.microsoft.com"
                        required
                      />
                    </label>
                    {realityAPICoverAvailable ? (
                      <label className="field">
                         {tr("Ответ без действительного ключа")} <select
                          name="cover_mode"
                          value={effectiveRealityCoverMode}
                          onChange={(event) => {
                            const nextMode = event.target.value;
                            setRealityCoverMode(nextMode);
                            if (nextMode === "api") {
                              const selectedStillMatches = realityAPICoverProfiles.some(
                                (profile) => asText(profile.id, "") === tlsProfileChoice,
                              );
                              if (!selectedStillMatches) {
                                selectTransportTlsProfile(
                                  asText(realityAPICoverProfiles[0]?.id, ""),
                                );
                              }
                            }
                            invalidateRealityProbe();
                          }}
                        >
                          <option value="api">{tr("API JSON на своём домене")}</option>
                          <option value="external">{tr("Внешний REALITY target")}</option>
                        </select>
                        <small>{tr("Доступно, потому что выбранный SNI покрыт собственным TLS-сертификатом.")}</small>
                      </label>
                    ) : null}
                    {effectiveRealityCoverMode === "external" ? (
                      <>
                        <label className="field">
                           {tr("Сервер рукопожатия")} <input
                            name="handshake_server"
                            value={realityHandshakeServer}
                            onChange={(event) => {
                              setRealityHandshakeServer(event.target.value);
                              setRealityHandshakeServerEdited(true);
                              invalidateRealityProbe();
                            }}
                            placeholder={tr("Подставляется из SNI")}
                            required
                          />
                          <small>{tr("Автоматически повторяет SNI, пока вы не измените target вручную.")}</small>
                        </label>
                        <label className="field">
                           {tr("Порт рукопожатия")} <input name="handshake_port" type="number" min="1" max="65535" defaultValue={asText(existingTransport.handshake_port, "443")} onChange={invalidateRealityProbe} required />
                        </label>
                        <div className="reality-target-check form-span">
                      <div>
                        <strong>{tr("Проверка target и SNI")}</strong>
                        <small>{tr("Основной SNI проверяется первым; затем каждое конкретное имя из SAN и введённого списка проверяется отдельным TLS-handshake.")}</small>
                      </div>
                      <button className="button button-secondary button-compact" type="button" disabled={realityProbeBusy} onClick={() => void checkRealityTarget()}>{realityProbeBusy ? tr("Проверяю…") : tr("Проверить target и SNI")}</button>
                      {realityProbeResult ? (
                        <div
                          className={`reality-probe-result is-${realityProbeTone}`}
                          role={realityProbeTone === "error" ? "alert" : "status"}
                        >
                          <strong>
                            {realityProbeTone === "error"
                              ? tr("Исправьте target")
                              : realityProbeTone === "warning"
                                ? tr("Совместимо с ограничением")
                                : tr("Проверка пройдена")}
                          </strong>
                          <small>{realityProbeResult}</small>
                          {realityProbeEndpoints.length ? (
                            <div className="reality-probe-endpoints" aria-label={tr("Проверенные адреса target")}>
                              {realityProbeEndpoints.map((endpoint, endpointIndex) => (
                                <span
                                  key={`${asText(endpoint.address, "endpoint")}-${endpointIndex}`}
                                  className={
                                    endpoint.ok === true
                                      ? "is-ok"
                                      : asText(endpoint.error_code, "") === "tls_probe_handshake_failed"
                                        ? "is-warning"
                                        : "is-error"
                                  }
                                >
                                  <code>{asText(endpoint.address, tr("IP не определён"))}</code>
                                  <small>
                                    {endpoint.ok === true
                                      ? `${asText(endpoint.tls_version, tr("TLS не определён"))} · ${asText(endpoint.alpn, tr("ALPN не согласован"))}`
                                      : asText(endpoint.error_message, tr("TLS-handshake не выполнен"))}
                                  </small>
                                </span>
                              ))}
                            </div>
                          ) : null}
                          {realityProbeWildcards.length ? (
                            <small>
                              Wildcard {realityProbeWildcards.join(", ")}  {tr("не добавляется автоматически. Введите конкретный поддомен и проверьте его.")} </small>
                          ) : null}
                        </div>
                      ) : null}
                        </div>
                      </>
                    ) : (
                      <aside className="notice notice-neutral form-span">
                        <span className="notice-icon">i</span>
                        <div>
                          <strong>{tr("Локальная API-маскировка")}</strong>
                          <p>{tr("Выберите ниже TLS-профиль, сертификат которого покрывает SNI. Внешний сайт для рукопожатия не используется.")}</p>
                        </div>
                      </aside>
                    )}
                    <div className="reality-sni-panel form-span">
                      <label className="field">
                         {tr("Дополнительные допустимые SNI")} <input
                          value={realitySniInput}
                          onChange={(event) => {
                            setRealitySniInput(event.target.value);
                            setRealitySniCheckPerformed(false);
                            setRealitySniChecks([]);
                          }}
                          placeholder="www.example.com, cdn.example.com"
                        />
                        <input
                          type="hidden"
                          name="server_names"
                          value={(effectiveRealityCoverMode === "api"
                            ? realitySniInput.split(/[\n,]/).map((value) => value.trim().toLowerCase()).filter(Boolean)
                            : realitySniCheckPerformed ? selectedRealitySnis : savedRealityServerNames).join(",")}
                        />
                        <small>{effectiveRealityCoverMode === "api" ? tr("Каждое имя должно входить в SAN выбранного сертификата.") : tr("Wildcard SAN не сохраняется: введите конкретное имя и запустите проверку.")}</small>
                      </label>
                      {realitySniChecks.length ? (
                        <div className="reality-sni-checks" aria-label={tr("Проверенные дополнительные SNI")}>
                          {realitySniChecks.map((item) => {
                            const confirmed = item.status === "confirmed";
                            const selected = selectedRealitySnis.includes(item.name);
                            return (
                              <label key={item.name} className={`reality-sni-option is-${item.status}`}>
                                <input
                                  type="checkbox"
                                  disabled={!confirmed}
                                  checked={confirmed && selected}
                                  onChange={() => setSelectedRealitySnis((current) =>
                                    current.includes(item.name)
                                      ? current.filter((name) => name !== item.name)
                                      : [...current, item.name]
                                  )}
                                />
                                <span>
                                  <strong>{item.name}</strong>
                                  <small>{confirmed ? tr("Подтверждено") : item.detail}</small>
                                </span>
                              </label>
                            );
                          })}
                        </div>
                      ) : null}
                    </div>
                    <details className="policy-check-advanced form-span">
                      <summary>{t("common.advanced")} · REALITY</summary>
                      <div className="form-grid">
                        {tcpStabilityFields}
                        <label className="field">
                           {tr("Минимальная версия клиента")} <input name="min_client_ver" defaultValue={asText(existingTransport.min_client_ver, "")} placeholder={tr("Без ограничения версии")} />
                        </label>
                        <label className="checkbox-field form-span">
                          <input name="reality_show" type="checkbox" defaultChecked={existingTransport.reality_show === true} />
                          <span><strong>{tr("Отладочный вывод REALITY")}</strong><small>{tr("Обычно выключен; включает подробные сообщения Xray для диагностики.")}</small></span>
                        </label>
                        <fieldset className="form-span nested-settings-group">
                          <legend>{tr("Ограничение непроверенного fallback · необязательно")}</legend>
                          <div className="form-grid">
                            <label className="field">{tr("Upload: после байт")}<input name="reality_fallback_upload_after_bytes" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_upload_after_bytes, "0")} /></label>
                            <label className="field">{tr("Upload: байт/сек.")}<input name="reality_fallback_upload_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_upload_bytes_per_sec, "0")} /></label>
                            <label className="field">{tr("Upload: burst байт/сек.")}<input name="reality_fallback_upload_burst_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_upload_burst_bytes_per_sec, "0")} /></label>
                            <label className="field">{tr("Download: после байт")}<input name="reality_fallback_download_after_bytes" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_download_after_bytes, "0")} /></label>
                            <label className="field">{tr("Download: байт/сек.")}<input name="reality_fallback_download_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_download_bytes_per_sec, "0")} /></label>
                            <label className="field">{tr("Download: burst байт/сек.")}<input name="reality_fallback_download_burst_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_download_burst_bytes_per_sec, "0")} /></label>
                          </div>
                          <small>{tr("Ограничивает только подключения, не прошедшие проверку REALITY. Скорость 0 отключает ограничение.")}</small>
                        </fieldset>
                        <label className="field">
                           {tr("Максимальная версия клиента")} <input name="max_client_ver" defaultValue={asText(existingTransport.max_client_ver, "")} placeholder={tr("Оставьте пустым")} />
                        </label>
                        <label className="field">
                           {tr("Допуск времени, мс")} <input name="max_time_diff" type="number" min="0" max="86400000" defaultValue={asText(existingTransport.max_time_diff, "0")} />
                        </label>
                        <label className="field">
                           {tr("PROXY protocol для fallback")} <select name="xver" defaultValue={asText(existingTransport.xver, "0")}>
                            <option value="0">{tr("Не передавать")}</option>
                            <option value="1">{tr("v1 · текстовый заголовок")}</option>
                            <option value="2">{tr("v2 · бинарный заголовок")}</option>
                          </select>
                          <small>{tr("Нужно только если fallback-сервис умеет принимать PROXY protocol.")}</small>
                        </label>
                        <label className="field">
                           {tr("spiderX клиента · необязательно")} <input name="spider_x" defaultValue={asText(existingTransport.spider_x, "")} placeholder="/" />
                          <small>{tr("Попадает в экспорт Xray-клиента. Пустое значение не добавляется.")}</small>
                        </label>
                        <label className="checkbox-field form-span">
                          <input name="reality_mldsa65_enabled" type="checkbox" defaultChecked={existingTransport.reality_mldsa65_enabled === true} />
                          <span><strong>{tr("ML-DSA-65 для REALITY")}</strong><small>{tr("Seed хранится в SecretStore, verify попадает клиенту. Target должен отдавать достаточно крупный сертификат; сначала проверьте его через `xray tls ping`.")}</small></span>
                        </label>
                      </div>
                    </details>
                    {transportKind === "reality-grpc" ? (
                      <details className="policy-check-advanced form-span">
                        <summary>{t("common.advanced")} · gRPC</summary>
                        <div className="form-grid">
                          {grpcClientTuningFields}
                        </div>
                      </details>
                    ) : null}
                  </>
                ) : null}
                {transportKind === "hysteria2" ? (
                  <>
                    <>
                        <details className="policy-check-advanced form-span">
                          <summary>{t("common.advanced")} · QUIC / masquerade</summary>
                          <div className="form-grid">
                            <label className="field">
                               {tr("UDP idle timeout, секунд")} <input name="hysteria_udp_idle_timeout" type="number" min="2" max="600" defaultValue={asText(existingXrayHysteria.udp_idle_timeout, "60")} required />
                              <small>{tr("Таймаут неактивной UDP-сессии Hysteria.")}</small>
                            </label>
                            <label className="field">
                               {tr("Управление перегрузкой QUIC")} <select
                                name="hysteria_congestion"
                                value={hysteriaCongestion}
                                onChange={(event) => setHysteriaCongestion(event.target.value)}
                              >
                                <option value="">{tr("Автоматически · Xray")}</option>
                                <option value="bbr">BBR</option>
                                <option value="brutal">Brutal</option>
                              </select>
                            </label>
                            {hysteriaCongestion === "brutal" ? (
                              <>
                                <label className="field">
                                   {tr("Brutal upload, Мбит/с")} <input name="hysteria_brutal_up_mbps" type="number" min="1" max="100000" defaultValue={asText(existingXrayQuic.brutal_up_mbps, "100")} required />
                                </label>
                                <label className="field">
                                   {tr("Brutal download, Мбит/с")} <input name="hysteria_brutal_down_mbps" type="number" min="1" max="100000" defaultValue={asText(existingXrayQuic.brutal_down_mbps, "100")} required />
                                </label>
                                <label className="checkbox-field form-span">
                                  <input name="hysteria_brutal_disable_loss_compensation" type="checkbox" defaultChecked={existingXrayQuic.brutal_disable_loss_compensation === true} />
                                  <span><strong>{tr("Brutal без компенсации потерь")}</strong><small>{tr("Не увеличивать скорость отправки для компенсации потерь.")}</small></span>
                                </label>
                              </>
                            ) : null}
                            <label className="field">
                               {tr("Max idle timeout QUIC, секунд")} <input name="hysteria_max_idle_timeout" type="number" min="4" max="120" defaultValue={asOptionalPositiveText(existingXrayQuic.max_idle_timeout)} placeholder={tr("Авто · 30")} />
                            </label>
                            <label className="field">
                               {tr("Keepalive QUIC, секунд")} <input name="hysteria_keep_alive_period" type="number" min="2" max="60" defaultValue={asOptionalPositiveText(existingXrayQuic.keep_alive_period) || (Object.keys(existingTransport).length ? "" : "15")} placeholder={tr("Пусто · выключено")} />
                            </label>
                            <label className="field">
                               {tr("Максимум входящих потоков")} <input name="hysteria_max_incoming_streams" type="number" min="8" max="1000000" defaultValue={asOptionalPositiveText(existingXrayQuic.max_incoming_streams)} placeholder={tr("Пусто · значение Xray")} />
                            </label>
                            <label className="checkbox-field">
                              <input name="hysteria_disable_path_mtu_discovery" type="checkbox" defaultChecked={existingXrayQuic.disable_path_mtu_discovery === true} />
                              <span><strong>{tr("Отключить Path MTU Discovery")}</strong><small>{tr("Используйте только при проблемах с MTU на маршруте.")}</small></span>
                            </label>
                            <label className="checkbox-field">
                              <input name="hysteria_disable_gso" type="checkbox" defaultChecked={existingXrayQuic.disable_gso === true} />
                              <span><strong>{tr("Отключить GSO")}</strong><small>{tr("Для несовместимых сетевых драйверов.")}</small></span>
                            </label>
                            <label className="checkbox-field">
                              <input name="hysteria_disable_stateless_reset" type="checkbox" defaultChecked={existingXrayQuic.disable_stateless_reset === true} />
                              <span><strong>{tr("Отключить Stateless Reset")}</strong><small>{tr("Не отправлять сброс для неизвестных QUIC-соединений.")}</small></span>
                            </label>
                            <label className="field">
                               {tr("Начальное окно потока, байты")} <input name="hysteria_init_stream_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.init_stream_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="field">
                               {tr("Максимальное окно потока, байты")} <input name="hysteria_max_stream_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.max_stream_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="field">
                               {tr("Начальное окно соединения, байты")} <input name="hysteria_init_connection_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.init_connection_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="field">
                               {tr("Максимальное окно соединения, байты")} <input name="hysteria_max_connection_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.max_connection_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="checkbox-field form-span">
                              <input
                                name="hysteria_udp_hop_enabled"
                                type="checkbox"
                                checked={hysteriaUDPHopEnabled}
                                onChange={(event) => setHysteriaUDPHopEnabled(event.target.checked)}
                              />
                              <span><strong>UDP port hopping</strong><small>{tr("Клиент меняет внешний порт, RouterOS перенаправляет диапазон на Hysteria.")}</small></span>
                            </label>
                            {hysteriaUDPHopEnabled ? (
                              <>
                                <label className="field">
                                   {tr("Первый UDP-порт")} <input name="hysteria_udp_hop_port_start" type="number" min="1024" max="65535" defaultValue={asText(existingXrayUDPHop.port_start, "20000")} required />
                                </label>
                                <label className="field">
                                   {tr("Последний UDP-порт")} <input name="hysteria_udp_hop_port_end" type="number" min="1024" max="65535" defaultValue={asText(existingXrayUDPHop.port_end, "20100")} required />
                                </label>
                                <label className="field">
                                   {tr("Минимальный интервал, секунд")} <input name="hysteria_udp_hop_interval_min" type="number" min="5" max="3600" defaultValue={asText(existingXrayUDPHop.interval_min, "15")} required />
                                </label>
                                <label className="field">
                                   {tr("Максимальный интервал, секунд")} <input name="hysteria_udp_hop_interval_max" type="number" min="5" max="3600" defaultValue={asText(existingXrayUDPHop.interval_max, "45")} required />
                                </label>
                                <label className="field form-span">
                                   {tr("Исключить занятые UDP-порты")} <input name="hysteria_udp_hop_excluded_ports" type="text" defaultValue={asText(existingXrayUDPHop.excluded_ports, "")} placeholder="20053, 20080" />
                                </label>
                              </>
                            ) : null}
                            <label className="field">
                               {tr("Masquerade для неизвестных запросов")} <select
                                name="hysteria_masquerade_type"
                                value={hysteriaMasqueradeType}
                                onChange={(event) => {
                                  setHysteriaMasqueradeType(event.target.value);
                                  if (event.target.value === "website") {
                                    setHysteriaWebsiteURL("");
                                    setHysteriaWebsiteBandwidth("1");
                                  }
                                }}
                              >
                                <option value="api">{tr("API JSON · рекомендуется")}</option>
                                <option value="">{tr("Стандартный ответ Xray")}</option>
                                <option value="string">{tr("Статический HTTP-ответ")}</option>
                                <option value="proxy">{tr("Локальный HTTP-сервис")}</option>
                                <option value="website">{tr("Проксировать сайт")}</option>
                              </select>
                              <small>{tr("API JSON отдаёт нейтральный 404 без данных о панели и Xray.")}</small>
                            </label>
                            {hysteriaMasqueradeType === "string" ? (
                              <>
                                <label className="field">
                                  HTTP status
                                  <input name="hysteria_masquerade_status_code" type="number" min="100" max="599" defaultValue={asText(existingXrayMasquerade.status_code, "200")} required />
                                </label>
                                <label className="field form-span">
                                   {tr("Тело ответа")} <textarea name="hysteria_masquerade_content" rows={4} maxLength={8192} defaultValue={asText(existingXrayMasquerade.content, "")} placeholder="Not found" />
                                </label>
                                <label className="field form-span">
                                   {tr("HTTP-заголовки · по одному на строку")} <textarea
                                    name="hysteria_masquerade_headers"
                                    rows={3}
                                    defaultValue={Object.entries(asObject(existingXrayMasquerade.headers)).map(([name, value]) => `${name}: ${asText(value, "")}`).join("\n")}
                                    placeholder={"Content-Type: text/plain\nCache-Control: no-store"}
                                  />
                                </label>
                              </>
                            ) : null}
                            {hysteriaMasqueradeType === "proxy" ? (
                              <>
                                <label className="field form-span">
                                   {tr("URL локального HTTP-сервиса")} <input name="hysteria_masquerade_url" type="url" pattern="http://(127\\.0\\.0\\.1|localhost|\\[::1\\])(:[0-9]{1,5})?(/.*)?" defaultValue={asText(existingXrayMasquerade.url, "")} placeholder="http://127.0.0.1:8080/" required />
                                  <small>{tr("Разрешён только loopback HTTP; внешний URL здесь намеренно запрещён.")}</small>
                                </label>
                                <label className="checkbox-field form-span">
                                  <input name="hysteria_masquerade_rewrite_host" type="checkbox" defaultChecked={existingXrayMasquerade.rewrite_host === true} />
                                  <span><strong>{tr("Переписать Host на адрес локального сервиса")}</strong><small>{tr("Иначе исходный Host запроса будет сохранён.")}</small></span>
                                </label>
                                <label className="checkbox-field form-span">
                                  <input name="hysteria_masquerade_x_forwarded" type="checkbox" defaultChecked={existingXrayMasquerade.x_forwarded === true} />
                                  <span><strong>{tr("Передавать X-Forwarded-*")}</strong><small>{tr("Только доверенному локальному HTTP-сервису.")}</small></span>
                                </label>
                              </>
                            ) : null}
                            {hysteriaMasqueradeType === "website" ? (
                              <>
                                <label className="field">
                                   {tr("Адрес сайта")} <input
                                    name="hysteria_masquerade_url"
                                    type="url"
                                    value={hysteriaWebsiteURL}
                                    onChange={(event) => setHysteriaWebsiteURL(event.target.value)}
                                    placeholder="https://example.com/"
                                    required
                                  />
                                </label>
                                <label className="field">
                                   {tr("Лимит скорости, Мбит/с")} <input
                                    name="hysteria_masquerade_bandwidth_mbps"
                                    type="number"
                                    min="0.1"
                                    max="100"
                                    step="0.1"
                                    value={hysteriaWebsiteBandwidth}
                                    onChange={(event) => setHysteriaWebsiteBandwidth(event.target.value)}
                                    required
                                  />
                                </label>
                                {hysteriaObfsEnabled ? (
                                  <small className="form-span">{tr("С Salamander сайт недоступен обычным HTTP/3-клиентам.")}</small>
                                ) : null}
                              </>
                            ) : null}
                          </div>
                        </details>
                    </>
                    <label className="checkbox-field form-span">
                      <input name="obfs_enabled" type="checkbox" checked={hysteriaObfsEnabled} onChange={(event) => setHysteriaObfsEnabled(event.target.checked)} />
                      <span><strong>Salamander obfuscation</strong><small>{tr("Пароль создаётся автоматически и хранится отдельно.")}</small></span>
                    </label>
                    <label className="checkbox-field form-span">
                      <input name="tls_pin_certificate" type="checkbox" defaultChecked={existingTransport.tls_pin_certificate === true} />
                      <span><strong>{tr("Закрепить выбранный TLS-сертификат")}</strong><small>{tr("Для самоподписанного сертификата профиль получит точный pin вместо небезопасного отключения проверки.")}</small></span>
                    </label>
                  </>
                ) : null}
                {sharedTlsManagedKind ? (
                  <>
                    <label className="field form-span">
                       {tr("TLS-профиль")} <select
                        name="tls_profile_id"
                        value={tlsProfileChoice}
                        onChange={(event) =>
                          selectTransportTlsProfile(event.target.value)
                        }
                        required
                      >
                        <option value="" disabled>{tr("Выберите TLS-профиль")}</option>
                        {tlsProfiles.map((profile) => (
                          <option
                            value={asText(profile.id, "")}
                            key={asText(profile.id, "")}
                          >
                            {itemName(profile)}
                            {asText(profile.certificate_secret_ref, "")
                              ? tr(" · настроен")
                              : tr(" · нужна пара")}
                          </option>
                        ))}
                      </select>
                    </label>
                    {tlsProfileChoice && !selectedTlsProfileComplete ? (
                      <small className="form-span">{tr("Настройте сертификат в TLS-профилях.")}</small>
                    ) : null}
                    {!tlsProfileChoice && tlsProfiles.length === 0 ? (
                      <small className="form-span">{tr("Создайте TLS-профиль в разделе TLS-профили.")}</small>
                    ) : null}
                  </>
                ) : cdnTransportKind ? (
                  <aside className="notice notice-neutral form-span">
                    <span className="notice-icon">i</span>
                    <div>
                      <strong>{tr("TLS origin настраивается в карточке каждого CDN")}</strong>
                      <p>
                         {tr("Так Cloudflare, Yandex и другие CDN могут использовать разные origin-домены, порты и сертификаты в одном транспортном профиле.")} </p>
                    </div>
                  </aside>
                ) : null}
                {transportRecommendation ? (
                  <section
                    className="transport-recommendations form-span"
                    aria-label={tr("Сброс параметров транспорта")}
                  >
                    <div className="transport-recommendations-heading">
                      <div>
                        <strong>{t("transport.base")}</strong>
                        <small>{t("transport.baseSafe")}</small>
                      </div>
                      <div className="transport-recommendations-actions">
                        {transportActionMenu}
                      </div>
                    </div>
                    {transportActionCount ? (
                      <div
                        className="transport-reset-summary"
                        role="status"
                        aria-live="polite"
                      >
                        <strong>{t("transport.resetStatus")}</strong>
                        <span>{selectedTransportActionLabels.join(" · ")}</span>
                      </div>
                    ) : null}
                  </section>
                ) : null}
                {directInboundKind || cdnTransportKind ? (
                  <Toggle
                    className="form-span direct-transport-enabled"
                    name="enabled"
                    checked={transportEnabled}
                    onChange={(enabled) => {
                      setTransportEnabled(enabled);
                      if (!enabled && cdnTransportKind) {
                        setCdnDeployments((current) =>
                          current.map((deployment) => ({ ...deployment, enabled: false })),
                        );
                      }
                    }}
                    tone="state"
                    label={tr("Транспорт включён")}
                    description={tr("Изменение вступит в силу только после проверки и Apply.")}
                  />
                ) : null}
              </div>
            )}
            {saveError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {saveError}
              </div>
            ) : null}
            <div className="modal-actions">
              {Boolean(subscriptionId) ? (
                <button
                  className="button button-danger"
                  type="button"
                  disabled={busy}
                  onClick={async () => {
                    if (!deleteArmed) {
                      setDeleteArmed(true);
                      setSaveError(
                        tr("Нажмите «Удалить подписку» ещё раз. Секретный URL останется в защищённом хранилище."),
                      );
                      return;
                    }
                    setBusy(true);
                    setSaveError("");
                    try {
                      await deleteCollectionItem(
                        "subscriptions",
                        workingSubscriptionId,
                      );
                      await onSaved();
                      onClose();
                    } catch (error) {
                      setSaveError(errorMessage(error));
                      setBusy(false);
                    }
                  }}
                >
                  {deleteArmed ? tr("Удалить подписку") : tr("Подготовить удаление")}
                </button>
              ) : null}
              <button
                className="button button-tertiary"
                type="button"
                onClick={onClose}
                disabled={busy}
              >
                 {tr("Отмена")} </button>
              <button
                className="button button-primary"
                type="submit"
                disabled={busy}
              >
                {busy
                  ? discoveryReady
                    ? tr("Сохраняю…")
                    : tr("Загружаю список…")
                  : kind === "subscription"
                    ? discoveryReady
                      ? tr("Сохранить выбор")
                      : tr("Проверить подписку и продолжить")
                    : tr("Сохранить изменения")}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}

function SetupWizard({
  onClose,
  onDraftChanged,
  config: initialConfig,
}: {
  onClose: () => void;
  onDraftChanged: () => Promise<void>;
  config: JsonObject;
}) {
  const { locale, tr } = useLanguage();
  const initialSystem = asObject(initialConfig.system);
  const initialManagement = asObject(initialSystem.management);
  const initialNetworking = asObject(initialSystem.networking);
  const initialDns = asObject(initialConfig.dns);
  const initialRouteros = asObject(initialConfig.routeros);
  const routerosConnectionSaved =
    typeof initialRouteros.base_url === "string" &&
    typeof initialRouteros.username_secret_ref === "string" &&
    typeof initialRouteros.password_secret_ref === "string" &&
    typeof initialRouteros.backup_password_secret_ref === "string";
  const initialImportReview = asObject(initialRouteros.import_review);
  const initialTopologySuggestions = asObject(
    initialImportReview.topology_suggestions,
  );
  const initialManagementNetworkSuggestions = asStringList(
    initialImportReview.management_network_suggestions,
  );
  const initialReviewNetworks = asObjectList(initialImportReview.networks);
  const initialConfiguredCidrs = new Set(
    asObjectList(initialConfig.networks)
      .filter(
        (network) =>
          network.enabled !== false &&
          ["internal", "management"].includes(asText(network.kind, "internal")),
      )
      .flatMap((network) => asStringList(network.cidrs)),
  );
  const configuredManagementCidr =
    asStringList(initialManagement.allowed_source_cidrs)[0] ?? "";
  const configuredBridgeName = asText(initialNetworking.bridge_name, "");
  const configuredVethName = asText(initialNetworking.veth_name, "");
  const configuredRouterGateway = asText(
    initialNetworking.routeros_gateway,
    "",
  );
  const configuredContainerAddress = asText(
    initialNetworking.container_address,
    "",
  );
  const configuredTunAddress = asText(initialNetworking.tun_address, "");
  const configuredInternalDns =
    asText(initialDns.internal_server, "") ||
    asText(initialNetworking.container_dns, "");
  const initialOfflinePrefilledFields = [
    !configuredManagementCidr &&
    initialManagementNetworkSuggestions.length > 0
      ? "management_cidr"
      : "",
    !configuredBridgeName &&
    asText(initialTopologySuggestions.bridge_name, "")
      ? "bridge_name"
      : "",
    !configuredVethName &&
    asText(initialTopologySuggestions.veth_name, "")
      ? "veth_name"
      : "",
    !configuredRouterGateway &&
    asText(initialTopologySuggestions.routeros_gateway, "")
      ? "routeros_gateway"
      : "",
    !configuredContainerAddress &&
    asText(initialTopologySuggestions.container_address, "")
      ? "container_address"
      : "",
    !configuredTunAddress &&
    asText(initialTopologySuggestions.tun_address, "")
      ? "tun_address"
      : "",
    !configuredInternalDns &&
    asText(initialTopologySuggestions.container_dns, "")
      ? "container_dns"
      : "",
  ].filter(Boolean);
  const hasInitialOfflineAddressPrefill = initialOfflinePrefilledFields.some(
    (field) =>
      [
        "management_cidr",
        "routeros_gateway",
        "container_address",
        "tun_address",
        "container_dns",
      ].includes(field),
  );
  const [step, setStep] = useState(0);
  const [exportName, setExportName] = useState("");
  const [exportFile, setExportFile] = useState<File | null>(null);
  const [channel, setChannel] = useState(
    asText(initialRouteros.channel, tr("не определён из .rsc")),
  );
  const [managementCidr, setManagementCidr] = useState(
    configuredManagementCidr ||
      initialManagementNetworkSuggestions[0] ||
      "",
  );
  const [managementIngressInterface, setManagementIngressInterface] = useState(
    asStringList(initialManagement.allowed_ingress_interfaces)[0] ?? "",
  );
  const [managementIngressSuggestions, setManagementIngressSuggestions] =
    useState<string[]>(
      asStringList(initialImportReview.management_ingress_suggestions),
    );
  const [managementNetworkSuggestions, setManagementNetworkSuggestions] =
    useState<string[]>(initialManagementNetworkSuggestions);
  const [topologySuggestions, setTopologySuggestions] = useState<JsonObject>(
    initialTopologySuggestions,
  );
  const [offlinePrefilledFields, setOfflinePrefilledFields] = useState<string[]>(
    initialOfflinePrefilledFields,
  );
  const [bridgeName, setBridgeName] = useState(
    configuredBridgeName ||
      asText(initialTopologySuggestions.bridge_name, ""),
  );
  const [vethName, setVethName] = useState(
    configuredVethName || asText(initialTopologySuggestions.veth_name, ""),
  );
  const [routerGateway, setRouterGateway] = useState(
    configuredRouterGateway ||
      asText(initialTopologySuggestions.routeros_gateway, ""),
  );
  const [containerAddress, setContainerAddress] = useState(
    configuredContainerAddress ||
      asText(initialTopologySuggestions.container_address, ""),
  );
  const [tunAddress, setTunAddress] = useState(
    configuredTunAddress || asText(initialTopologySuggestions.tun_address, ""),
  );
  const [internalDns, setInternalDns] = useState(
    configuredInternalDns ||
      asText(initialTopologySuggestions.container_dns, ""),
  );
  const [internalNetworks, setInternalNetworks] = useState<string[]>(
    initialReviewNetworks
      .filter(
        (item) =>
          networkReviewStatus(item.status) === "accepted" &&
          !initialConfiguredCidrs.has(asText(item.cidr, "")),
      )
      .map((item) => asText(item.cidr, ""))
      .filter(Boolean),
  );
  const [discoveredNetworks, setDiscoveredNetworks] = useState<string[]>(
    initialReviewNetworks
      .map((item) => asText(item.cidr, ""))
      .filter(Boolean),
  );
  const [networkDecisions, setNetworkDecisions] = useState<
    Record<string, NetworkReviewStatus>
  >(
    Object.fromEntries(
      initialReviewNetworks
        .map((item) => [
          asText(item.cidr, ""),
          networkReviewStatus(item.status),
        ])
        .filter(([cidr]) => Boolean(cidr)),
    ),
  );
  const [importCapabilities, setImportCapabilities] = useState<JsonObject>({});
  const [importWarnings, setImportWarnings] = useState<string[]>(
    asStringList(initialImportReview.posture_warnings),
  );
  const [importAnalyzed, setImportAnalyzed] = useState(
    typeof initialImportReview.source_fingerprint === "string",
  );
  const [manualNetworkCidr, setManualNetworkCidr] = useState("");
  const [networkQuery, setNetworkQuery] = useState("");
  const [networkStatusFilter, setNetworkStatusFilter] = useState<
    "all" | NetworkReviewStatus
  >("pending");
  const [subscriptionHost, setSubscriptionHost] = useState("");
  const [providerName, setProviderName] = useState(tr("Основной провайдер"));
  const [wizardBusy, setWizardBusy] = useState(false);
  const [wizardMessage, setWizardMessage] = useState("");
  const [wizardSaved, setWizardSaved] = useState(false);
  const routerBaseUrlRef = useRef<HTMLInputElement>(null);
  const routerSshPortRef = useRef<HTMLInputElement>(null);
  const routerUsernameRef = useRef<HTMLInputElement>(null);
  const routerPasswordRef = useRef<HTMLInputElement>(null);
  const routerCaRef = useRef<HTMLTextAreaElement>(null);
  const providerUrlRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!hasInitialOfflineAddressPrefill) return;
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const draft = await getCurrentDraft<{ config?: JsonObject }>();
          const config = asObject(draft.config);
          const system = asObject(config.system);
          const networking = asObject(system.networking);
          const dns = asObject(config.dns);
          if (
            networking.addresses_confirmed === false &&
            dns.address_confirmed === false
          ) {
            return;
          }
          await saveCurrentDraft({
            config: withDeploymentReadiness(
              {
                ...config,
                system: {
                  ...system,
                  networking: {
                    ...networking,
                    addresses_confirmed: false,
                  },
                },
                dns: {
                  ...dns,
                  address_confirmed: false,
                },
              },
              false,
            ),
          });
          await onDraftChanged();
        } catch (error) {
          setWizardMessage(
            tr("Не удалось сбросить подтверждение offline-кандидатов: {value1}", { value1: errorMessage(error) }),
          );
        }
      })();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [hasInitialOfflineAddressPrefill, onDraftChanged, tr]);

  const steps = [
    "MikroTik",
    tr("Сети"),
    tr("Удалённый вход"),
    tr("Провайдер"),
    tr("Проверка"),
  ];
  const manualNetworkChoices = internalNetworks.filter(
    (cidr) => !discoveredNetworks.includes(cidr),
  );
  const pendingNetworks = discoveredNetworks.filter(
    (cidr) => networkReviewStatus(networkDecisions[cidr]) === "pending",
  );
  const acceptedSuggestionCount = discoveredNetworks.filter(
    (cidr) => networkReviewStatus(networkDecisions[cidr]) === "accepted",
  ).length;
  const ignoredSuggestionCount = discoveredNetworks.filter(
    (cidr) => networkReviewStatus(networkDecisions[cidr]) === "ignored",
  ).length;
  const visibleDiscoveredNetworks = discoveredNetworks.filter((cidr) => {
    const query = networkQuery.trim().toLowerCase();
    const status = networkReviewStatus(networkDecisions[cidr]);
    return (
      (!query ||
        cidr.toLowerCase().includes(query) ||
        importedNetworkKind(cidr, managementNetworkSuggestions)
          .toLowerCase()
          .includes(query)) &&
      (networkStatusFilter === "all" || status === networkStatusFilter)
    );
  });
  const unknownImportCapabilities = routerCapabilityLabels.filter(
    ([name]) => typeof importCapabilities[name] !== "boolean",
  );
  const isOfflinePrefilled = (
    field: string,
    value: string,
    candidate: unknown,
  ) =>
    offlinePrefilledFields.includes(field) &&
    Boolean(value) &&
    value === asText(candidate, "");
  const activeOfflinePrefillCount = [
    isOfflinePrefilled(
      "management_cidr",
      managementCidr,
      managementNetworkSuggestions[0],
    ),
    isOfflinePrefilled(
      "bridge_name",
      bridgeName,
      topologySuggestions.bridge_name,
    ),
    isOfflinePrefilled(
      "veth_name",
      vethName,
      topologySuggestions.veth_name,
    ),
    isOfflinePrefilled(
      "routeros_gateway",
      routerGateway,
      topologySuggestions.routeros_gateway,
    ),
    isOfflinePrefilled(
      "container_address",
      containerAddress,
      topologySuggestions.container_address,
    ),
    isOfflinePrefilled(
      "tun_address",
      tunAddress,
      topologySuggestions.tun_address,
    ),
    isOfflinePrefilled(
      "container_dns",
      internalDns,
      topologySuggestions.container_dns,
    ),
  ].filter(Boolean).length;

  function decideNetwork(cidr: string, status: "accepted" | "ignored") {
    setNetworkDecisions((current) => ({ ...current, [cidr]: status }));
    setInternalNetworks((current) => {
      if (status === "accepted") {
        return current.includes(cidr) ? current : [...current, cidr];
      }
      return current.filter((item) => item !== cidr);
    });
  }

  function decideVisibleNetworks(status: "accepted" | "ignored") {
    if (!visibleDiscoveredNetworks.length) return;
    const visible = new Set(visibleDiscoveredNetworks);
    setNetworkDecisions((current) => ({
      ...current,
      ...Object.fromEntries(
        visibleDiscoveredNetworks.map((cidr) => [cidr, status]),
      ),
    }));
    setInternalNetworks((current) =>
      status === "accepted"
        ? [...new Set([...current, ...visibleDiscoveredNetworks])]
        : current.filter((cidr) => !visible.has(cidr)),
    );
  }

  async function advance() {
    setWizardMessage("");
    if (step === 0) {
      if (!exportFile) {
        setWizardMessage(
          tr("Выберите обычный экспорт RouterOS без флага show-sensitive."),
        );
        return;
      }
      const baseUrl = routerBaseUrlRef.current?.value.trim() ?? "";
      const routerSshPort = Number(routerSshPortRef.current?.value ?? "22");
      const routerUsername = routerUsernameRef.current?.value.trim() ?? "";
      const routerPassword = routerPasswordRef.current?.value ?? "";
      const caCertificate = routerCaRef.current?.value.trim() ?? "";
      if (!isExplicitRouterHttpsOrigin(baseUrl) || !routerUsername) {
        setWizardMessage(
          tr("Укажите HTTPS origin RouterOS REST с явным портом www-ssl и отдельного пользователя управления."),
        );
        return;
      }
      if (!Number.isInteger(routerSshPort) || routerSshPort < 1 || routerSshPort > 65535) {
        setWizardMessage(tr("Укажите действующий SSH-порт RouterOS для Safe Mode."));
        routerSshPortRef.current?.focus();
        return;
      }
      if (routerPassword.length < 16) {
        setWizardMessage(tr("Пароль RouterOS должен содержать не менее 16 символов."));
        routerPasswordRef.current?.focus();
        return;
      }
      if (routerPasswordRef.current) routerPasswordRef.current.value = "";
      if (routerCaRef.current) routerCaRef.current.value = "";
      setWizardBusy(true);
      try {
        const result = await importRouterOsExport(exportFile);
        const resultObject = asObject(result);
        const discovered = asObject(resultObject.discovered);
        if (typeof discovered.channel === "string") {
          setChannel(discovered.channel);
        } else {
          setChannel(tr("не определён из .rsc"));
        }
        const importedInventory = asObjectList(resultObject.network_inventory);
        const fallbackSuggestions = asStringList(
          resultObject.network_suggestions,
        );
        const inventoryRows = importedInventory.length
          ? importedInventory
          : fallbackSuggestions.map((cidr) => ({
              cidr,
              status: "pending",
            }));
        const suggestedNetworks = inventoryRows
          .map((item) => asText(item.cidr, ""))
          .filter(Boolean);
        const importedDecisions = Object.fromEntries(
          inventoryRows
            .map((item) => [
              asText(item.cidr, ""),
              networkReviewStatus(item.status),
            ])
            .filter(([cidr]) => Boolean(cidr)),
        );
        const suggestedIngressInterfaces = asStringList(
          resultObject.management_ingress_suggestions ??
            discovered.management_ingress_suggestions,
        );
        const suggestedManagementNetworks = asStringList(
          resultObject.management_network_suggestions ??
            discovered.management_network_suggestions,
        );
        const suggestedTopology = asObject(
          resultObject.topology_suggestions ??
            discovered.topology_suggestions,
        );
        const newlyPrefilled: string[] = [];
        const prefill = (
          field: string,
          current: string,
          value: unknown,
          setter: (value: string) => void,
        ) => {
          const candidate = asText(value, "").trim();
          if (!current.trim() && candidate) {
            setter(candidate);
            newlyPrefilled.push(field);
          }
        };
        prefill(
          "management_cidr",
          managementCidr,
          suggestedManagementNetworks[0],
          setManagementCidr,
        );
        prefill(
          "bridge_name",
          bridgeName,
          suggestedTopology.bridge_name,
          setBridgeName,
        );
        prefill(
          "veth_name",
          vethName,
          suggestedTopology.veth_name,
          setVethName,
        );
        prefill(
          "routeros_gateway",
          routerGateway,
          suggestedTopology.routeros_gateway,
          setRouterGateway,
        );
        prefill(
          "container_address",
          containerAddress,
          suggestedTopology.container_address,
          setContainerAddress,
        );
        prefill(
          "tun_address",
          tunAddress,
          suggestedTopology.tun_address,
          setTunAddress,
        );
        prefill(
          "container_dns",
          internalDns,
          suggestedTopology.container_dns,
          setInternalDns,
        );
        setInternalNetworks((current) => {
          const retained = current.filter(
            (cidr) => !discoveredNetworks.includes(cidr),
          );
          const newlyAccepted = suggestedNetworks.filter(
            (cidr) =>
              networkReviewStatus(importedDecisions[cidr]) === "accepted" &&
              !initialConfiguredCidrs.has(cidr),
          );
          return [...new Set([...retained, ...newlyAccepted])];
        });
        setDiscoveredNetworks(suggestedNetworks);
        setNetworkDecisions(importedDecisions);
        setManagementIngressSuggestions(suggestedIngressInterfaces);
        setManagementNetworkSuggestions(suggestedManagementNetworks);
        setTopologySuggestions(suggestedTopology);
        setOfflinePrefilledFields((current) => [
          ...new Set([...current, ...newlyPrefilled]),
        ]);
        setImportCapabilities(asObject(discovered.capabilities));
        setImportWarnings(asStringList(resultObject.warnings));
        setImportAnalyzed(true);
        if (
          newlyPrefilled.some((field) =>
            [
              "management_cidr",
              "routeros_gateway",
              "container_address",
              "tun_address",
              "container_dns",
            ].includes(field),
          )
        ) {
          const importedDraft = await getCurrentDraft<{
            config?: JsonObject;
          }>();
          const importedConfig = asObject(importedDraft.config);
          const importedSystem = asObject(importedConfig.system);
          const importedNetworking = asObject(importedSystem.networking);
          const importedDns = asObject(importedConfig.dns);
          await saveCurrentDraft({
            config: withDeploymentReadiness(
              {
                ...importedConfig,
                system: {
                  ...importedSystem,
                  networking: {
                    ...importedNetworking,
                    addresses_confirmed: false,
                  },
                },
                dns: {
                  ...importedDns,
                  address_confirmed: false,
                },
              },
              false,
            ),
          });
        }
        await provisionRouterOsCredentials({
          base_url: baseUrl,
          username: routerUsername,
          password: routerPassword,
          ssh_port: routerSshPort,
          ca_certificate: caCertificate || undefined,
        });
        await onDraftChanged();
        setStep(1);
      } catch (error) {
        setWizardMessage(errorMessage(error));
        await onDraftChanged();
      } finally {
        setWizardBusy(false);
      }
      return;
    }
    if (step === 1) {
      if (!managementIngressInterface.trim()) {
        setWizardMessage(
          tr("Выберите предложенный bridge или введите точное имя фактического management ingress-интерфейса."),
        );
        return;
      }
      if (!bridgeName.trim() || !vethName.trim() || bridgeName === vethName) {
        setWizardMessage(
          tr("Проверьте имена нового container bridge и veth: оба обязательны и должны различаться."),
        );
        return;
      }
      if (pendingNetworks.length) {
        setWizardMessage(
          tr("Для {value1} сетевых подсказок ещё не выбрано «принять» или «игнорировать». К следующему шагу перейти нельзя.", { value1: pendingNetworks.length }),
        );
        return;
      }
      if (!isIpv4Cidr(managementCidr, false)) {
        setWizardMessage(
          tr("Укажите фактический IPv4 management CIDR с префиксом, например /24 или /32."),
        );
        return;
      }
      if (!routerGateway.trim() || routerGateway.includes("/")) {
        setWizardMessage(
          tr("Укажите фактический IPv4 RouterOS на container bridge без префикса."),
        );
        return;
      }
      if (!containerAddress.trim() || !containerAddress.includes("/")) {
        setWizardMessage(
          tr("Укажите фактический IPv4/CIDR контейнера на veth — он должен совпадать с SB_CONTAINER_ADDRESS."),
        );
        return;
      }
      if (!tunAddress.trim() || !tunAddress.includes("/")) {
        setWizardMessage(
          tr("Укажите подтверждённый TUN IPv4/CIDR, который не пересекается с вашими сетями."),
        );
        return;
      }
      if (!internalDns.trim() || internalDns.includes("/")) {
        setWizardMessage(
          tr("Укажите фактический IP внутреннего DNS; обычно это RouterOS на container bridge."),
        );
        return;
      }
    }
    if (step === 2 && subscriptionHost && !subscriptionHost.includes(".")) {
      setWizardMessage(
        tr("Укажите фактическое DNS-имя клиентской HTTPS-подписки."),
      );
      return;
    }
    if (step === 3) {
      const providerUrl = providerUrlRef.current?.value.trim() ?? "";
      if (providerUrlRef.current) providerUrlRef.current.value = "";
      if (!providerUrl) {
        setStep(4);
        return;
      }
      if (!providerUrl.startsWith("https://")) {
        setWizardMessage(
          tr("Подписка должна использовать HTTPS. Введите URL ещё раз."),
        );
        return;
      }
      setWizardBusy(true);
      try {
        const draft = await getCurrentDraft<{ config?: JsonObject }>();
        const config = asObject(draft.config);
        const provider = {
          id: "provider-main",
          display_name: providerName,
          enabled: true,
          url: providerUrl,
          refresh_minutes: 360,
          allowed_locations: [],
        };
        const providerExists = asObjectList(config.subscriptions).some(
          (item) => item.id === "provider-main",
        );
        if (providerExists) {
          await updateCollectionItem("subscriptions", "provider-main", provider);
        } else {
          await createCollectionItem("subscriptions", provider);
        }
        await onDraftChanged();
        setStep(4);
      } catch (error) {
        setWizardMessage(errorMessage(error));
        await onDraftChanged();
      } finally {
        setWizardBusy(false);
      }
      return;
    }
    if (step < steps.length - 1) {
      setStep(step + 1);
      return;
    }

    setWizardBusy(true);
    try {
      const draft = await getCurrentDraft<{ config?: JsonObject }>();
      const config = asObject(draft.config);
      const system = asObject(config.system);
      const management = asObject(system.management);
      const networking = asObject(system.networking);
      const routeros = asObject(config.routeros);
      const importReview = asObject(routeros.import_review);
      const ingress = asObject(config.ingress);
      const dns = asObject(config.dns);

      const existingNetworks = asObjectList(config.networks);
      const retainedNetworks = existingNetworks.filter(
        (network) =>
          !["wizard-internal-", "management-lan"].some((prefix) =>
            String(network.id ?? "").startsWith(prefix),
          ),
      );
      const wizardNetworks = internalNetworks.map((cidr, index) => ({
        id: `wizard-internal-${index + 1}`,
        enabled: true,
        kind: "internal",
        cidrs: [cidr],
      }));
      const nextNetworks = [
        ...retainedNetworks,
        ...wizardNetworks,
        {
          id: "management-lan",
          enabled: true,
          kind: "management",
          cidrs: [managementCidr],
        },
      ];

      const currentTransports = asObjectList(config.transports);
      await saveCurrentDraft({
        config: withDeploymentReadiness({
          ...config,
          routeros: {
            ...routeros,
            channel_policy: "informational",
            preserve_channel: true,
            automatic_update: false,
            import_review: {
              ...importReview,
              networks: discoveredNetworks.map((cidr) => ({
                cidr,
                status: networkReviewStatus(networkDecisions[cidr]),
              })),
            },
          },
          system: {
            ...system,
            management: {
              ...management,
              allowed_source_cidrs: [managementCidr],
              allowed_ingress_interfaces: [managementIngressInterface],
            },
            networking: {
              ...networking,
              bridge_name: bridgeName,
              veth_name: vethName,
              routeros_gateway: routerGateway,
              container_address: containerAddress,
              container_dns: internalDns,
              tun_address: tunAddress,
              addresses_confirmed: true,
            },
          },
          dns: {
            ...dns,
            internal_server: internalDns,
            address_confirmed: true,
          },
          ingress: {
            ...ingress,
            status_hostname: "",
            subscription_endpoint_enabled: Boolean(subscriptionHost),
            subscription_hostname: subscriptionHost,
            subscription_listen_port: Number(
              ingress.subscription_listen_port ?? ingress.public_listen_port ?? 443,
            ),
            subscription_public_port: Number(
              ingress.subscription_public_port ?? ingress.subscription_listen_port ?? ingress.public_listen_port ?? 443,
            ),
            subscription_tls_profile_id: asText(
              ingress.tls_profile_id,
              "cdn-default",
            ),
          },
          networks: nextNetworks,
          transports: currentTransports.map((transport) => ({
            ...transport,
            enabled: false,
            cdn_deployments: cdnDeploymentsForTransport(transport).map((deployment) => ({
              ...deployment,
              enabled: false,
            })),
          })),
          tls_profiles: asObjectList(config.tls_profiles).filter(
            (profile) =>
              Boolean(asText(profile.certificate_secret_ref, "")) ||
              Boolean(asText(profile.private_key_secret_ref, "")),
          ),
        }, false),
      });
      await onDraftChanged();
      setWizardSaved(true);
      setWizardMessage(
        tr("Черновик сохранён. Теперь запустите проверку и изучите точный план изменений."),
      );
    } catch (error) {
      setWizardMessage(errorMessage(error));
      await onDraftChanged();
    } finally {
      setWizardBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="modal setup-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="setup-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        <div className="setup-heading">
          <div>
            <p className="eyebrow">{tr("Первичная настройка")}</p>
            <h2 id="setup-title">{tr("Подготовим шлюз без догадок")}</h2>
            <p>
               {tr("Мастер собирает реальные параметры в черновик. Ничего не применяется до preflight, backup и вашего подтверждения.")} </p>
          </div>
          <StatusPill tone="info">
             {tr("Шаг")} {step + 1}  {tr("из")} {steps.length}
          </StatusPill>
        </div>

        <ol className="wizard-steps" aria-label={tr("Этапы настройки")}>
          {steps.map((label, index) => (
            <li
              className={index === step ? "wizard-current" : ""}
              key={label}
            >
              <span>{index < step ? "✓" : index + 1}</span>
              <small>{label}</small>
            </li>
          ))}
        </ol>

        <div className="wizard-body">
          {step === 0 ? (
            <div>
              <h3>{tr("Сначала разберём офлайн-снимок конфигурации")}</h3>
              <p>
                 {tr("Загрузите обычный")} <code>{tr("/export file=имя")}</code>  {tr("без флага show-sensitive. Панель прочитает сохранённые интерфейсы, маршруты, VPN и FastTrack. Архитектура, пакеты, device-mode, накопители и доступность REST подтверждаются только последующим live preflight.")} </p>
              <label className="drop-zone">
                <input
                  type="file"
                  accept=".rsc,.txt"
                  onChange={(event) => {
                    const file = event.target.files?.[0] ?? null;
                    setExportFile(file);
                    setExportName(file?.name ?? "");
                    setWizardMessage("");
                  }}
                />
                <span className="drop-icon">⇧</span>
                <strong>{exportName || "Выберите экспорт MikroTik"}</strong>
                <small>{tr("Секреты в экспорт включать нельзя")}</small>
              </label>
              <div className="form-grid">
                <label className="field">
                  RouterOS REST HTTPS URL
                  <input
                    ref={routerBaseUrlRef}
                    type="url"
                    pattern="https://.+:[0-9]+/?"
                    defaultValue={asText(initialRouteros.base_url, "")}
                    placeholder="https://172.31.255.1:59443"
                    required
                  />
                  <small>
                     {tr("RouterOS REST обслуживается службой www-ssl, не api-ssl. В URL укажите выбранный свободный порт; TCP 443 нельзя считать свободным по умолчанию. В Available From оставьте ровно выбранные management CIDR и container /32, без 0.0.0.0/0. Только HTTPS, проверка сертификата не отключается.")} </small>
                </label>
                <label className="field">
                   {tr("SSH-порт RouterOS для Safe Mode")} <input
                    ref={routerSshPortRef}
                    type="number"
                    min={1}
                    max={65535}
                    defaultValue={
                      typeof initialRouteros.ssh_port === "number"
                        ? initialRouteros.ssh_port
                        : 22
                    }
                    required
                  />
                  <small>
                     {tr("Через постоянную SSH-сессию панель применяет патч в Safe Mode. При потере связи RouterOS откатит незавершённые изменения.")} </small>
                </label>
                <label className="field">
                   {tr("Отдельный REST-пользователь")} <input
                    ref={routerUsernameRef}
                    defaultValue="sb-gateway-api"
                    autoComplete="username"
                    required
                  />
                </label>
                <label className="field">
                   {tr("Пароль RouterOS · минимум 16 символов")} <input
                    ref={routerPasswordRef}
                    type="password"
                    minLength={16}
                    autoComplete="new-password"
                    required
                  />
                </label>
                <div className="locked-field">
                  <span>{tr("Шифрование резервных копий")}</span>
                  <strong>{tr("Пароль администратора панели")}</strong>
                  <small>{tr("Отдельный пароль не требуется")}</small>
                </div>
                <label className="field form-span">
                   {tr("CA certificate PEM для RouterOS (если не публичный CA)")} <textarea
                    ref={routerCaRef}
                    rows={5}
                    autoComplete="off"
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                  <small>
                     {tr("Оставьте пустым только для сертификата, уже доверенного системным хранилищем. Режима insecure skip нет.")} </small>
                </label>
              </div>
              <div className="wizard-inline-fields">
                <label className="field">
                   {tr("Канал из .rsc · только офлайн-метаданные")} <input
                    value={channel}
                    readOnly
                  />
                  <small>
                     {tr("Любой канал RouterOS 7 разрешён; Apply проверяет только capabilities и не переключает канал.")} </small>
                </label>
                <div className="locked-field">
                  <span>{tr("Проверка версии")}</span>
                  <strong>{tr("По возможностям RouterOS 7")}</strong>
                  <small>{tr("Без точного hardcode номера")}</small>
                </div>
              </div>
              {importAnalyzed ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>{tr(".rsc импортирован, но live preflight ещё не выполнен")}</strong>
                    <p>
                       {tr("Неопределённых обязательных capabilities:")}{" "}
                      {unknownImportCapabilities.length}{tr(". Неизвестное состояние никогда не считается успешной проверкой.")} </p>
                    <p>
                       {tr("После настройки мастер сохранит черновик. Перед Apply control plane заново прочитает текущий RouterOS через HTTPS REST и проверит все обязательные возможности.")} </p>
                    {importWarnings.length ? (
                      <ul>
                        {importWarnings.map((warning) => (
                          <li key={warning}>
                            {routerImportWarningText(warning, locale)}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                </aside>
              ) : null}
              {importAnalyzed && routerosConnectionSaved && !exportFile ? (
                <aside className="notice notice-safe">
                  <span className="notice-icon">✓</span>
                  <div>
                    <strong>{tr("Сохранённый импорт и HTTPS REST уже готовы")}</strong>
                    <p>
                       {tr("Можно продолжить review без повторной загрузки `.rsc` и без повторного ввода секретов. Live preflight всё равно будет выполнен перед Apply.")} </p>
                    <div className="card-actions">
                      <button
                        className="button button-primary"
                        type="button"
                        onClick={() => setStep(1)}
                      >
                         {tr("Продолжить с сохранённым снимком")} </button>
                    </div>
                  </div>
                </aside>
              ) : null}
            </div>
          ) : null}

          {step === 1 ? (
            <div>
              <h3>{tr("Какие сети действительно внутренние?")}</h3>
              <p>
                 {tr("Не выбирайте весь приватный диапазон. Только эти точные сети будут обходить proxy-ядро и идти обычными маршрутами RouterOS.")} </p>
              {activeOfflinePrefillCount ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>
                       {tr("Заполнены офлайн-кандидаты:")} {activeOfflinePrefillCount}
                    </strong>
                    <p>
                       {tr("Они подобраны без пересечения с сетями из `.rsc`, но файл не показывает актуальное состояние RouterOS. Проверьте каждое значение. До финального сохранения мастер держит")}{" "}
                      <code>addresses_confirmed=false</code>{tr("; затем Apply всё равно потребует live discovery.")} </p>
                  </div>
                </aside>
              ) : null}
              <label className="field">
                 {tr("Доверенный ingress-интерфейс панели")} <input
                  list="management-ingress-options"
                  value={managementIngressInterface}
                  onChange={(event) =>
                    setManagementIngressInterface(event.target.value)
                  }
                  placeholder={tr("Выберите bridge или введите точное имя")}
                  required
                />
                <datalist id="management-ingress-options">
                  {managementIngressSuggestions.map((interfaceName) => (
                    <option value={interfaceName} key={interfaceName}>
                      {interfaceName}
                    </option>
                  ))}
                </datalist>
                <small>
                   {tr("Панель будет принимать управление только с выбранного локального bridge. Кандидаты из списка — лишь эвристика экспорта; точное ручное имя допустимо и обязательно проверяется live preflight.")} </small>
              </label>
              {!managementIngressSuggestions.length ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>{tr("Экспорт не предложил доверенный bridge")}</strong>
                    <p>
                       {tr("Эвристика не является источником истины. Введите точное имя фактического LAN/management bridge вручную; не выбирайте WAN. Live preflight проверит интерфейс до Apply.")} </p>
                  </div>
                </aside>
              ) : null}
              {managementIngressInterface &&
              !managementIngressSuggestions.includes(
                managementIngressInterface,
              ) ? (
                <aside className="notice notice-neutral">
                  <span className="notice-icon">i</span>
                  <div>
                    <strong>{tr("Интерфейс введён вручную")}</strong>
                    <p>
                       {tr("Офлайн-экспорт не классифицировал его как management ingress. Значение будет принято только после live-проверки; WAN-интерфейс здесь выбирать нельзя.")} </p>
                  </div>
                </aside>
              ) : null}
              <label className="field">
                Management CIDR
                <input
                  value={managementCidr}
                  onChange={(event) => setManagementCidr(event.target.value)}
                  placeholder={tr("Введите фактическую management сеть")}
                />
                <small>
                  {isOfflinePrefilled(
                    "management_cidr",
                    managementCidr,
                    managementNetworkSuggestions[0],
                  )
                    ? tr("Кандидат из offline export · проверьте фактическую management-сеть; live-подтверждения ещё нет.")
                    : tr("Отсюда будет доступна панель на порту 9443.")}
                </small>
              </label>
              <div className="form-grid">
                <label className="field">
                   {tr("Имя нового container bridge")} <input
                    value={bridgeName}
                    onChange={(event) => setBridgeName(event.target.value)}
                    placeholder={tr("Введите свободное имя bridge")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "bridge_name",
                      bridgeName,
                      topologySuggestions.bridge_name,
                    )
                      ? tr("Кандидат из offline export · коллизий в файле не найдено, live-проверка обязательна.")
                      : tr("Имя не должно совпадать с существующим интерфейсом RouterOS.")}
                  </small>
                </label>
                <label className="field">
                   {tr("Имя нового veth")} <input
                    value={vethName}
                    onChange={(event) => setVethName(event.target.value)}
                    placeholder={tr("Введите свободное имя veth")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "veth_name",
                      vethName,
                      topologySuggestions.veth_name,
                    )
                      ? tr("Кандидат из offline export · коллизий в файле не найдено, live-проверка обязательна.")
                      : tr("Имя будет использовано только для контейнера SB-GATEWAY.")}
                  </small>
                </label>
                <label className="field">
                   {tr("RouterOS IP на container bridge")} <input
                    value={routerGateway}
                    onChange={(event) => setRouterGateway(event.target.value)}
                    placeholder={tr("Введите адрес из вашего WebFig bootstrap")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "routeros_gateway",
                      routerGateway,
                      topologySuggestions.routeros_gateway,
                    )
                      ? tr("Непересекающийся кандидат из offline export · не фактический адрес и не live-подтверждение.")
                      : tr("Должен совпадать с фактическим SB_ROUTER_IP; пример из ТЗ автоматически не подставляется.")}
                  </small>
                </label>
                <label className="field">
                  Container IPv4/CIDR
                  <input
                    value={containerAddress}
                    onChange={(event) => setContainerAddress(event.target.value)}
                    placeholder={tr("Фактический SB_CONTAINER_ADDRESS с префиксом")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "container_address",
                      containerAddress,
                      topologySuggestions.container_address,
                    )
                      ? tr("Непересекающийся кандидат из offline export · проверьте подсеть и свободный адрес live.")
                      : tr("Должен быть отдельным адресом той же container bridge-подсети; пример из ТЗ автоматически не подставляется.")}
                  </small>
                </label>
                <label className="field">
                  TUN IPv4/CIDR
                  <input
                    value={tunAddress}
                    onChange={(event) => setTunAddress(event.target.value)}
                    placeholder={tr("Выберите свободную непересекающуюся подсеть")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "tun_address",
                      tunAddress,
                      topologySuggestions.tun_address,
                    )
                      ? tr("Непересекающийся кандидат из offline export · Apply повторно проверит live LAN/VPN-маршруты.")
                      : tr("Apply проверит пересечение с импортированными LAN/VPN сетями.")}
                  </small>
                </label>
                <label className="field form-span">
                   {tr("Внутренний DNS")} <input
                    value={internalDns}
                    onChange={(event) => setInternalDns(event.target.value)}
                    placeholder={tr("Фактический IP RouterOS или другого DNS")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "container_dns",
                      internalDns,
                      topologySuggestions.container_dns,
                    )
                      ? tr("Кандидат из offline export · должен быть подтверждён как фактический внутренний DNS.")
                      : tr("Внутренние зоны не отправляются внешнему DNS-провайдеру.")}
                  </small>
                </label>
              </div>
              <div className="wizard-inline-fields">
                <label className="field">
                   {tr("Добавить внутренний CIDR вручную")} <input
                    value={manualNetworkCidr}
                    onChange={(event) => setManualNetworkCidr(event.target.value)}
                    placeholder={tr("Введите точный IPv4/IPv6 CIDR")}
                  />
                </label>
                <button
                  className="button button-secondary"
                  type="button"
                  disabled={
                    !manualNetworkCidr.trim() ||
                    !manualNetworkCidr.includes("/")
                  }
                  onClick={() => {
                    const cidr = manualNetworkCidr.trim();
                    setInternalNetworks((current) =>
                      current.includes(cidr) ? current : [...current, cidr],
                    );
                    setManualNetworkCidr("");
                  }}
                >
                   {tr("Добавить CIDR")} </button>
              </div>
              {!discoveredNetworks.length && !manualNetworkChoices.length ? (
                <aside className="notice notice-neutral">
                  <span className="notice-icon">i</span>
                  <div>
                    <strong>{tr("Экспорт не дал сетевых подсказок")}</strong>
                    <p>
                       {tr("Список намеренно пуст. Добавьте только проверенные CIDR вручную; демонстрационные адреса не подставляются.")} </p>
                  </div>
                </aside>
              ) : null}
              {discoveredNetworks.length ? (
                <div className="network-review-toolbar">
                  <label className="search-field">
                    <span className="sr-only">{tr("Найти импортированную сеть")}</span>
                    <input
                      value={networkQuery}
                      onChange={(event) => setNetworkQuery(event.target.value)}
                      placeholder={tr("CIDR или тип сети")}
                    />
                  </label>
                  <label className="field compact-field">
                     {tr("Показывать")} <select
                      value={networkStatusFilter}
                      onChange={(event) =>
                        setNetworkStatusFilter(
                          event.target.value as "all" | NetworkReviewStatus,
                        )
                      }
                    >
                      <option value="pending">{tr("Требуют решения")}</option>
                      <option value="accepted">{tr("Принятые")}</option>
                      <option value="ignored">{tr("Игнорируемые")}</option>
                      <option value="all">{tr("Все")}</option>
                    </select>
                  </label>
                  <div className="card-actions network-review-bulk">
                    <button
                      className="button button-secondary"
                      type="button"
                      disabled={!visibleDiscoveredNetworks.length}
                      onClick={() => decideVisibleNetworks("accepted")}
                    >
                       {tr("Принять видимые ·")} {visibleDiscoveredNetworks.length}
                    </button>
                    <button
                      className="button button-tertiary"
                      type="button"
                      disabled={!visibleDiscoveredNetworks.length}
                      onClick={() => decideVisibleNetworks("ignored")}
                    >
                       {tr("Игнорировать видимые ·")} {visibleDiscoveredNetworks.length}
                    </button>
                  </div>
                  <small>
                     {tr("Массовое действие применяется только к текущему фильтру и остаётся явным решением в черновике. Для полного переноса существующих VPN-маршрутов можно показать все и принять их.")} </small>
                </div>
              ) : null}
              {discoveredNetworks.length ? (
                <aside
                  className={
                    pendingNetworks.length
                      ? "notice notice-danger"
                      : "notice notice-safe"
                  }
                >
                  <span className="notice-icon">
                    {pendingNetworks.length ? "!" : "✓"}
                  </span>
                  <div>
                    <strong>
                      {pendingNetworks.length
                        ? tr("Ожидают решения: {value1}", { value1: pendingNetworks.length })
                        : tr("Все подсказки классифицированы")}
                    </strong>
                    <p>
                       {tr("Принято:")} {acceptedSuggestionCount}{tr("; проигнорировано:")}{" "}
                      {ignoredSuggestionCount}{tr(". Простое отсутствие галочки не считается решением.")} </p>
                  </div>
                </aside>
              ) : null}
              <div className="discovered-networks">
                {visibleDiscoveredNetworks.map((cidr) => {
                  const decision = networkReviewStatus(networkDecisions[cidr]);
                  return (
                    <div className="checkbox-field" key={cidr}>
                      <span aria-hidden="true">
                        {decision === "accepted"
                          ? "✓"
                          : decision === "ignored"
                            ? "×"
                            : "?"}
                      </span>
                      <span>
                        <strong>{cidr}</strong>
                        <small>
                          {importedNetworkKind(
                            cidr,
                            managementNetworkSuggestions,
                          )}  {tr("· подсказка из офлайн-экспорта")} </small>
                      </span>
                      <div
                        className="card-actions"
                        role="group"
                        aria-label={tr("Тип сети {value1}", { value1: cidr })}
                      >
                        <button
                          className={`button ${
                            decision === "accepted"
                              ? "button-primary"
                              : "button-secondary"
                          }`}
                          type="button"
                          aria-pressed={decision === "accepted"}
                          onClick={() => decideNetwork(cidr, "accepted")}
                        >
                           {tr("Принять как внутреннюю")} </button>
                        <button
                          className={`button ${
                            decision === "ignored"
                              ? "button-primary"
                              : "button-tertiary"
                          }`}
                          type="button"
                          aria-pressed={decision === "ignored"}
                          onClick={() => decideNetwork(cidr, "ignored")}
                        >
                           {tr("Игнорировать")} </button>
                      </div>
                    </div>
                  );
                })}
                {!visibleDiscoveredNetworks.length && discoveredNetworks.length ? (
                  <div className="empty-result">
                     {tr("По выбранному фильтру сетей нет.")} </div>
                ) : null}
                {manualNetworkChoices.map((cidr) => (
                  <label key={`manual-${cidr}`}>
                    <input
                      type="checkbox"
                      checked
                      onChange={() =>
                        setInternalNetworks((current) =>
                          current.filter((item) => item !== cidr),
                        )
                      }
                    />
                    <span>
                      <strong>{cidr}</strong>
                      <small>{tr("Добавлено вручную · снимите флажок, чтобы удалить")}</small>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          ) : null}

          {step === 2 ? (
            <div>
              <h3>{tr("HTTPS-подписка для удалённых устройств")}</h3>
              <p>
                 {tr("Ссылка подписки настраивается отдельно. После мастера включите только нужные транспорты: WebSocket не является обязательным.")} </p>
              <div className="form-grid">
                <label className="field form-span">
                   {tr("DNS-имя клиентской подписки")} <input
                    value={subscriptionHost}
                    onChange={(event) => setSubscriptionHost(event.target.value)}
                    placeholder="sub.example.com"
                  />
                  <small>
                     {tr("Постоянная HTTPS-ссылка нужна VPN-клиентам для импорта и автоматического обновления конфигурации. Контейнер отдельно проверяет сам MikroTik по внутренней сети.")} </small>
                </label>
              </div>
              <aside className="notice notice-neutral">
                <span className="notice-icon">i</span>
                <div>
                  <strong>{tr("Транспорты настраиваются независимо")}</strong>
                  <p>
                     {tr("Можно включить только gRPC и XHTTP либо любой другой набор. Все включённые транспорты попадут в ту же постоянную ссылку.")} </p>
                </div>
              </aside>
            </div>
          ) : null}

          {step === 3 ? (
            <div>
              <h3>{tr("Добавьте первого исходящего прокси-провайдера")}</h3>
              <p>
                 {tr("URL проверяется без сохранения в журнал. Рабочая конфигурация не заменяется, пока candidate не пройдёт проверку активного proxy-ядра.")} </p>
              <label className="field">
                 {tr("Понятное название")} <input
                  value={providerName}
                  onChange={(event) => setProviderName(event.target.value)}
                />
              </label>
              <label className="field">
                 {tr("URL подписки")} <input
                  ref={providerUrlRef}
                  type="password"
                  placeholder={tr("Будет записан с правами 0600")}
                  autoComplete="off"
                />
                <small>
                   {tr("После сохранения URL можно только заменить — прочитать его из панели нельзя.")} </small>
              </label>
              <div className="wizard-provider-check">
                <StatusPill tone="info">{tr("Проверка при сохранении")}</StatusPill>
                <span>
                   {tr("URL уйдёт прямо в SecretStore. Импортируются VLESS, REALITY и Hysteria 2 URI, Base64-списки и Xray JSON.")} </span>
              </div>
            </div>
          ) : null}

          {step === 4 ? (
            <div>
              <h3>{tr("Черновик готов к проверке")}</h3>
              <p>
                 {tr("Это ещё не применение. Сначала панель покажет точный RouterOS diff и результаты всех проверок.")} </p>
              <dl className="wizard-summary">
                <div>
                  <dt>RouterOS</dt>
                  <dd>7 · {channel} · capability-check</dd>
                </div>
                <div>
                  <dt>Management</dt>
                  <dd>
                    {managementCidr} · ingress {managementIngressInterface} →
                    HTTPS 9443
                  </dd>
                </div>
                <div>
                  <dt>Container/TUN/DNS</dt>
                  <dd>
                    bridge {bridgeName} · veth {vethName} · RouterOS{" "}
                    {routerGateway} · container {containerAddress} · TUN{" "}
                    {tunAddress} · DNS {internalDns}
                  </dd>
                </div>
                <div>
                  <dt>{tr("Внутренние сети")}</dt>
                  <dd>{internalNetworks.length}  {tr("точных CIDR")}</dd>
                </div>
                <div>
                  <dt>{tr("Подсказки из .rsc")}</dt>
                  <dd>
                     {tr("принято")} {acceptedSuggestionCount}  {tr("· проигнорировано")}{" "}
                    {ignoredSuggestionCount}  {tr("· ожидает")} {pendingNetworks.length}
                  </dd>
                </div>
                <div>
                  <dt>{tr("Удалённый вход")}</dt>
                  <dd>{subscriptionHost ? <>{tr("подписка:")} {subscriptionHost} {tr("· транспорты настраиваются отдельно")}</> : tr("клиентский режим · публичная подписка выключена")}</dd>
                </div>
                <div>
                  <dt>{tr("Провайдер")}</dt>
                  <dd>{providerName}  {tr("· секрет скрыт")}</dd>
                </div>
                <div>
                  <dt>{tr("Отказ контейнера")}</dt>
                  <dd>{tr("Локальные → WAN; удалённые → block")}</dd>
                </div>
              </dl>
              {activeOfflinePrefillCount ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>{tr("Вы подтверждаете офлайн-кандидаты")}</strong>
                    <p>
                       {tr("После «Сохранить черновик» эти")} {activeOfflinePrefillCount}{" "}
                       {tr("значений будут отмечены как проверенные оператором. Это не заменяет live discovery: Apply повторно проверит адреса, интерфейсы и пересечения.")} </p>
                  </div>
                </aside>
              ) : null}
              <aside className="notice notice-danger">
                <span className="notice-icon">!</span>
                <div>
                  <strong>{tr("Офлайн-импорт не подтверждает capabilities")}</strong>
                  <p>
                     {tr("Сохранение черновика не разрешает Apply. Следующим отдельным действием запустите live preflight; неизвестные или отсутствующие возможности заблокируют новую установку.")} </p>
                </div>
              </aside>
              <aside className="notice notice-safe">
                <span className="notice-icon">✓</span>
                <div>
                  <strong>{tr("Перед применением автоматически")}</strong>
                  <p>
                     {tr("RouterOS preflight → точный diff → проверка активного ядра → nginx -t. Export, backup и Safe Mode добавляются только если сам RouterOS-патч действительно изменился; иначе обновляется только контейнер с runtime-откатом.")} </p>
                </div>
              </aside>
            </div>
          ) : null}
        </div>

        {wizardMessage ? (
          <div
            className={`inline-result ${
              wizardSaved ? "" : "inline-result-error"
            }`}
            role={wizardSaved ? "status" : "alert"}
          >
            <span>{wizardSaved ? "✓" : "!"}</span>
            {wizardMessage}
          </div>
        ) : null}

        <div className="wizard-actions">
          <button
            className="button button-tertiary"
            onClick={() => (step === 0 ? onClose() : setStep(step - 1))}
            disabled={wizardBusy}
          >
            {step === 0 ? tr("Закрыть") : tr("Назад")}
          </button>
          <button
            className="button button-primary"
            onClick={wizardSaved ? onClose : advance}
            disabled={
              wizardBusy ||
              (step === 1 &&
                (pendingNetworks.length > 0 ||
                  !managementIngressInterface.trim() ||
                  !bridgeName.trim() ||
                  !vethName.trim() ||
                  bridgeName === vethName))
            }
          >
            {wizardBusy
              ? tr("Сохраняю…")
              : wizardSaved
                ? tr("Закрыть мастер")
                : step === steps.length - 1
                  ? tr("Сохранить черновик")
                  : tr("Продолжить")}
          </button>
        </div>
      </section>
    </div>
  );
}

function GatewayConsole({
  username,
  onSessionEnded,
}: {
  username: string;
  onSessionEnded: () => void;
}) {
  const { locale, setLocale, t, tr } = useLanguage();
  const [screen, setScreen] = useState<Screen>("overview");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [applyMode, setApplyMode] = useState<"check" | "apply" | null>(null);
  const [resetDraftOpen, setResetDraftOpen] = useState(false);
  const [addKind, setAddKind] = useState<"local" | "remote" | null>(null);
  const [editingLocalId, setEditingLocalId] = useState("");
  const [editingRemoteId, setEditingRemoteId] = useState("");
  const [setupOpen, setSetupOpen] = useState(false);
  const [policyDialog, setPolicyDialog] = useState<{
    policyId?: string;
  } | null>(null);
  const [connectionDialog, setConnectionDialog] = useState<{
    kind: "subscription" | "transport";
    transportId?: string;
    subscriptionId?: string;
  } | null>(null);
  const [tlsProfileDialog, setTlsProfileDialog] = useState<{
    profileId?: string;
  } | null>(null);
  const [runtimeStatus, setRuntimeStatus] = useState<JsonObject>();
  const [subscriptionMetadata, setSubscriptionMetadata] = useState<Record<string, JsonObject>>({});
  const [runtimeDetailsReady, setRuntimeDetailsReady] = useState(false);
  const [overviewData, setOverviewData] = useState<JsonObject>();
  const [liveRouteros, setLiveRouteros] = useState<JsonObject>({});
  const [clientTelemetry, setClientTelemetry] = useState<JsonObject>();
  const [runtimeError, setRuntimeError] = useState("");
  const [draftEnvelope, setDraftEnvelope] = useState<DraftEnvelope>();
  const [draftError, setDraftError] = useState("");
  const [pendingChangePopoverOpen, setPendingChangePopoverOpen] =
    useState(false);
  const runtimeRefreshInFlight = useRef(false);
  const detailedStatusRefreshInFlight = useRef(false);
  const clientTelemetryRefreshInFlight = useRef(false);
  const draftRefreshInFlight = useRef(false);
  const routerosRefreshInFlight = useRef(false);
  const routerosContainerRefreshInFlight = useRef(false);
  const routerosRefreshedAt = useRef(0);

  const navigateToScreen = useCallback((nextScreen: Screen) => {
    const currentScreen = screenFromHash(window.location.hash);
    if (currentScreen === nextScreen) return;
    const commitNavigation = () => {
      if (currentScreen === "routing" && nextScreen !== "routing") {
        window.sessionStorage.removeItem(ROUTING_EXPANDED_POLICY_STORAGE_KEY);
        window.sessionStorage.removeItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY);
      }
      flushSync(() => setScreen(nextScreen));
      window.history.pushState(null, "", screenHash(nextScreen));
    };
    const transitionDocument = document as ViewTransitionDocument;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reduceMotion && transitionDocument.startViewTransition) {
      try {
        const transition = transitionDocument.startViewTransition(commitNavigation);
        // Chromium rejects `ready` when a newer lateral navigation supersedes
        // an in-flight transition. The state update still completes, so consume
        // that expected rejection instead of surfacing a false page error.
        void transition.ready?.catch(() => undefined);
        void transition.updateCallbackDone?.catch(() => undefined);
        void transition.finished?.catch(() => undefined);
      } catch {
        commitNavigation();
      }
    } else {
      commitNavigation();
    }
  }, []);

  useEffect(() => {
    let previousScreen = screenFromHash(window.location.hash);
    const syncScreenFromLocation = () => {
      const nextScreen = screenFromHash(window.location.hash);
      if (previousScreen === "routing" && nextScreen !== "routing") {
        window.sessionStorage.removeItem(ROUTING_EXPANDED_POLICY_STORAGE_KEY);
        window.sessionStorage.removeItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY);
      }
      previousScreen = nextScreen;
      setScreen(nextScreen);
    };

    if (window.location.hash) {
      syncScreenFromLocation();
    } else {
      window.history.replaceState(null, "", screenHash("overview"));
    }

    window.addEventListener("hashchange", syncScreenFromLocation);
    window.addEventListener("popstate", syncScreenFromLocation);
    return () => {
      window.removeEventListener("hashchange", syncScreenFromLocation);
      window.removeEventListener("popstate", syncScreenFromLocation);
    };
  }, []);

  const current = navigation.find((item) => item.id === screen)!;
  const routerosSummary: JsonObject = {
    ...asObject(overviewData?.routeros),
    ...liveRouteros,
  };
  const displayedOverview = overviewData
    ? { ...overviewData, routeros: routerosSummary }
    : undefined;
  const draftConfig = asObject(draftEnvelope?.config);
  const draftRevision = asText(draftEnvelope?.revision, "");
  const activeRevision = asText(overviewData?.active_revision, "");
  // A periodic overview for an older draft must not hide a just-saved change.
  const overviewForDraft = asText(overviewData?.draft_revision, "") === draftRevision
    ? overviewData : undefined;
  const overviewPendingChangeCount = overviewForDraft?.pending_change_count;
  const configurationHydrated = Boolean(overviewData && draftEnvelope);
  const reportedPendingChangeCount =
    typeof overviewPendingChangeCount === "number"
      ? overviewPendingChangeCount
      : draftEnvelope?.pending_change_count;
  const pendingChangeCount =
    typeof reportedPendingChangeCount === "number"
      ? Math.max(0, Math.trunc(reportedPendingChangeCount))
      : activeRevision && activeRevision === draftRevision
        ? 0
        : 0;
  const overviewConfigChangeCount = overviewForDraft?.pending_config_change_count;
  const reportedConfigChangeCount =
    typeof overviewConfigChangeCount === "number"
      ? overviewConfigChangeCount
      : draftEnvelope?.pending_config_change_count;
  const revisionsMatch = Boolean(
    activeRevision && draftRevision && activeRevision === draftRevision,
  );
  const pendingConfigChangeCount =
    typeof reportedConfigChangeCount === "number"
      ? Math.max(0, Math.trunc(reportedConfigChangeCount))
      : revisionsMatch
        ? 0
        : pendingChangeCount;
  const pendingConfigChanges = asObjectList(
    draftEnvelope?.pending_config_changes ??
      overviewForDraft?.pending_config_changes,
  );
  const reportedRuntimeUpdateRequired =
    overviewForDraft?.runtime_update_required ??
    draftEnvelope?.runtime_update_required;
  const reportedRuntimeUpdateOnly =
    overviewForDraft?.runtime_update_only ?? draftEnvelope?.runtime_update_only;
  const runtimeUpdateOnly =
    configurationHydrated &&
    (reportedRuntimeUpdateOnly === true ||
      (reportedRuntimeUpdateRequired === true && pendingConfigChangeCount === 0) ||
      (revisionsMatch &&
        pendingChangeCount > 0 &&
        pendingConfigChangeCount === 0));
  const hasPendingAction =
    configurationHydrated &&
    (pendingConfigChangeCount > 0 || runtimeUpdateOnly);
  const hasActiveConfiguration = Boolean(
    activeRevision || draftEnvelope?.has_active_configuration,
  );
  const revisionState: RevisionState =
    !configurationHydrated
      ? "loading"
      : hasActiveConfiguration && pendingConfigChangeCount === 0
        ? "applied"
        : "draft";
  const draftReviewCounts = importReviewCounts(draftConfig);
  const draftManagement = asObject(asObject(draftConfig.system).management);
  const selectedManagementIngress = asStringList(
    draftManagement.allowed_ingress_interfaces,
  );
  const managementIngressReady = selectedManagementIngress.length > 0;

  const refreshLiveRouterOS = useCallback(async () => {
    if (
      routerosRefreshInFlight.current ||
      Date.now() - routerosRefreshedAt.current < 30_000
    ) {
      return;
    }
    routerosRefreshInFlight.current = true;
    try {
      const response = await loadRouterOSDiscovery();
      setLiveRouteros(response);
      routerosRefreshedAt.current = Date.now();
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
      // The saved RouterOS summary remains usable when live REST is unavailable.
    } finally {
      routerosRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshLiveRouterOSContainer = useCallback(async () => {
    if (routerosContainerRefreshInFlight.current) return;
    routerosContainerRefreshInFlight.current = true;
    try {
      const response = await getRouterOsContainerStatus<JsonObject>();
      const container = asObject(response.container);
      setLiveRouteros((current) => ({ ...current, container }));
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
      // Keep the last confirmed value when the lightweight REST read fails.
    } finally {
      routerosContainerRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshRuntime = useCallback(async () => {
    if (runtimeRefreshInFlight.current) return;
    runtimeRefreshInFlight.current = true;
    try {
      const response = await getOverview<JsonObject>();
      setOverviewData(response);
      setRuntimeStatus((current) =>
        mergeRuntimeStatus(current, asObject(response.status)),
      );
      setRuntimeError("");
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
        return;
      }
      setRuntimeError(errorMessage(error));
    } finally {
      runtimeRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshDraft = useCallback(async () => {
    if (draftRefreshInFlight.current) return;
    draftRefreshInFlight.current = true;
    try {
      const response = await getCurrentDraft<DraftEnvelope>();
      setDraftEnvelope(response);
      setDraftError("");
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
        return;
      }
      setDraftError(errorMessage(error));
    } finally {
      draftRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshInitialState = useCallback(async () => {
    if (runtimeRefreshInFlight.current || draftRefreshInFlight.current) return;
    runtimeRefreshInFlight.current = true;
    draftRefreshInFlight.current = true;
    try {
      const [response, detailedStatus] = await Promise.all([
        getBootstrapState<JsonObject>(),
        getStatus<JsonObject>().catch((error) => {
          if (error instanceof GatewayApiError && error.status === 401) throw error;
          return undefined;
        }),
      ]);
      const overview = asObject(response.overview);
      const draft = asObject(response.draft) as DraftEnvelope;
      setOverviewData(overview);
      setRuntimeStatus((current) =>
        detailedStatus
          ? mergeRuntimeStatus(
              mergeRuntimeStatus(current, asObject(overview.status)),
              detailedStatus,
            )
          : mergeRuntimeStatus(current, asObject(overview.status)),
      );
      setRuntimeDetailsReady(Boolean(detailedStatus));
      setDraftEnvelope(draft);
      setRuntimeError("");
      setDraftError("");
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
        return;
      }
      const message = errorMessage(error);
      setRuntimeError(message);
      setDraftError(message);
    } finally {
      runtimeRefreshInFlight.current = false;
      draftRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshDetailedStatus = useCallback(async () => {
    if (detailedStatusRefreshInFlight.current) return;
    detailedStatusRefreshInFlight.current = true;
    try {
      const detailedStatus = await getStatus<JsonObject>();
      setRuntimeStatus((current) => mergeRuntimeStatus(current, detailedStatus));
      setRuntimeDetailsReady(true);
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
      // Overview already contains the compact runtime status. A delayed
      // selector-history refresh must never blank or block the main screen.
    } finally {
      detailedStatusRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshClientTelemetry = useCallback(async () => {
    if (clientTelemetryRefreshInFlight.current) return;
    clientTelemetryRefreshInFlight.current = true;
    try {
      const nextTelemetry = await getClientTelemetry<JsonObject>();
      setClientTelemetry((current) => {
        const currentSample = asText(current?.sampled_at, "");
        const nextSample = asText(nextTelemetry.sampled_at, "");
        return current && currentSample === nextSample ? current : nextTelemetry;
      });
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
    } finally {
      clientTelemetryRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const selectorRefreshInFlight = useRef(false);
  const refreshSelectorStatus = useCallback(async () => {
    if (selectorRefreshInFlight.current) return;
    selectorRefreshInFlight.current = true;
    try {
      const status = await getSelectorStatus<JsonObject>();
      setRuntimeStatus((current) => mergeRuntimeStatus(current, status));
      setRuntimeDetailsReady(true);
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) onSessionEnded();
    } finally {
      selectorRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshRuntime(), refreshDraft(), refreshDetailedStatus(), refreshSelectorStatus()]);
  }, [refreshDetailedStatus, refreshDraft, refreshRuntime, refreshSelectorStatus]);

  useEffect(() => {
    if (screen !== "routing") return;
    const refresh = () => {
      if (document.visibilityState === "visible") void refreshSelectorStatus();
    };
    const initial = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 5_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [screen, refreshSelectorStatus]);

  useEffect(() => {
    const initial = window.setTimeout(() => {
      void refreshInitialState();
      void refreshLiveRouterOS();
    }, 0);
    const timer = window.setInterval(refreshRuntime, 60_000);
    const routerosTimer = window.setInterval(refreshLiveRouterOS, 300_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      window.clearInterval(routerosTimer);
    };
  }, [refreshInitialState, refreshLiveRouterOS, refreshRuntime]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (screen !== "overview") void refreshLiveRouterOS();
      if (screen === "routing" || screen === "operations") {
        void refreshDetailedStatus();
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [refreshDetailedStatus, refreshLiveRouterOS, screen]);

  useEffect(() => {
    const refreshVisibleState = () => {
      if (document.visibilityState !== "visible") return;
      void refreshRuntime();
      void refreshDetailedStatus();
      void refreshLiveRouterOS();
    };
    document.addEventListener("visibilitychange", refreshVisibleState);
    return () => document.removeEventListener("visibilitychange", refreshVisibleState);
  }, [refreshDetailedStatus, refreshLiveRouterOS, refreshRuntime]);

  useEffect(() => {
    if (!overviewData) return;
    const initial = window.setTimeout(() => void refreshDetailedStatus(), 3_000);
    const timer = window.setInterval(
      refreshDetailedStatus,
      screen === "overview" ? 30_000 : 60_000,
    );
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [overviewData, refreshDetailedStatus, screen]);

  useEffect(() => {
    if (screen !== "overview" || !overviewData) return;
    const refreshVisible = () => {
      if (document.visibilityState === "visible") void refreshClientTelemetry();
    };
    const initial = window.setTimeout(refreshVisible, 750);
    // Poll between the agent's 30-second samples. Identical sampled_at values
    // are discarded above, so the table is not repainted for duplicate data.
    const timer = window.setInterval(refreshVisible, 15_000);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, [overviewData, refreshClientTelemetry, screen]);

  useEffect(() => {
    if (screen !== "overview" || !overviewData) return;
    const refreshVisible = () => {
      if (document.visibilityState === "visible") {
        void refreshLiveRouterOSContainer();
      }
    };
    const initial = window.setTimeout(refreshVisible, 500);
    const timer = window.setInterval(refreshVisible, 30_000);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, [overviewData, refreshLiveRouterOSContainer, screen]);

  return (
    <ConnectionAddressContext.Provider value={asObject(overviewData?.connection_address)}>
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        {t("shell.skip")}
      </a>
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <span className="brand-mark">SB</span>
          <div>
            <strong>Gateway</strong>
            <small>VLESS · MikroTik</small>
          </div>
          <button
            className="sidebar-close"
            onClick={() => setSidebarOpen(false)}
            aria-label={t("shell.closeMenu")}
          >
            ×
          </button>
        </div>

        <nav aria-label={t("shell.navigation")}>
          {navigation.map((item) => (
            <button
              key={item.id}
              className={screen === item.id ? "nav-active" : ""}
              onClick={() => {
                navigateToScreen(item.id);
                setSidebarOpen(false);
              }}
            >
              <span className="nav-icon">{t(item.short)}</span>
              <span>
                <strong>{t(item.label)}</strong>
                <small>{t(item.description)}</small>
              </span>
            </button>
          ))}
        </nav>

        <div className="sidebar-system">
          <div className="system-title">
            <span
              className={
                runtimeStatus?.state === "healthy" ? "pulse-dot" : "status-dot"
              }
            />
            <strong>
              {runtimeError
                ? t("status.error")
                : runtimeStatus?.state === "healthy"
                  ? t("status.healthy")
                  : runtimeStatus?.state === "unconfigured"
                    ? t("status.unconfigured")
                    : t("status.checking")}
            </strong>
          </div>
          {(() => {
            const build = asObject(overviewData?.build);
            const containerVersion = asText(build.container_version, "");
            return (
          <dl>
            <div>
              <dt>RouterOS</dt>
              <dd>{asText(routerosSummary.detected_version, t("status.fromExport"))}</dd>
            </div>
            <div>
              <dt>{t("status.channel")}</dt>
              <dd>{asText(routerosSummary.channel, t("status.notDetected"))}</dd>
            </div>
            <div>
              <dt>{t("status.core")}</dt>
              <dd title={`${asText(build.active_core_name, t("status.notDefined"))} ${asText(build.active_core_version, "")}`}>
                {asText(build.active_core_name, t("status.notDefined"))} {asText(build.active_core_version, "")}
              </dd>
            </div>
            <div>
              <dt>{t("status.container")}</dt>
              <dd>{containerVersion ? `v${containerVersion}` : "—"}</dd>
            </div>
          </dl>
            );
          })()}
        </div>

        <div className="profile">
          <span className="avatar avatar-small">A</span>
          <div>
            <strong>{username}</strong>
            <small>{t("shell.localNetwork")}</small>
          </div>
          <button
            className="language-toggle"
            type="button"
            title={
              locale === "ru"
                ? t("language.switchToEnglish")
                : t("language.switchToRussian")
            }
            aria-label={
              locale === "ru"
                ? t("language.switchToEnglish")
                : t("language.switchToRussian")
            }
            onClick={() => setLocale(locale === "ru" ? "en" : "ru")}
          >
            {locale.toUpperCase()}
          </button>
          <button
            className="icon-button"
            aria-label={t("shell.logout")}
            onClick={async () => {
              try {
                await logout();
              } finally {
                onSessionEnded();
              }
            }}
          >
            ↪
          </button>
        </div>
      </aside>

      {sidebarOpen ? (
        <button
          className="sidebar-scrim"
          aria-label={t("shell.closeMenu")}
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <div className={`workspace screen-${screen}-workspace`}>
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu"
              onClick={() => setSidebarOpen(true)}
              aria-label={t("shell.openMenu")}
            >
              ☰
            </button>
            <div>
              <span>SB Gateway</span>
              <i>/</i>
              <strong>{t(current.label)}</strong>
            </div>
          </div>
          <div className="draft-actions">
            <div
              className={`draft-change-disclosure ${
                pendingChangePopoverOpen ? "is-open" : ""
              }`}
              onMouseEnter={() => {
                if (pendingConfigChangeCount > 0) setPendingChangePopoverOpen(true);
              }}
              onMouseLeave={() => setPendingChangePopoverOpen(false)}
              onBlur={(event) => {
                if (!event.currentTarget.contains(event.relatedTarget)) {
                  setPendingChangePopoverOpen(false);
                }
              }}
            >
              {pendingConfigChangeCount > 0 && !draftError ? (
                <button
                  type="button"
                  className={`draft-label revision-${revisionState}`}
                  aria-expanded={pendingChangePopoverOpen}
                  aria-controls="pending-change-popover"
                  onFocus={() => setPendingChangePopoverOpen(true)}
                  onClick={() =>
                    setPendingChangePopoverOpen((currentValue) => !currentValue)
                  }
                >
                  <i aria-hidden="true" />
                  {tr("Изменения · {value1}", { value1: pendingConfigChangeCount })}
                </button>
              ) : (
                <span
                  className={`draft-label ${
                    runtimeUpdateOnly
                      ? "revision-runtime"
                      : `revision-${revisionState}`
                  }`}
                >
                  <i aria-hidden="true" />
                  {draftError
                    ? tr("Ошибка загрузки изменений")
                    : runtimeUpdateOnly
                      ? tr("Есть обновление шлюза")
                      : revisionState === "applied"
                        ? tr("Применено")
                        : tr("Загружаю изменения")}
                </span>
              )}
              {pendingConfigChangeCount > 0 ? (
                <div
                  className="draft-change-popover"
                  id="pending-change-popover"
                  role="tooltip"
                >
                  <strong>{tr("Что изменилось")}</strong>
                  <ul>
                    {(pendingConfigChanges.length
                      ? pendingConfigChanges.slice(0, 8)
                      : [{
                          collection: "configuration",
                          op: "replace",
                        }]
                    ).map((change, index) => (
                      <li key={`${asText(change.path, "change")}-${index}`}>
                        {pendingConfigChanges.length
                          ? pendingChangeText(change, locale)
                          : tr("{value1} изменений конфигурации", { value1: pendingConfigChangeCount })}
                      </li>
                    ))}
                  </ul>
                  {pendingConfigChanges.length > 8 ? (
                    <small>{tr("Ещё")} {pendingConfigChanges.length - 8}</small>
                  ) : null}
                </div>
              ) : null}
            </div>
            <button
              className="button button-secondary"
              onClick={() => setResetDraftOpen(true)}
              disabled={pendingConfigChangeCount === 0 || !hasActiveConfiguration}
              title={
                !hasActiveConfiguration
                  ? tr("Сначала примените первую конфигурацию")
                  : pendingConfigChangeCount === 0
                    ? runtimeUpdateOnly
                      ? tr("Черновик не изменён — доступно обновление компонентов шлюза")
                      : tr("Несохранённых изменений нет")
                    : tr("Вернуть черновик к последней применённой конфигурации")
              }
            >
               {tr("Сбросить")} </button>
            <button
              className="button button-primary"
              onClick={() => setApplyMode("apply")}
              disabled={revisionState === "loading" || !hasPendingAction}
              title={
                runtimeUpdateOnly
                  ? tr("Проверить, затрагивает ли обновление runtime или управляемые правила RouterOS")
                  : revisionState === "loading"
                    ? tr("Сначала дождитесь загрузки ревизий")
                    : revisionState === "applied"
                      ? tr("Текущая ревизия уже применена")
                    : tr("Безопасно применить проверенный черновик")
              }
            >
              {runtimeUpdateOnly
                ? tr("Применить обновление")
                : revisionState === "applied"
                  ? tr("Применено")
                  : tr("Применить ({value1})", { value1: pendingConfigChangeCount })}
            </button>
          </div>
        </header>

        <main id="main-content" className={`main-content screen-${screen}`}>
          {screen === "overview" ? (
            <Overview
              onNavigate={navigateToScreen}
              onOpenSetup={() => setSetupOpen(true)}
              onAddClient={() => navigateToScreen("clients")}
              onEditClient={(kind, id) => {
                if (kind === "remote") setEditingRemoteId(id);
                else setEditingLocalId(id);
              }}
              runtime={runtimeStatus}
              runtimeError={runtimeError}
              overview={displayedOverview}
              clientTelemetry={clientTelemetry}
              config={draftConfig}
            />
          ) : null}
          {screen === "clients" ? (
            <Clients
              onAdd={setAddKind}
              onEditLocal={setEditingLocalId}
              onEditRemote={setEditingRemoteId}
              config={draftConfig}
              revisionState={revisionState}
            />
          ) : null}
          {screen === "routing" ? (
            configurationHydrated ? (
              <Routing
                onAddPolicy={() => setPolicyDialog({})}
                onEditPolicy={(policyId) => setPolicyDialog({ policyId })}
                config={draftConfig}
                runtime={runtimeStatus}
                runtimeDetailsReady={runtimeDetailsReady}
                revisionState={revisionState}
                routeros={routerosSummary}
                onDraftChanged={refreshDraft}
              />
            ) : (
              <section className="card screen-hydration-state" role="status">
                 {tr("Загружаю настройки маршрутизации…")} </section>
            )
          ) : null}
          {screen === "connections" ? (
            configurationHydrated ? (
              <Connections
                certificateStatus={asObject(asObject(runtimeStatus).acme)}
                subscriptionMetadata={subscriptionMetadata}
                setSubscriptionMetadata={setSubscriptionMetadata}
                onAddSubscription={() =>
                  setConnectionDialog({ kind: "subscription" })
                }
                onEditSubscription={(subscriptionId) =>
                  setConnectionDialog({ kind: "subscription", subscriptionId })
                }
                onConfigureTransport={(transportId) =>
                  setConnectionDialog({ kind: "transport", transportId })
                }
                onAddTlsProfile={() => setTlsProfileDialog({})}
                onEditTlsProfile={(profileId) => setTlsProfileDialog({ profileId })}
                onDraftChanged={refreshDraft}
                config={draftConfig}
                revisionState={revisionState}
              />
            ) : (
              <section className="card screen-hydration-state" role="status">
                 {tr("Загружаю настройки подключений…")} </section>
            )
          ) : null}
          {screen === "operations" ? (
            <Operations
              onRefresh={refreshAll}
              onDraftChanged={refreshDraft}
              onNavigate={navigateToScreen}
              overview={displayedOverview}
              runtime={runtimeStatus}
              config={draftConfig}
            />
          ) : null}
          {screen === "settings" ? (
            <Settings
              key={draftRevision || "draft-loading"}
              config={draftConfig}
              routeros={routerosSummary}
              onDraftChanged={refreshDraft}
            />
          ) : null}
        </main>
      </div>

      {applyMode ? (
        <ApplyDialog
          mode={applyMode}
          publicTlsReady={hasPublicTlsPair(draftConfig)}
          networkReviewPending={draftReviewCounts.pending}
          managementIngressReady={managementIngressReady}
          onPlan={() =>
            runDraftOperation("plan", {
              config: withDeploymentReadiness(draftConfig, true),
            })
          }
          onClose={() => setApplyMode(null)}
          onRun={async (operation) => {
            let targetRevision = "";
            try {
              if (operation === "apply") {
                const saved = await saveCurrentDraft<DraftEnvelope>({
                  config: withDeploymentReadiness(draftConfig, true),
                });
                targetRevision = asText(saved.revision, "");
              }
              try {
                return await runDraftOperation(operation);
              } catch (error) {
                if (operation === "apply") {
                  const uncertain = isUncertainOperationError(error);
                  if (uncertain && targetRevision) {
                    for (let attempt = 0; attempt < 12; attempt += 1) {
                      await new Promise((resolve) => window.setTimeout(resolve, 5000));
                      try {
                        const status = await getStatus<JsonObject>();
                        const appliedRevision = asText(
                          status.active_revision,
                          asText(asObject(status.last_apply).revision, ""),
                        );
                        if (appliedRevision === targetRevision) {
                          return {
                            ok: true,
                            operation: "applied_after_reconnect",
                            revision: targetRevision,
                            message:
                              tr("Связь с запросом прерывалась, но control plane подтвердил, что именно эта ревизия успешно применена."),
                          };
                        }
                      } catch {
                        // The next bounded status attempt may succeed while the
                        // already-running Safe Mode operation continues.
                      }
                    }
                    throw new GatewayApiError(
                      tr("Ответ Apply потерян, а итог пока не подтверждён. Не запускайте применение повторно: обновите статус через минуту."),
                      { code: "apply_status_unknown" },
                    );
                  }
                  await markCurrentDraftUnready();
                }
                throw error;
              }
            } finally {
              await refreshAll();
            }
          }}
        />
      ) : null}
      {resetDraftOpen ? (
        <ResetDraftDialog
          changeCount={pendingConfigChangeCount}
          onClose={() => setResetDraftOpen(false)}
          onReset={async () => {
            try {
              return await runDraftOperation("reset");
            } finally {
              await refreshAll();
            }
          }}
        />
      ) : null}
      {addKind ? (
        <AddDialog
          kind={addKind}
          onClose={() => setAddKind(null)}
          config={draftConfig}
          onSave={async (kind, item, servicePacks) => {
            try {
              if (kind === "local") {
                return await saveCurrentDraft({
                  config: withDeploymentReadiness({
                    ...draftConfig,
                    service_packs: servicePacks,
                    local_clients: [
                      ...asObjectList(draftConfig.local_clients),
                      item,
                    ],
                  }, false),
                });
              }
              await saveCurrentDraft({
                config: withDeploymentReadiness(
                  { ...draftConfig, service_packs: servicePacks },
                  false,
                ),
              });
              return await createCollectionItem("remote-users", item);
            } finally {
              await refreshDraft();
            }
          }}
        />
      ) : null}
      {editingLocalId ? (
        <AddDialog
          kind="local"
          existingItem={
            asObjectList(draftConfig.local_clients).find(
              (item) => asText(item.id, "") === editingLocalId,
            ) ?? {}
          }
          config={draftConfig}
          onClose={() => setEditingLocalId("")}
          onSave={async (_kind, item, servicePacks) => {
            const nextConfig: JsonObject = {
              ...draftConfig,
              service_packs: servicePacks,
              local_clients: asObjectList(draftConfig.local_clients).map((client) =>
                client.id === editingLocalId ? item : client,
              ),
            };
            if (draftConfigsMatchIgnoringReadiness(draftConfig, nextConfig)) {
              return { ok: true, unchanged: true };
            }
            try {
              return await saveCurrentDraft({
                config: withDeploymentReadiness(
                  nextConfig,
                  false,
                ),
              });
            } finally {
              await refreshDraft();
            }
          }}
          onDelete={async () => {
            try {
              await saveCurrentDraft({
                config: withDeploymentReadiness(
                  {
                    ...draftConfig,
                    local_clients: asObjectList(draftConfig.local_clients).filter(
                      (client) => client.id !== editingLocalId,
                    ),
                  },
                  false,
                ),
              });
              setEditingLocalId("");
            } finally {
              await refreshDraft();
            }
          }}
        />
      ) : null}
      {editingRemoteId ? (
        <AddDialog
          kind="remote"
          existingItem={
            asObjectList(draftConfig.remote_users).find(
              (item) => asText(item.id, "") === editingRemoteId,
            ) ?? {}
          }
          onClose={() => setEditingRemoteId("")}
          config={draftConfig}
          onSave={async (_kind, item, servicePacks) => {
            try {
              await saveCurrentDraft({
                config: withDeploymentReadiness(
                  { ...draftConfig, service_packs: servicePacks },
                  false,
                ),
              });
              return await updateCollectionItem(
                "remote-users",
                editingRemoteId,
                item,
              );
            } finally {
              await refreshDraft();
            }
          }}
          onDelete={async () => {
            try {
              await deleteCollectionItem("remote-users", editingRemoteId);
              setEditingRemoteId("");
            } finally {
              await refreshDraft();
            }
          }}
        />
      ) : null}
      {setupOpen ? (
        <SetupWizard
          onClose={() => setSetupOpen(false)}
          onDraftChanged={refreshAll}
          config={draftConfig}
        />
      ) : null}
      {connectionDialog ? (
        <ConnectionDialog
          kind={connectionDialog.kind}
          transportId={connectionDialog.transportId}
          subscriptionId={connectionDialog.subscriptionId}
          onClose={() => setConnectionDialog(null)}
          onSaved={refreshDraft}
          config={draftConfig}
          certificateStatus={asObject(asObject(runtimeStatus).acme)}
        />
      ) : null}
      {tlsProfileDialog ? (
        <TlsProfileDialog
          profileId={tlsProfileDialog.profileId}
          onClose={() => setTlsProfileDialog(null)}
          onSaved={refreshDraft}
          config={draftConfig}
        />
      ) : null}
      {policyDialog ? (
        <PolicyDialog
          policyId={policyDialog.policyId}
          onClose={() => setPolicyDialog(null)}
          onSaved={refreshDraft}
          config={draftConfig}
        />
      ) : null}
    </div>
    </ConnectionAddressContext.Provider>
  );
}

function BootstrapPanel({
  onAuthenticated,
}: {
  onAuthenticated: (username: string) => void;
}) {
  const { locale, setLocale, t } = useLanguage();
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = passwordRef.current?.value ?? "";
    const confirmation = confirmationRef.current?.value ?? "";
    if (password.length < 12) {
      setMessage(t("bootstrap.shortPassword"));
      passwordRef.current?.focus();
      return;
    }
    if (password !== confirmation) {
      setMessage(t("bootstrap.mismatch"));
      confirmationRef.current?.focus();
      return;
    }
    if (passwordRef.current) passwordRef.current.value = "";
    if (confirmationRef.current) confirmationRef.current.value = "";
    setBusy(true);
    setMessage("");
    try {
      const response = await bootstrapAdministrator(password, confirmation);
      onAuthenticated(response.user?.username ?? "admin");
    } catch (error) {
      setMessage(errorMessage(error));
      passwordRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="bootstrap-title">
        <button
          className="login-language-toggle"
          type="button"
          onClick={() => setLocale(locale === "ru" ? "en" : "ru")}
          aria-label={locale === "ru" ? t("language.switchToEnglish") : t("language.switchToRussian")}
        >
          {locale.toUpperCase()}
        </button>
        <div className="brand login-brand">
          <span className="brand-mark">SB</span>
          <div>
            <strong>Gateway</strong>
            <small>{t("bootstrap.brand")}</small>
          </div>
        </div>
        <p className="eyebrow">{t("bootstrap.eyebrow")}</p>
        <h1 id="bootstrap-title">{t("bootstrap.title")}</h1>
        <p className="login-lead">
          {t("bootstrap.leadBefore")} <code>admin</code>. {t("bootstrap.leadAfter")}
        </p>
        <form className="login-form" onSubmit={submit}>
          <label className="field">
            {t("bootstrap.password")}
            <input
              ref={passwordRef}
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
              autoFocus
            />
          </label>
          <label className="field">
            {t("bootstrap.confirm")}
            <input
              ref={confirmationRef}
              type="password"
              autoComplete="new-password"
              minLength={12}
              required
            />
          </label>
          {message ? (
            <div className="inline-result inline-result-error" role="alert">
              <span>!</span>
              {message}
            </div>
          ) : null}
          <button className="button button-primary" type="submit" disabled={busy}>
            {busy ? t("bootstrap.creating") : t("bootstrap.create")}
          </button>
        </form>
        <aside className="notice notice-safe">
          <span className="notice-icon">✓</span>
          <div>
            <strong>{t("bootstrap.once")}</strong>
            <p>{t("bootstrap.onceText")}</p>
          </div>
        </aside>
      </section>
    </main>
  );
}

function LoginPanel({
  state,
  initialMessage,
  onRetry,
}: {
  state: "checking" | "unauthenticated" | "offline";
  initialMessage: string;
  onRetry: () => void;
}) {
  const { locale, setLocale, t } = useLanguage();
  const [busy, setBusy] = useState(false);
  const [rememberCredentials, setRememberCredentials] = useState(true);

  function beginNativeSubmit() {
    setBusy(true);
  }

  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="login-title">
        <button
          className="login-language-toggle"
          type="button"
          onClick={() => setLocale(locale === "ru" ? "en" : "ru")}
          aria-label={locale === "ru" ? t("language.switchToEnglish") : t("language.switchToRussian")}
        >
          {locale.toUpperCase()}
        </button>
        <div className="brand login-brand">
          <span className="brand-mark">SB</span>
          <div>
            <strong>Gateway</strong>
            <small>{t("login.brand")}</small>
          </div>
        </div>
        <p className="eyebrow">HTTPS · management LAN</p>
        <h1 id="login-title">
          {state === "checking"
            ? t("login.checkingTitle")
            : state === "offline"
              ? t("login.offlineTitle")
              : t("login.title")}
        </h1>
        {state === "offline" ? <p className="login-lead">{t("login.offlineLead")}</p> : null}
        {state === "checking" ? (
          <div className="login-progress" role="status">
            <span className="spinner" />
            {t("login.connecting")}
          </div>
        ) : state === "offline" ? (
          <>
            <div className="inline-result inline-result-error" role="alert">
              <span>!</span>
              {initialMessage ||
                t("login.offlineHelp")}
            </div>
            <button className="button button-primary" onClick={onRetry}>
              {t("common.retry")}
            </button>
          </>
        ) : (
          <form
            className="login-form"
            action="/api/v1/auth/login-form"
            method="post"
            onSubmit={beginNativeSubmit}
            autoComplete={rememberCredentials ? "on" : "off"}
          >
            <label className="field" htmlFor="username">
              {t("login.username")}
              <input
                id="username"
                name="username"
                type="text"
                autoComplete={rememberCredentials ? "username" : "off"}
                autoCapitalize="none"
                spellCheck={false}
                required
                autoFocus
              />
            </label>
            <label className="field" htmlFor="current-password">
              {t("login.password")}
              <input
                id="current-password"
                name="password"
                type="password"
                autoComplete={rememberCredentials ? "current-password" : "off"}
                required
              />
            </label>
            <label className="login-remember" htmlFor="remember-credentials">
              <input
                id="remember-credentials"
                name="remember"
                type="checkbox"
                autoComplete="off"
                checked={rememberCredentials}
                onChange={(event) => setRememberCredentials(event.target.checked)}
              />
              <span>{t("login.remember")}</span>
            </label>
            {initialMessage ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {initialMessage}
              </div>
            ) : null}
            <button
              className="button button-primary"
              type="submit"
              disabled={busy}
            >
              {busy ? t("login.signingIn") : t("login.signIn")}
            </button>
          </form>
        )}
      </section>
    </main>
  );
}

function loginFailureMessage(
  code: string | null,
  t: (key: MessageKey) => string,
): string {
  if (code === "invalid_credentials") return t("login.invalid");
  if (code === "login_rate_limited") {
    return t("login.rateLimited");
  }
  if (code === "bootstrap_required") {
    return t("login.bootstrapRequired");
  }
  return code ? t("login.failed") : "";
}

function GatewayHome() {
  const { t } = useLanguage();
  const [authState, setAuthState] = useState<
    | "checking"
    | "authenticated"
    | "bootstrap"
    | "unauthenticated"
    | "offline"
  >("checking");
  const [username, setUsername] = useState("");
  const [authMessage, setAuthMessage] = useState(() =>
    typeof window === "undefined"
      ? ""
      : loginFailureMessage(
          new URL(window.location.href).searchParams.get("login_error"),
          t,
        ),
  );
  const [sessionAttempt, setSessionAttempt] = useState(0);
  const endSession = useCallback(() => {
    setUsername("");
    setAuthState("unauthenticated");
  }, []);

  useEffect(() => {
    const current = new URL(window.location.href);
    if (!current.searchParams.has("login_error")) return;
    current.searchParams.delete("login_error");
    window.history.replaceState(window.history.state, "", current);
  }, []);

  useEffect(() => {
    let active = true;
    session()
      .then((response) => {
        if (!active) return;
        if (response.authenticated) {
          setUsername(
            response.user?.username ?? response.username ?? "Администратор",
          );
          setAuthState("authenticated");
        } else if (response.bootstrap_required) {
          setAuthState("bootstrap");
        } else {
          setAuthState("unauthenticated");
        }
      })
      .catch((error) => {
        if (!active) return;
        if (error instanceof GatewayApiError && error.status === 401) {
          setAuthState("unauthenticated");
          return;
        }
        setAuthMessage(
          error instanceof GatewayApiError
            ? `${t("login.serverHttp")} ${error.status}`
            : errorMessage(error),
        );
        setAuthState("offline");
      });
    return () => {
      active = false;
    };
  }, [sessionAttempt, t]);

  useEffect(() => {
    if (authState !== "offline") return;
    const timer = window.setTimeout(() => {
      setAuthState("checking");
      setAuthMessage("");
      setSessionAttempt((current) => current + 1);
    }, 4_000);
    return () => window.clearTimeout(timer);
  }, [authState]);

  if (authState === "bootstrap") {
    return (
      <BootstrapPanel
        onAuthenticated={(name) => {
          setUsername(name);
          setAuthState("authenticated");
        }}
      />
    );
  }

  if (authState !== "authenticated") {
    return (
      <LoginPanel
        state={authState}
        initialMessage={authMessage}
        onRetry={() => {
          setAuthState("checking");
          setAuthMessage("");
          setSessionAttempt((current) => current + 1);
        }}
      />
    );
  }

  return (
    <GatewayConsole
      username={username}
      onSessionEnded={endSession}
    />
  );
}

export default function Home() {
  return (
    <LanguageProvider>
      <GatewayHome />
    </LanguageProvider>
  );
}
