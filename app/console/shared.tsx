"use client";

import { GatewayApiError, JsonObject, discoverRouterOs, getCurrentDraft, resolveServicePack, saveCurrentDraft } from "../api-client";
import { type Locale, type MessageKey, useLanguage } from "../i18n";
import { localizedText } from "../i18n-text";
import { LTE_PINPOINT_DOMAINS, LTE_PINPOINT_DOMAINS_BY_PACK } from "../lte-pinpoint-domains";
import { nodeDisplayLabel, nodeLocationDetail, nodePresentation } from "../node-presentation";
import { subscriptionFeedGroups } from "../subscription-feed";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

export type Screen =
  | "overview"
  | "clients"
  | "routing"
  | "connections"
  | "operations"
  | "settings";

export type RuntimeLogSource = "error" | "process" | "system" | "routing" | "nginx" | "lifecycle";

export function runtimeLogTabId(source: RuntimeLogSource): string {
  return `gateway-log-tab-${source}`;
}

export type ViewTransitionDocument = Document & {
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

export function screenFromHash(hash: string): Screen {
  const candidate = hash.replace(/^#\/?/, "").split(/[/?]/, 1)[0];
  return SCREEN_IDS.includes(candidate as Screen)
    ? (candidate as Screen)
    : "overview";
}

export function screenHash(screen: Screen): string {
  return `#/${screen}`;
}

export const ROUTING_EXPANDED_POLICY_STORAGE_KEY =
  "sb-gateway:routing:expanded-policy";

export const ROUTING_SAVE_MESSAGE_STORAGE_KEY =
  "sb-gateway:routing:save-message";

export const QUALITY_24H_BASELINE_STORAGE_KEY =
  "sb-gateway:routing:quality-24h-baselines";

export type Tone = "ok" | "warn" | "danger" | "info" | "muted";

export const ConnectionAddressContext = createContext<JsonObject>({});

export function useConnectionHostname() {
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

export const CLOUDFLARE_HTTPS_PORTS = [443, 2053, 2083, 2087, 2096, 8443] as const;

export const CDN_PROVIDERS = [
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

export const TRANSPORT_RECOMMENDATIONS: Record<string, TransportRecommendation> = {
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

export function subscriptionCdnProviderNote(value: unknown): string {
  const id = asText(value, "cloudflare");
  if (id === "cloudflare") {
    return "Origin: официальные CIDR · авто.";
  }
  if (id === "custom") {
    return "Origin: секретный заголовок или CIDR вручную.";
  }
  return "Origin: секретный HTTP-заголовок.";
}

export function cdnProviderName(value: unknown): string {
  const id = asText(value, "cloudflare");
  return CDN_PROVIDERS.find((provider) => provider.id === id)?.name ?? id;
}

const DIRECT_SERVICE_PACKS = [
  { id: "ewelink", name: "eWeLink / Sonoff", category: "Умный дом", description: "API, региональные диспетчеры и облачные соединения eWeLink.", updateMode: "official", broad: false },
  { id: "xiaomi-home", name: "Xiaomi Home / Mi Home", category: "Умный дом", description: "MIoT API, MQTT и вход в аккаунт Xiaomi.", updateMode: "official", broad: false },
  { id: "tuya", name: "Tuya / Smart Life", category: "Умный дом", description: "Региональные API и MQTT облака Tuya.", updateMode: "official", broad: false },
  { id: "aqara", name: "Aqara Home", category: "Умный дом", description: "Региональные API приложения и облачные сервисы устройств Aqara.", updateMode: "official", broad: false },
  { id: "shelly", name: "Shelly Smart Control", category: "Умный дом", description: "Облачный API и WebSocket-соединения устройств Shelly.", updateMode: "official", broad: false },
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
  { id: "cn-baidu", name: "Baidu", category: "Китай · поиск", description: "Поиск, карты и сервисы Baidu.", updateMode: "daily", broad: false },
  { id: "cn-bilibili", name: "Bilibili", category: "Китай · видео", description: "Видео, приложение и CDN Bilibili.", updateMode: "daily", broad: false },
  { id: "cn-tencent", name: "Tencent / WeChat", category: "Китай · сервисы", description: "Основные сервисы Tencent, WeChat и CDN.", updateMode: "daily", broad: false },
  { id: "cn-alibaba", name: "Alibaba / Taobao", category: "Китай · покупки", description: "Магазины Taobao и сервисы Alibaba.", updateMode: "daily", broad: false },
  { id: "cn-jd", name: "JD.com", category: "Китай · покупки", description: "Магазин JD.com и связанные домены.", updateMode: "daily", broad: false },
  { id: "cn-douyin", name: "Douyin", category: "Китай · видео", description: "Видео Douyin и CDN.", updateMode: "daily", broad: false },
  { id: "cn-iqiyi", name: "iQIYI", category: "Китай · видео", description: "Видео iQIYI и медиадомены.", updateMode: "daily", broad: false },
  { id: "cn-kuaishou", name: "Kuaishou", category: "Китай · видео", description: "Видео Kuaishou и CDN.", updateMode: "daily", broad: false },
  { id: "ir-banks", name: "Банки Ирана", category: "Иран · платежи", description: "Банковские домены из каталога category-bank-ir.", updateMode: "daily", broad: false },
  { id: "ir-snapp", name: "Snapp", category: "Иран · сервисы", description: "Поездки, доставка и другие сервисы Snapp.", updateMode: "daily", broad: false },
  { id: "ir-aparat", name: "Aparat", category: "Иран · видео", description: "Видеосервис Aparat и связанные домены.", updateMode: "daily", broad: false },
  { id: "ir-government", name: "Госуслуги Ирана", category: "Иран · государство", description: "Государственные порталы из category-gov-ir.", updateMode: "daily", broad: false },
  { id: "ir-shopping", name: "Покупки Ирана", category: "Иран · покупки", description: "Магазины и объявления из category-shopping-ir.", updateMode: "daily", broad: false },
  { id: "ir-payment", name: "Платежи Ирана", category: "Иран · платежи", description: "Платежные сервисы из category-payment-ir.", updateMode: "daily", broad: false },
  { id: "ir-social", name: "Соцсети Ирана", category: "Иран · общение", description: "Местные соцсети из category-social-media-ir.", updateMode: "daily", broad: false },
  { id: "ir-tech", name: "ИТ-сервисы Ирана", category: "Иран · сервисы", description: "Каталоги приложений и облака из category-tech-ir.", updateMode: "daily", broad: false },
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

export const PINPOINT_DOMAINS_BY_PACK: Record<string, string[]> = {
  ...Object.fromEntries(
    Object.entries(LTE_PINPOINT_DOMAINS_BY_PACK).map(([packId, domains]) => [
      packId,
      [...domains],
    ]),
  ),
  "ru-all": [...LTE_PINPOINT_DOMAINS],
};

export function parsePinpointDomains(value: string): string[] {
  return [...new Set(
    value
      .split(/[\n,]/)
      .map((domain) => domain.trim().toLowerCase().replace(/^\.+/, ""))
      .filter(Boolean),
  )];
}

export function mergePinpointDomains(current: string, recommended: string[]): string {
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

export function errorMessage(error: unknown, locale: Locale = currentUiLocale()): string {
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

export function planValidationIssueLabel(path: string, locale: Locale): string {
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

export function planValidationIssueMessage(issue: JsonObject, locale: Locale): string {
  const code = asText(issue.code, "");
  const message =
    code === "inactive_tls_profile"
      ? "Выбранный TLS-профиль выключен или не содержит пару сертификата и private key."
      : asText(issue.message, "Параметр не прошёл проверку.");
  return localizedText(message, locale);
}

export async function copyText(value: string): Promise<void> {
  if (!navigator.clipboard?.writeText) {
    throw new Error("Браузер не разрешил копирование. Выделите ссылку и скопируйте её вручную.");
  }
  await navigator.clipboard.writeText(value);
}

export function resultMessage(
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

export function prefixedErrorMessage(error: unknown, locale: Locale = currentUiLocale()): string {
  return `${locale === "en" ? "Error" : "Ошибка"}: ${errorMessage(error, locale)}`;
}

export function isErrorMessage(message: string): boolean {
  return message.startsWith("Ошибка:") || message.startsWith("Error:");
}

export function formatElapsed(seconds: number): string {
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

export function entityIdFromName(
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

export function ipv4CidrRange(value: string): [number, number] | null {
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

export function ipv4RangesOverlap(
  left: [number, number],
  right: [number, number],
): boolean {
  return left[0] <= right[1] && right[0] <= left[1];
}

export function isPrivateIpv4Cidr(value: string): boolean {
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

export function clientTunAddressError(
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

export function remoteConnectionNameError(
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

export function suggestedClientTunAddress(
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

export function NodeName({ label, country = "", provider }: { label: string; country?: string; provider?: string }) {
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

export function transportKindLabel(value: unknown): string {
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

export function reverseTransportKindLabel(value: unknown): string {
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

export function transportChangeLead(kind: string): string {
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

export function cdnDeploymentScopeNote(kind: string): string {
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

export function cdnOriginNameNote(kind: string): string {
  if (kind === "grpc") {
    return "TLS SNI соединения CDN → origin шлюза.";
  }
  if (kind === "xhttp") {
    return "SNI/Host соединения CDN → origin; это отдельный origin-домен, не домен раздачи.";
  }
  return "SNI/Host соединения CDN → origin шлюза.";
}

export function formatBytes(value: unknown, locale: Locale = "ru"): string {
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

export function formatNodeCount(value: number, locale: Locale = "ru"): string {
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

export function formatBitRate(value: unknown, locale: Locale = "ru"): string {
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

export function expiryText(value: unknown, locale: Locale = "ru"): string {
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

export function subscriptionIntervalText(subscription: JsonObject, locale: Locale = "ru"): string {
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

export function countryName(code: string, locale: Locale = "ru"): string {
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

export function wireguardEgressId(interfaceName: string): string {
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

export function subscriptionRegionGroups(
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

export type PolicySelectionMode = "best" | "priority";

export function normalizePolicySelectionMode(value: unknown): PolicySelectionMode {
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

export function initialPolicySelectionOrder(policy: JsonObject): string[] {
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

export function policySelectionMirrorsFromOrder(
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

export function selectorDescription(
  token: string,
  regions: SubscriptionRegionGroup[],
  wireguardExits: JsonObject[] = [],
  reverseVlessExits: JsonObject[] = [],
  locale: Locale = "ru",
  nodeGroups: JsonObject[] = [],
): { title: string; detail: string } {
  if (token.startsWith("group:")) {
    const group = nodeGroups.find((item) => asText(item.id, "") === token.slice(6));
    return {
      title: group ? asText(group.name, token) : localizedText("Недоступная группа", locale),
      detail: group
        ? localizedText("Правило отбора обновляет состав при загрузке подписки", locale)
        : localizedText("Правило группы удалено", locale),
    };
  }
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

function nodeMatchesUserGroup(group: JsonObject, node: JsonObject): boolean {
  const subscriptions = asStringList(group.subscription_ids);
  const countries = asStringList(group.countries);
  const protocols = asStringList(group.protocols);
  const nameTokens = asText(group.name_contains, "").split(",").map((value) => value.trim().toLocaleLowerCase().replace(/[\uFE0E\uFE0F]/g, "")).filter(Boolean);
  const excludedWords = asText(group.name_excludes, "").split(",").map((value) => value.trim().toLocaleLowerCase()).filter(Boolean);
  if (!subscriptions.length && !countries.length && !protocols.length && !nameTokens.length) return false;
  const label = asText(node.label, "").toLocaleLowerCase().replace(/[\uFE0E\uFE0F]/g, "");
  const labelWords = new Set(label.match(/[\p{L}\p{N}]+/gu) ?? []);
  const subscriptionID = asText(node.subscription_id, "");
  return (!subscriptions.length || (subscriptions.includes("*") ? Boolean(subscriptionID) : subscriptions.includes(subscriptionID))) &&
    (!countries.length || countries.includes(asText(node.country, "").toUpperCase())) &&
    (!protocols.length || protocols.includes(asText(node.protocol, "").toLowerCase())) &&
    nameTokens.every((token) => label.includes(token)) &&
    !excludedWords.some((word) => labelWords.has(word));
}

function selectorNodeIds(
  token: string,
  nodes: JsonObject[],
  wireguardExits: JsonObject[],
  reverseVlessExits: JsonObject[],
  nodeGroups: JsonObject[] = [],
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
  const userGroup = token.startsWith("group:")
    ? nodeGroups.find((item) => asText(item.id, "") === token.slice(6))
    : undefined;
  const cityToken = decodeCitySelectionToken(token);
  return nodes.flatMap((node) => {
    const id = asText(node.id, asText(node.location_key, ""));
    if (!id) return [];
    const country = asText(node.country, "ZZ").toUpperCase();
    const city = asText(node.city, asText(node.label, ""));
    const matches = userGroup
      ? nodeMatchesUserGroup(userGroup, node)
      : token.startsWith("region:")
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

export function orderedCandidateNodeIds(
  order: string[],
  nodes: JsonObject[],
  wireguardExits: JsonObject[],
  reverseVlessExits: JsonObject[],
  nodeGroups: JsonObject[] = [],
): string[] {
  const claimed = new Set<string>();
  const result: string[] = [];
  for (const token of order) {
    for (const id of selectorNodeIds(token, nodes, wireguardExits, reverseVlessExits, nodeGroups)) {
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

export function SubscriptionLocationPicker({
  nodes,
  nodeGroups,
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
  nodeGroups: JsonObject[];
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
  const [nodeView, setNodeView] = useState<"geography" | "subscription">("geography");
  const subscriptionFeeds = subscriptionFeedGroups(nodes);
  const visibleExpandedRegions =
    expandedRegions ?? (regions[0] ? [regions[0].id] : []);

  function tokenSelected(
    token: string,
    nextCountries: string[],
    nextLocations: string[],
  ): boolean {
    if (token.startsWith("group:")) {
      return selectionOrder.includes(token) && nodeGroups.some((group) => asText(group.id, "") === token.slice(6));
    }
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
      if (token.startsWith("wireguard:") || token.startsWith("reverse:") || token.startsWith("group:")) {
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
    nodeGroups,
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
            const description = selectorDescription(token, regions, wireguardExits, reverseVlessExits, locale, nodeGroups);
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
                      const optionDescription = selectorDescription(option, regions, wireguardExits, reverseVlessExits, locale, nodeGroups);
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
          <strong>{nodeView === "geography" ? tr("Группы, страны и города подписки") : tr("Узлы как в подписке")}</strong>
          <small>{nodeView === "geography"
            ? tr("Страны показаны полностью и по алфавиту. Названия городов, эмодзи и протоколы сохранены как в подписке.")
            : tr("Узлы показаны в порядке подписки. Переключение вида не меняет выбор и приоритеты.")}</small>
        </div>
        <div className="subscription-view-switch" role="group" aria-label={tr("Вид списка узлов")}>
          <button type="button" aria-pressed={nodeView === "geography"} onClick={() => setNodeView("geography")}>{tr("По странам")}</button>
          <button type="button" aria-pressed={nodeView === "subscription"} onClick={() => setNodeView("subscription")}>{tr("Как в подписке")}</button>
        </div>
      </div>
      {nodeGroups.length ? (
        <div className="subscription-user-groups" aria-label={tr("Пользовательские группы узлов")}>
          {nodeGroups.map((group) => {
            const id = asText(group.id, "");
            const token = `group:${id}`;
            const members = nodes.filter((node) => nodeMatchesUserGroup(group, node));
            return (
              <label key={id} className="subscription-user-group">
                <input
                  type="checkbox"
                  checked={selectionOrder.includes(token)}
                  onChange={() => commitSelectionOrder(selectionOrder.includes(token)
                    ? selectionOrder.filter((item) => item !== token)
                    : [...selectionOrder, token])}
                />
                <span><strong>{asText(group.name, id)}</strong><small>{members.length} {tr("узл. сейчас")}</small></span>
              </label>
            );
          })}
        </div>
      ) : null}
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
        {nodeView === "subscription" ? subscriptionFeeds.map((feed) => (
          <section className="subscription-feed" key={feed.id} aria-label={feed.name}>
            <div className="subscription-feed-heading">
              <strong>{feed.name}</strong>
              <small>{feed.nodes.length} {tr("узл.")}</small>
            </div>
            <div className="subscription-feed-nodes">
              {feed.nodes.map((node) => {
                const key = asText(node.location_key, "");
                const id = asText(node.id, key);
                const country = countries.find((item) => item.locationKeys.includes(key));
                const checked = Boolean(country && (selectedCountries.includes(country.code) || selectedLocations.includes(key)));
                const label = asText(node.label, id);
                return (
                  <label className="subscription-feed-node" key={id}>
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={!country || !key}
                      onChange={() => { if (country && key) toggleLocation(country, key); }}
                    />
                    <span>
                      <strong>{label}</strong>
                      <small>{country ? `${countryFlag(country.code)} ${country.name}` : tr("Страна не определена")} · {protocolLabel(node.protocol)}</small>
                    </span>
                  </label>
                );
              })}
            </div>
          </section>
        )) : regions.map((region) => {
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

export function resultRows(value: unknown, locale: Locale = "ru"): Array<[string, string]> {
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

export function asObject(value: unknown): JsonObject {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

export function asText(value: unknown, fallback = "—"): string {
  return typeof value === "string" || typeof value === "number"
    ? String(value)
    : fallback;
}

export function asOptionalPositiveText(value: unknown): string {
  const text = asText(value, "").trim();
  return Number(text) > 0 ? text : "";
}

export function asObjectList(value: unknown): JsonObject[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is JsonObject =>
          Boolean(item && typeof item === "object" && !Array.isArray(item)),
      )
    : [];
}

export function cdnDeploymentsForTransport(transport: JsonObject): JsonObject[] {
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

export function generateOriginHeaderSecret(): string {
  if (typeof globalThis.crypto?.getRandomValues !== "function") return "";
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

export function asStringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value
        .filter((item): item is string => typeof item === "string")
        .map((item) => item.trim())
        .filter(Boolean)
    : [];
}

export function clientDnsAddress(config: JsonObject): string {
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

export type RouterSourceKind = "lan" | "wireguard" | "ppp-vpn";

let routerOSDiscoveryCache: JsonObject = {};

let routerOSDiscoveryCachedAt = 0;

let routerOSDiscoveryRequest: Promise<JsonObject> | null = null;

export async function loadRouterOSDiscovery(force = false): Promise<JsonObject> {
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

export function normalizeRouterSourceKind(value: unknown): RouterSourceKind {
  const kind = asText(value, "lan");
  if (kind === "wireguard") return "wireguard";
  if (["ppp-vpn", "openvpn", "other-vpn"].includes(kind)) return "ppp-vpn";
  return "lan";
}

export function useRouterClientSources() {
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

export function sourceCidrsForRow(row: JsonObject): string[] {
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

export function wireGuardPeerMatchesDevice(peerName: unknown, deviceName: unknown): boolean {
  const peer = normalizedClientIdentity(peerName);
  const device = normalizedClientIdentity(deviceName);
  if (peer.length < 4 || device.length < 4) return false;
  return peer === device || peer.startsWith(device) || device.startsWith(peer);
}

export function RouterSourcePicker({
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

export function uniqueListInput(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ];
}

export function isRouterOsInterfaceName(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_.:+@ -]{0,62}$/.test(value);
}

export function isExplicitRouterHttpsOrigin(value: string): boolean {
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

export function isIpv4Cidr(value: string, allowDefault = true): boolean {
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

export type NetworkReviewStatus = "pending" | "accepted" | "ignored";

export const routerCapabilityLabels: Array<[string, string]> = [
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

export function routerImportWarningText(value: string, locale: Locale = "ru"): string {
  return localizedText(routerImportWarningLabels[value] ?? value, locale);
}

export function networkReviewStatus(value: unknown): NetworkReviewStatus {
  return value === "accepted" || value === "ignored" ? value : "pending";
}

function importReviewNetworks(config: JsonObject): JsonObject[] {
  const routeros = asObject(config.routeros);
  return asObjectList(asObject(routeros.import_review).networks);
}

export function importReviewCounts(config: JsonObject): {
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

export function importedNetworkKind(cidr: string, managementCidrs: string[]): string {
  if (managementCidrs.includes(cidr)) return "Management LAN";
  if (/\/(32|128)$/.test(cidr)) return "Адрес VPN / PPP";
  return "Маршрутизируемая или подключённая сеть";
}

export function itemName(item: JsonObject): string {
  return asText(
    item.display_name ?? item.name ?? item.label ?? item.id,
    "Без названия",
  );
}

export function shortRevision(value: unknown): string {
  const revision = asText(value, "");
  return revision ? revision.slice(0, 12) : "";
}

export function formatTimestamp(value: unknown, locale: Locale = "ru"): string {
  if (typeof value !== "string" || !value) return localizedText("время не записано", locale);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(locale === "en" ? "en-GB" : "ru-RU", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(parsed);
}

export function activityTitle(action: unknown, outcome: unknown, locale: Locale = "ru"): string {
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

export function activityTone(outcome: unknown): "ok" | "info" | "warn" {
  const result = asText(outcome, "");
  if (["failed", "rolled_back", "candidate_rejected"].includes(result)) {
    return "warn";
  }
  if (["ok", "unchanged"].includes(result)) return "ok";
  return "info";
}

export function activityMetadata(event: JsonObject, locale: Locale = "ru"): string {
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

export function withDeploymentReadiness(
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

export function draftConfigsMatchIgnoringReadiness(
  left: JsonObject,
  right: JsonObject,
): boolean {
  return JSON.stringify(draftValueForComparison(left)) ===
    JSON.stringify(draftValueForComparison(right));
}

export async function markCurrentDraftUnready(): Promise<void> {
  const draft = await getCurrentDraft<{ config?: JsonObject }>();
  const config = asObject(draft.config);
  const system = asObject(config.system);
  if (system.deployment_ready === false) return;
  await saveCurrentDraft({
    config: withDeploymentReadiness(config, false),
  });
}

export function hasPublicTlsPair(config: JsonObject): boolean {
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

export function tlsProfileExpiry(profile: JsonObject, locale: Locale = "ru"): string {
  const metadata = asObject(profile.certificate_metadata);
  return asText(metadata.not_after, "")
    ? formatTimestamp(metadata.not_after, locale)
    : localizedText("срок не определён", locale);
}

export interface DraftEnvelope {
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

export function pendingChangeText(change: JsonObject, locale: Locale = "ru"): string {
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

export type RevisionState = "loading" | "applied" | "draft";

export function configuredItemStatus(
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

export function russianCount(
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

export function configuredItemTone(
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

export const navigation: Array<{
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

export function StatusPill({
  children,
  tone = "muted",
}: {
  children: React.ReactNode;
  tone?: Tone;
}) {
  return <span className={`status-pill status-${tone}`}>{children}</span>;
}

export function SectionTitle({
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

export function Toggle({
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

export function DirectServicePackPicker({
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
  onGeoIPResolved,
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
  onGeoIPResolved?: (pack: JsonObject) => void;
}) {
  const { tr } = useLanguage();
  const [region, setRegion] = useState<"ru" | "cn" | "ir" | "other">("ru");
  const [geoIPBusy, setGeoIPBusy] = useState(false);
  const [geoIPError, setGeoIPError] = useState("");
  const controlled = selectedValues !== undefined;
  const selected = new Set(selectedValues ?? defaultValues);
  const regionGeoIPId = region === "other" ? "" : `geoip-${region}`;
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
        category: asText(pack.id, "").startsWith("geoip-") ? "GeoIP · WAN/VLESS" : tr("Добавленный сервис"),
        description: asText(pack.id, "").startsWith("geoip-")
          ? tr("IP-диапазоны страны, загруженные для шлюза. Индивидуальные клиентские профили не поддерживаются.")
          : tr("Домены, поддомены и CDN из доверенного каталога."),
        updateMode: "daily",
        broad: false,
      })),
  ].filter((pack) => !excluded.has(pack.id) && !hidden.has(pack.id));
  const activeOptionCount = options.filter(
    (pack) => selected.has(pack.id) || locked.has(pack.id),
  ).length;
  const visibleOptions = options.filter((pack) => {
    if (pack.id === regionGeoIPId) return false;
    const scopedRegion = pack.id === "yandex" || pack.id === "mailru-group"
      ? "ru"
      : pack.id.startsWith("ru-") ? "ru"
      : pack.id.startsWith("cn-") ? "cn"
      : pack.id.startsWith("ir-") ? "ir"
      : pack.id === "geoip-ru" ? "ru"
      : pack.id === "geoip-cn" ? "cn"
      : pack.id === "geoip-ir" ? "ir"
      : "common";
    return scopedRegion === "common" || scopedRegion === region;
  });
  async function toggleRegionGeoIP(checked: boolean): Promise<void> {
    if (!regionGeoIPId || !onSelectedValuesChange) return;
    setGeoIPError("");
    if (!checked) {
      onSelectedValuesChange([...selected].filter((id) => id !== regionGeoIPId));
      return;
    }
    if (customIds.has(regionGeoIPId)) {
      onSelectedValuesChange([...selected, regionGeoIPId]);
      return;
    }
    if (!onGeoIPResolved) return;
    setGeoIPBusy(true);
    try {
      const result = await resolveServicePack<JsonObject>(`geoip:${region}`);
      const pack = asObject(result.pack);
      if (asText(pack.id, "") !== regionGeoIPId) throw new Error(tr("Каталог не вернул сервисный пакет."));
      onGeoIPResolved(pack);
    } catch (error) {
      setGeoIPError(errorMessage(error));
    } finally {
      setGeoIPBusy(false);
    }
  }
  return (
    <fieldset className="field form-span service-pack-field">
      <legend className="service-pack-legend">
        <span>{legend}</span>
        <small>{activeOptionCount}  {tr("из")} {options.length}  {tr("активно")}</small>
      </legend>
      <div className="service-pack-regions" role="group" aria-label={tr("Регион каталога")}>
        {(["ru", "cn", "ir", "other"] as const).map((value) => (
          <button key={value} type="button" aria-pressed={region === value} disabled={geoIPBusy}
            className={`service-pack-region${region === value ? " is-active" : ""}`}
            onClick={() => { setRegion(value); setGeoIPError(""); }}>{value === "other" ? "Other" : value.toUpperCase()}</button>
        ))}
        {regionGeoIPId && onGeoIPResolved ? (
          <label className="service-pack-geoip">
            <input type="checkbox" checked={selected.has(regionGeoIPId)} disabled={geoIPBusy}
              onChange={(event) => void toggleRegionGeoIP(event.target.checked)} />
            <span>{geoIPBusy ? tr("Загружаю GeoIP…") : `GeoIP ${region.toUpperCase()}`}</span>
          </label>
        ) : null}
        <small>{tr("Общие карточки видны во всех режимах. Выбор скрытых карточек сохраняется.")}</small>
      </div>
      {regionGeoIPId && onGeoIPResolved ? <small className="service-pack-geoip-note">{tr("GeoIP направляет IP-диапазоны страны только на шлюзе; индивидуальные клиентские профили не поддерживаются.")}</small> : null}
      {geoIPError ? <small className="service-pack-geoip-error" role="alert">{geoIPError}</small> : null}
      <div className="service-pack-grid">
        {visibleOptions.map((pack) => (
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

export function withoutServicePackReferences(
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

export function CatalogServiceAdder({
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
      setMessage(asText(pack.id, "").startsWith("geoip-")
        ? tr("{value1}: проверенный список IP выбран для шлюза. Индивидуальные клиентские профили GeoIP не экспортируют.", { value1: asText(pack.name, raw) })
        : tr("{value1} {value2}: правил — {value3}. Домены, поддомены, IP-диапазоны и CDN из пакета будут применены автоматически{value4}.", { value1: asText(pack.name, raw), value2: alreadyConfigured ? tr("уже загружен и выбран") : tr("выбран"), value3: asText(result.rules, tr("готово")), value4: destinationLabel ? ` через ${destinationLabel}` : "" }),
      );
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="field form-span custom-service-pack">
      <span>{tr("Добавить сервис, GeoSite или GeoIP из доверенного каталога")}</span>
      <div className="custom-service-pack-row">
        <input
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder={tr("Например: avito.ru, geosite:baidu, geoip:cn")}
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

export const ROUTING_MONITOR_DEFAULTS = {
  active_liveness_interval_seconds: 3,
  active_quality_interval_seconds: 60,
  probe_batch_size: 10,
} as const;

export function SubscriptionNodeGroupEditor({
  groups, originalGroups, nodes, subscriptions, onChange,
}: {
  groups: JsonObject[];
  originalGroups: JsonObject[];
  nodes: JsonObject[];
  subscriptions: JsonObject[];
  onChange: (groups: JsonObject[]) => void;
}) {
  const { tr } = useLanguage();
  const [newName, setNewName] = useState("");
  const [newSubscription, setNewSubscription] = useState("");
  function update(id: string, field: string, value: unknown) {
    onChange(groups.map((group) => asText(group.id, "") === id ? { ...group, [field]: value } : group));
  }
  function memberIDs(group: JsonObject): string[] {
    return nodes.filter((node) => nodeMatchesUserGroup(group, node)).map((node) => asText(node.id, "")).filter(Boolean);
  }
  return (
    <section className="subscription-node-group-editor" aria-label={tr("Группы по правилам")}>
      <div className="subscription-location-heading">
        <div><strong>{tr("Группы по правилам")}</strong><small>{tr("Состав обновляется по условиям после загрузки подписки. Смена названия узла не влияет на выбор по подписке, стране и протоколу.")}</small></div>
      </div>
      {groups.map((group) => {
        const id = asText(group.id, "");
        const old = originalGroups.find((item) => asText(item.id, "") === id);
        const before = new Set(old ? memberIDs(old) : []);
        const after = new Set(memberIDs(group));
        const added = [...after].filter((item) => !before.has(item));
        const removed = [...before].filter((item) => !after.has(item));
        const invalidCountry = asStringList(group.countries).some((value) => !/^[A-Z]{2}$/.test(value));
        const invalidExcludedWord = asText(group.name_excludes, "").split(",").some((value) => value.trim() !== "" && !/^[\p{L}\p{N}]+$/u.test(value.trim()));
        return (
          <div className="subscription-node-group-definition" key={id}>
            <div className="subscription-node-group-title">
              <label className="field">{tr("Название группы")}<input value={asText(group.name, "")} maxLength={128} onChange={(event) => update(id, "name", event.target.value)} /></label>
              <button type="button" className="button button-ghost" onClick={() => onChange(groups.filter((item) => asText(item.id, "") !== id))}>{tr("Удалить")}</button>
            </div>
            <div className="subscription-node-group-filters">
              <label className="field">{tr("Подписки")}<select value={asStringList(group.subscription_ids)[0] ?? ""} onChange={(event) => update(id, "subscription_ids", event.target.value ? [event.target.value] : [])}>
                <option value="">{tr("Любой источник (старое правило)")}</option>
                <option value="*">{tr("Все подписки")}</option>
                {subscriptions.map((item) => <option key={asText(item.id, "")} value={asText(item.id, "")}>{asText(item.display_name, asText(item.id, ""))}</option>)}
              </select></label>
              <label className="field">{tr("Страны ISO, через запятую")}<input value={asStringList(group.countries).join(", ")} placeholder="CA, DE" aria-invalid={invalidCountry} onChange={(event) => update(id, "countries", event.target.value.toUpperCase().split(/[\s,]+/).filter(Boolean))} />{invalidCountry ? <small className="field-error">{tr("Для эмодзи используйте поле имени узла.")}</small> : null}</label>
              <label className="field">{tr("Протоколы, через запятую")}<input value={asStringList(group.protocols).join(", ")} placeholder="vless, hysteria2" onChange={(event) => update(id, "protocols", event.target.value.toLowerCase().split(/[\s,]+/).filter(Boolean))} /></label>
              <label className="field">{tr("Имя или эмодзи узла (через запятую)")}<input value={asText(group.name_contains, "")} maxLength={128} placeholder={tr("Например: premium")} onChange={(event) => update(id, "name_contains", event.target.value)} /><small>{tr("Все указанные части должны быть в названии узла.")}</small></label>
              <label className="field">{tr("Исключить слова из имени (через запятую)")}<input value={asText(group.name_excludes, "")} maxLength={128} placeholder={tr("Например: тест, резерв")} aria-invalid={invalidExcludedWord} onChange={(event) => update(id, "name_excludes", event.target.value)} /><small className={invalidExcludedWord ? "field-error" : undefined}>{invalidExcludedWord ? tr("Введите отдельные слова через запятую, без пробелов внутри слова.") : tr("Исключается только целое слово, без учёта регистра.")}</small></label>
            </div>
            <div className="subscription-node-group-preview" role="status">
              {tr("Сейчас совпадает: {count}; добавится: {added}; исчезнет: {removed}", { count: after.size, added: added.length, removed: removed.length })}
              {added.length || removed.length ? <small>{[...added.map((item) => `+ ${item}`), ...removed.map((item) => `− ${item}`)].slice(0, 8).join(" · ")}</small> : null}
            </div>
          </div>
        );
      })}
      <div className="subscription-node-group-add">
        <label className="field">{tr("Новая группа")}<input value={newName} onChange={(event) => setNewName(event.target.value)} maxLength={128} placeholder={tr("Например: основной маршрут")} /></label>
        <label className="field">{tr("Подписка")}<select value={newSubscription} onChange={(event) => setNewSubscription(event.target.value)}><option value="">{tr("Выберите подписку")}</option><option value="*">{tr("Все подписки")}</option>{subscriptions.map((item) => <option key={asText(item.id, "")} value={asText(item.id, "")}>{asText(item.display_name, asText(item.id, ""))}</option>)}</select></label>
        <button type="button" className="button button-secondary" disabled={!newName.trim() || !newSubscription || groups.length >= 32} onClick={() => {
          const id = entityIdFromName(newName, new Set(groups.map((group) => asText(group.id, ""))), "group");
          onChange([...groups, { id, name: newName.trim(), subscription_ids: [newSubscription], countries: [], protocols: [], name_contains: "", name_excludes: "" }]);
          setNewName("");
          setNewSubscription("");
        }}>{tr("Добавить группу")}</button>
      </div>
    </section>
  );
}
