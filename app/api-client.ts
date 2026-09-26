"use client";

const API_PREFIX = "/api/v1";
const CSRF_STORAGE_KEY = "sb-gateway-csrf";

export type JsonObject = Record<string, unknown>;

export interface ApiErrorPayload {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
    request_id?: string;
  };
  detail?: string;
}

export class GatewayApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  readonly requestId?: string;

  constructor(
    message: string,
    options: {
      status?: number;
      code?: string;
      details?: unknown;
      requestId?: string;
    } = {},
  ) {
    super(message);
    this.name = "GatewayApiError";
    this.status = options.status ?? 0;
    this.code = options.code ?? "request_failed";
    this.details = options.details;
    this.requestId = options.requestId;
  }
}

function csrfToken(): string {
  if (typeof window === "undefined") return "";
  return window.sessionStorage.getItem(CSRF_STORAGE_KEY) ?? "";
}

export function rememberCsrfToken(token: string | undefined): void {
  if (typeof window === "undefined" || !token) return;
  window.sessionStorage.setItem(CSRF_STORAGE_KEY, token);
}

export function forgetCsrfToken(): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.removeItem(CSRF_STORAGE_KEY);
}

function isMutation(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

async function parseBody(response: Response): Promise<unknown> {
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  const text = await response.text();
  return text ? { detail: text } : null;
}

function safeErrorDetail(response: Response, detail: unknown): string | undefined {
  if (typeof detail !== "string") return undefined;
  const normalized = detail.replace(/\s+/g, " ").trim();
  if (!normalized) return undefined;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("text/html") || /^<(?:!doctype|html)\b/i.test(normalized)) {
    return undefined;
  }
  return normalized.slice(0, 600);
}

function upstreamFailureMessage(status: number): string | undefined {
  if (status < 502 || status > 504) return undefined;
  return status === 504
    ? "Локальный control plane не завершил запрос в срок. Проверьте фактическое состояние перед повтором."
    : "Прокси временно потерял связь с локальным control plane. Дождитесь восстановления соединения и проверьте фактическое состояние.";
}

export function isUncertainOperationError(error: unknown): error is GatewayApiError {
  return (
    error instanceof GatewayApiError &&
    (["timeout", "unreachable", "upstream_unavailable", "apply_recovery_pending", "apply_state_unconfirmed"].includes(error.code) ||
      (error.status >= 502 && error.status <= 504))
  );
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit & {
    timeoutMs?: number;
    retries?: number;
    retryDelayMs?: number;
  } = {},
): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const {
    timeoutMs = 30_000,
    retries = 0,
    retryDelayMs = 400,
    ...requestInit
  } = init;
  const headers = new Headers(requestInit.headers);
  headers.set("Accept", "application/json");
  if (
    requestInit.body &&
    !(requestInit.body instanceof FormData) &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }
  if (isMutation(method)) {
    const token = csrfToken();
    if (token) headers.set("X-CSRF-Token", token);
  }

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(`${API_PREFIX}${path}`, {
        ...requestInit,
        method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      });
      const body = await parseBody(response);
      if (!response.ok) {
        const payload = (body ?? {}) as ApiErrorPayload;
        const upstreamMessage = upstreamFailureMessage(response.status);
        const safeDetail = safeErrorDetail(response, payload.detail);
        throw new GatewayApiError(
          payload.error?.message ??
            upstreamMessage ??
            safeDetail ??
            `Сервер вернул HTTP ${response.status}`,
          {
            status: response.status,
            code:
              payload.error?.code ??
              (upstreamMessage ? "upstream_unavailable" : "request_failed"),
            details: payload.error?.details,
            requestId: payload.error?.request_id,
          },
        );
      }
      return body as T;
    } catch (error) {
      const normalized =
        error instanceof GatewayApiError
          ? error
          : error instanceof DOMException && error.name === "AbortError"
            ? new GatewayApiError("Сервер не ответил за отведённое время.", {
                code: "timeout",
              })
            : new GatewayApiError(
                "Панель не может связаться с локальным control plane.",
                { code: "unreachable", details: String(error) },
              );
      const transient =
        method === "GET" &&
        (normalized.code === "timeout" ||
          normalized.code === "unreachable" ||
          (typeof normalized.status === "number" &&
            normalized.status >= 500 &&
            normalized.status <= 504));
      if (!transient || attempt >= retries) throw normalized;
      await new Promise((resolve) =>
        window.setTimeout(resolve, retryDelayMs * (attempt + 1)),
      );
    } finally {
      window.clearTimeout(timeout);
    }
  }

  throw new GatewayApiError("Панель не может связаться с local control plane.", {
    code: "unreachable",
  });
}

export interface SessionResponse {
  authenticated: boolean;
  bootstrap_required?: boolean;
  username?: string;
  user?: {
    username?: string;
    role?: string;
  } | null;
  csrf_token?: string;
  expires_at?: string;
}

export async function bootstrapAdministrator(
  password: string,
  passwordConfirmation: string,
): Promise<SessionResponse> {
  const result = await apiRequest<SessionResponse>("/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify({
      username: "admin",
      password,
      password_confirmation: passwordConfirmation,
    }),
  });
  rememberCsrfToken(result.csrf_token);
  return result;
}

export async function login(
  username: string,
  password: string,
): Promise<SessionResponse> {
  const result = await apiRequest<SessionResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  rememberCsrfToken(result.csrf_token);
  return result;
}

export async function session(): Promise<SessionResponse> {
  const result = await apiRequest<SessionResponse>("/auth/session", {
    timeoutMs: 6_000,
    retries: 2,
    retryDelayMs: 350,
  });
  rememberCsrfToken(result.csrf_token);
  return result;
}

export async function logout(): Promise<void> {
  try {
    await apiRequest<unknown>("/auth/logout", { method: "POST" });
  } finally {
    forgetCsrfToken();
  }
}

export async function changeAdministratorPassword(
  currentPassword: string,
  newPassword: string,
  passwordConfirmation: string,
): Promise<SessionResponse> {
  const result = await apiRequest<SessionResponse>("/auth/password", {
    method: "POST",
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
      password_confirmation: passwordConfirmation,
    }),
  });
  rememberCsrfToken(result.csrf_token);
  return result;
}

export function getOverview<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/overview", {
    timeoutMs: 15_000,
    retries: 1,
    retryDelayMs: 500,
  });
}

export function getBootstrapState<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/bootstrap-state", {
    timeoutMs: 15_000,
    retries: 1,
    retryDelayMs: 500,
  });
}

export function getClientTelemetry<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/client-telemetry", { timeoutMs: 10_000 });
}

export function getStatus<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/status");
}

export function getSelectorStatus<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/status?view=selectors", { timeoutMs: 10_000 });
}

export function getLifecycleStatus<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/lifecycle");
}

export function getRecoveryBackups<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/recovery/backups", { timeoutMs: 120_000 });
}

export function createRecoveryBackup<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/recovery/backups", {
    method: "POST",
    timeoutMs: 5 * 60_000,
  });
}

export function uploadRecoveryBackup<T = JsonObject>(file: File): Promise<T> {
  return apiRequest<T>("/recovery/backups/upload", {
    method: "PUT",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-SB-Recovery-Filename": file.name,
    },
    body: file,
    timeoutMs: 5 * 60_000,
  });
}

export function restoreRecoveryBackup<T = JsonObject>(value: JsonObject): Promise<T> {
  return apiRequest<T>("/recovery/restore", {
    method: "POST",
    body: JSON.stringify(value),
    timeoutMs: 120_000,
  });
}

export async function downloadRecoveryBackup(
  name: string,
): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(
    `${API_PREFIX}/recovery/backups/${encodeURIComponent(name)}/download`,
    { credentials: "same-origin", cache: "no-store" },
  );
  if (!response.ok) {
    const body = await parseBody(response);
    const payload = (body ?? {}) as ApiErrorPayload;
    throw new GatewayApiError(
      payload.error?.message ?? payload.detail ?? `Сервер вернул HTTP ${response.status}`,
      { status: response.status, code: payload.error?.code },
    );
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = disposition.match(/filename="?([^";]+)"?/)?.[1] ?? name;
  return { blob: await response.blob(), filename };
}

export function scheduleImageUpdate<T = JsonObject>(
  value: JsonObject,
): Promise<T> {
  return apiRequest<T>("/lifecycle/image-update", {
    method: "POST",
    body: JSON.stringify(value),
    timeoutMs: 15 * 60_000,
  });
}

export interface UploadProgress {
  loadedBytes: number;
  totalBytes: number;
  percent: number;
}

export function preflightContainerImageUpload<T = JsonObject>(file: File): Promise<T> {
  return apiRequest<T>("/lifecycle/image-upload/preflight", {
    method: "POST",
    body: JSON.stringify({ filename: file.name, size_bytes: file.size }),
  });
}

export function uploadContainerImage<T = JsonObject>(
  file: File,
  onProgress?: (progress: UploadProgress) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("PUT", `${API_PREFIX}/lifecycle/image-upload`);
    request.timeout = 30 * 60_000;
    request.withCredentials = true;
    request.setRequestHeader("Accept", "application/json");
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.setRequestHeader("X-SB-Filename", file.name);
    const token = csrfToken();
    if (token) request.setRequestHeader("X-CSRF-Token", token);
    request.upload.addEventListener("progress", (event) => {
      const totalBytes = event.lengthComputable && event.total > 0 ? event.total : file.size;
      const loadedBytes = Math.min(event.loaded, totalBytes);
      onProgress?.({
        loadedBytes,
        totalBytes,
        percent: totalBytes > 0 ? Math.min(100, Math.round((loadedBytes / totalBytes) * 100)) : 0,
      });
    });
    request.addEventListener("load", () => {
      let body: unknown = null;
      try {
        body = request.responseText ? JSON.parse(request.responseText) : null;
      } catch {
        body = request.responseText ? { detail: request.responseText } : null;
      }
      if (request.status >= 200 && request.status < 300) {
        onProgress?.({ loadedBytes: file.size, totalBytes: file.size, percent: 100 });
        resolve(body as T);
        return;
      }
      const payload = (body ?? {}) as ApiErrorPayload;
      const upstreamMessage = upstreamFailureMessage(request.status);
      reject(new GatewayApiError(
        payload.error?.message ?? upstreamMessage ?? `Сервер вернул HTTP ${request.status}`,
        {
          status: request.status,
          code: payload.error?.code ?? (upstreamMessage ? "upstream_unavailable" : "request_failed"),
          details: payload.error?.details,
          requestId: payload.error?.request_id,
        },
      ));
    });
    request.addEventListener("error", () => reject(new GatewayApiError(
      "Панель не может передать архив локальному control plane.",
      { code: "unreachable" },
    )));
    request.addEventListener("timeout", () => reject(new GatewayApiError(
      "Загрузка архива не завершилась за 30 минут.",
      { code: "timeout" },
    )));
    request.addEventListener("abort", () => reject(new GatewayApiError(
      "Загрузка архива отменена.",
      { code: "aborted" },
    )));
    request.send(file);
  });
}

export function getUninstallPreview<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/lifecycle/uninstall");
}

export function scheduleFullUninstall<T = JsonObject>(
  value: JsonObject,
): Promise<T> {
  return apiRequest<T>("/lifecycle/uninstall", {
    method: "POST",
    body: JSON.stringify(value),
    timeoutMs: 120_000,
  });
}

export async function downloadReverseVlessClientConfig(
  exitId: string,
): Promise<{ blob: Blob; filename: string }> {
  const response = await fetch(
    `${API_PREFIX}/reverse-vless-exits/${encodeURIComponent(exitId)}/client-config`,
    {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
    },
  );
  if (!response.ok) {
    const body = await parseBody(response);
    const payload = (body ?? {}) as ApiErrorPayload;
    throw new GatewayApiError(
      payload.error?.message ?? payload.detail ?? `Сервер вернул HTTP ${response.status}`,
      {
        status: response.status,
        code: payload.error?.code,
        details: payload.error?.details,
        requestId: payload.error?.request_id,
      },
    );
  }
  const disposition = response.headers.get("content-disposition") ?? "";
  const filename = disposition.match(/filename="([^"]+)"/)?.[1]
    ?? `xray-reverse-${exitId}.json`;
  return { blob: await response.blob(), filename };
}

export function getCurrentDraft<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/drafts/current", {
    timeoutMs: 15_000,
    retries: 1,
    retryDelayMs: 500,
  });
}

export function saveCurrentDraft<T = JsonObject>(
  draft: unknown,
): Promise<T> {
  return apiRequest<T>("/drafts/current", {
    method: "PUT",
    body: JSON.stringify(draft),
  });
}

export function patchDraftSection<T = JsonObject>(
  section: string,
  value: unknown,
): Promise<T> {
  return apiRequest<T>("/drafts/current", {
    method: "PATCH",
    body: JSON.stringify({ section, value }),
  });
}

export function runDraftOperation<T = JsonObject>(
  operation: "check" | "plan" | "apply" | "reset" | "rollback",
  payload: JsonObject = {},
): Promise<T> {
  return apiRequest<T>(`/drafts/${operation}`, {
    method: "POST",
    body: JSON.stringify(payload),
    timeoutMs:
      operation === "apply" || operation === "rollback" ? 900_000 : 120_000,
  });
}

type EditableCollection =
  | "tls-profiles"
  | "local-clients"
  | "remote-users"
  | "networks"
  | "policies"
  | "subscriptions"
  | "subscription-reserves"
  | "reverse-vless-exits"
  | "transports";

export function createCollectionItem<T = JsonObject>(
  collection: EditableCollection,
  item: unknown,
): Promise<T> {
  return apiRequest<T>(`/${collection}`, {
    method: "POST",
    body: JSON.stringify(item),
  });
}

export function updateCollectionItem<T = JsonObject>(
  collection: EditableCollection,
  id: string,
  item: unknown,
): Promise<T> {
  return apiRequest<T>(`/${collection}/${encodeURIComponent(id)}`, {
    method: "PUT",
    body: JSON.stringify(item),
  });
}

export function deleteCollectionItem<T = JsonObject>(
  collection: EditableCollection,
  id: string,
): Promise<T> {
  return apiRequest<T>(`/${collection}/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export async function importRouterOsExport<T = JsonObject>(
  file: File,
): Promise<T> {
  const exportText = await file.text();
  return apiRequest<T>("/routeros/import", {
    method: "POST",
    body: JSON.stringify({
      export_text: exportText,
      source_name: file.name,
    }),
    timeoutMs: 60_000,
  });
}

export interface RouterOsCredentials {
  base_url: string;
  username: string;
  password: string;
  ssh_port?: number;
  ca_certificate?: string;
}

export function provisionRouterOsCredentials<T = JsonObject>(
  credentials: RouterOsCredentials,
): Promise<T> {
  return apiRequest<T>("/routeros/credentials", {
    method: "POST",
    body: JSON.stringify(credentials),
    timeoutMs: 60_000,
  });
}

export function discoverRouterOs<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/routeros/discover", { timeoutMs: 60_000 });
}

export function getRouterOsContainerStatus<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/routeros/container-status", { timeoutMs: 15_000 });
}

export interface RouteSimulationRequest {
  source_type: "local" | "remote";
  source_id?: string;
  source_ip?: string;
  destination_ip?: string;
  destination_domain?: string;
  destination_kind: "internal" | "service" | "public";
  service?: string;
  container_healthy?: boolean;
  vless_healthy?: boolean;
}

export function simulateRoute<T = JsonObject>(
  simulation: RouteSimulationRequest,
): Promise<T> {
  return apiRequest<T>("/route/simulate", {
    method: "POST",
    body: JSON.stringify(simulation),
  });
}

export function refreshSubscription<T = JsonObject>(id: string): Promise<T> {
  return apiRequest<T>(`/subscriptions/${encodeURIComponent(id)}/refresh`, {
    method: "POST",
    body: "{}",
    timeoutMs: 180_000,
  });
}

export function getSubscriptionNodes<T = JsonObject>(id: string): Promise<T> {
  return apiRequest<T>(`/subscriptions/${encodeURIComponent(id)}/nodes`);
}

export function getSubscriptionMetadata<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/status?view=subscriptions", { timeoutMs: 10_000 });
}

export function getAcmeStatus(id: string): Promise<JsonObject> {
  return apiRequest(`/tls-profiles/${encodeURIComponent(id)}/acme`);
}

export function configureAcme(id: string, body: JsonObject): Promise<JsonObject> {
  return apiRequest(`/tls-profiles/${encodeURIComponent(id)}/acme`, {
    method: "POST", body: JSON.stringify(body),
  });
}

export function checkAcmeDNS(body: JsonObject): Promise<JsonObject> {
  return apiRequest("/tls-profiles/acme-dns/check", { method: "POST", body: JSON.stringify(body) });
}

export function getSubscriptionUrl<T = JsonObject>(id: string): Promise<T> {
  return apiRequest<T>(`/subscriptions/${encodeURIComponent(id)}/url`);
}

export function resolveServicePack<T = JsonObject>(
  upstreamName: string,
  displayName?: string,
): Promise<T> {
  return apiRequest<T>("/service-packs/resolve", {
    method: "POST",
    body: JSON.stringify({
      upstream_name: upstreamName,
      display_name: displayName || undefined,
    }),
    timeoutMs: 60_000,
  });
}

export function runDiagnostics<T = JsonObject>(): Promise<T> {
  return apiRequest<T>("/diagnostics", {
    method: "POST",
    body: "{}",
    timeoutMs: 120_000,
  });
}

export function getXrayLogs<T = JsonObject>(
  source: "error" | "process",
  lines = 200,
): Promise<T> {
  return apiRequest<T>(
    `/runtime/xray-logs?source=${encodeURIComponent(source)}&lines=${Math.max(1, Math.min(500, Math.trunc(lines)))}`,
    { timeoutMs: 10_000 },
  );
}

export function getSystemLogs<T = JsonObject>(
  source: "system" | "routing" | "nginx" | "lifecycle",
  lines = 200,
): Promise<T> {
  return apiRequest<T>(
    `/runtime/system-logs?source=${encodeURIComponent(source)}&lines=${Math.max(1, Math.min(500, Math.trunc(lines)))}`,
    { timeoutMs: 10_000 },
  );
}

export function revealTransportHttpPath<T = JsonObject>(id: string): Promise<T> {
  return apiRequest<T>(
    `/transports/${encodeURIComponent(id)}/http-path/reveal`,
    {
      method: "POST",
      body: "{}",
    },
  );
}

export function probeTlsEndpoint<T = JsonObject>(
  hostname: string,
  port: number,
  serverName = "",
  rejectRouterAddresses = false,
): Promise<T> {
  return apiRequest<T>("/network/tls-probe", {
    method: "POST",
    body: JSON.stringify({
      hostname,
      port,
      server_name: serverName || hostname,
      reject_router_addresses: rejectRouterAddresses,
    }),
    timeoutMs: 60_000,
  });
}

export function getRemoteUserExports<T = JsonObject>(id: string): Promise<T> {
  return apiRequest<T>(
    `/remote-users/${encodeURIComponent(id)}/exports`,
  );
}

export interface RemoteUserSubscriptionLink extends JsonObject {
  user_id: string;
  url: string;
  urls?: Array<{
    id: string;
    kind: string;
    url: string;
    primary: boolean;
  }>;
  active: boolean;
  transport_count: number;
  transport_kinds: string[];
  updates_after_apply: boolean;
}

export function getRemoteUserSubscriptionLink(
  id: string,
): Promise<RemoteUserSubscriptionLink> {
  return apiRequest<RemoteUserSubscriptionLink>(
    `/remote-users/${encodeURIComponent(id)}/subscription-link`,
    {
      method: "POST",
      body: "{}",
    },
  );
}

export function rotateRemoteUserSubscriptionLink(
  id: string,
): Promise<RemoteUserSubscriptionLink> {
  return apiRequest<RemoteUserSubscriptionLink>(
    `/remote-users/${encodeURIComponent(id)}/subscription-link/rotate`,
    {
      method: "POST",
    },
  );
}

export interface DownloadedExport {
  blob: Blob;
  filename: string;
}

function downloadFilename(disposition: string | null, fallback: string): string {
  const encoded = disposition?.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const quoted = disposition?.match(/filename="([^"]+)"/i)?.[1];
  const plain = disposition?.match(/filename=([^;]+)/i)?.[1]?.trim();
  let candidate = encoded ?? quoted ?? plain ?? fallback;
  if (encoded) {
    try {
      candidate = decodeURIComponent(encoded);
    } catch {
      candidate = fallback;
    }
  }
  const leaf = candidate.split(/[\\/]/).pop()?.replace(/[\u0000-\u001f\u007f]/g, "");
  return leaf || fallback;
}

export async function downloadRemoteUserExports(
  id: string,
  password: string,
): Promise<DownloadedExport> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 60_000);
  const headers = new Headers({
    Accept: "application/zip",
    "Content-Type": "application/json",
  });
  const csrf = csrfToken();
  if (csrf) headers.set("X-CSRF-Token", csrf);

  try {
    const response = await fetch(
      `${API_PREFIX}/remote-users/${encodeURIComponent(id)}/exports/download`,
      {
        method: "POST",
        headers,
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
        body: JSON.stringify({ password }),
      },
    );
    if (!response.ok) {
      const body = (await parseBody(response)) as ApiErrorPayload | null;
      throw new GatewayApiError(
        body?.error?.message ??
          body?.detail ??
          `Сервер вернул HTTP ${response.status}`,
        {
          status: response.status,
          code: body?.error?.code,
          details: body?.error?.details,
          requestId: body?.error?.request_id,
        },
      );
    }
    return {
      blob: await response.blob(),
      filename: downloadFilename(
        response.headers.get("content-disposition"),
        `${id}-profiles.zip`,
      ),
    };
  } catch (error) {
    if (error instanceof GatewayApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new GatewayApiError("Экспорт не был подготовлен за отведённое время.", {
        code: "timeout",
      });
    }
    throw new GatewayApiError(
      "Панель не может получить ZIP из локального control plane.",
      { code: "unreachable", details: String(error) },
    );
  } finally {
    window.clearTimeout(timeout);
  }
}
