"use client";

import { type ChangeEvent, useEffect, useRef, useState } from "react";
import { checkAcmeDNS, configureAcme, getAcmeStatus, type JsonObject } from "./api-client";
import { acmeDNSDelegations, acmeDNSDomains, importAcmeDNSAccounts, type AcmeDNSDelegation } from "./acme-dns";
import { acmeDNSTimeoutMinutes } from "./acme-timeout";

export type AcmeSettings = {
  enabled: boolean; provider: string; email: string;
  domains: string[]; terms_accepted: boolean;
  acme_dns_server?: string;
  propagation_timeout_minutes?: number;
};
const defaults: AcmeSettings = {
  enabled: true, provider: "regru", email: "", domains: [], terms_accepted: false,
};

function canonicalAcmeDomains(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((domain): domain is string => typeof domain === "string")
    .map((domain) => domain.trim().toLowerCase().replace(/\.+$/, "")).filter(Boolean))].sort();
}

function sameAcmeDomains(left: unknown, right: unknown): boolean {
  const first = canonicalAcmeDomains(left), second = canonicalAcmeDomains(right);
  return first.length === second.length && first.every((domain, index) => domain === second[index]);
}

function acmeIssueAvailable(loaded: boolean, loadError: string, settings: AcmeSettings, status: JsonObject): boolean {
  const savedSettings = status.settings as AcmeSettings | undefined;
  // An absent hint must not strand a new profile or an older controller. Only
  // a verified pair reported by the server may hide the manual action.
  return loaded && !loadError && settings.enabled && (status.manual_issue_needed !== false || !sameAcmeDomains(settings.domains, savedSettings?.domains));
}

function acmeRunningStage(status: JsonObject): string | undefined {
  if (status.state !== "running" || typeof status.operation_stage !== "string") return undefined;
  switch (status.operation_stage) {
    case "preparing": return "Подготовка выпуска…";
    case "ca_registration": return "Регистрация в центре сертификации…";
    case "ca_obtain": return "Запрос сертификата в центре сертификации…";
    case "dns_present": return "Создание DNS-записи…";
    case "dns_precheck": return "Проверка DNS и подтверждение домена…";
    case "certificate_received": return "Сертификат получен.";
    case "local_install": return "Установка сертификата…";
    default: return undefined;
  }
}

function acmeRunningOperationStatus(status: JsonObject): string | undefined {
  if (status.state !== "running" || typeof status.last_attempt !== "string" ||
    typeof status.operation_timeout_seconds !== "number" ||
    !Number.isSafeInteger(status.operation_timeout_seconds) || status.operation_timeout_seconds < 1) return undefined;
  const started = new Date(status.last_attempt);
  if (Number.isNaN(started.getTime())) return undefined;
  const seconds = status.operation_timeout_seconds;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainder = seconds % 60;
  const limit = [hours ? `${hours} ч` : "", minutes ? `${minutes} мин` : "", !hours && !minutes ? `${remainder} с` : ""].filter(Boolean).join(" ");
  return `Начато: ${started.toLocaleString("ru-RU")} · Лимит ожидания: ${limit}`;
}

export function useAcmeProfile(id?: string, initialMode = "manual") {
  const [mode, setMode] = useState(initialMode);
  const [settings, setSettings] = useState<AcmeSettings>(defaults);
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [status, setStatus] = useState<JsonObject>({});
  const [loaded, setLoaded] = useState(!id);
  const [loadError, setLoadError] = useState("");
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    if (!id) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    let initialized = false;
    const refresh = async () => {
      try {
        const result = await getAcmeStatus(id);
        if (disposed) return;
        setStatus(result); setLoadError(""); setLoaded(true);
        if (!initialized) {
          const saved = result.settings as AcmeSettings | undefined;
          if (saved?.provider) setSettings(saved);
          setMode(saved?.enabled ? "acme" : initialMode);
          initialized = true;
        }
      } catch {
        if (!disposed) setLoadError("Не удалось получить статус сертификата.");
      } finally {
        if (!disposed) timer = setTimeout(refresh, 5000);
      }
    };
    void refresh();
    return () => { disposed = true; clearTimeout(timer); };
  }, [id, initialMode, retry]);
  async function save(profileId: string, issue: boolean) {
    if (!loaded) throw new Error("Дождитесь загрузки настроек сертификата.");
    if (mode !== "acme") {
      await configureAcme(profileId, { disable: true });
      return;
    }
    const supplied = Object.values(credentials).some(Boolean);
    const result = await configureAcme(profileId, {
      settings, issue, ...(supplied ? { credentials } : {}),
    });
    setCredentials({});
    setStatus((previous) => ({ ...previous, ...result, settings, credentials_configured: true,
      ...(credentials.accounts ? { delegations: acmeDNSDelegations(credentials.accounts) } : {}),
      message: issue ? "Выпуск поставлен в очередь." : "Настройки сохранены." }));
  }
  const issueAvailable = acmeIssueAvailable(loaded, loadError, settings, status);
  return { mode, setMode, settings, setSettings, credentials, setCredentials,
    status, loaded, loadError, issueAvailable, save, profileId: id, retry: () => setRetry((value) => value + 1) };
}

export function AcmeFields({ model }: { model: ReturnType<typeof useAcmeProfile> }) {
  const [keyFileError, setKeyFileError] = useState("");
  const keyReadGeneration = useRef(0);
  const { settings, setSettings, credentials, setCredentials, status, loadError } = model;
  const storedProvider = (status.settings as AcmeSettings | undefined)?.provider;
  const credentialsReady = status.credentials_configured === true && storedProvider === settings.provider
    && (settings.provider !== "acmedns" || (status.settings as AcmeSettings | undefined)?.acme_dns_server === settings.acme_dns_server);
  const metadata = status.metadata as JsonObject | undefined;
  const expiry = typeof metadata?.not_after === "string" ? new Date(metadata.not_after).toLocaleString("ru-RU") : "";
  const manualRetryOnly = status.manual_retry_only === true;
  const caRetryNotBefore = typeof status.ca_retry_not_before === "string" ? new Date(status.ca_retry_not_before).toLocaleString("ru-RU") : "";
  const runningStage = acmeRunningStage(status);
  const runningOperationStatus = acmeRunningOperationStatus(status);
  return <>
    <label className="field form-span">
      Домены сертификата
      <input name="acme_domains" required defaultValue={settings.domains.join(", ")}
        placeholder="api.example.com" maxLength={2550}
        onChange={(event) => setSettings({ ...settings, domains: event.target.value.toLowerCase().split(/[\s,;]+/).filter(Boolean) })} />
    </label>
    <label className="field">
      DNS-провайдер
      <select value={settings.provider} onChange={(event) => {
        keyReadGeneration.current++;
        setSettings({ ...settings, provider: event.target.value, acme_dns_server: event.target.value === "acmedns" ? settings.acme_dns_server : undefined,
          propagation_timeout_minutes: event.target.value === "acmedns" ? settings.propagation_timeout_minutes : undefined }); setCredentials({}); setKeyFileError("");
      }}>
        <option value="regru">REG.RU</option><option value="gcore">Gcore DNS</option><option value="cloudflare">Cloudflare DNS</option>
        <option value="yandexcloud">Yandex Cloud DNS</option>
        <option value="acmedns">ACME-DNS · другой провайдер</option>
      </select>
    </label>
    <label className="field">
      Email для ACME
      <input type="email" required autoComplete="email" maxLength={254} value={settings.email}
        onChange={(event) => setSettings({ ...settings, email: event.target.value })} />
    </label>
    {settings.provider === "acmedns" ? <AcmeDNSFields model={model} credentialsReady={credentialsReady} /> : settings.provider === "regru" ? <>
      <label className="field">Логин API
        <input autoComplete="off" required={!credentialsReady} value={credentials.username ?? ""}
          placeholder={credentialsReady ? "Сохранён" : ""}
          onChange={(event) => setCredentials({ ...credentials, username: event.target.value })} />
      </label>
      <label className="field">Пароль API
        <input type="password" autoComplete="new-password" required={!credentialsReady} value={credentials.password ?? ""}
          placeholder={credentialsReady ? "Сохранён" : ""}
          onChange={(event) => setCredentials({ ...credentials, password: event.target.value })} />
      </label>
    </> : settings.provider === "yandexcloud" ? <>
      <label className="field">ID каталога
        <input autoComplete="off" required={!credentialsReady || Boolean(credentials.service_account_key)} maxLength={64} value={credentials.folder_id ?? ""}
          placeholder={credentialsReady ? "Сохранён" : ""}
          onChange={(event) => setCredentials({ ...credentials, folder_id: event.target.value })} />
      </label>
      <label className="field">Ключ сервисного аккаунта · JSON
        <input type="file" accept=".json,application/json" required={!credentialsReady || Boolean(credentials.folder_id)}
          onChange={async (event) => {
            const input = event.currentTarget;
            const generation = ++keyReadGeneration.current;
            const file = input.files?.[0];
            setKeyFileError("");
            setCredentials((previous) => ({ ...previous, service_account_key: "" }));
            if (!file) return;
            try {
              if (file.size > 16384) throw new Error("Ключ слишком большой: максимум 16 КиБ.");
              const value = await file.text();
              if (generation !== keyReadGeneration.current) return;
              const key = JSON.parse(value);
              if (!key.id || !key.service_account_id || !key.private_key) throw new Error("Нужен JSON авторизованного ключа сервисного аккаунта.");
              setCredentials((previous) => ({ ...previous, service_account_key: value }));
            } catch (error) { input.value = ""; setKeyFileError(error instanceof Error ? error.message : "Не удалось прочитать ключ."); }
          }} />
        {credentialsReady ? <span className="field-hint">Ключ сохранён</span> : null}
      </label>
      {keyFileError ? <p className="form-error form-span" role="alert">{keyFileError}</p> : null}
    </> : <label className="field form-span">API-токен
      <input type="password" autoComplete="new-password" required={!credentialsReady} value={credentials.token ?? ""}
        placeholder={credentialsReady ? "Сохранён" : ""}
        onChange={(event) => setCredentials({ token: event.target.value })} />
    </label>}
    <label className="acme-check form-span">
      <input type="checkbox" checked={settings.enabled} onChange={(event) => setSettings({ ...settings, enabled: event.target.checked })} />
      Автоматическое продление
    </label>
    <label className="acme-check form-span">
      <input type="checkbox" required checked={settings.terms_accepted} onChange={(event) => setSettings({ ...settings, terms_accepted: event.target.checked })} />
      <span>Принимаю <a href="https://letsencrypt.org/repository/" target="_blank" rel="noreferrer">условия Let’s Encrypt</a></span>
    </label>
    {!loadError && typeof status.message === "string" && status.message ? <div className={`inline-result acme-status form-span${status.state === "failed" ? " inline-result-error" : ""}`} role="status">
      <div>{runningStage ?? status.message}{expiry ? <div>Действует до: {expiry}</div> : null}
        {runningOperationStatus ? <div>{runningOperationStatus}</div> : null}
        {status.state === "failed" && manualRetryOnly && caRetryNotBefore ? <div>Ручной повтор возможен после: {caRetryNotBefore}</div> : null}
        {status.state === "failed" && !manualRetryOnly && typeof status.next_attempt === "string" ? <div>Следующая попытка: {new Date(status.next_attempt).toLocaleString("ru-RU")}</div> : null}
      </div>
    </div> : null}
  </>;
}

function AcmeDNSFields({ model, credentialsReady }: { model: ReturnType<typeof useAcmeProfile>; credentialsReady: boolean }) {
  const { settings, setSettings, credentials, setCredentials, status } = model;
  const [fileError, setFileError] = useState("");
  const [checking, setChecking] = useState(false);
  const [check, setCheck] = useState({ signature: "", message: "", ok: false });
  const configuredTimeout = settings.propagation_timeout_minutes;
  const [manualTimeout, setManualTimeout] = useState(Boolean(configuredTimeout));
  const [timeoutText, setTimeoutText] = useState(configuredTimeout ? String(configuredTimeout) : "");
  const synchronizedTimeout = useRef(configuredTimeout);
  const reading = useRef(0);
  const signature = JSON.stringify([settings.acme_dns_server, settings.domains, credentials.accounts]);
  const current = useRef(signature);
  useEffect(() => { current.current = signature; }, [signature]);
  useEffect(() => () => { reading.current++; current.current = ""; }, []);
  useEffect(() => {
    if (synchronizedTimeout.current === configuredTimeout) return;
    synchronizedTimeout.current = configuredTimeout;
    setManualTimeout(Boolean(configuredTimeout));
    setTimeoutText(configuredTimeout ? String(configuredTimeout) : "");
  }, [configuredTimeout]);
  const names = acmeDNSDomains(settings.domains);
  const records = (credentials.accounts ? acmeDNSDelegations(credentials.accounts)
    : credentialsReady && Array.isArray(status.delegations) ? status.delegations as AcmeDNSDelegation[] : [])
    .filter(record => names.includes(record.domain));
  async function verify() {
    const started = signature;
    setChecking(true);
    try {
      await checkAcmeDNS({ settings, profile_id: model.profileId ?? "", ...(credentials.accounts ? { credentials } : {}) });
      if (current.current === started) setCheck({ signature: started, message: "CNAME подтверждены. Доступ к API проверится при выпуске.", ok: true });
    } catch (error) {
      if (current.current === started) setCheck({ signature: started, message: error instanceof Error ? error.message : "Не удалось проверить CNAME.", ok: false });
    } finally { setChecking(false); }
  }
  function saveTimeout(timeout: number | undefined) {
    synchronizedTimeout.current = timeout;
    setSettings({ ...settings, propagation_timeout_minutes: timeout });
  }
  function setManualMode(manual: boolean) {
    setManualTimeout(manual);
    if (!manual) {
      setTimeoutText(""); saveTimeout(undefined);
      return;
    }
    const value = configuredTimeout || 255;
    setTimeoutText(String(value)); saveTimeout(value);
  }
  function updateTimeout(event: ChangeEvent<HTMLInputElement>) {
    const value = event.target.value;
    setTimeoutText(value);
    const minutes = acmeDNSTimeoutMinutes(value);
    event.target.setCustomValidity(minutes === undefined ? "Укажите целое число от 1 до 1440." : "");
    saveTimeout(minutes);
  }
  return <>
    <label className="field form-span">Адрес сервиса ACME-DNS
      <input type="url" name="acme_dns_server" required maxLength={2048} autoComplete="off" placeholder="https://auth.example.net"
        value={settings.acme_dns_server ?? ""} onChange={event => {
          reading.current++; setCredentials({}); setFileError("");
          setSettings({ ...settings, acme_dns_server: event.target.value });
        }} />
    </label>
    <label className="field">Ожидание DNS
      <select value={manualTimeout ? "manual" : "automatic"} onChange={event => setManualMode(event.target.value === "manual")}>
        <option value="automatic">Автоматически</option>
        <option value="manual">Вручную</option>
      </select>
    </label>
    {manualTimeout ? <label className="field">Минуты
      <input type="number" required min={1} max={1440} step={1} inputMode="numeric" value={timeoutText} onChange={updateTimeout} />
    </label> : null}
    <label className="field form-span">Учётные записи · JSON
      <input key={settings.acme_dns_server ?? ""} type="file" accept=".json,application/json" required={!credentialsReady && !credentials.accounts}
        onChange={async event => {
          const input = event.currentTarget;
          const generation = ++reading.current;
          const started = signature;
          const file = input.files?.[0];
          setFileError("");
          input.setCustomValidity("");
          if (!file) return;
          try {
            if (file.size > 20480) throw new Error("JSON слишком большой: максимум 20 КиБ.");
            const text = await file.text();
            if (generation !== reading.current || current.current !== started) return;
            const accounts = importAcmeDNSAccounts(text, settings.domains);
            setCredentials({ accounts });
          } catch (error) {
            if (generation !== reading.current || current.current !== started) return;
            input.value = ""; setCredentials({});
            const message = error instanceof Error ? error.message : "Не удалось прочитать JSON.";
            input.setCustomValidity(message); setFileError(message);
          }
        }} />
      {credentialsReady && !credentials.accounts ? <span className="field-hint">Учётные записи сохранены</span> : null}
      <span className="field-hint">JSON от сервиса. Для нескольких имён — отдельная запись на каждое; wildcard использует запись основного имени.</span>
    </label>
    {fileError ? <p className="form-error form-span" role="alert">{fileError}</p> : null}
    {records.length ? <div className="acme-dns-records form-span">
      <strong>Добавьте CNAME у своего DNS-провайдера</strong>
      {records.map(record => <div className="acme-dns-record" key={record.domain}>
        <label className="field">Имя записи<input readOnly value={record.name} onFocus={event => event.target.select()} /></label>
        <label className="field">Значение<input readOnly value={record.target} onFocus={event => event.target.select()} /></label>
      </div>)}
      <button type="button" className="button button-secondary" disabled={checking || !model.loaded} onClick={() => void verify()}>
        {checking ? "Проверка CNAME…" : "Проверить CNAME"}
      </button>
    </div> : null}
    {check.signature === signature && check.message ? <p role="status" className={`form-span ${check.ok ? "field-hint" : "form-error"}`}>{check.message}</p> : null}
    <p className="acme-help form-span">Используйте доверенный сервис: он сможет подтверждать выпуск сертификатов для этих имён.</p>
  </>;
}
