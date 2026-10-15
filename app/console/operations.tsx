"use client";

import { JsonObject, createRecoveryBackup, discoverRouterOs, downloadRecoveryBackup, getLifecycleStatus, getRecoveryBackups, getSystemLogs, getUninstallPreview, getXrayLogs, importRouterOsExport, isUncertainOperationError, preflightContainerImageUpload, restoreRecoveryBackup, runDiagnostics, runDraftOperation, saveCurrentDraft, scheduleFullUninstall, scheduleImageUpdate, uploadContainerImage, uploadRecoveryBackup } from "../api-client";
import { useLanguage } from "../i18n";
import { RollbackDialog } from "./apply-dialog";
import { RuntimeLogSource, Screen, SectionTitle, StatusPill, asObject, asObjectList, asStringList, asText, formatBytes, formatElapsed, formatTimestamp, importReviewCounts, isErrorMessage, networkReviewStatus, prefixedErrorMessage, resultMessage, resultRows, routerCapabilityLabels, routerImportWarningText, runtimeLogTabId, shortRevision } from "./shared";
import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

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

export function Operations({
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
