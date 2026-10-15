"use client";

import { JsonObject, runDraftOperation } from "../api-client";
import { useLanguage } from "../i18n";
import { StatusPill, asObject, asObjectList, asText, errorMessage, formatElapsed, planValidationIssueLabel, planValidationIssueMessage, resultMessage } from "./shared";
import { FormEvent, useEffect, useRef, useState } from "react";

export function ResetDraftDialog({
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

export function ApplyDialog({
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

export function RollbackDialog({
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
