"use client";

import { validWatchdogSettings } from "../settings-validation";

import { JsonObject, changeAdministratorPassword, saveCurrentDraft } from "../api-client";
import { ContainerMemory } from "../container-memory";
import { useLanguage } from "../i18n";
import { ConnectionAddressContext, SectionTitle, StatusPill, Toggle, asObject, asObjectList, asStringList, asText, isErrorMessage, isIpv4Cidr, isRouterOsInterfaceName, prefixedErrorMessage, uniqueListInput, withDeploymentReadiness } from "./shared";
import { FormEvent, useContext, useState } from "react";

export function Settings({
  config,
  routeros,
  onDraftChanged,
  onRouterOSChanged,
}: {
  config: JsonObject;
  routeros: JsonObject;
  onDraftChanged: () => Promise<void>;
  onRouterOSChanged: () => Promise<void>;
}) {
  const { tr } = useLanguage();
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
  const watchdogSettingsValid = validWatchdogSettings({
    interval: watchdogInterval,
    failures: failureThreshold,
    recoveries: recoveryThreshold,
    cooldown: recoveryCooldown,
    restarts: restartBudget,
  });
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
  const currentStorage = asObject(config.storage);
  const liveContainer = asObject(routeros.container);
  const usbPath = asText(
    liveContainer.root_dir,
    asText(currentStorage.root, tr("Live REST недоступен")),
  );
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
          <ContainerMemory container={liveContainer} onChanged={onRouterOSChanged} />
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
