"use client";

import { JsonObject } from "../api-client";
import { useLanguage } from "../i18n";
import { Screen, SectionTitle, StatusPill, Tone, activityMetadata, activityTitle, activityTone, asObject, asObjectList, asStringList, asText, formatBitRate, formatBytes, formatTimestamp, itemName, reverseTransportKindLabel, useConnectionHostname } from "./shared";

export function Overview({
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
