"use client";

import { JsonObject } from "../api-client";
import { useLanguage } from "../i18n";
import { SubscriptionDialog } from "./routing";
import { RevisionState, SectionTitle, StatusPill, asObjectList, asStringList, asText, configuredItemStatus, formatNodeCount, itemName } from "./shared";
import { useState } from "react";

export function Clients({
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
