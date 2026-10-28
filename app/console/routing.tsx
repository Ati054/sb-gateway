"use client";

import { JsonObject, RemoteUserSubscriptionLink, createCollectionItem, deleteCollectionItem, downloadReverseVlessClientConfig, getCurrentDraft, getRemoteUserSubscriptionLink, getSubscriptionNodes, isUncertainOperationError, rotateRemoteUserSubscriptionLink, saveCurrentDraft } from "../api-client";
import { DraftAutosave } from "../draft-autosave";
import { type MessageKey, useLanguage } from "../i18n";
import { compareRouteCandidates, nodeDisplayLabel, routeCandidateIds, selectorCandidateIds } from "../node-presentation";
import { confirmedUnstableRoute, qualitySheet } from "../node-quality";
import { activeQualityMetrics, displayedLatencyComparison, qualityStatsSince } from "../quality-window";
import { reverseAvailability } from "../runtime-status";
import { DraftEnvelope, NodeName, QUALITY_24H_BASELINE_STORAGE_KEY, ROUTING_EXPANDED_POLICY_STORAGE_KEY, ROUTING_MONITOR_DEFAULTS, ROUTING_SAVE_MESSAGE_STORAGE_KEY, RevisionState, SectionTitle, StatusPill, Toggle, Tone, asObject, asObjectList, asStringList, asText, configuredItemStatus, configuredItemTone, copyText, countryName, errorMessage, formatTimestamp, isErrorMessage, itemName, normalizePolicySelectionMode, orderedCandidateNodeIds, prefixedErrorMessage, reverseTransportKindLabel, selectorDescription, subscriptionRegionGroups, useConnectionHostname, useRouterClientSources, wireguardEgressId, withDeploymentReadiness } from "./shared";
import { useCallback, useEffect, useRef, useState } from "react";

export function SubscriptionDialog({
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

export function Routing({
  onAddPolicy,
  onEditPolicy,
  config,
  runtime,
  runtimeDetailsReady,
  revisionState,
  routeros,
  onDraftChanged,
  onAutosaveChange,
  onPendingChange,
  onSavingChange,
}: {
  onAddPolicy: () => void;
  onEditPolicy: (id: string) => void;
  config: JsonObject;
  runtime?: JsonObject;
  runtimeDetailsReady: boolean;
  revisionState: RevisionState;
  routeros: JsonObject;
  onDraftChanged: () => Promise<void>;
  onAutosaveChange: (autosave: DraftAutosave | null, reset?: () => void) => void;
  onPendingChange: (pending: boolean) => void;
  onSavingChange: (saving: boolean) => void;
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
        const currentMedian = activeQualityMetrics(health, selected, visibleBaseline ?? 0).median;
        const nodeStats = candidateIds
          .map((candidate) => {
            const stats = asObject(dailyStats[candidate]);
            const comparison = displayedLatencyComparison(health, candidate, Date.now() / 1000, visibleBaseline ?? 0);
            const unstable = confirmedUnstableRoute(
              asObject(health.availability_ok)[candidate] as boolean | undefined,
              Number(stats.samples ?? 0),
              typeof stats.loss_percent === "number" ? stats.loss_percent : null,
              40,
            );
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
              unstable,
              availabilityKnown: typeof asObject(health.availability_ok)[candidate] === "boolean",
              samples: Number(stats.samples ?? 0),
              loss: typeof stats.loss_percent === "number" ? stats.loss_percent : null,
              availability:
                typeof stats.availability_percent === "number"
                  ? stats.availability_percent
                  : null,
              median: typeof stats.median_ms === "number" ? stats.median_ms : null,
              comparison,
            };
          })
          .sort((left, right) => {
            if (left.selected !== right.selected) return left.selected ? -1 : 1;
            if (left.available !== right.available) return left.available ? -1 : 1;
            const availability = (right.availability ?? -1) - (left.availability ?? -1);
            if (availability) return availability;
            const loss = (left.loss ?? 101) - (right.loss ?? 101);
            if (loss) return loss;
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
        const chosenIds = orderedCandidateNodeIds(displayOrder, routingNodes, configuredWireguardExits, configuredReverseVlessExits, asObjectList(policy.node_groups));
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
                  (token) => selectorDescription(token, routingRegions, configuredWireguardExits, configuredReverseVlessExits, locale, asObjectList(policy.node_groups)).title,
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
          median: typeof currentMedian === "number" ? tr("{value1} мс", { value1: currentMedian }) : "—",
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
                      {policy.median !== "—" ? <code title={tr("Медиана")}>{policy.median}</code> : null}
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
                    <th>{tr("Доступность / ошибки HTTPS")}</th>
                    <th>{tr("Медиана")}</th>
                    <th title={tr("Последнее парное сравнение с активным: минус — быстрее, плюс — медленнее.")}>{tr("Delta, %")}</th>
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
                          <strong>{node.unstable ? tr("Нестабилен") : node.availability == null ? tr("Нет замера") : `${node.availability.toFixed(1)}%`}</strong>
                          {node.unstable ? <small>{tr("Срыв маршрута")}</small> : node.loss == null ? null : <small>({node.loss.toFixed(1)}{tr("% ошибок HTTPS)")}</small>}
                        </span>
                      </td>
                      <td className="quality-measurement"><strong>{node.median == null ? "—" : tr("{value1} мс", { value1: node.median })}</strong></td>
                      <td className={node.comparison ? `quality-comparison ${node.comparison.percent < 0 ? "is-faster" : node.comparison.percent > 0 ? "is-slower" : ""}` : "quality-comparison"}
                        title={node.comparison ? tr("Последнее парное сравнение. Активный: {value1}; кандидат: {value2}", {
                          value1: formatTimestamp(new Date(node.comparison.activeAt * 1000).toISOString(), locale),
                          value2: formatTimestamp(new Date(node.comparison.candidateAt * 1000).toISOString(), locale),
                        }) : tr("Нет свежего подтверждённого сравнения")}>
                        {node.comparison ? `${node.comparison.percent > 0 ? "+" : ""}${node.comparison.percent.toLocaleString(locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%` : "—"}
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
        onAutosaveChange={onAutosaveChange}
        onPendingChange={onPendingChange}
        onSavingChange={onSavingChange}
      />
    </>
  );
}

type RoutingMonitorValues = {
  [Key in keyof typeof ROUTING_MONITOR_DEFAULTS]: number;
};

export function routingMonitorValues(config: JsonObject): RoutingMonitorValues {
  const monitor = asObject(asObject(config.system).routing_monitor);
  return Object.fromEntries(
    Object.entries(ROUTING_MONITOR_DEFAULTS).map(([key, fallback]) => {
      const value = Number(monitor[key]);
      return [key, Number.isInteger(value) && !(key === "probe_batch_size" && value === 0) ? value : fallback];
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
            {values.active_liveness_interval_seconds} / {values.active_quality_interval_seconds} {tr("сек.")}
          </span>
        </summary>
        <div className="routing-monitor-form">
          <div className="routing-monitor-grid">
            {numberField("active_liveness_interval_seconds", "Доступность активного узла, сек.", 2, 30)}
            {numberField("active_quality_interval_seconds", "Интервал оценки задержки, сек.", 10, 3600)}
            <label className="field">
              <span>{tr("Максимум проверок за цикл")}</span>
              <input
                type="number"
                min={1}
                max={64}
                step={1}
                required
                disabled={disabled}
                value={values.probe_batch_size}
                onChange={(event) => update("probe_batch_size", event.target.value)}
              />
              <small>{tr("Общий лимит одновременно проверяемых узлов: от 1 до 64. По умолчанию 10.")}</small>
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
  onAutosaveChange,
  onPendingChange,
  onSavingChange,
}: {
  config: JsonObject;
  runtime?: JsonObject;
  routeros: JsonObject;
  onDraftChanged: () => Promise<void>;
  onAutosaveChange: (autosave: DraftAutosave | null, reset?: () => void) => void;
  onPendingChange: (pending: boolean) => void;
  onSavingChange: (saving: boolean) => void;
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
  const [allowWanPing, setAllowWanPing] = useState(networking.allow_wan_ping !== false);
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
  const autosaveRef = useRef<DraftAutosave | null>(null);
  const saveRoutingRef = useRef<() => Promise<void>>(async () => undefined);
  const resetRoutingRef = useRef<() => void>(() => undefined);
  useEffect(() => {
    const autosave = new DraftAutosave({
      save: () => saveRoutingRef.current(),
      onPending: onPendingChange,
      onSaving: (saving) => { setSaveBusy(saving); onSavingChange(saving); },
      onError: (error) => setSaveMessage(prefixedErrorMessage(error)),
    });
    autosaveRef.current = autosave;
    onAutosaveChange(autosave, () => resetRoutingRef.current());
    return () => {
      autosave.dispose();
      autosaveRef.current = null;
      onAutosaveChange(null);
    };
  }, [onAutosaveChange, onPendingChange, onSavingChange]);
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
    autosaveRef.current?.discard();
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
    setAllowWanPing(networking.allow_wan_ping !== false);
    setForceTcpForProxyServices(dns.force_tcp_for_proxy_services === true);
    setRoutingMonitor(routingMonitorValues(config));
    setRoutingResetVersion((current) => current + 1);
    setSaveMessage(tr("Изменения формы сброшены."));
  }

  async function saveRoutingInfrastructure() {
    const monitorRanges: Array<[keyof RoutingMonitorValues, number, number]> = [
      ["active_liveness_interval_seconds", 2, 30],
      ["active_quality_interval_seconds", 10, 3600],
      ["probe_batch_size", 1, 64],
    ];
    if (monitorRanges.some(([key, minimum, maximum]) =>
      !Number.isInteger(routingMonitor[key]) || routingMonitor[key] < minimum || routingMonitor[key] > maximum
    )) {
      throw new Error(tr("Проверьте значения мониторинга маршрутов."));
    }

    if (!wireguardValid) {
      throw new Error(tr("Ошибка: выберите хотя бы один доступный WireGuard-интерфейс."));
    }
    setSaveBusy(true);
    setSaveMessage("");
    window.sessionStorage.removeItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY);
    try {
      const reverseVlessExits =
        reverseVlessCollector.current?.() ??
        asObjectList(config.reverse_vless_exits);
      const latest = await getCurrentDraft<DraftEnvelope>();
      const latestConfig = asObject(latest.config);
      const latestSystem = asObject(latestConfig.system);
      await saveCurrentDraft({
        config: withDeploymentReadiness(
          {
            ...latestConfig,
            reverse_vless_exits: reverseVlessExits,
            system: {
              ...latestSystem,
              routing_monitor: routingMonitor,
              networking: {
                ...asObject(latestSystem.networking),
                wireguard_egress_enabled: wireguardEnabled,
                wireguard_egress_exits: wireguardExits,
                remote_ipv6_mode: remoteIpv6Enabled ? "proxy_only" : "disabled",
                allow_wan_ping: allowWanPing,
              },
            },
            dns: {
              ...asObject(latestConfig.dns),
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
      throw error;
    } finally {
      setSaveBusy(false);
    }
  }

  useEffect(() => {
    saveRoutingRef.current = saveRoutingInfrastructure;
    resetRoutingRef.current = resetRoutingInfrastructure;
  });

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
    <section className="routing-infrastructure"
      onChangeCapture={() => autosaveRef.current?.update()}>
      <div className="routing-infrastructure-grid">
        <ReverseVlessSettings
          key={routingResetVersion}
          config={config}
          runtime={runtime}
          onDraftChanged={onDraftChanged}
          onCollectorChange={registerReverseVlessCollector}
          beforeMutation={async () => { await autosaveRef.current?.flush(); }}
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
              checked={allowWanPing}
              onChange={setAllowWanPing}
              label={tr("Ping через WAN")}
              description={allowWanPing ? tr("Ping использует WAN-IP, не VPN.") : tr("Публичный ping управляемых клиентов заблокирован.")}
            />
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
        onChange={(values) => { setRoutingMonitor(values); autosaveRef.current?.update(); }}
        disabled={saveBusy}
      />
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
  beforeMutation,
  saving,
}: {
  config: JsonObject;
  runtime?: JsonObject;
  onDraftChanged: () => Promise<void>;
  onCollectorChange: (collector: (() => JsonObject[]) | null) => void;
  beforeMutation: () => Promise<void>;
  saving: boolean;
}) {
  const { tr } = useLanguage();
  const xraySelected = true;
  const [statusNow, setStatusNow] = useState(0);
  const reverseSampledAt = asText(asObject(runtime?.reverse_telemetry).sampled_at, "");
  useEffect(() => {
    const refresh = () => setStatusNow(Date.now());
    const initial = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 30_000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [reverseSampledAt]);
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
      await beforeMutation();
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
      await beforeMutation();
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
        <form ref={formRef} onChange={() => setMessage("")} onSubmit={(event) => event.preventDefault()}>
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
                    aria-label={tr(availability.label)}
                    title={tr(availability.label)}
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
