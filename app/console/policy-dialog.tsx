"use client";

import { JsonObject, deleteCollectionItem, getSubscriptionNodes, saveCurrentDraft } from "../api-client";
import { useLanguage } from "../i18n";
import { withoutRetiredURLTestSettings } from "../urltest-settings";
import { routingMonitorValues } from "./routing";
import { CatalogServiceAdder, DirectServicePackPicker, PINPOINT_DOMAINS_BY_PACK, PolicySelectionMode, SubscriptionLocationPicker, SubscriptionNodeGroupEditor, Toggle, asObject, asObjectList, asStringList, asText, entityIdFromName, errorMessage, initialPolicySelectionOrder, itemName, mergePinpointDomains, normalizePolicySelectionMode, parsePinpointDomains, policySelectionMirrorsFromOrder, withDeploymentReadiness, withoutServicePackReferences } from "./shared";
import { FormEvent, useEffect, useRef, useState } from "react";

function CustomRouteEditor({ rules, onChange }: { rules: JsonObject[]; onChange: (rules: JsonObject[]) => void }) {
  const { tr } = useLanguage();
  function update(index: number, field: string, value: string) {
    onChange(rules.map((rule, at) => at === index ? { ...rule, [field]: value } : rule));
  }
  return (
    <section className="custom-route-editor form-span" aria-label={tr("Свои правила маршрутизации")}>
      <div className="subscription-location-heading">
        <div><strong>{tr("Свои правила маршрутизации")}</strong><small>{tr("Первое совпавшее правило направит трафик в выбранный путь. Эти правила выше карточек и действуют независимо от основного режима.")}</small></div>
      </div>
      {rules.map((rule, index) => <div className={`custom-route-row${rule.kind === "port" ? " custom-route-row-port" : ""}`} key={index}>
        <span className="custom-route-position">{index + 1}</span>
        <label className="field">{tr("Тип")}
          <select value={asText(rule.kind, "domain")} onChange={(event) => onChange(rules.map((item, at) => at === index ? { ...item, kind: event.target.value, value: "" } : item))}>
            <option value="domain">{tr("Домен и поддомены")}</option>
            <option value="ip">IP / CIDR</option>
            <option value="port">TCP / UDP {tr("порт")}</option>
          </select>
        </label>
        <label className="field custom-route-value">{tr("Значение")}
          <input value={asText(rule.value, "")} onChange={(event) => update(index, "value", event.target.value)} placeholder={asText(rule.kind, "domain") === "ip" ? "203.0.113.0/24" : asText(rule.kind, "domain") === "port" ? "443 или 1000-2000" : "example.com"} />
        </label>
        {rule.kind === "port" ? <label className="field">{tr("Сеть")}
          <select value={asText(rule.network, "tcp")} onChange={(event) => update(index, "network", event.target.value)}><option value="tcp">TCP</option><option value="udp">UDP</option></select>
        </label> : null}
        <label className="field">{tr("Направить")}
          <select value={asText(rule.target, "wan")} onChange={(event) => update(index, "target", event.target.value)}><option value="wan">WAN</option><option value="vless">VLESS</option></select>
        </label>
        <button type="button" className="button button-ghost custom-route-remove" title={tr("Удалить правило {number}", { number: index + 1 })} aria-label={tr("Удалить правило {number}", { number: index + 1 })} onClick={() => onChange(rules.filter((_, at) => at !== index))}>×</button>
        {(rule.kind === "domain" || rule.kind === "ip") ? <div className="custom-route-protocol-filter" role="group" aria-label={tr("Протоколы (необязательно)")}>
          <span>{tr("Протоколы (необязательно)")}</span>
          <div className="custom-route-protocol-options">{["http", "tls", "quic"].map((protocol) => <label key={protocol}><input type="checkbox" checked={asText(rule.protocols, "").split(",").includes(protocol)} onChange={(event) => {
            const selected = asText(rule.protocols, "").split(",").filter(Boolean);
            update(index, "protocols", (event.target.checked ? [...selected, protocol] : selected.filter((item) => item !== protocol)).join(","));
          }} />{protocol}</label>)}</div>
        </div> : null}
      </div>)}
      <button type="button" className="button button-secondary" disabled={rules.length >= 128} onClick={() => onChange([...rules, { kind: "domain", value: "", target: "wan", network: "tcp" }])}>{tr("Добавить правило")}</button>
      {rules.length ? <p className="custom-route-preview" role="status">{tr("Перед применением: {count} правил; порядок сверху вниз. IP- и портовые правила не перехватывают все DNS-запросы.", { count: rules.length })}</p> : null}
    </section>
  );
}

export function PolicyDialog({
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
  const [nodeGroups, setNodeGroups] = useState<JsonObject[]>(
    () => asObjectList(existingPolicy.node_groups),
  );
  const [customRoutes, setCustomRoutes] = useState<JsonObject[]>(
    () => asObjectList(existingPolicy.custom_routes),
  );
  const candidateLimit = routingMonitorValues(config).probe_batch_size;
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
        !selectedReverseVlessExits.length &&
        !selectionOrder.some((token) => token.startsWith("group:") && nodeGroups.some((group) => `group:${asText(group.id, "")}` === token))
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
        ...withoutRetiredURLTestSettings(existingPolicy),
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
        node_groups: nodeGroups,
        custom_routes: customRoutes,
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
        switch_improvement_ms: Number(data.get("switch_improvement_ms") ?? existingPolicy.switch_improvement_ms ?? 50),
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
                      <small>{tr("Выбирает узел по свежему HTTPS-отклику. Плановая смена требует подтверждённого преимущества.")}</small>
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
                <SubscriptionNodeGroupEditor
                  groups={nodeGroups}
                  originalGroups={asObjectList(existingPolicy.node_groups)}
                  nodes={subscriptionNodes}
                  subscriptions={asObjectList(config.subscriptions).filter((item) => item.enabled !== false)}
                  onChange={setNodeGroups}
                />
                {nodesBusy ? (
                  <div className="subscription-discovery-empty">{tr("Загружаю расположения из подписок…")}</div>
                ) : nodesError ? (
                  <div className="inline-result inline-result-error" role="alert"><span>!</span>{nodesError}</div>
                ) : (
                  <SubscriptionLocationPicker
                    nodes={subscriptionNodes}
                    nodeGroups={nodeGroups}
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
              <CustomRouteEditor rules={customRoutes} onChange={setCustomRoutes} />
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
                onGeoIPResolved={(pack) => {
                  const id = asText(pack.id, "");
                  setCustomPacks((current) => current.some((item) => asText(item.id, "") === id)
                    ? current
                    : [...current, pack]);
                  setExceptionServices((current) => current.includes(id) ? current : [...current, id]);
                }}
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
              {mode === "best" ? (
                <label className="field form-span policy-latency-tolerance">
                  <span>{tr("Порог переключения URLTest, мс")}</span>
                  <input name="switch_improvement_ms" type="number" min="0" max="30000" defaultValue={asText(existingPolicy.switch_improvement_ms, "50")} />
                  <small>{tr("Минимальное преимущество свежего HTTPS-отклика над активным узлом.")}</small>
                </label>
              ) : null}
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
