"use client";

import { JsonObject, RemoteUserSubscriptionLink, getRemoteUserSubscriptionLink } from "../api-client";
import { useLanguage } from "../i18n";
import { RouterSourceKind, RouterSourcePicker, Toggle, asObject, asObjectList, asStringList, asText, clientDnsAddress, clientTunAddressError, copyText, entityIdFromName, errorMessage, ipv4CidrRange, ipv4RangesOverlap, isPrivateIpv4Cidr, itemName, normalizeRouterSourceKind, remoteConnectionNameError, sourceCidrsForRow, suggestedClientTunAddress, transportKindLabel, useConnectionHostname, useRouterClientSources, wireGuardPeerMatchesDevice } from "./shared";
import { FormEvent, useEffect, useMemo, useState } from "react";

export function AddDialog({
  kind,
  onClose,
  onSave,
  onDelete,
  existingItem,
  config,
}: {
  kind: "local" | "remote";
  onClose: () => void;
  onSave: (
    kind: "local" | "remote",
    item: JsonObject,
    servicePacks: JsonObject[],
  ) => Promise<unknown>;
  onDelete?: () => Promise<void>;
  existingItem?: JsonObject;
  config: JsonObject;
}) {
  const { tr, locale } = useLanguage();
  const editing = Boolean(existingItem && asText(existingItem.id, ""));
  const connectionHostname = useConnectionHostname();
  const configuredInternalNetworks = asObjectList(config.networks)
    .filter(
      (network) =>
        network.enabled !== false &&
        ["internal", "management"].includes(
          asText(network.kind, "internal"),
        ),
    )
    .map((network) => {
      const id = asText(network.id, "");
      const name = itemName(network);
      const kind = asText(network.kind, "internal");
      const imported = id.startsWith("imported-") || network.imported === true;
      const displayName = imported
        ? kind === "management"
          ? tr("Сеть управления MikroTik")
          : tr("Внутренние маршрутизируемые сети")
        : name;
      return {
        id,
        name,
        displayName,
        kind,
        interfaceName: asText(
          network.interface ?? network.source_interface,
          "",
        ),
        cidrs: asStringList(network.cidrs),
      };
    })
    .filter((network) => network.id && network.cidrs.length);
  const [saved, setSaved] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [remoteRole, setRemoteRole] = useState(() => {
    const role = asText(existingItem?.role, "trusted-full");
    return role === "disabled" ? "internet-only" : role;
  });
  const [savedSubscription, setSavedSubscription] =
    useState<RemoteUserSubscriptionLink | null>(null);
  const [savedSubscriptionError, setSavedSubscriptionError] = useState("");
  const [subscriptionCopied, setSubscriptionCopied] = useState(false);
  const [selectedAllowedCidrs, setSelectedAllowedCidrs] = useState<string[]>(
    () => {
      const selected = new Set(asStringList(existingItem?.allowed_cidrs));
      const legacyNetworkIds = new Set(
        asStringList(existingItem?.allowed_network_ids),
      );
      for (const network of configuredInternalNetworks) {
        if (legacyNetworkIds.has(network.id)) {
          network.cidrs.forEach((cidr) => selected.add(cidr));
        }
      }
      return [...selected];
    },
  );
  const [allowedNetworkQuery, setAllowedNetworkQuery] = useState("");
  const [savedName, setSavedName] = useState("");
  const [remoteConnectionName, setRemoteConnectionName] = useState(
    asText(existingItem?.display_name, ""),
  );
  const [localDeviceName, setLocalDeviceName] = useState(
    asText(existingItem?.name, ""),
  );
  const [remoteTunAddress, setRemoteTunAddress] = useState(
    asText(existingItem?.client_tun_address, ""),
  );
  const [sourceKind, setSourceKind] = useState<RouterSourceKind>(
    normalizeRouterSourceKind(existingItem?.source_kind),
  );
  const [allLanDevices, setAllLanDevices] = useState(
    asText(existingItem?.source_scope, "") === "lan-all",
  );
  const [selectedSourceCidrs, setSelectedSourceCidrs] = useState<string[]>(
    asStringList(existingItem?.source_cidrs),
  );
  const [selectedSourcePeerRefs, setSelectedSourcePeerRefs] = useState<string[]>(
    asStringList(existingItem?.source_peer_refs),
  );
  const [excludedTransportIds, setExcludedTransportIds] = useState<string[]>(
    asStringList(existingItem?.excluded_transports),
  );
  const [happIncludeAllNetworks, setHappIncludeAllNetworks] = useState(
    existingItem?.happ_include_all_networks !== false,
  );
  const [happExcludeLocalNetworks, setHappExcludeLocalNetworks] = useState(
    existingItem?.happ_exclude_local_networks !== false,
  );
  const [happExcludeAPNs, setHappExcludeAPNs] = useState(
    existingItem?.happ_exclude_apns !== false,
  );
  const happProviderConfigured = Boolean(
    asText(
      asObject(asObject(config.public_exposure).subscription).happ_provider_id,
      "",
    ).trim(),
  );
  const routerSources = useRouterClientSources();
  const existingId = asText(existingItem?.id, "");
  const tunSuggestion = suggestedClientTunAddress(
    config,
    routerSources.discovery,
    existingId,
  );
  const remoteNameError =
    kind === "remote"
      ? remoteConnectionNameError(config, existingId, remoteConnectionName, locale)
      : "";
  const remoteTunError =
    kind === "remote"
      ? clientTunAddressError(
          config,
          routerSources.discovery,
          existingId,
          remoteTunAddress,
          locale,
        )
      : "";
  const sourceRows = useMemo(() => {
    const sourceInventory = asObject(routerSources.discovery.client_sources);
    return asObjectList(sourceInventory[sourceKind]);
  }, [routerSources.discovery, sourceKind]);
  const sourceInventoryComplete =
    asObject(routerSources.discovery.client_source_inventory_complete)[sourceKind] ===
    true;
  const allLANInventoryComplete =
    routerSources.discovery.lan_source_inventory_complete === true;
  const discoveredAllLANCidrs = asStringList(
    routerSources.discovery.lan_source_cidrs,
  );
  const availableSourceCidrs = useMemo(
    () => new Set(sourceRows.flatMap(sourceCidrsForRow)),
    [sourceRows],
  );
  const sourceRowsByCidr = useMemo(
    () => new Map(
      sourceRows.flatMap((row) =>
        sourceCidrsForRow(row).map((cidr) => [cidr, row] as const),
      ),
    ),
    [sourceRows],
  );
  const effectiveSourceCidrs = allLanDevices
    ? allLANInventoryComplete
      ? discoveredAllLANCidrs
      : selectedSourceCidrs
    : sourceInventoryComplete
      ? selectedSourceCidrs.filter((cidr) => availableSourceCidrs.has(cidr))
      : selectedSourceCidrs;
  const invalidSelectedSource = selectedSourceCidrs.find((cidr) => {
    const row = sourceRowsByCidr.get(cidr);
    return sourceInventoryComplete && (!row || row.valid === false);
  });
  useEffect(() => {
    if (
      sourceKind !== "wireguard" ||
      !sourceInventoryComplete ||
      !selectedSourcePeerRefs.length
    ) {
      return;
    }
    const currentCidrs = sourceRows
      .filter((row) =>
        selectedSourcePeerRefs.includes(asText(row.peer_ref, "")),
      )
      .flatMap(sourceCidrsForRow);
    if (!currentCidrs.length) return;
    const currentKey = [...new Set(currentCidrs)].sort().join("|");
    const selectedKey = [...new Set(selectedSourceCidrs)].sort().join("|");
    if (currentKey !== selectedKey) {
      const timer = window.setTimeout(
        () => setSelectedSourceCidrs([...new Set(currentCidrs)]),
        0,
      );
      return () => window.clearTimeout(timer);
    }
  }, [
    selectedSourceCidrs,
    selectedSourcePeerRefs,
    sourceInventoryComplete,
    sourceKind,
    sourceRows,
  ]);
  useEffect(() => {
    if (
      kind !== "local" ||
      !editing ||
      sourceKind !== "wireguard" ||
      !sourceRows.length ||
      selectedSourcePeerRefs.length ||
      selectedSourceCidrs.length !== 1
    ) {
      return;
    }
    const legacyCidr = selectedSourceCidrs[0];
    if (availableSourceCidrs.has(legacyCidr)) return;
    const matchingPeers = sourceRows.filter((row) =>
      Boolean(asText(row.peer_ref, "")) &&
      wireGuardPeerMatchesDevice(row.peer_name, localDeviceName),
    );
    if (matchingPeers.length !== 1) return;
    const peer = matchingPeers[0];
    const peerRef = asText(peer.peer_ref, "");
    const peerCidrs = sourceCidrsForRow(peer);
    if (!peerRef || !peerCidrs.length) return;
    const timer = window.setTimeout(() => {
      setSelectedSourcePeerRefs([peerRef]);
      setSelectedSourceCidrs(peerCidrs);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [
    availableSourceCidrs,
    editing,
    kind,
    localDeviceName,
    selectedSourceCidrs,
    selectedSourcePeerRefs,
    sourceKind,
    sourceRows,
  ]);
  const directClientDns = clientDnsAddress(config);
  const anotherAllLANClient = asObjectList(config.local_clients).find(
    (client) =>
      asText(client.id, "") !== existingId &&
      asText(client.source_kind, "lan") === "lan" &&
      asText(client.source_scope, "") === "lan-all",
  );
  const policyOptions = asObjectList(config.policies)
    .filter(
      (policy) =>
        policy.enabled !== false &&
        typeof policy.id === "string",
    )
    .map((policy) => ({
      id: asText(policy.id),
      name: itemName(policy),
    }));
  const remoteTransportOptions = asObjectList(config.transports)
    .filter(
      (transport) =>
        transport.enabled !== false &&
        typeof transport.id === "string",
    )
    .map((transport) => ({
      id: asText(transport.id, ""),
      name: itemName(transport),
      kind: asText(transport.kind, ""),
      kindLabel: transportKindLabel(transport.kind),
      hostname: connectionHostname(transport, tr("Адрес ещё не настроен")),
      port: Number(
        transport.listen_port ??
          asObject(config.ingress).public_listen_port ??
          443,
      ),
    }))
    .filter((transport) => transport.id);
  const configuredNetworkByCidr = new Map(
    configuredInternalNetworks.flatMap((network) =>
      network.cidrs.map((cidr) => [cidr, network] as const),
    ),
  );
  const runtimeNetworking = asObject(asObject(config.system).networking);
  const runtimeLinkRanges = [
    asText(runtimeNetworking.container_address, ""),
    asText(runtimeNetworking.tun_address, ""),
  ]
    .map(ipv4CidrRange)
    .filter((range): range is [number, number] => range !== null);
  const discoveredAccessDestinations = asObjectList(
    routerSources.discovery.access_destinations,
  ).filter((destination) => {
    const cidr = asText(destination.cidr, "");
    if (configuredNetworkByCidr.has(cidr)) return true;
    const range = ipv4CidrRange(cidr);
    return Boolean(
      range &&
        isPrivateIpv4Cidr(cidr) &&
        !runtimeLinkRanges.some((reserved) => ipv4RangesOverlap(range, reserved)),
    );
  });
  const liveUnconfiguredGroupId = "routeros-live-unconfigured";
  const hasLiveUnconfiguredDestinations = discoveredAccessDestinations.some(
    (destination) => {
      const cidr = asText(destination.cidr, "");
      return Boolean(cidr && !configuredNetworkByCidr.has(cidr));
    },
  );
  const destinationGroupDefinitions = [
    ...configuredInternalNetworks.map((network) => ({
      id: network.id,
      displayName: network.displayName,
      description:
        network.kind === "management"
          ? tr("Доступ к самому роутеру и его служебной сети")
          : tr("Сети назначения, уже настроенные в маршрутизации MikroTik"),
    })),
    ...(hasLiveUnconfiguredDestinations
      ? [{
          id: liveUnconfiguredGroupId,
          displayName: tr("Новые маршруты MikroTik"),
          description: tr("Автоматически обнаружены в актуальной таблице маршрутов"),
        }]
      : []),
  ];
  const liveDestinationEntries = discoveredAccessDestinations
    .map((destination) => {
      const cidr = asText(destination.cidr, "");
      const configuredNetwork = configuredNetworkByCidr.get(cidr);
      if (!cidr) return null;
      const groupId = configuredNetwork?.id ?? liveUnconfiguredGroupId;
      const comment = asText(destination.comment, "");
      const title =
        configuredNetwork?.kind === "management"
          ? tr("Сеть управления")
          : !configuredNetwork
            ? tr("Новый внутренний маршрут")
          : /\/(32|128)$/.test(cidr)
            ? tr("Маршрутизируемый внутренний адрес")
            : tr("Внутренняя подсеть");
      return {
        cidr,
        groupId,
        title,
        detail: [
          configuredNetwork
            ? tr("Маршрут уже настроен в MikroTik")
            : tr("Обнаружен автоматически; полный доступ использует live-набор"),
          comment,
        ]
          .filter(Boolean)
          .join(" · "),
      };
    })
    .filter(
      (
        entry,
      ): entry is {
        cidr: string;
        groupId: string;
        title: string;
        detail: string;
      } => entry !== null,
    );
  const fallbackDestinationEntries = configuredInternalNetworks.flatMap(
    (network) =>
      network.cidrs
        .filter((cidr) => !/\/(32|128)$/.test(cidr))
        .map((cidr) => ({
          cidr,
          groupId: network.id,
          title:
            network.kind === "management"
              ? tr("Сеть управления")
              : tr("Внутренняя подсеть"),
          detail: tr("Подсеть из группы «{value1}»; live-маршрут временно недоступен", { value1: network.displayName }),
        })),
  );
  const destinationEntries =
    discoveredAccessDestinations.length ||
    routerSources.discovery.access_destination_inventory_complete === true
      ? liveDestinationEntries
      : fallbackDestinationEntries;
  const networkOptions = destinationGroupDefinitions
    .map((group) => ({
      ...group,
      entries: destinationEntries
        .filter((entry) => entry.groupId === group.id)
        .sort((left, right) => left.cidr.localeCompare(right.cidr, "en")),
    }))
    .filter((group) => group.entries.length);
  const normalizedNetworkQuery = allowedNetworkQuery.trim().toLocaleLowerCase("ru");
  const visibleNetworkOptions = networkOptions
    .map((network) => ({
      ...network,
      entries: network.entries.filter((entry) =>
        !normalizedNetworkQuery ||
        `${network.displayName} ${network.description} ${entry.cidr} ${entry.title} ${entry.detail}`
          .toLocaleLowerCase("ru")
          .includes(normalizedNetworkQuery),
      ),
    }))
    .filter((network) => network.entries.length);
  const availableAllowedCidrs = networkOptions.flatMap((network) =>
    network.entries.map((entry) => entry.cidr),
  );
  const effectiveSelectedAllowedCidrs = selectedAllowedCidrs.filter((cidr) =>
    availableAllowedCidrs.includes(cidr),
  );

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    setSaveBusy(true);
    setSaveError("");
    const data = new FormData(form);
    const name = String(data.get("name") ?? "").trim();
    if (kind === "remote" && remoteNameError) {
      setSaveError(remoteNameError);
      setSaveBusy(false);
      return;
    }
    if (kind === "remote" && remoteTunError) {
      setSaveError(remoteTunError);
      setSaveBusy(false);
      return;
    }
    const collection = kind === "local" ? config.local_clients : config.remote_users;
    const occupiedIds = new Set(
      asObjectList(collection)
        .map((item) => asText(item.id, ""))
        .filter((id) => id && id !== existingId),
    );
    const id = editing
      ? existingId
      : entityIdFromName(
          name,
          occupiedIds,
          kind === "local" ? "device" : "user",
        );
    const allowedPortTokens = String(data.get("allowed_ports") ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    const allowedPorts = allowedPortTokens.map(Number);
    if (
      kind === "remote" &&
      allowedPorts.some(
        (value) => !Number.isInteger(value) || value < 1 || value > 65535,
      )
    ) {
      setSaveError(tr("Порты должны быть целыми числами от 1 до 65535 через запятую."));
      setSaveBusy(false);
      return;
    }
    if (kind === "local" && !allLanDevices && invalidSelectedSource) {
      const row = sourceRowsByCidr.get(invalidSelectedSource);
      setSaveError(
        asText(
          row?.validation_message,
          tr("Адрес WireGuard {value1} отсутствует или конфликтует с адресом RouterOS.", { value1: invalidSelectedSource }),
        ),
      );
      setSaveBusy(false);
      return;
    }
    if (kind === "local" && !effectiveSourceCidrs.length) {
      setSaveError(
        allLanDevices
          ? tr("MikroTik не вернул ни одной IPv4-подсети из списка интерфейсов LAN. Проверьте список LAN и обновите инвентарь.")
          : tr("Выберите хотя бы один статический адрес с MikroTik."),
      );
      setSaveBusy(false);
      return;
    }
    if (
      kind === "remote" &&
      remoteRole === "trusted-limited" &&
      !effectiveSelectedAllowedCidrs.length
    ) {
      setSaveError(
        tr("Для ограниченного доступа выберите хотя бы одну внутреннюю сеть."),
      );
      setSaveBusy(false);
      return;
    }
    const item: JsonObject =
      kind === "local"
        ? {
            ...existingItem,
            id,
            name,
            source_kind: sourceKind,
            source_scope: allLanDevices ? "lan-all" : undefined,
            source_cidrs: effectiveSourceCidrs,
            source_peer_refs:
              sourceKind === "wireguard" ? selectedSourcePeerRefs : [],
            policy_id: String(data.get("policy") ?? ""),
            container_outage: String(data.get("container_outage") ?? "direct"),
            direct_domains: undefined,
            direct_services: undefined,
            service_routes: undefined,
            final: undefined,
            enabled: data.get("enabled") === "on",
          }
        : {
            ...existingItem,
            id,
            display_name: name,
            role: String(data.get("role") ?? ""),
            policy_id: String(data.get("policy") ?? ""),
            client_tun_address: String(
              data.get("client_tun_address") ?? "",
            ),
            subscription_format: String(
              data.get("subscription_format") ?? "auto",
            ),
            client_fingerprint: String(
              data.get("client_fingerprint") ?? "chrome",
            ),
            client_tun_stack: String(
              data.get("client_tun_stack") ?? "auto",
            ),
            client_individual_routing:
              data.get("client_individual_routing") === "on",
            client_auto_fallback:
              data.get("client_auto_fallback") === "on",
            client_adblock: data.get("client_adblock") === "on",
            happ_include_all_networks: happIncludeAllNetworks,
            happ_exclude_local_networks: happExcludeLocalNetworks,
            happ_exclude_apns: happExcludeAPNs,
            excluded_transports: [...new Set(excludedTransportIds)],
            allowed_network_ids: [],
            allowed_cidrs:
              remoteRole === "trusted-limited"
                ? effectiveSelectedAllowedCidrs
                : [],
            allowed_ports: allowedPorts,
            direct_domains: undefined,
            direct_services: undefined,
            generate_uuid: !editing,
            enabled: data.get("enabled") === "on",
          };
    try {
      await onSave(kind, item, asObjectList(config.service_packs));
      if (kind === "remote") {
        try {
          setSavedSubscription(await getRemoteUserSubscriptionLink(id));
          setSavedSubscriptionError("");
        } catch (error) {
          setSavedSubscriptionError(errorMessage(error));
        }
      }
      setSavedName(name);
      setSaved(true);
    } catch (error) {
      setSaveError(errorMessage(error));
    } finally {
      setSaveBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="modal modal-wide"
        role="dialog"
        aria-modal="true"
        aria-labelledby="add-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        {saved ? (
          <div className="modal-success">
            <span>✓</span>
            <h2 id="add-title">
              {kind === "remote"
                ? editing
                  ? tr("Профиль пользователя обновлён")
                  : tr("Профиль «{value1}» создан", { value1: savedName })
                : editing
                  ? tr("Изменения сохранены")
                  : tr("Устройство добавлено")}
            </h2>
            <p>
              {kind === "remote"
                ? tr("Одна постоянная подписка автоматически включает все серверные транспорты, кроме снятых вами. До успешного Apply она не отдаёт черновые или нерабочие изменения.")
                : allLanDevices
                  ? tr("Все устройства из выбранных LAN-подсетей получат этот маршрут после Apply. Отдельные карточки устройств сохраняют приоритет.")
                  : tr("Сеть пока не менялась. Для включения примените сохранённые изменения.")}
            </p>
            {kind === "remote" && savedSubscription ? (
              <div className="saved-subscription">
                <label className="field">
                   {tr("URL подписки")} <input
                    type="text"
                    value={savedSubscription.url}
                    readOnly
                    onFocus={(event) => event.currentTarget.select()}
                  />
                </label>
                <button
                  className="button button-secondary"
                  type="button"
                  onClick={async () => {
                    try {
                      await copyText(savedSubscription.url);
                      setSubscriptionCopied(true);
                      setSavedSubscriptionError("");
                    } catch (error) {
                      setSavedSubscriptionError(errorMessage(error));
                    }
                  }}
                >
                  {subscriptionCopied ? tr("Скопировано") : tr("Скопировать ссылку")}
                </button>
                <small>
                  {savedSubscription.active
                    ? tr("Ссылка уже активна; изменения транспортов появятся после следующего Apply.")
                    : tr("Ссылка начнёт отдавать профиль после первого успешного Apply.")}
                </small>
              </div>
            ) : null}
            {kind === "remote" && savedSubscriptionError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {savedSubscriptionError}
              </div>
            ) : null}
            <button className="button button-primary" onClick={onClose}>
              {kind === "remote" ? tr("Перейти к карточке профиля") : tr("Вернуться к устройствам")}
            </button>
          </div>
        ) : (
          <form onSubmit={submit}>
            <p className="eyebrow">
              {kind === "local" ? tr("Локальное или VPN") : tr("Удалённый VPN")}
            </p>
            <h2 id="add-title">
              {kind === "local"
                ? editing
                  ? tr("Настроить устройство")
                  : tr("Добавить устройство")
                : editing
                  ? tr("Настроить пользователя")
                  : tr("Добавить пользователя")}
            </h2>
            <p className="modal-lead">
              {kind === "local"
                ? tr("Выберите отдельные адреса или назначьте один маршрут всем устройствам LAN / Wi‑Fi. Отдельная карточка устройства всегда имеет приоритет.")
                : tr("Технический идентификатор и UUID создаются автоматически. Пользователь подключается через любой включённый серверный транспорт по одной обновляемой подписке.")}
            </p>
            <div className="form-grid">
              <label className="field">
                {kind === "remote" ? tr("Имя подключения") : tr("Имя устройства")}
                {kind === "remote" ? (
                  <>
                    <input
                      required
                      name="name"
                      value={remoteConnectionName}
                      onChange={(event) => setRemoteConnectionName(event.target.value)}
                      aria-invalid={remoteNameError ? "true" : undefined}
                      aria-describedby={remoteNameError ? "remote-name-error" : undefined}
                    />
                    {remoteNameError ? (
                      <small className="field-inline-error" id="remote-name-error" role="alert">
                        {remoteNameError}
                      </small>
                    ) : null}
                  </>
                ) : (
                  <input
                    required
                    name="name"
                    value={localDeviceName}
                    onChange={(event) => setLocalDeviceName(event.target.value)}
                  />
                )}
              </label>
              {kind === "local" ? (
                <>
                  <label className="field">
                     {tr("Откуда подключён клиент")} <select
                      value={sourceKind}
                      onChange={(event) => {
                        setSourceKind(event.target.value as RouterSourceKind);
                        setAllLanDevices(false);
                        setSelectedSourceCidrs([]);
                        setSelectedSourcePeerRefs([]);
                      }}
                    >
                      <option value="lan">LAN / Wi‑Fi MikroTik</option>
                      <option value="wireguard">WireGuard</option>
                      <option value="ppp-vpn">{tr("PPP / OpenVPN / другой VPN")}</option>
                    </select>
                    <small>
                      {sourceKind === "lan"
                        ? tr("Для одного устройства используется статическая аренда; общий режим охватывает и динамические адреса.")
                        : tr("Показываются только фактические статические адреса выбранного типа.")}
                    </small>
                  </label>
                  <label className="field">
                     {tr("Маршрутный лист")} <select
                      name="policy"
                      defaultValue={asText(existingItem?.policy_id, "") || policyOptions[0]?.id}
                      disabled={!policyOptions.length}
                      required
                    >
                      {!policyOptions.length ? <option value="">{tr("Сначала создайте маршрутный лист")}</option> : null}
                      {policyOptions.map((policy) => <option value={policy.id} key={policy.id}>{policy.name}</option>)}
                    </select>
                    <small>{tr("Режим WAN/VLESS, расположения и карточки настраиваются в разделе «Маршрутизация».")}</small>
                  </label>
                  {sourceKind === "lan" ? (
                    <Toggle
                      className="form-span"
                      checked={allLanDevices}
                      disabled={Boolean(anotherAllLANClient)}
                      onChange={(checked) => {
                        setAllLanDevices(checked);
                        if (checked && discoveredAllLANCidrs.length) {
                          setSelectedSourceCidrs(discoveredAllLANCidrs);
                        }
                      }}
                      tone="state"
                      label={tr("Все устройства LAN / Wi‑Fi")}
                      description={
                        anotherAllLANClient
                          ? tr("Общий маршрут уже задан записью «{value1}». Откройте её для изменения.", { value1: itemName(anotherAllLANClient) })
                          : tr("Работает для статических и динамических адресов во всех подсетях интерфейсов RouterOS LAN. Отдельные устройства исключаются автоматически и используют свой маршрутный лист и DNS.")
                      }
                    />
                  ) : null}
                  {allLanDevices ? (
                    <fieldset className="field form-span router-source-picker">
                      <legend className="sr-only">{tr("Подсети общего маршрута LAN / Wi‑Fi")}</legend>
                      <div className="router-source-picker-heading">
                        <strong>{tr("Подсети интерфейсов LAN")}</strong>
                        <button
                          type="button"
                          className="text-button"
                          disabled={routerSources.busy}
                          onClick={() => void routerSources.refresh()}
                        >
                          {routerSources.busy ? tr("Обновляю…") : tr("Обновить список")}
                        </button>
                      </div>
                      {routerSources.error ? (
                        <div className="inline-result inline-result-error" role="alert">
                          <span>!</span>{routerSources.error}
                        </div>
                      ) : effectiveSourceCidrs.length ? (
                        <div className="all-lan-cidr-list">
                          {effectiveSourceCidrs.map((cidr) => <code key={cidr}>{cidr}</code>)}
                        </div>
                      ) : (
                        <div className="subscription-discovery-empty">
                          {allLANInventoryComplete
                            ? tr("В списке RouterOS LAN нет интерфейсов с IPv4-подсетями.")
                            : tr("Читаю подсети интерфейсов LAN с MikroTik…")}
                        </div>
                      )}
                      <small>
                         {tr("Изменение DHCP-адреса устройства не требует редактирования карточки. Новую LAN-подсеть нужно сохранить и применить после обновления списка.")} </small>
                    </fieldset>
                  ) : (
                    <RouterSourcePicker
                      kind={sourceKind}
                      selectedCidrs={selectedSourceCidrs}
                      selectedPeerRefs={selectedSourcePeerRefs}
                      onChange={setSelectedSourceCidrs}
                      onPeerRefsChange={setSelectedSourcePeerRefs}
                      discovery={routerSources.discovery}
                      busy={routerSources.busy}
                      error={routerSources.error}
                      onRefresh={routerSources.refresh}
                    />
                  )}
                  {sourceKind === "wireguard" ? (
                    <div className="wireguard-client-hint form-span">
                      <strong>{tr("На устройстве WireGuard при")}</strong>
                      <span>AllowedIPs 0.0.0.0/0 · DNS {directClientDns}</span>
                      <small>{tr("DNS перехватывается шлюзом и следует выбранному маршруту.")}</small>
                    </div>
                  ) : null}
                  <label className="field form-span">
                     {tr("Если контейнер на MikroTik остановился")} <select name="container_outage" defaultValue={asText(existingItem?.container_outage, "direct")}>
                      <option value="direct">{tr("Полный доступ через обычный WAN")}</option>
                      <option value="lan_only">{tr("Только LAN + списки исключений маршрутного листа")}</option>
                    </select>
                    <small>
                       {tr("Это аварийное поведение только выбранных IP. Другие устройства сохраняют собственный режим.")} </small>
                  </label>
                  <Toggle
                    className="form-span"
                    name="enabled"
                    defaultChecked={existingItem?.enabled !== false}
                    tone="state"
                    label={tr("Устройство включено")}
                    description={tr("Выключенная запись сохраняется и не участвует в маршрутизации.")}
                  />
                </>
              ) : (
                <>
                  <label className="field">
                     {tr("Доступ к LAN")} <select
                      name="role"
                      value={remoteRole}
                      onChange={(event) => setRemoteRole(event.target.value)}
                    >
                      <option value="trusted-full">
                         {tr("Полный доступ к LAN")} </option>
                      <option value="trusted-limited">
                         {tr("Ограниченный доступ к LAN")} </option>
                      <option value="internet-only">{tr("Без доступа к LAN")}</option>
                    </select>
                  </label>
                  <label className="field">
                     {tr("Политика интернета")} <select
                      name="policy"
                      defaultValue={
                        asText(existingItem?.policy_id, "") || policyOptions[0]?.id
                      }
                      disabled={!policyOptions.length}
                    >
                      {!policyOptions.length ? (
                        <option value="">{tr("Сначала создайте политику")}</option>
                      ) : null}
                      {policyOptions.map((policy) => (
                        <option value={policy.id} key={policy.id}>
                          {policy.name}
                        </option>
                      ))}
                    </select>
                    <small>{tr("Страны, города, режим WAN/VLESS и исключения настраиваются только в этом маршрутном листе.")}</small>
                  </label>
                  <label className="field remote-tun-field">
                     {tr("TUN-адрес")} <input
                      required
                      name="client_tun_address"
                      value={remoteTunAddress}
                      onChange={(event) => setRemoteTunAddress(event.target.value)}
                      autoCapitalize="none"
                      spellCheck={false}
                      placeholder={tunSuggestion || "IPv4/CIDR"}
                      aria-invalid={remoteTunError ? "true" : undefined}
                      aria-describedby={remoteTunError ? "remote-tun-error" : "remote-tun-hint"}
                    />
                    {remoteTunError ? (
                      <small className="field-inline-error" id="remote-tun-error" role="alert">
                        {remoteTunError}
                      </small>
                    ) : (
                      <small id="remote-tun-hint">
                        {routerSources.busy
                          ? tr("Проверяю сети…")
                          : tunSuggestion
                            ? <>{tr("Свободный:")} <code>{tunSuggestion}</code></>
                            : tr("Укажите свободный IPv4/CIDR.")}
                      </small>
                    )}
                  </label>
                  {remoteRole === "trusted-limited" ? (
                    <fieldset className="field form-span lan-access-picker">
                      <legend>{tr("К каким внутренним сетям разрешить доступ")}</legend>
                      <p className="lan-access-explanation">
                         {tr("Выберите сети назначения. MikroTik уже знает, через какой маршрут их передавать; адреса VPN-транспорта здесь не показываются.")} </p>
                      <div className="lan-access-toolbar">
                        <label className="lan-access-search">
                          <span>{tr("Найти внутреннюю сеть")}</span>
                          <input
                            type="search"
                            value={allowedNetworkQuery}
                            onChange={(event) =>
                              setAllowedNetworkQuery(event.target.value)
                            }
                            placeholder={tr("Например: 192.168.55.0/24")}
                          />
                        </label>
                        <div className="lan-access-actions">
                          <span aria-live="polite">
                             {tr("Выбрано:")} <strong>{effectiveSelectedAllowedCidrs.length}</strong>
                          </span>
                          <button
                            className="text-button"
                            type="button"
                            onClick={() =>
                              setSelectedAllowedCidrs(availableAllowedCidrs)
                            }
                            disabled={!availableAllowedCidrs.length}
                          >
                             {tr("Выбрать все сети")} </button>
                          <button
                            className="text-button"
                            type="button"
                            onClick={() => setSelectedAllowedCidrs([])}
                            disabled={!effectiveSelectedAllowedCidrs.length}
                          >
                             {tr("Снять выбор")} </button>
                        </div>
                      </div>
                      {routerSources.busy ? (
                        <div className="lan-access-source-status" role="status">
                           {tr("Читаю сети назначения из таблицы маршрутов MikroTik…")} </div>
                      ) : routerSources.error ? (
                        <div className="lan-access-source-status lan-access-source-status-warn">
                           {tr("Live RouterOS сейчас недоступен. Показаны только подсети из черновика; транспортные адреса /32 скрыты.")} </div>
                      ) : null}
                      <div className="lan-network-list">
                        {visibleNetworkOptions.length ? (
                          visibleNetworkOptions.map((network) => {
                            const networkCidrs = network.entries.map(
                              (entry) => entry.cidr,
                            );
                            const selectedInNetwork = networkCidrs.filter((cidr) =>
                              effectiveSelectedAllowedCidrs.includes(cidr),
                            ).length;
                            const wholeNetworkSelected =
                              selectedInNetwork === networkCidrs.length;
                            return (
                              <section className="lan-network-group" key={network.id}>
                                <header className="lan-network-group-header">
                                  <span>
                                    <strong>{network.displayName}</strong>
                                    <small>
                                      {network.description}
                                      {tr(" · выбрано {value1} из {value2}", { value1: selectedInNetwork, value2: networkCidrs.length })}
                                    </small>
                                  </span>
                                  <button
                                    className="text-button"
                                    type="button"
                                    onClick={() =>
                                      setSelectedAllowedCidrs(() => {
                                        const next = new Set(
                                          effectiveSelectedAllowedCidrs,
                                        );
                                        networkCidrs.forEach((cidr) =>
                                          wholeNetworkSelected
                                            ? next.delete(cidr)
                                            : next.add(cidr),
                                        );
                                        return [...next];
                                      })
                                    }
                                  >
                                    {wholeNetworkSelected
                                      ? normalizedNetworkQuery
                                        ? tr("Снять найденные")
                                        : tr("Снять группу")
                                      : normalizedNetworkQuery
                                        ? tr("Выбрать найденные")
                                        : tr("Выбрать группу")}
                                  </button>
                                </header>
                                <div className="lan-cidr-options">
                                  {network.entries.map((entry) => {
                                    const checked =
                                      effectiveSelectedAllowedCidrs.includes(
                                        entry.cidr,
                                      );
                                    return (
                                      <label className="lan-cidr-option" key={entry.cidr}>
                                        <input
                                          name="allowed_cidrs"
                                          type="checkbox"
                                          value={entry.cidr}
                                          checked={checked}
                                          onChange={() =>
                                            setSelectedAllowedCidrs((current) =>
                                              checked
                                                ? current.filter(
                                                    (cidr) => cidr !== entry.cidr,
                                                  )
                                                : [...current, entry.cidr],
                                            )
                                          }
                                        />
                                        <span className="lan-cidr-copy">
                                          <code>{entry.cidr}</code>
                                          <span>
                                            <strong>{entry.title}</strong>
                                            <small>{entry.detail}</small>
                                          </span>
                                        </span>
                                      </label>
                                    );
                                  })}
                                </div>
                              </section>
                            );
                          })
                        ) : (
                          <div className="subscription-discovery-empty">
                            {networkOptions.length
                              ? tr("По этому запросу ничего не найдено.")
                              : tr("В черновике нет включённых внутренних сетей. Сначала импортируйте и классифицируйте сети MikroTik.")}
                          </div>
                        )}
                      </div>
                      <label className="field lan-access-ports">
                         {tr("Разрешённые TCP/UDP-порты")} <input
                          name="allowed_ports"
                          inputMode="numeric"
                          defaultValue={
                            Array.isArray(existingItem?.allowed_ports)
                              ? existingItem.allowed_ports.map(String).join(", ")
                              : ""
                          }
                          placeholder={tr("Например: 22, 80, 443")}
                        />
                        <small>
                           {tr("Пустое поле разрешает все порты только у отмеченных выше назначений.")} </small>
                      </label>
                    </fieldset>
                  ) : null}
                  <label className="field">
                     {tr("Формат подписки")} <select
                      name="subscription_format"
                      defaultValue={asText(
                        existingItem?.subscription_format,
                        "auto",
                      )}
                    >
                      <option value="auto">{tr("Совместимый список · рекомендуется")}</option>
                      <option value="array">{tr("JSON-массив · узлы и автовыбор")}</option>
                      <option value="xray">{tr("Xray JSON · только Xray-клиенты")}</option>
                      <option value="singbox">Sing-box JSON · Hiddify/Karing</option>
                      <option value="mihomo">{tr("Mihomo YAML · только Mihomo/Clash")}</option>
                      <option value="links">{tr("Список ссылок · только узлы")}</option>
                    </select>
                  </label>
                  <label className="field">
                    uTLS fingerprint
                    <select
                      name="client_fingerprint"
                      defaultValue={asText(existingItem?.client_fingerprint, "chrome")}
                    >
                      <option value="chrome">{tr("Chrome · по умолчанию")}</option>
                      <option value="firefox">Firefox</option>
                      <option value="safari">Safari</option>
                      <option value="ios">iOS</option>
                      <option value="android">Android</option>
                      <option value="edge">Edge</option>
                      <option value="360">360 Secure Browser</option>
                      <option value="qq">QQ Browser</option>
                      <option value="random">{tr("Random из известных профилей")}</option>
                    </select>
                  </label>
                  <fieldset className="client-profile-options form-span">
                    <legend>{tr("Полный профиль · Xray / Sing-box / Mihomo")}</legend>
                    <label className="field client-tun-stack-field">
                       {tr("Стек TUN")} <select
                        name="client_tun_stack"
                        defaultValue={asText(existingItem?.client_tun_stack, "auto")}
                      >
                        <option value="auto">{tr("Автоматически · рекомендуется")}</option>
                        <option value="mixed">Mixed · TCP system, UDP gVisor</option>
                        <option value="system">{tr("System · меньше нагрузки")}</option>
                        <option value="gvisor">{tr("gVisor · максимальная изоляция")}</option>
                      </select>
                      <small>
                         {tr("Авто не добавляет чужое поле в Xray/Happ/Streisand; sing-box выбирает стек ядра, Mihomo получает mixed.")} </small>
                    </label>
                    <div className="client-profile-option-grid">
                      <label className="client-profile-option">
                        <input
                          name="client_individual_routing"
                          type="checkbox"
                          defaultChecked={
                            existingItem?.client_individual_routing === true
                          }
                        />
                        <span>
                          <strong>{tr("Индивидуальная маршрутизация")}</strong>
                          <small>
                             {tr("Правила WAN/VLESS выполняются на устройстве.")} </small>
                        </span>
                      </label>
                      <label className="client-profile-option">
                        <input
                          name="client_auto_fallback"
                          type="checkbox"
                          defaultChecked={
                            existingItem?.client_auto_fallback === true
                          }
                        />
                        <span>
                          <strong>{tr("Автоматический выбор узла")}</strong>
                          <small>
                             {tr("Клиент проверяет доступность и переключается на рабочий транспорт без смены подписки.")} </small>
                        </span>
                      </label>
                      <label className="client-profile-option">
                        <input
                          name="client_adblock"
                          type="checkbox"
                          defaultChecked={existingItem?.client_adblock === true}
                        />
                        <span>
                          <strong>{tr("Блокировка рекламы")}</strong>
                          <small>
                             {tr("Консервативный список рекламных сетей добавляется прямо в клиентский профиль.")} </small>
                        </span>
                      </label>
                    </div>
                  </fieldset>
                  <details className="happ-tunnel-disclosure form-span">
                    <summary>
                      <span>
                        <strong>{tr("Happ на iOS · системный туннель")}</strong>
                        <small>
                          {happProviderConfigured
                            ? tr("3 параметра приложения")
                            : tr("Нужен Happ Provider ID")
                          }
                        </small>
                      </span>
                    </summary>
                    <fieldset
                      className="client-profile-options happ-tunnel-options"
                      disabled={!happProviderConfigured}
                    >
                      <legend className="sr-only">{tr("Параметры системного туннеля Happ")}</legend>
                      <p className="happ-tunnel-help">
                        {happProviderConfigured
                          ? tr("Значения передаются по ссылке этого пользователя. В самом Happ это общие настройки приложения: последняя обновившаяся подписка имеет приоритет.")
                          : tr("Доступно только после настройки Happ Provider ID в общей ссылке подписки.")
                        }
                      </p>
                      <div className="client-profile-option-grid">
                        <label className="client-profile-option">
                          <input
                            type="checkbox"
                            checked={happIncludeAllNetworks}
                            onChange={(event) =>
                              setHappIncludeAllNetworks(event.target.checked)
                            }
                          />
                          <span>
                            <strong>{tr("Весь трафик через VPN")}</strong>
                            <small>
                               {tr("Включает Include all networks в NetworkExtension.")} </small>
                          </span>
                        </label>
                        <label className="client-profile-option">
                          <input
                            type="checkbox"
                            checked={happExcludeLocalNetworks}
                            disabled={!happIncludeAllNetworks}
                            onChange={(event) =>
                              setHappExcludeLocalNetworks(event.target.checked)
                            }
                          />
                          <span>
                            <strong>{tr("Текущая локальная сеть напрямую")}</strong>
                            <small>
                               {tr("Сохраняет AirPlay, AirDrop и CarPlay в локальной сети iPhone.")} </small>
                          </span>
                        </label>
                        <label className="client-profile-option">
                          <input
                            type="checkbox"
                            checked={happExcludeAPNs}
                            disabled={!happIncludeAllNetworks}
                            onChange={(event) => setHappExcludeAPNs(event.target.checked)}
                          />
                          <span>
                            <strong>{tr("Уведомления Apple напрямую")}</strong>
                            <small>
                               {tr("Исключает APNs из туннеля для надёжной доставки в фоне.")} </small>
                          </span>
                        </label>
                      </div>
                    </fieldset>
                  </details>
                  <section className="automatic-transport-summary form-span">
                    <div className="automatic-transport-head">
                      <div>
                        <span>{tr("Подписка и транспорты")}</span>
                        <strong>
                          {remoteTransportOptions.length
                            ? tr("Выбрано: {value1} из {value2}", { value1: remoteTransportOptions.filter((transport) => !excludedTransportIds.includes(transport.id)).length, value2: remoteTransportOptions.length })
                            : tr("Транспортов в подписке пока нет")}
                        </strong>
                      </div>
                      <span className="automatic-badge">{tr("Новые — автоматически")}</span>
                    </div>
                    {remoteTransportOptions.length ? (
                      <ul className="automatic-transport-list">
                        {remoteTransportOptions.map((transport) => {
                          const checked = !excludedTransportIds.includes(transport.id);
                          return (
                            <li key={transport.id}>
                              <label>
                                <input
                                  type="checkbox"
                                  checked={checked}
                                  onChange={() =>
                                    setExcludedTransportIds((current) =>
                                      checked
                                        ? [...new Set([...current, transport.id])]
                                        : current.filter((id) => id !== transport.id),
                                    )
                                  }
                                />
                                <span>
                                  <strong>{transport.kindLabel}</strong>
                                  <small>{transport.hostname}:{transport.port}</small>
                                </span>
                              </label>
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <p>
                         {tr("Клиента и постоянную ссылку можно создать уже сейчас. Добавьте транспорт позже и нажмите Apply — URL менять не придётся.")} </p>
                    )}
                    <small>
                       {tr("По умолчанию отмечены все включённые транспорты. Снимите галочки с ненужных; новые транспорты появятся отмеченными автоматически после Apply.")} </small>
                  </section>
                  <Toggle
                    className="form-span"
                    name="enabled"
                    defaultChecked={existingItem?.enabled !== false}
                    tone="state"
                    label={tr("Пользователь включён")}
                    description={tr("Выключенный пользователь сохраняется, но не получает inbound-профили после Apply.")}
                  />
                </>
              )}
            </div>
            {!policyOptions.length ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                 {tr("Сначала создайте фактическую политику выхода в разделе «Маршрутизация». Демонстрационные варианты здесь не подставляются.")} </div>
            ) : null}
            {saveError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {saveError}
              </div>
            ) : null}
            <div className="modal-actions">
              {editing && onDelete ? (
                <button
                  className="button button-danger"
                  type="button"
                  disabled={saveBusy}
                  onClick={async () => {
                    if (!deleteArmed) {
                      setDeleteArmed(true);
                      setSaveError(
                        tr("Нажмите «Удалить пользователя» ещё раз. Секреты сохранятся для восстановления."),
                      );
                      return;
                    }
                    setSaveBusy(true);
                    setSaveError("");
                    try {
                      await onDelete();
                    } catch (error) {
                      setSaveError(errorMessage(error));
                      setSaveBusy(false);
                    }
                  }}
                >
                  {deleteArmed ? tr("Удалить пользователя") : tr("Подготовить удаление")}
                </button>
              ) : null}
              <button
                className="button button-tertiary"
                type="button"
                onClick={onClose}
                disabled={saveBusy}
              >
                 {tr("Отмена")} </button>
              <button
                className="button button-primary"
                type="submit"
                disabled={
                  saveBusy ||
                  !policyOptions.length ||
                  Boolean(remoteNameError) ||
                  Boolean(remoteTunError) ||
                  (kind === "local" && !allLanDevices && Boolean(invalidSelectedSource)) ||
                  (kind === "remote" &&
                    (!remoteConnectionName.trim() || !remoteTunAddress.trim()))
                }
              >
                {saveBusy
                  ? tr("Сохраняю…")
                  : editing
                    ? tr("Сохранить изменения")
                    : tr("Добавить")}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
