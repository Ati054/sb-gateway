"use client";

import { JsonObject, createCollectionItem, getCurrentDraft, importRouterOsExport, provisionRouterOsCredentials, saveCurrentDraft, updateCollectionItem } from "../api-client";
import { useLanguage } from "../i18n";
import { NetworkReviewStatus, StatusPill, asObject, asObjectList, asStringList, asText, cdnDeploymentsForTransport, errorMessage, importedNetworkKind, isExplicitRouterHttpsOrigin, isIpv4Cidr, networkReviewStatus, routerCapabilityLabels, routerImportWarningText, withDeploymentReadiness } from "./shared";
import { useEffect, useRef, useState } from "react";

export function SetupWizard({
  onClose,
  onDraftChanged,
  config: initialConfig,
}: {
  onClose: () => void;
  onDraftChanged: () => Promise<void>;
  config: JsonObject;
}) {
  const { locale, tr } = useLanguage();
  const initialSystem = asObject(initialConfig.system);
  const initialManagement = asObject(initialSystem.management);
  const initialNetworking = asObject(initialSystem.networking);
  const initialDns = asObject(initialConfig.dns);
  const initialRouteros = asObject(initialConfig.routeros);
  const routerosConnectionSaved =
    typeof initialRouteros.base_url === "string" &&
    typeof initialRouteros.username_secret_ref === "string" &&
    typeof initialRouteros.password_secret_ref === "string" &&
    typeof initialRouteros.backup_password_secret_ref === "string";
  const initialImportReview = asObject(initialRouteros.import_review);
  const initialTopologySuggestions = asObject(
    initialImportReview.topology_suggestions,
  );
  const initialManagementNetworkSuggestions = asStringList(
    initialImportReview.management_network_suggestions,
  );
  const initialReviewNetworks = asObjectList(initialImportReview.networks);
  const initialConfiguredCidrs = new Set(
    asObjectList(initialConfig.networks)
      .filter(
        (network) =>
          network.enabled !== false &&
          ["internal", "management"].includes(asText(network.kind, "internal")),
      )
      .flatMap((network) => asStringList(network.cidrs)),
  );
  const configuredManagementCidr =
    asStringList(initialManagement.allowed_source_cidrs)[0] ?? "";
  const configuredBridgeName = asText(initialNetworking.bridge_name, "");
  const configuredVethName = asText(initialNetworking.veth_name, "");
  const configuredRouterGateway = asText(
    initialNetworking.routeros_gateway,
    "",
  );
  const configuredContainerAddress = asText(
    initialNetworking.container_address,
    "",
  );
  const configuredTunAddress = asText(initialNetworking.tun_address, "");
  const configuredInternalDns =
    asText(initialDns.internal_server, "") ||
    asText(initialNetworking.container_dns, "");
  const initialOfflinePrefilledFields = [
    !configuredManagementCidr &&
    initialManagementNetworkSuggestions.length > 0
      ? "management_cidr"
      : "",
    !configuredBridgeName &&
    asText(initialTopologySuggestions.bridge_name, "")
      ? "bridge_name"
      : "",
    !configuredVethName &&
    asText(initialTopologySuggestions.veth_name, "")
      ? "veth_name"
      : "",
    !configuredRouterGateway &&
    asText(initialTopologySuggestions.routeros_gateway, "")
      ? "routeros_gateway"
      : "",
    !configuredContainerAddress &&
    asText(initialTopologySuggestions.container_address, "")
      ? "container_address"
      : "",
    !configuredTunAddress &&
    asText(initialTopologySuggestions.tun_address, "")
      ? "tun_address"
      : "",
    !configuredInternalDns &&
    asText(initialTopologySuggestions.container_dns, "")
      ? "container_dns"
      : "",
  ].filter(Boolean);
  const hasInitialOfflineAddressPrefill = initialOfflinePrefilledFields.some(
    (field) =>
      [
        "management_cidr",
        "routeros_gateway",
        "container_address",
        "tun_address",
        "container_dns",
      ].includes(field),
  );
  const [step, setStep] = useState(0);
  const [exportName, setExportName] = useState("");
  const [exportFile, setExportFile] = useState<File | null>(null);
  const [channel, setChannel] = useState(
    asText(initialRouteros.channel, tr("не определён из .rsc")),
  );
  const [managementCidr, setManagementCidr] = useState(
    configuredManagementCidr ||
      initialManagementNetworkSuggestions[0] ||
      "",
  );
  const [managementIngressInterface, setManagementIngressInterface] = useState(
    asStringList(initialManagement.allowed_ingress_interfaces)[0] ?? "",
  );
  const [managementIngressSuggestions, setManagementIngressSuggestions] =
    useState<string[]>(
      asStringList(initialImportReview.management_ingress_suggestions),
    );
  const [managementNetworkSuggestions, setManagementNetworkSuggestions] =
    useState<string[]>(initialManagementNetworkSuggestions);
  const [topologySuggestions, setTopologySuggestions] = useState<JsonObject>(
    initialTopologySuggestions,
  );
  const [offlinePrefilledFields, setOfflinePrefilledFields] = useState<string[]>(
    initialOfflinePrefilledFields,
  );
  const [bridgeName, setBridgeName] = useState(
    configuredBridgeName ||
      asText(initialTopologySuggestions.bridge_name, ""),
  );
  const [vethName, setVethName] = useState(
    configuredVethName || asText(initialTopologySuggestions.veth_name, ""),
  );
  const [routerGateway, setRouterGateway] = useState(
    configuredRouterGateway ||
      asText(initialTopologySuggestions.routeros_gateway, ""),
  );
  const [containerAddress, setContainerAddress] = useState(
    configuredContainerAddress ||
      asText(initialTopologySuggestions.container_address, ""),
  );
  const [tunAddress, setTunAddress] = useState(
    configuredTunAddress || asText(initialTopologySuggestions.tun_address, ""),
  );
  const [internalDns, setInternalDns] = useState(
    configuredInternalDns ||
      asText(initialTopologySuggestions.container_dns, ""),
  );
  const [internalNetworks, setInternalNetworks] = useState<string[]>(
    initialReviewNetworks
      .filter(
        (item) =>
          networkReviewStatus(item.status) === "accepted" &&
          !initialConfiguredCidrs.has(asText(item.cidr, "")),
      )
      .map((item) => asText(item.cidr, ""))
      .filter(Boolean),
  );
  const [discoveredNetworks, setDiscoveredNetworks] = useState<string[]>(
    initialReviewNetworks
      .map((item) => asText(item.cidr, ""))
      .filter(Boolean),
  );
  const [networkDecisions, setNetworkDecisions] = useState<
    Record<string, NetworkReviewStatus>
  >(
    Object.fromEntries(
      initialReviewNetworks
        .map((item) => [
          asText(item.cidr, ""),
          networkReviewStatus(item.status),
        ])
        .filter(([cidr]) => Boolean(cidr)),
    ),
  );
  const [importCapabilities, setImportCapabilities] = useState<JsonObject>({});
  const [importWarnings, setImportWarnings] = useState<string[]>(
    asStringList(initialImportReview.posture_warnings),
  );
  const [importAnalyzed, setImportAnalyzed] = useState(
    typeof initialImportReview.source_fingerprint === "string",
  );
  const [manualNetworkCidr, setManualNetworkCidr] = useState("");
  const [networkQuery, setNetworkQuery] = useState("");
  const [networkStatusFilter, setNetworkStatusFilter] = useState<
    "all" | NetworkReviewStatus
  >("pending");
  const [subscriptionHost, setSubscriptionHost] = useState("");
  const [providerName, setProviderName] = useState(tr("Основной провайдер"));
  const [wizardBusy, setWizardBusy] = useState(false);
  const [wizardMessage, setWizardMessage] = useState("");
  const [wizardSaved, setWizardSaved] = useState(false);
  const routerBaseUrlRef = useRef<HTMLInputElement>(null);
  const routerSshPortRef = useRef<HTMLInputElement>(null);
  const routerUsernameRef = useRef<HTMLInputElement>(null);
  const routerPasswordRef = useRef<HTMLInputElement>(null);
  const routerCaRef = useRef<HTMLTextAreaElement>(null);
  const providerUrlRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!hasInitialOfflineAddressPrefill) return;
    const timer = window.setTimeout(() => {
      void (async () => {
        try {
          const draft = await getCurrentDraft<{ config?: JsonObject }>();
          const config = asObject(draft.config);
          const system = asObject(config.system);
          const networking = asObject(system.networking);
          const dns = asObject(config.dns);
          if (
            networking.addresses_confirmed === false &&
            dns.address_confirmed === false
          ) {
            return;
          }
          await saveCurrentDraft({
            config: withDeploymentReadiness(
              {
                ...config,
                system: {
                  ...system,
                  networking: {
                    ...networking,
                    addresses_confirmed: false,
                  },
                },
                dns: {
                  ...dns,
                  address_confirmed: false,
                },
              },
              false,
            ),
          });
          await onDraftChanged();
        } catch (error) {
          setWizardMessage(
            tr("Не удалось сбросить подтверждение offline-кандидатов: {value1}", { value1: errorMessage(error) }),
          );
        }
      })();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [hasInitialOfflineAddressPrefill, onDraftChanged, tr]);

  const steps = [
    "MikroTik",
    tr("Сети"),
    tr("Удалённый вход"),
    tr("Провайдер"),
    tr("Проверка"),
  ];
  const manualNetworkChoices = internalNetworks.filter(
    (cidr) => !discoveredNetworks.includes(cidr),
  );
  const pendingNetworks = discoveredNetworks.filter(
    (cidr) => networkReviewStatus(networkDecisions[cidr]) === "pending",
  );
  const acceptedSuggestionCount = discoveredNetworks.filter(
    (cidr) => networkReviewStatus(networkDecisions[cidr]) === "accepted",
  ).length;
  const ignoredSuggestionCount = discoveredNetworks.filter(
    (cidr) => networkReviewStatus(networkDecisions[cidr]) === "ignored",
  ).length;
  const visibleDiscoveredNetworks = discoveredNetworks.filter((cidr) => {
    const query = networkQuery.trim().toLowerCase();
    const status = networkReviewStatus(networkDecisions[cidr]);
    return (
      (!query ||
        cidr.toLowerCase().includes(query) ||
        importedNetworkKind(cidr, managementNetworkSuggestions)
          .toLowerCase()
          .includes(query)) &&
      (networkStatusFilter === "all" || status === networkStatusFilter)
    );
  });
  const unknownImportCapabilities = routerCapabilityLabels.filter(
    ([name]) => typeof importCapabilities[name] !== "boolean",
  );
  const isOfflinePrefilled = (
    field: string,
    value: string,
    candidate: unknown,
  ) =>
    offlinePrefilledFields.includes(field) &&
    Boolean(value) &&
    value === asText(candidate, "");
  const activeOfflinePrefillCount = [
    isOfflinePrefilled(
      "management_cidr",
      managementCidr,
      managementNetworkSuggestions[0],
    ),
    isOfflinePrefilled(
      "bridge_name",
      bridgeName,
      topologySuggestions.bridge_name,
    ),
    isOfflinePrefilled(
      "veth_name",
      vethName,
      topologySuggestions.veth_name,
    ),
    isOfflinePrefilled(
      "routeros_gateway",
      routerGateway,
      topologySuggestions.routeros_gateway,
    ),
    isOfflinePrefilled(
      "container_address",
      containerAddress,
      topologySuggestions.container_address,
    ),
    isOfflinePrefilled(
      "tun_address",
      tunAddress,
      topologySuggestions.tun_address,
    ),
    isOfflinePrefilled(
      "container_dns",
      internalDns,
      topologySuggestions.container_dns,
    ),
  ].filter(Boolean).length;

  function decideNetwork(cidr: string, status: "accepted" | "ignored") {
    setNetworkDecisions((current) => ({ ...current, [cidr]: status }));
    setInternalNetworks((current) => {
      if (status === "accepted") {
        return current.includes(cidr) ? current : [...current, cidr];
      }
      return current.filter((item) => item !== cidr);
    });
  }

  function decideVisibleNetworks(status: "accepted" | "ignored") {
    if (!visibleDiscoveredNetworks.length) return;
    const visible = new Set(visibleDiscoveredNetworks);
    setNetworkDecisions((current) => ({
      ...current,
      ...Object.fromEntries(
        visibleDiscoveredNetworks.map((cidr) => [cidr, status]),
      ),
    }));
    setInternalNetworks((current) =>
      status === "accepted"
        ? [...new Set([...current, ...visibleDiscoveredNetworks])]
        : current.filter((cidr) => !visible.has(cidr)),
    );
  }

  async function advance() {
    setWizardMessage("");
    if (step === 0) {
      if (!exportFile) {
        setWizardMessage(
          tr("Выберите обычный экспорт RouterOS без флага show-sensitive."),
        );
        return;
      }
      const baseUrl = routerBaseUrlRef.current?.value.trim() ?? "";
      const routerSshPort = Number(routerSshPortRef.current?.value ?? "22");
      const routerUsername = routerUsernameRef.current?.value.trim() ?? "";
      const routerPassword = routerPasswordRef.current?.value ?? "";
      const caCertificate = routerCaRef.current?.value.trim() ?? "";
      if (!isExplicitRouterHttpsOrigin(baseUrl) || !routerUsername) {
        setWizardMessage(
          tr("Укажите HTTPS origin RouterOS REST с явным портом www-ssl и отдельного пользователя управления."),
        );
        return;
      }
      if (!Number.isInteger(routerSshPort) || routerSshPort < 1 || routerSshPort > 65535) {
        setWizardMessage(tr("Укажите действующий SSH-порт RouterOS для Safe Mode."));
        routerSshPortRef.current?.focus();
        return;
      }
      if (routerPassword.length < 16) {
        setWizardMessage(tr("Пароль RouterOS должен содержать не менее 16 символов."));
        routerPasswordRef.current?.focus();
        return;
      }
      if (routerPasswordRef.current) routerPasswordRef.current.value = "";
      if (routerCaRef.current) routerCaRef.current.value = "";
      setWizardBusy(true);
      try {
        const result = await importRouterOsExport(exportFile);
        const resultObject = asObject(result);
        const discovered = asObject(resultObject.discovered);
        if (typeof discovered.channel === "string") {
          setChannel(discovered.channel);
        } else {
          setChannel(tr("не определён из .rsc"));
        }
        const importedInventory = asObjectList(resultObject.network_inventory);
        const fallbackSuggestions = asStringList(
          resultObject.network_suggestions,
        );
        const inventoryRows = importedInventory.length
          ? importedInventory
          : fallbackSuggestions.map((cidr) => ({
              cidr,
              status: "pending",
            }));
        const suggestedNetworks = inventoryRows
          .map((item) => asText(item.cidr, ""))
          .filter(Boolean);
        const importedDecisions = Object.fromEntries(
          inventoryRows
            .map((item) => [
              asText(item.cidr, ""),
              networkReviewStatus(item.status),
            ])
            .filter(([cidr]) => Boolean(cidr)),
        );
        const suggestedIngressInterfaces = asStringList(
          resultObject.management_ingress_suggestions ??
            discovered.management_ingress_suggestions,
        );
        const suggestedManagementNetworks = asStringList(
          resultObject.management_network_suggestions ??
            discovered.management_network_suggestions,
        );
        const suggestedTopology = asObject(
          resultObject.topology_suggestions ??
            discovered.topology_suggestions,
        );
        const newlyPrefilled: string[] = [];
        const prefill = (
          field: string,
          current: string,
          value: unknown,
          setter: (value: string) => void,
        ) => {
          const candidate = asText(value, "").trim();
          if (!current.trim() && candidate) {
            setter(candidate);
            newlyPrefilled.push(field);
          }
        };
        prefill(
          "management_cidr",
          managementCidr,
          suggestedManagementNetworks[0],
          setManagementCidr,
        );
        prefill(
          "bridge_name",
          bridgeName,
          suggestedTopology.bridge_name,
          setBridgeName,
        );
        prefill(
          "veth_name",
          vethName,
          suggestedTopology.veth_name,
          setVethName,
        );
        prefill(
          "routeros_gateway",
          routerGateway,
          suggestedTopology.routeros_gateway,
          setRouterGateway,
        );
        prefill(
          "container_address",
          containerAddress,
          suggestedTopology.container_address,
          setContainerAddress,
        );
        prefill(
          "tun_address",
          tunAddress,
          suggestedTopology.tun_address,
          setTunAddress,
        );
        prefill(
          "container_dns",
          internalDns,
          suggestedTopology.container_dns,
          setInternalDns,
        );
        setInternalNetworks((current) => {
          const retained = current.filter(
            (cidr) => !discoveredNetworks.includes(cidr),
          );
          const newlyAccepted = suggestedNetworks.filter(
            (cidr) =>
              networkReviewStatus(importedDecisions[cidr]) === "accepted" &&
              !initialConfiguredCidrs.has(cidr),
          );
          return [...new Set([...retained, ...newlyAccepted])];
        });
        setDiscoveredNetworks(suggestedNetworks);
        setNetworkDecisions(importedDecisions);
        setManagementIngressSuggestions(suggestedIngressInterfaces);
        setManagementNetworkSuggestions(suggestedManagementNetworks);
        setTopologySuggestions(suggestedTopology);
        setOfflinePrefilledFields((current) => [
          ...new Set([...current, ...newlyPrefilled]),
        ]);
        setImportCapabilities(asObject(discovered.capabilities));
        setImportWarnings(asStringList(resultObject.warnings));
        setImportAnalyzed(true);
        if (
          newlyPrefilled.some((field) =>
            [
              "management_cidr",
              "routeros_gateway",
              "container_address",
              "tun_address",
              "container_dns",
            ].includes(field),
          )
        ) {
          const importedDraft = await getCurrentDraft<{
            config?: JsonObject;
          }>();
          const importedConfig = asObject(importedDraft.config);
          const importedSystem = asObject(importedConfig.system);
          const importedNetworking = asObject(importedSystem.networking);
          const importedDns = asObject(importedConfig.dns);
          await saveCurrentDraft({
            config: withDeploymentReadiness(
              {
                ...importedConfig,
                system: {
                  ...importedSystem,
                  networking: {
                    ...importedNetworking,
                    addresses_confirmed: false,
                  },
                },
                dns: {
                  ...importedDns,
                  address_confirmed: false,
                },
              },
              false,
            ),
          });
        }
        await provisionRouterOsCredentials({
          base_url: baseUrl,
          username: routerUsername,
          password: routerPassword,
          ssh_port: routerSshPort,
          ca_certificate: caCertificate || undefined,
        });
        await onDraftChanged();
        setStep(1);
      } catch (error) {
        setWizardMessage(errorMessage(error));
        await onDraftChanged();
      } finally {
        setWizardBusy(false);
      }
      return;
    }
    if (step === 1) {
      if (!managementIngressInterface.trim()) {
        setWizardMessage(
          tr("Выберите предложенный bridge или введите точное имя фактического management ingress-интерфейса."),
        );
        return;
      }
      if (!bridgeName.trim() || !vethName.trim() || bridgeName === vethName) {
        setWizardMessage(
          tr("Проверьте имена нового container bridge и veth: оба обязательны и должны различаться."),
        );
        return;
      }
      if (pendingNetworks.length) {
        setWizardMessage(
          tr("Для {value1} сетевых подсказок ещё не выбрано «принять» или «игнорировать». К следующему шагу перейти нельзя.", { value1: pendingNetworks.length }),
        );
        return;
      }
      if (!isIpv4Cidr(managementCidr, false)) {
        setWizardMessage(
          tr("Укажите фактический IPv4 management CIDR с префиксом, например /24 или /32."),
        );
        return;
      }
      if (!routerGateway.trim() || routerGateway.includes("/")) {
        setWizardMessage(
          tr("Укажите фактический IPv4 RouterOS на container bridge без префикса."),
        );
        return;
      }
      if (!containerAddress.trim() || !containerAddress.includes("/")) {
        setWizardMessage(
          tr("Укажите фактический IPv4/CIDR контейнера на veth — он должен совпадать с SB_CONTAINER_ADDRESS."),
        );
        return;
      }
      if (!tunAddress.trim() || !tunAddress.includes("/")) {
        setWizardMessage(
          tr("Укажите подтверждённый TUN IPv4/CIDR, который не пересекается с вашими сетями."),
        );
        return;
      }
      if (!internalDns.trim() || internalDns.includes("/")) {
        setWizardMessage(
          tr("Укажите фактический IP внутреннего DNS; обычно это RouterOS на container bridge."),
        );
        return;
      }
    }
    if (step === 2 && subscriptionHost && !subscriptionHost.includes(".")) {
      setWizardMessage(
        tr("Укажите фактическое DNS-имя клиентской HTTPS-подписки."),
      );
      return;
    }
    if (step === 3) {
      const providerUrl = providerUrlRef.current?.value.trim() ?? "";
      if (providerUrlRef.current) providerUrlRef.current.value = "";
      if (!providerUrl) {
        setStep(4);
        return;
      }
      if (!providerUrl.startsWith("https://")) {
        setWizardMessage(
          tr("Подписка должна использовать HTTPS. Введите URL ещё раз."),
        );
        return;
      }
      setWizardBusy(true);
      try {
        const draft = await getCurrentDraft<{ config?: JsonObject }>();
        const config = asObject(draft.config);
        const provider = {
          id: "provider-main",
          display_name: providerName,
          enabled: true,
          url: providerUrl,
          refresh_minutes: 360,
          allowed_locations: [],
        };
        const providerExists = asObjectList(config.subscriptions).some(
          (item) => item.id === "provider-main",
        );
        if (providerExists) {
          await updateCollectionItem("subscriptions", "provider-main", provider);
        } else {
          await createCollectionItem("subscriptions", provider);
        }
        await onDraftChanged();
        setStep(4);
      } catch (error) {
        setWizardMessage(errorMessage(error));
        await onDraftChanged();
      } finally {
        setWizardBusy(false);
      }
      return;
    }
    if (step < steps.length - 1) {
      setStep(step + 1);
      return;
    }

    setWizardBusy(true);
    try {
      const draft = await getCurrentDraft<{ config?: JsonObject }>();
      const config = asObject(draft.config);
      const system = asObject(config.system);
      const management = asObject(system.management);
      const networking = asObject(system.networking);
      const routeros = asObject(config.routeros);
      const importReview = asObject(routeros.import_review);
      const ingress = asObject(config.ingress);
      const dns = asObject(config.dns);

      const existingNetworks = asObjectList(config.networks);
      const retainedNetworks = existingNetworks.filter(
        (network) =>
          !["wizard-internal-", "management-lan"].some((prefix) =>
            String(network.id ?? "").startsWith(prefix),
          ),
      );
      const wizardNetworks = internalNetworks.map((cidr, index) => ({
        id: `wizard-internal-${index + 1}`,
        enabled: true,
        kind: "internal",
        cidrs: [cidr],
      }));
      const nextNetworks = [
        ...retainedNetworks,
        ...wizardNetworks,
        {
          id: "management-lan",
          enabled: true,
          kind: "management",
          cidrs: [managementCidr],
        },
      ];

      const currentTransports = asObjectList(config.transports);
      await saveCurrentDraft({
        config: withDeploymentReadiness({
          ...config,
          routeros: {
            ...routeros,
            channel_policy: "informational",
            preserve_channel: true,
            automatic_update: false,
            import_review: {
              ...importReview,
              networks: discoveredNetworks.map((cidr) => ({
                cidr,
                status: networkReviewStatus(networkDecisions[cidr]),
              })),
            },
          },
          system: {
            ...system,
            management: {
              ...management,
              allowed_source_cidrs: [managementCidr],
              allowed_ingress_interfaces: [managementIngressInterface],
            },
            networking: {
              ...networking,
              bridge_name: bridgeName,
              veth_name: vethName,
              routeros_gateway: routerGateway,
              container_address: containerAddress,
              container_dns: internalDns,
              tun_address: tunAddress,
              addresses_confirmed: true,
            },
          },
          dns: {
            ...dns,
            internal_server: internalDns,
            address_confirmed: true,
          },
          ingress: {
            ...ingress,
            status_hostname: "",
            subscription_endpoint_enabled: Boolean(subscriptionHost),
            subscription_hostname: subscriptionHost,
            subscription_listen_port: Number(
              ingress.subscription_listen_port ?? ingress.public_listen_port ?? 443,
            ),
            subscription_public_port: Number(
              ingress.subscription_public_port ?? ingress.subscription_listen_port ?? ingress.public_listen_port ?? 443,
            ),
            subscription_tls_profile_id: asText(
              ingress.tls_profile_id,
              "cdn-default",
            ),
          },
          networks: nextNetworks,
          transports: currentTransports.map((transport) => ({
            ...transport,
            enabled: false,
            cdn_deployments: cdnDeploymentsForTransport(transport).map((deployment) => ({
              ...deployment,
              enabled: false,
            })),
          })),
          tls_profiles: asObjectList(config.tls_profiles).filter(
            (profile) =>
              Boolean(asText(profile.certificate_secret_ref, "")) ||
              Boolean(asText(profile.private_key_secret_ref, "")),
          ),
        }, false),
      });
      await onDraftChanged();
      setWizardSaved(true);
      setWizardMessage(
        tr("Черновик сохранён. Теперь запустите проверку и изучите точный план изменений."),
      );
    } catch (error) {
      setWizardMessage(errorMessage(error));
      await onDraftChanged();
    } finally {
      setWizardBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className="modal setup-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="setup-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        <div className="setup-heading">
          <div>
            <p className="eyebrow">{tr("Первичная настройка")}</p>
            <h2 id="setup-title">{tr("Подготовим шлюз без догадок")}</h2>
            <p>
               {tr("Мастер собирает реальные параметры в черновик. Ничего не применяется до preflight, backup и вашего подтверждения.")} </p>
          </div>
          <StatusPill tone="info">
             {tr("Шаг")} {step + 1}  {tr("из")} {steps.length}
          </StatusPill>
        </div>

        <ol className="wizard-steps" aria-label={tr("Этапы настройки")}>
          {steps.map((label, index) => (
            <li
              className={index === step ? "wizard-current" : ""}
              key={label}
            >
              <span>{index < step ? "✓" : index + 1}</span>
              <small>{label}</small>
            </li>
          ))}
        </ol>

        <div className="wizard-body">
          {step === 0 ? (
            <div>
              <h3>{tr("Сначала разберём офлайн-снимок конфигурации")}</h3>
              <p>
                 {tr("Загрузите обычный")} <code>{tr("/export file=имя")}</code>  {tr("без флага show-sensitive. Панель прочитает сохранённые интерфейсы, маршруты, VPN и FastTrack. Архитектура, пакеты, device-mode, накопители и доступность REST подтверждаются только последующим live preflight.")} </p>
              <label className="drop-zone">
                <input
                  type="file"
                  accept=".rsc,.txt"
                  onChange={(event) => {
                    const file = event.target.files?.[0] ?? null;
                    setExportFile(file);
                    setExportName(file?.name ?? "");
                    setWizardMessage("");
                  }}
                />
                <span className="drop-icon">⇧</span>
                <strong>{exportName || "Выберите экспорт MikroTik"}</strong>
                <small>{tr("Секреты в экспорт включать нельзя")}</small>
              </label>
              <div className="form-grid">
                <label className="field">
                  RouterOS REST HTTPS URL
                  <input
                    ref={routerBaseUrlRef}
                    type="url"
                    pattern="https://.+:[0-9]+/?"
                    defaultValue={asText(initialRouteros.base_url, "")}
                    placeholder="https://172.31.255.1:59443"
                    required
                  />
                  <small>
                     {tr("RouterOS REST обслуживается службой www-ssl, не api-ssl. В URL укажите выбранный свободный порт; TCP 443 нельзя считать свободным по умолчанию. В Available From оставьте ровно выбранные management CIDR и container /32, без 0.0.0.0/0. Только HTTPS, проверка сертификата не отключается.")} </small>
                </label>
                <label className="field">
                   {tr("SSH-порт RouterOS для Safe Mode")} <input
                    ref={routerSshPortRef}
                    type="number"
                    min={1}
                    max={65535}
                    defaultValue={
                      typeof initialRouteros.ssh_port === "number"
                        ? initialRouteros.ssh_port
                        : 22
                    }
                    required
                  />
                  <small>
                     {tr("Через постоянную SSH-сессию панель применяет патч в Safe Mode. При потере связи RouterOS откатит незавершённые изменения.")} </small>
                </label>
                <label className="field">
                   {tr("Отдельный REST-пользователь")} <input
                    ref={routerUsernameRef}
                    defaultValue="sb-gateway-api"
                    autoComplete="username"
                    required
                  />
                </label>
                <label className="field">
                   {tr("Пароль RouterOS · минимум 16 символов")} <input
                    ref={routerPasswordRef}
                    type="password"
                    minLength={16}
                    autoComplete="new-password"
                    required
                  />
                </label>
                <div className="locked-field">
                  <span>{tr("Шифрование резервных копий")}</span>
                  <strong>{tr("Пароль администратора панели")}</strong>
                  <small>{tr("Отдельный пароль не требуется")}</small>
                </div>
                <label className="field form-span">
                   {tr("CA certificate PEM для RouterOS (если не публичный CA)")} <textarea
                    ref={routerCaRef}
                    rows={5}
                    autoComplete="off"
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                  <small>
                     {tr("Оставьте пустым только для сертификата, уже доверенного системным хранилищем. Режима insecure skip нет.")} </small>
                </label>
              </div>
              <div className="wizard-inline-fields">
                <label className="field">
                   {tr("Канал из .rsc · только офлайн-метаданные")} <input
                    value={channel}
                    readOnly
                  />
                  <small>
                     {tr("Любой канал RouterOS 7 разрешён; Apply проверяет только capabilities и не переключает канал.")} </small>
                </label>
                <div className="locked-field">
                  <span>{tr("Проверка версии")}</span>
                  <strong>{tr("По возможностям RouterOS 7")}</strong>
                  <small>{tr("Без точного hardcode номера")}</small>
                </div>
              </div>
              {importAnalyzed ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>{tr(".rsc импортирован, но live preflight ещё не выполнен")}</strong>
                    <p>
                       {tr("Неопределённых обязательных capabilities:")}{" "}
                      {unknownImportCapabilities.length}{tr(". Неизвестное состояние никогда не считается успешной проверкой.")} </p>
                    <p>
                       {tr("После настройки мастер сохранит черновик. Перед Apply control plane заново прочитает текущий RouterOS через HTTPS REST и проверит все обязательные возможности.")} </p>
                    {importWarnings.length ? (
                      <ul>
                        {importWarnings.map((warning) => (
                          <li key={warning}>
                            {routerImportWarningText(warning, locale)}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                </aside>
              ) : null}
              {importAnalyzed && routerosConnectionSaved && !exportFile ? (
                <aside className="notice notice-safe">
                  <span className="notice-icon">✓</span>
                  <div>
                    <strong>{tr("Сохранённый импорт и HTTPS REST уже готовы")}</strong>
                    <p>
                       {tr("Можно продолжить review без повторной загрузки `.rsc` и без повторного ввода секретов. Live preflight всё равно будет выполнен перед Apply.")} </p>
                    <div className="card-actions">
                      <button
                        className="button button-primary"
                        type="button"
                        onClick={() => setStep(1)}
                      >
                         {tr("Продолжить с сохранённым снимком")} </button>
                    </div>
                  </div>
                </aside>
              ) : null}
            </div>
          ) : null}

          {step === 1 ? (
            <div>
              <h3>{tr("Какие сети действительно внутренние?")}</h3>
              <p>
                 {tr("Не выбирайте весь приватный диапазон. Только эти точные сети будут обходить proxy-ядро и идти обычными маршрутами RouterOS.")} </p>
              {activeOfflinePrefillCount ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>
                       {tr("Заполнены офлайн-кандидаты:")} {activeOfflinePrefillCount}
                    </strong>
                    <p>
                       {tr("Они подобраны без пересечения с сетями из `.rsc`, но файл не показывает актуальное состояние RouterOS. Проверьте каждое значение. До финального сохранения мастер держит")}{" "}
                      <code>addresses_confirmed=false</code>{tr("; затем Apply всё равно потребует live discovery.")} </p>
                  </div>
                </aside>
              ) : null}
              <label className="field">
                 {tr("Доверенный ingress-интерфейс панели")} <input
                  list="management-ingress-options"
                  value={managementIngressInterface}
                  onChange={(event) =>
                    setManagementIngressInterface(event.target.value)
                  }
                  placeholder={tr("Выберите bridge или введите точное имя")}
                  required
                />
                <datalist id="management-ingress-options">
                  {managementIngressSuggestions.map((interfaceName) => (
                    <option value={interfaceName} key={interfaceName}>
                      {interfaceName}
                    </option>
                  ))}
                </datalist>
                <small>
                   {tr("Панель будет принимать управление только с выбранного локального bridge. Кандидаты из списка — лишь эвристика экспорта; точное ручное имя допустимо и обязательно проверяется live preflight.")} </small>
              </label>
              {!managementIngressSuggestions.length ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>{tr("Экспорт не предложил доверенный bridge")}</strong>
                    <p>
                       {tr("Эвристика не является источником истины. Введите точное имя фактического LAN/management bridge вручную; не выбирайте WAN. Live preflight проверит интерфейс до Apply.")} </p>
                  </div>
                </aside>
              ) : null}
              {managementIngressInterface &&
              !managementIngressSuggestions.includes(
                managementIngressInterface,
              ) ? (
                <aside className="notice notice-neutral">
                  <span className="notice-icon">i</span>
                  <div>
                    <strong>{tr("Интерфейс введён вручную")}</strong>
                    <p>
                       {tr("Офлайн-экспорт не классифицировал его как management ingress. Значение будет принято только после live-проверки; WAN-интерфейс здесь выбирать нельзя.")} </p>
                  </div>
                </aside>
              ) : null}
              <label className="field">
                Management CIDR
                <input
                  value={managementCidr}
                  onChange={(event) => setManagementCidr(event.target.value)}
                  placeholder={tr("Введите фактическую management сеть")}
                />
                <small>
                  {isOfflinePrefilled(
                    "management_cidr",
                    managementCidr,
                    managementNetworkSuggestions[0],
                  )
                    ? tr("Кандидат из offline export · проверьте фактическую management-сеть; live-подтверждения ещё нет.")
                    : tr("Отсюда будет доступна панель на порту 9443.")}
                </small>
              </label>
              <div className="form-grid">
                <label className="field">
                   {tr("Имя нового container bridge")} <input
                    value={bridgeName}
                    onChange={(event) => setBridgeName(event.target.value)}
                    placeholder={tr("Введите свободное имя bridge")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "bridge_name",
                      bridgeName,
                      topologySuggestions.bridge_name,
                    )
                      ? tr("Кандидат из offline export · коллизий в файле не найдено, live-проверка обязательна.")
                      : tr("Имя не должно совпадать с существующим интерфейсом RouterOS.")}
                  </small>
                </label>
                <label className="field">
                   {tr("Имя нового veth")} <input
                    value={vethName}
                    onChange={(event) => setVethName(event.target.value)}
                    placeholder={tr("Введите свободное имя veth")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "veth_name",
                      vethName,
                      topologySuggestions.veth_name,
                    )
                      ? tr("Кандидат из offline export · коллизий в файле не найдено, live-проверка обязательна.")
                      : tr("Имя будет использовано только для контейнера SB-GATEWAY.")}
                  </small>
                </label>
                <label className="field">
                   {tr("RouterOS IP на container bridge")} <input
                    value={routerGateway}
                    onChange={(event) => setRouterGateway(event.target.value)}
                    placeholder={tr("Введите адрес из вашего WebFig bootstrap")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "routeros_gateway",
                      routerGateway,
                      topologySuggestions.routeros_gateway,
                    )
                      ? tr("Непересекающийся кандидат из offline export · не фактический адрес и не live-подтверждение.")
                      : tr("Должен совпадать с фактическим SB_ROUTER_IP; пример из ТЗ автоматически не подставляется.")}
                  </small>
                </label>
                <label className="field">
                  Container IPv4/CIDR
                  <input
                    value={containerAddress}
                    onChange={(event) => setContainerAddress(event.target.value)}
                    placeholder={tr("Фактический SB_CONTAINER_ADDRESS с префиксом")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "container_address",
                      containerAddress,
                      topologySuggestions.container_address,
                    )
                      ? tr("Непересекающийся кандидат из offline export · проверьте подсеть и свободный адрес live.")
                      : tr("Должен быть отдельным адресом той же container bridge-подсети; пример из ТЗ автоматически не подставляется.")}
                  </small>
                </label>
                <label className="field">
                  TUN IPv4/CIDR
                  <input
                    value={tunAddress}
                    onChange={(event) => setTunAddress(event.target.value)}
                    placeholder={tr("Выберите свободную непересекающуюся подсеть")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "tun_address",
                      tunAddress,
                      topologySuggestions.tun_address,
                    )
                      ? tr("Непересекающийся кандидат из offline export · Apply повторно проверит live LAN/VPN-маршруты.")
                      : tr("Apply проверит пересечение с импортированными LAN/VPN сетями.")}
                  </small>
                </label>
                <label className="field form-span">
                   {tr("Внутренний DNS")} <input
                    value={internalDns}
                    onChange={(event) => setInternalDns(event.target.value)}
                    placeholder={tr("Фактический IP RouterOS или другого DNS")}
                  />
                  <small>
                    {isOfflinePrefilled(
                      "container_dns",
                      internalDns,
                      topologySuggestions.container_dns,
                    )
                      ? tr("Кандидат из offline export · должен быть подтверждён как фактический внутренний DNS.")
                      : tr("Внутренние зоны не отправляются внешнему DNS-провайдеру.")}
                  </small>
                </label>
              </div>
              <div className="wizard-inline-fields">
                <label className="field">
                   {tr("Добавить внутренний CIDR вручную")} <input
                    value={manualNetworkCidr}
                    onChange={(event) => setManualNetworkCidr(event.target.value)}
                    placeholder={tr("Введите точный IPv4/IPv6 CIDR")}
                  />
                </label>
                <button
                  className="button button-secondary"
                  type="button"
                  disabled={
                    !manualNetworkCidr.trim() ||
                    !manualNetworkCidr.includes("/")
                  }
                  onClick={() => {
                    const cidr = manualNetworkCidr.trim();
                    setInternalNetworks((current) =>
                      current.includes(cidr) ? current : [...current, cidr],
                    );
                    setManualNetworkCidr("");
                  }}
                >
                   {tr("Добавить CIDR")} </button>
              </div>
              {!discoveredNetworks.length && !manualNetworkChoices.length ? (
                <aside className="notice notice-neutral">
                  <span className="notice-icon">i</span>
                  <div>
                    <strong>{tr("Экспорт не дал сетевых подсказок")}</strong>
                    <p>
                       {tr("Список намеренно пуст. Добавьте только проверенные CIDR вручную; демонстрационные адреса не подставляются.")} </p>
                  </div>
                </aside>
              ) : null}
              {discoveredNetworks.length ? (
                <div className="network-review-toolbar">
                  <label className="search-field">
                    <span className="sr-only">{tr("Найти импортированную сеть")}</span>
                    <input
                      value={networkQuery}
                      onChange={(event) => setNetworkQuery(event.target.value)}
                      placeholder={tr("CIDR или тип сети")}
                    />
                  </label>
                  <label className="field compact-field">
                     {tr("Показывать")} <select
                      value={networkStatusFilter}
                      onChange={(event) =>
                        setNetworkStatusFilter(
                          event.target.value as "all" | NetworkReviewStatus,
                        )
                      }
                    >
                      <option value="pending">{tr("Требуют решения")}</option>
                      <option value="accepted">{tr("Принятые")}</option>
                      <option value="ignored">{tr("Игнорируемые")}</option>
                      <option value="all">{tr("Все")}</option>
                    </select>
                  </label>
                  <div className="card-actions network-review-bulk">
                    <button
                      className="button button-secondary"
                      type="button"
                      disabled={!visibleDiscoveredNetworks.length}
                      onClick={() => decideVisibleNetworks("accepted")}
                    >
                       {tr("Принять видимые ·")} {visibleDiscoveredNetworks.length}
                    </button>
                    <button
                      className="button button-tertiary"
                      type="button"
                      disabled={!visibleDiscoveredNetworks.length}
                      onClick={() => decideVisibleNetworks("ignored")}
                    >
                       {tr("Игнорировать видимые ·")} {visibleDiscoveredNetworks.length}
                    </button>
                  </div>
                  <small>
                     {tr("Массовое действие применяется только к текущему фильтру и остаётся явным решением в черновике. Для полного переноса существующих VPN-маршрутов можно показать все и принять их.")} </small>
                </div>
              ) : null}
              {discoveredNetworks.length ? (
                <aside
                  className={
                    pendingNetworks.length
                      ? "notice notice-danger"
                      : "notice notice-safe"
                  }
                >
                  <span className="notice-icon">
                    {pendingNetworks.length ? "!" : "✓"}
                  </span>
                  <div>
                    <strong>
                      {pendingNetworks.length
                        ? tr("Ожидают решения: {value1}", { value1: pendingNetworks.length })
                        : tr("Все подсказки классифицированы")}
                    </strong>
                    <p>
                       {tr("Принято:")} {acceptedSuggestionCount}{tr("; проигнорировано:")}{" "}
                      {ignoredSuggestionCount}{tr(". Простое отсутствие галочки не считается решением.")} </p>
                  </div>
                </aside>
              ) : null}
              <div className="discovered-networks">
                {visibleDiscoveredNetworks.map((cidr) => {
                  const decision = networkReviewStatus(networkDecisions[cidr]);
                  return (
                    <div className="checkbox-field" key={cidr}>
                      <span aria-hidden="true">
                        {decision === "accepted"
                          ? "✓"
                          : decision === "ignored"
                            ? "×"
                            : "?"}
                      </span>
                      <span>
                        <strong>{cidr}</strong>
                        <small>
                          {importedNetworkKind(
                            cidr,
                            managementNetworkSuggestions,
                          )}  {tr("· подсказка из офлайн-экспорта")} </small>
                      </span>
                      <div
                        className="card-actions"
                        role="group"
                        aria-label={tr("Тип сети {value1}", { value1: cidr })}
                      >
                        <button
                          className={`button ${
                            decision === "accepted"
                              ? "button-primary"
                              : "button-secondary"
                          }`}
                          type="button"
                          aria-pressed={decision === "accepted"}
                          onClick={() => decideNetwork(cidr, "accepted")}
                        >
                           {tr("Принять как внутреннюю")} </button>
                        <button
                          className={`button ${
                            decision === "ignored"
                              ? "button-primary"
                              : "button-tertiary"
                          }`}
                          type="button"
                          aria-pressed={decision === "ignored"}
                          onClick={() => decideNetwork(cidr, "ignored")}
                        >
                           {tr("Игнорировать")} </button>
                      </div>
                    </div>
                  );
                })}
                {!visibleDiscoveredNetworks.length && discoveredNetworks.length ? (
                  <div className="empty-result">
                     {tr("По выбранному фильтру сетей нет.")} </div>
                ) : null}
                {manualNetworkChoices.map((cidr) => (
                  <label key={`manual-${cidr}`}>
                    <input
                      type="checkbox"
                      checked
                      onChange={() =>
                        setInternalNetworks((current) =>
                          current.filter((item) => item !== cidr),
                        )
                      }
                    />
                    <span>
                      <strong>{cidr}</strong>
                      <small>{tr("Добавлено вручную · снимите флажок, чтобы удалить")}</small>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          ) : null}

          {step === 2 ? (
            <div>
              <h3>{tr("HTTPS-подписка для удалённых устройств")}</h3>
              <p>
                 {tr("Ссылка подписки настраивается отдельно. После мастера включите только нужные транспорты: WebSocket не является обязательным.")} </p>
              <div className="form-grid">
                <label className="field form-span">
                   {tr("DNS-имя клиентской подписки")} <input
                    value={subscriptionHost}
                    onChange={(event) => setSubscriptionHost(event.target.value)}
                    placeholder="sub.example.com"
                  />
                  <small>
                     {tr("Постоянная HTTPS-ссылка нужна VPN-клиентам для импорта и автоматического обновления конфигурации. Контейнер отдельно проверяет сам MikroTik по внутренней сети.")} </small>
                </label>
              </div>
              <aside className="notice notice-neutral">
                <span className="notice-icon">i</span>
                <div>
                  <strong>{tr("Транспорты настраиваются независимо")}</strong>
                  <p>
                     {tr("Можно включить только gRPC и XHTTP либо любой другой набор. Все включённые транспорты попадут в ту же постоянную ссылку.")} </p>
                </div>
              </aside>
            </div>
          ) : null}

          {step === 3 ? (
            <div>
              <h3>{tr("Добавьте первого исходящего прокси-провайдера")}</h3>
              <p>
                 {tr("URL проверяется без сохранения в журнал. Рабочая конфигурация не заменяется, пока candidate не пройдёт проверку активного proxy-ядра.")} </p>
              <label className="field">
                 {tr("Понятное название")} <input
                  value={providerName}
                  onChange={(event) => setProviderName(event.target.value)}
                />
              </label>
              <label className="field">
                 {tr("URL подписки")} <input
                  ref={providerUrlRef}
                  type="password"
                  placeholder={tr("Будет записан с правами 0600")}
                  autoComplete="off"
                />
                <small>
                   {tr("После сохранения URL можно только заменить — прочитать его из панели нельзя.")} </small>
              </label>
              <div className="wizard-provider-check">
                <StatusPill tone="info">{tr("Проверка при сохранении")}</StatusPill>
                <span>
                   {tr("URL уйдёт прямо в SecretStore. Импортируются VLESS, REALITY и Hysteria 2 URI, Base64-списки и Xray JSON.")} </span>
              </div>
            </div>
          ) : null}

          {step === 4 ? (
            <div>
              <h3>{tr("Черновик готов к проверке")}</h3>
              <p>
                 {tr("Это ещё не применение. Сначала панель покажет точный RouterOS diff и результаты всех проверок.")} </p>
              <dl className="wizard-summary">
                <div>
                  <dt>RouterOS</dt>
                  <dd>7 · {channel} · capability-check</dd>
                </div>
                <div>
                  <dt>Management</dt>
                  <dd>
                    {managementCidr} · ingress {managementIngressInterface} →
                    HTTPS 9443
                  </dd>
                </div>
                <div>
                  <dt>Container/TUN/DNS</dt>
                  <dd>
                    bridge {bridgeName} · veth {vethName} · RouterOS{" "}
                    {routerGateway} · container {containerAddress} · TUN{" "}
                    {tunAddress} · DNS {internalDns}
                  </dd>
                </div>
                <div>
                  <dt>{tr("Внутренние сети")}</dt>
                  <dd>{internalNetworks.length}  {tr("точных CIDR")}</dd>
                </div>
                <div>
                  <dt>{tr("Подсказки из .rsc")}</dt>
                  <dd>
                     {tr("принято")} {acceptedSuggestionCount}  {tr("· проигнорировано")}{" "}
                    {ignoredSuggestionCount}  {tr("· ожидает")} {pendingNetworks.length}
                  </dd>
                </div>
                <div>
                  <dt>{tr("Удалённый вход")}</dt>
                  <dd>{subscriptionHost ? <>{tr("подписка:")} {subscriptionHost} {tr("· транспорты настраиваются отдельно")}</> : tr("клиентский режим · публичная подписка выключена")}</dd>
                </div>
                <div>
                  <dt>{tr("Провайдер")}</dt>
                  <dd>{providerName}  {tr("· секрет скрыт")}</dd>
                </div>
                <div>
                  <dt>{tr("Отказ контейнера")}</dt>
                  <dd>{tr("Локальные → WAN; удалённые → block")}</dd>
                </div>
              </dl>
              {activeOfflinePrefillCount ? (
                <aside className="notice notice-danger">
                  <span className="notice-icon">!</span>
                  <div>
                    <strong>{tr("Вы подтверждаете офлайн-кандидаты")}</strong>
                    <p>
                       {tr("После «Сохранить черновик» эти")} {activeOfflinePrefillCount}{" "}
                       {tr("значений будут отмечены как проверенные оператором. Это не заменяет live discovery: Apply повторно проверит адреса, интерфейсы и пересечения.")} </p>
                  </div>
                </aside>
              ) : null}
              <aside className="notice notice-danger">
                <span className="notice-icon">!</span>
                <div>
                  <strong>{tr("Офлайн-импорт не подтверждает capabilities")}</strong>
                  <p>
                     {tr("Сохранение черновика не разрешает Apply. Следующим отдельным действием запустите live preflight; неизвестные или отсутствующие возможности заблокируют новую установку.")} </p>
                </div>
              </aside>
              <aside className="notice notice-safe">
                <span className="notice-icon">✓</span>
                <div>
                  <strong>{tr("Перед применением автоматически")}</strong>
                  <p>
                     {tr("RouterOS preflight → точный diff → проверка активного ядра → nginx -t. Export, backup и Safe Mode добавляются только если сам RouterOS-патч действительно изменился; иначе обновляется только контейнер с runtime-откатом.")} </p>
                </div>
              </aside>
            </div>
          ) : null}
        </div>

        {wizardMessage ? (
          <div
            className={`inline-result ${
              wizardSaved ? "" : "inline-result-error"
            }`}
            role={wizardSaved ? "status" : "alert"}
          >
            <span>{wizardSaved ? "✓" : "!"}</span>
            {wizardMessage}
          </div>
        ) : null}

        <div className="wizard-actions">
          <button
            className="button button-tertiary"
            onClick={() => (step === 0 ? onClose() : setStep(step - 1))}
            disabled={wizardBusy}
          >
            {step === 0 ? tr("Закрыть") : tr("Назад")}
          </button>
          <button
            className="button button-primary"
            onClick={wizardSaved ? onClose : advance}
            disabled={
              wizardBusy ||
              (step === 1 &&
                (pendingNetworks.length > 0 ||
                  !managementIngressInterface.trim() ||
                  !bridgeName.trim() ||
                  !vethName.trim() ||
                  bridgeName === vethName))
            }
          >
            {wizardBusy
              ? tr("Сохраняю…")
              : wizardSaved
                ? tr("Закрыть мастер")
                : step === steps.length - 1
                  ? tr("Сохранить черновик")
                  : tr("Продолжить")}
          </button>
        </div>
      </section>
    </div>
  );
}
