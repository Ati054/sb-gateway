"use client";

import { JsonObject, createCollectionItem, deleteCollectionItem, getSubscriptionMetadata, getSubscriptionNodes, probeTlsEndpoint, refreshSubscription, saveCurrentDraft, updateCollectionItem } from "../api-client";
import { automaticCidrHint, supportsAutomaticCidr } from "../cdn-capabilities";
import { useLanguage } from "../i18n";
import { mergeSubscriptionMetadata } from "../subscription-metadata";
import { disableSubscriptionPublication } from "../subscription-publication";
import { hostnameAfterTLSProfileChange, hostnameForTLSProfileInitialization, subscriptionEndpointUsesTLSHostname, subscriptionEndpointValueAfterConfigRefresh, tlsConcreteHostnames } from "../tls-hostnames";
import { TlsTransferDialog } from "../tls-transfer";
import { CDN_PROVIDERS, CLOUDFLARE_HTTPS_PORTS, RevisionState, SectionTitle, StatusPill, Toggle, Tone, asObject, asObjectList, asStringList, asText, cdnDeploymentsForTransport, cdnProviderName, configuredItemStatus, configuredItemTone, entityIdFromName, expiryText, generateOriginHeaderSecret, isErrorMessage, itemName, prefixedErrorMessage, resultMessage, russianCount, subscriptionIntervalText, tlsProfileExpiry, transportKindLabel, useConnectionHostname, withDeploymentReadiness } from "./shared";
import { FormEvent, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

export function Connections({
  certificateStatus,
  subscriptionMetadata,
  setSubscriptionMetadata,
  onAddSubscription,
  onEditSubscription,
  onConfigureTransport,
  onAddTlsProfile,
  onEditTlsProfile,
  onDraftChanged,
  config,
  revisionState,
}: {
  certificateStatus: JsonObject;
  subscriptionMetadata: Record<string, JsonObject>;
  setSubscriptionMetadata: (update: (current: Record<string, JsonObject>) => Record<string, JsonObject>) => void;
  onAddSubscription: () => void;
  onEditSubscription: (id: string) => void;
  onConfigureTransport: (id: string) => void;
  onAddTlsProfile: () => void;
  onEditTlsProfile: (id: string) => void;
  onDraftChanged: () => Promise<void>;
  config: JsonObject;
  revisionState: RevisionState;
}) {
  const { locale, t, tr } = useLanguage();
  const [subscriptionBusy, setSubscriptionBusy] = useState("");
  const connectionHostname = useConnectionHostname();
  const [subscriptionMessage, setSubscriptionMessage] = useState("");
  const [nodeSubscriptionId, setNodeSubscriptionId] = useState("");
  const [nodeRows, setNodeRows] = useState<JsonObject[]>([]);
  const [nodeCities, setNodeCities] = useState<Record<string, string>>({});
  const [initialNodeCities, setInitialNodeCities] = useState<Record<string, string>>({});
  const [nodeBusy, setNodeBusy] = useState(false);
  const [subscriptionMetadataError, setSubscriptionMetadataError] = useState(false);
  const [reserveName, setReserveName] = useState("");
  const [reserveLink, setReserveLink] = useState("");
  const [editingReserveId, setEditingReserveId] = useState("");
  const [reserveBusy, setReserveBusy] = useState(false);
  const [reserveMessage, setReserveMessage] = useState("");
  const [subscriptionEndpointDialogOpen, setSubscriptionEndpointDialogOpen] =
    useState(false);
  const subscriptionEndpointBodyRef = useRef<HTMLDivElement>(null);
  const [reserveDialogOpen, setReserveDialogOpen] = useState(false);
  const configuredPublicPort = Number(
    asObject(config.ingress).public_listen_port ?? 443,
  );
  const configuredCloudflareTlsProfileId = asText(
    asObject(config.ingress).tls_profile_id,
    "cdn-default",
  );
  const configuredStatusHostname = asText(
    asObject(config.ingress).status_hostname,
    "",
  );
  const configuredSubscriptionHostnameValue = asText(
    asObject(config.ingress).subscription_hostname,
    "",
  );
  const configuredSubscriptionHostname = configuredSubscriptionHostnameValue;
  const configuredSubscriptionCdnHostnameValue = asText(
    asObject(config.ingress).subscription_cdn_hostname,
    "",
  );
  const configuredSubscriptionOriginServerName = asText(
    asObject(config.ingress).subscription_origin_server_name,
    "",
  );
  const configuredSubscriptionTlsProfileId = asText(
    asObject(config.ingress).subscription_tls_profile_id,
    configuredCloudflareTlsProfileId,
  );
  const configuredSubscriptionOriginPort = Number(
    asObject(config.ingress).subscription_listen_port ?? configuredPublicPort,
  );
  const configuredSubscriptionPublicPort = Number(
    asObject(config.ingress).subscription_public_port ?? configuredSubscriptionOriginPort,
  );
  const configuredSubscriptionCdnProvider = asText(
    asObject(config.ingress).subscription_cdn_provider,
    "cloudflare",
  );
  const configuredSubscriptionDisplayName = asText(
    asObject(asObject(config.public_exposure).subscription).display_name,
    "SB Gateway",
  );
  const configuredHappProviderId = asText(
    asObject(asObject(config.public_exposure).subscription).happ_provider_id,
    "",
  );
  const configuredSubscriptionEndpointMode = asText(
    asObject(config.ingress).subscription_endpoint_mode,
    "separate",
  );
  const configuredSubscriptionEndpointEnabled =
    asObject(config.ingress).subscription_endpoint_enabled !== false;
  const configuredSubscriptionTransportId = asText(
    asObject(config.ingress).subscription_transport_id,
    "",
  );
  const configuredSubscriptionDeploymentId = asText(
    asObject(config.ingress).subscription_deployment_id,
    "",
  );
  const configuredSubscriptionPrimaryEndpoint = asText(
    asObject(config.ingress).subscription_primary_endpoint,
    "cdn",
  );
  const configuredSubscriptionOriginProtectionMode = asText(
    asObject(config.ingress).subscription_origin_protection_mode,
    configuredSubscriptionCdnProvider === "cloudflare"
      ? "auto-cidr"
      : "secret-header",
  );
  const configuredSubscriptionOriginHeaderRef = asText(
    asObject(config.ingress).subscription_origin_header_secret_ref,
    "",
  );
  const configuredTlsProfiles = asObjectList(config.tls_profiles).map((profile) => {
    const status = asObject(certificateStatus[asText(profile.id, "")]);
    const metadata = asObject(status.metadata);
    return asText(profile.certificate_secret_ref, "").endsWith("/acme-bundle.pem") && metadata.not_after
      ? { ...profile, certificate_metadata: metadata }
      : profile;
  });
  const configuredSubscriptionTlsProfile = configuredTlsProfiles.find(
    (profile) => asText(profile.id, "") === configuredSubscriptionTlsProfileId,
  );
  const configuredSubscriptionDirectHostname = ["direct", "direct-and-cdn"].includes(
    configuredSubscriptionEndpointMode,
  )
    ? configuredSubscriptionHostname
    : configuredSubscriptionEndpointMode === "separate"
      ? configuredSubscriptionOriginServerName
      : "";
  const configuredSubscriptionCdnHostname = configuredSubscriptionCdnHostnameValue ||
    (configuredSubscriptionEndpointMode === "separate"
      ? configuredSubscriptionHostname
      : "");
  const initialSubscriptionHostname = hostnameForTLSProfileInitialization(
    configuredSubscriptionTlsProfile,
    configuredSubscriptionDirectHostname,
    !configuredSubscriptionDirectHostname,
  );
  const initialSubscriptionOriginServerName = hostnameForTLSProfileInitialization(
    configuredSubscriptionTlsProfile,
    configuredSubscriptionOriginServerName,
    configuredSubscriptionEndpointMode === "separate" &&
      !configuredSubscriptionOriginServerName,
  );
  const [subscriptionOriginPort, setSubscriptionOriginPort] = useState(
    configuredSubscriptionOriginPort,
  );
  const [subscriptionPublicPort, setSubscriptionPublicPort] = useState(
    configuredSubscriptionPublicPort,
  );
  const [subscriptionHostname, setSubscriptionHostname] = useState(
    initialSubscriptionHostname,
  );
  const [subscriptionCdnHostname, setSubscriptionCdnHostname] = useState(
    configuredSubscriptionCdnHostname,
  );
  const [subscriptionOriginServerName, setSubscriptionOriginServerName] =
    useState(initialSubscriptionOriginServerName);
  const [subscriptionTlsProfileId, setSubscriptionTlsProfileId] = useState(
    configuredSubscriptionTlsProfileId,
  );
  const [subscriptionCdnProvider, setSubscriptionCdnProvider] = useState(
    configuredSubscriptionCdnProvider,
  );
  const [subscriptionEndpointMode, setSubscriptionEndpointMode] = useState(
    configuredSubscriptionEndpointMode,
  );
  const [subscriptionEndpointEnabled, setSubscriptionEndpointEnabled] = useState(
    configuredSubscriptionEndpointEnabled,
  );
  const [subscriptionPrimaryEndpoint, setSubscriptionPrimaryEndpoint] = useState(
    configuredSubscriptionPrimaryEndpoint,
  );
  const [subscriptionDeploymentSelection, setSubscriptionDeploymentSelection] =
    useState(
      configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
        ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
        : configuredSubscriptionCdnHostname
          ? "subscription-cdn"
          : "",
    );
  const [subscriptionDisplayName, setSubscriptionDisplayName] = useState(
    configuredSubscriptionDisplayName,
  );
  const [happProviderId, setHappProviderId] = useState(
    configuredHappProviderId,
  );
  const [subscriptionOriginProtectionMode, setSubscriptionOriginProtectionMode] =
    useState(configuredSubscriptionOriginProtectionMode);
  const [subscriptionOriginHeaderValue, setSubscriptionOriginHeaderValue] =
    useState(
      configuredSubscriptionOriginProtectionMode === "secret-header" &&
        !configuredSubscriptionOriginHeaderRef
        ? generateOriginHeaderSecret()
        : "",
    );
  const [cloudflarePortBusy, setCloudflarePortBusy] = useState(false);
  const [cloudflarePortMessage, setCloudflarePortMessage] = useState("");
  const [subscriptionProbeBusy, setSubscriptionProbeBusy] = useState(false);
  const [subscriptionProbeResult, setSubscriptionProbeResult] = useState("");
  function openSubscriptionEndpointDialog() {
    setSubscriptionOriginPort(configuredSubscriptionOriginPort);
    setSubscriptionPublicPort(configuredSubscriptionPublicPort);
    setSubscriptionHostname(initialSubscriptionHostname);
    setSubscriptionCdnHostname(configuredSubscriptionCdnHostname);
    setSubscriptionOriginServerName(initialSubscriptionOriginServerName);
    setSubscriptionTlsProfileId(configuredSubscriptionTlsProfileId);
    setSubscriptionCdnProvider(configuredSubscriptionCdnProvider);
    setSubscriptionEndpointMode(configuredSubscriptionEndpointMode);
    setSubscriptionEndpointEnabled(configuredSubscriptionEndpointEnabled);
    setSubscriptionPrimaryEndpoint(configuredSubscriptionPrimaryEndpoint);
    setSubscriptionDeploymentSelection(
      configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
        ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
        : configuredSubscriptionCdnHostname
          ? "subscription-cdn"
          : "",
    );
    setSubscriptionDisplayName(configuredSubscriptionDisplayName);
    setHappProviderId(configuredHappProviderId);
    setSubscriptionOriginProtectionMode(configuredSubscriptionOriginProtectionMode);
    setSubscriptionOriginHeaderValue(
      configuredSubscriptionOriginProtectionMode === "secret-header" &&
        !configuredSubscriptionOriginHeaderRef
        ? generateOriginHeaderSecret()
        : "",
    );
    setCloudflarePortMessage("");
    setSubscriptionProbeResult("");
    setSubscriptionEndpointDialogOpen(true);
  }
  useEffect(() => {
    if (!subscriptionEndpointDialogOpen) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const frame = window.requestAnimationFrame(() => {
      subscriptionEndpointBodyRef.current?.scrollTo({ top: 0 });
    });
    return () => {
      window.cancelAnimationFrame(frame);
      document.body.style.overflow = previousOverflow;
    };
  }, [subscriptionEndpointDialogOpen]);
  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setSubscriptionOriginPort((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionOriginPort,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionPublicPort((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionPublicPort,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionHostname((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          initialSubscriptionHostname,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionCdnHostname((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionCdnHostname,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionOriginServerName((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          initialSubscriptionOriginServerName,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionTlsProfileId((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionTlsProfileId,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionCdnProvider((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionCdnProvider,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionEndpointMode((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionEndpointMode,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionEndpointEnabled((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionEndpointEnabled,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionPrimaryEndpoint((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionPrimaryEndpoint,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionDeploymentSelection((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
            ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
            : configuredSubscriptionCdnHostname
              ? "subscription-cdn"
              : "",
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionDisplayName((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionDisplayName,
          subscriptionEndpointDialogOpen,
        ),
      );
      setHappProviderId((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredHappProviderId,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionOriginProtectionMode((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          configuredSubscriptionOriginProtectionMode,
          subscriptionEndpointDialogOpen,
        ),
      );
      setSubscriptionOriginHeaderValue((current) =>
        subscriptionEndpointValueAfterConfigRefresh(
          current,
          "",
          subscriptionEndpointDialogOpen,
        ),
      );
    }, 0);
    return () => window.clearTimeout(timeout);
  }, [
    initialSubscriptionHostname,
    initialSubscriptionOriginServerName,
    configuredSubscriptionCdnHostname,
    configuredSubscriptionOriginPort,
    configuredSubscriptionPublicPort,
    configuredSubscriptionCdnProvider,
    configuredSubscriptionTlsProfileId,
    configuredSubscriptionEndpointMode,
    configuredSubscriptionEndpointEnabled,
    configuredSubscriptionPrimaryEndpoint,
    configuredSubscriptionTransportId,
    configuredSubscriptionDeploymentId,
    configuredSubscriptionDisplayName,
    configuredHappProviderId,
    configuredSubscriptionOriginProtectionMode,
    subscriptionEndpointDialogOpen,
  ]);
  const subscriptionHostnameCandidates = subscriptionEndpointUsesTLSHostname(
    subscriptionEndpointMode,
  )
    ? tlsConcreteHostnames(
        configuredTlsProfiles.find(
          (profile) => asText(profile.id, "") === subscriptionTlsProfileId,
        ),
      )
    : [];
  const subscriptionHostnameDatalistId = "subscription-endpoint-tls-dns-names";
  const subscriptionOriginDatalistId = "subscription-endpoint-origin-tls-dns-names";
  const subscriptionOriginHostnameCandidates =
    subscriptionEndpointMode === "separate"
      ? tlsConcreteHostnames(
          configuredTlsProfiles.find(
            (profile) => asText(profile.id, "") === subscriptionTlsProfileId,
          ),
        )
      : [];
  function selectSubscriptionTlsProfile(profileId: string) {
    const profile = configuredTlsProfiles.find(
      (item) => asText(item.id, "") === profileId,
    );
    setSubscriptionTlsProfileId(profileId);
    setSubscriptionHostname((current) =>
      hostnameAfterTLSProfileChange(profile, current),
    );
    if (subscriptionEndpointMode === "separate") {
      setSubscriptionOriginServerName((current) =>
        hostnameAfterTLSProfileChange(profile, current),
      );
    }
    setCloudflarePortMessage("");
  }
  const configuredTransports = asObjectList(config.transports);
  const subscriptionDeploymentOptions = configuredTransports.flatMap(
    (transport) =>
      ["ws", "grpc", "httpupgrade", "xhttp"].includes(
        asText(transport.kind, ""),
      )
        ? cdnDeploymentsForTransport(transport)
            .filter(
              (deployment) =>
                deployment.enabled !== false &&
                Boolean(asText(deployment.hostname, "").trim()),
            )
            .map((deployment) => ({
              value: `${asText(transport.id, "")}::${asText(deployment.id, "")}`,
              label: `${transportKindLabel(asText(transport.kind, ""))} · ${asText(deployment.display_name, "CDN")} · ${asText(deployment.hostname, "")}`,
              hostname: asText(deployment.hostname, ""),
              port: Number(deployment.listen_port ?? 443),
              serverName: asText(
                deployment.tls_server_name,
                asText(deployment.hostname, ""),
              ),
              transportId: asText(transport.id, ""),
              deploymentId: asText(deployment.id, ""),
            }))
        : [],
  );
  const selectedSubscriptionDeployment = subscriptionDeploymentOptions.find(
    (option) => option.value === subscriptionDeploymentSelection,
  );
  const subscriptionUsesDedicatedCdn =
    subscriptionEndpointMode === "direct-and-cdn" &&
    subscriptionDeploymentSelection === "subscription-cdn";
  const subscriptionHasEditablePublicCdnPort =
    subscriptionEndpointMode === "separate" || subscriptionUsesDedicatedCdn;
  const subscriptionHasDedicatedHttpsEndpoint = [
    "separate",
    "direct",
    "direct-and-cdn",
  ].includes(subscriptionEndpointMode);
  const subscriptionTcpPortConflicts = configuredTransports
    .filter(
      (transport) =>
        transport.enabled !== false &&
        ["reality", "reality-grpc", "grpc-tls", "xhttp-reality"].includes(
          asText(transport.kind, ""),
        ) &&
        Number(transport.listen_port) === subscriptionOriginPort &&
        !asText(transport.wan_destination_address, "").trim(),
    )
    .map((transport) => transportKindLabel(transport.kind));
  const configuredSubscriptionDeployment = subscriptionDeploymentOptions.find(
    (option) =>
      option.value ===
      (configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
        ? `${configuredSubscriptionTransportId}::${configuredSubscriptionDeploymentId}`
        : ""),
  );
  const configuredDualCdnHostname = configuredSubscriptionTransportId && configuredSubscriptionDeploymentId
    ? configuredSubscriptionDeployment?.hostname || ""
    : configuredSubscriptionCdnHostname;
  const subscriptionEndpointSummaryHost =
    configuredSubscriptionEndpointMode === "reuse-cdn"
      ? configuredSubscriptionDeployment?.hostname || tr("CDN-домен не выбран")
      : configuredSubscriptionEndpointMode === "direct-and-cdn"
        ? `${configuredSubscriptionHostname || tr("Прямой домен не задан")} + ${configuredDualCdnHostname || tr("CDN-домен не выбран")}`
        : configuredSubscriptionHostname || tr("Домен не настроен");
  const configuredSubscriptions = asObjectList(config.subscriptions);
  const configuredSubscriptionReserves = asObjectList(
    config.subscription_reserves,
  );
  const subscriptionIdsKey = configuredSubscriptions
    .map((subscription) => asText(subscription.id, ""))
    .filter(Boolean)
    .sort()
    .join("|");
  useEffect(() => {
    let active = true;
    const ids = subscriptionIdsKey.split("|").filter(Boolean);
    let inFlight = false;
    const refresh = async () => {
      if (document.visibilityState !== "visible" || inFlight || !ids.length) return;
      inFlight = true;
      try {
        const response = await getSubscriptionMetadata<JsonObject>();
        const entries = asObject(response.subscriptions) as Record<string, JsonObject>;
        if (active) {
          setSubscriptionMetadata((current) => mergeSubscriptionMetadata(current,
            Object.fromEntries(ids.map((id) => [id, entries[id] ?? { provider: {} }])), ids));
          setSubscriptionMetadataError(false);
        }
      } catch {
        if (active) setSubscriptionMetadataError(true);
      } finally {
        inFlight = false;
      }
    };
    void refresh();
    const timer = window.setInterval(refresh, 30_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      active = false;
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [subscriptionIdsKey, setSubscriptionMetadata]);
  const tlsProfilesById = new Map(
    configuredTlsProfiles.map((profile) => [asText(profile.id, ""), profile]),
  );
  const kindNames: Record<string, string> = {
    ws: "WebSocket + TLS",
    grpc: "gRPC + TLS",
    "grpc-tls": "VLESS + gRPC + TLS Pin",
    httpupgrade: "HTTPUpgrade + TLS",
    xhttp: "XHTTP + TLS",
    "xhttp-reality": "VLESS + XHTTP + REALITY",
    reality: "VLESS + REALITY + Vision",
    "reality-grpc": "VLESS + gRPC + REALITY",
    hysteria2: "Hysteria 2",
  };
  const transportRows = configuredTransports.length
    ? configuredTransports.map((transport) => {
        const kind = asText(transport.kind, "");
        const enabled = transport.enabled !== false;
        const cdnDeployments = ["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)
          ? cdnDeploymentsForTransport(transport).filter(
              (deployment) => deployment.enabled !== false,
            )
          : [];
        const profile = tlsProfilesById.get(
          asText(transport.tls_profile_id, ""),
        );
        const cdnProfiles = cdnDeployments.map((deployment) =>
          tlsProfilesById.get(
            asText(
              deployment.tls_profile_id,
              asText(transport.tls_profile_id, ""),
            ),
          ),
        );
        const cdnProfileNames = [
          ...new Set(
            cdnProfiles
              .filter((item): item is JsonObject => Boolean(item))
              .map((item) => itemName(item)),
          ),
        ];
        const tlsKind = [
          "ws",
          "grpc",
          "grpc-tls",
          "httpupgrade",
          "xhttp",
          "hysteria2",
        ].includes(kind);
        const tlsReady = cdnDeployments.length
          ? cdnProfiles.length > 0 && cdnProfiles.every((item) => Boolean(
              item &&
                asText(item.certificate_secret_ref, "") &&
                asText(item.private_key_secret_ref, ""),
            ))
          : Boolean(
              profile &&
                asText(profile.certificate_secret_ref, "") &&
                asText(profile.private_key_secret_ref, ""),
            );
        const tlsSummary = cdnDeployments.length
          ? cdnProfileNames.length
            ? cdnProfileNames.join(" + ")
            : tr("профиль не выбран")
          : profile
            ? itemName(profile)
            : tr("профиль не выбран");
        const port = asText(
          transport.listen_port,
          kind === "reality"
            ? "2443"
            : kind === "reality-grpc"
              ? "2444"
              : kind === "grpc-tls"
                ? "2445"
                : kind === "xhttp-reality"
                  ? "2446"
                  : String(configuredPublicPort),
        );
        const cdnProvider = cdnDeployments.length
          ? [...new Set(cdnDeployments.map((deployment) => cdnProviderName(deployment.cdn_provider)))].join(" + ")
          : cdnProviderName(transport.cdn_provider);
        const xhttpMode = asText(
          transport.mode,
          kind === "xhttp-reality" ? "auto" : "packet-up",
        );
        const xhttpUplinkMethod = asText(
          transport.uplink_http_method,
          xhttpMode === "packet-up" ? "GET" : "POST",
        ).toUpperCase();
        const xhttpVision = transport.vless_encryption_enabled === true;
        return {
          id: asText(transport.id, kind || "transport"),
          name: kindNames[kind] ?? itemName(transport),
          host: cdnDeployments.length
            ? cdnDeployments
                .map(
                  (deployment) =>
                    `${asText(deployment.hostname, tr("hostname не задан"))}:${asText(deployment.listen_port, "443")}`,
                )
                .join(" · ")
            : `${connectionHostname(transport)}:${port}`,
          status:
            enabled && tlsKind && !tlsReady
              ? tr("Нужен TLS-профиль")
                : configuredItemStatus(
                  enabled,
                  revisionState,
                    tr("Выключен"),
                    locale,
                ),
          detail:
            kind === "reality"
              ? tr("VLESS/TCP · XTLS Vision · REALITY · прямой вход")
              : kind === "reality-grpc"
                ? tr("gRPC/HTTP2 + REALITY · без Vision · прямой вход")
                : kind === "grpc-tls"
                  ? tr("gRPC/HTTP2 · TLS Pin · прямой вход")
                  : kind === "xhttp-reality"
                    ? `XHTTP ${xhttpMode} + REALITY · ${xhttpUplinkMethod} uplink${xhttpVision ? tr(" · Vision с VLESS Encryption") : ""}`
                    : kind === "hysteria2"
                      ? `QUIC/UDP · ${profile ? itemName(profile) : tr("профиль не выбран")}`
                      : kind === "xhttp"
                        ? tr("{value1} · {value2} CDN-развёрт. · TLS · XHTTP {value3} · {value4}", { value1: cdnProvider, value2: cdnDeployments.length, value3: xhttpMode, value4: tlsSummary })
                        : kind === "httpupgrade"
                          ? tr("{value1} · {value2} CDN-развёрт. · TLS · HTTPUpgrade · {value3}", { value1: cdnProvider, value2: cdnDeployments.length, value3: tlsSummary })
                          : kind === "grpc"
                            ? tr("{value1} · {value2} CDN-развёрт. · TLS · HTTP/2 · {value3}", { value1: cdnProvider, value2: cdnDeployments.length, value3: tlsSummary })
                            : kind === "ws"
                              ? tr("{value1} · {value2} CDN-развёрт. · TLS · {value3}", { value1: cdnProvider, value2: cdnDeployments.length, value3: tlsSummary })
                              : tr("Прямое подключение"),
          group: ["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)
            ? "cdn"
            : ["reality", "reality-grpc", "xhttp-reality"].includes(kind)
              ? "reality"
              : "direct-tls",
          tlsProfile: cdnDeployments.length ? tlsSummary : profile ? itemName(profile) : "",
          tlsExpiry:
            cdnProfiles.length === 1 && cdnProfiles[0]
              ? tlsProfileExpiry(cdnProfiles[0], locale)
              : profile
                ? tlsProfileExpiry(profile, locale)
                : "",
          tone:
            enabled && tlsKind && !tlsReady
              ? ("warn" as Tone)
              : configuredItemTone(enabled, revisionState),
        };
      })
    : [];
  const transportGroups = [
    {
      id: "cdn",
      title: tr("Через CDN + TLS"),
    },
    {
      id: "reality",
      title: tr("Прямые + REALITY"),
    },
    {
      id: "direct-tls",
      title: tr("Прямые TLS / QUIC"),
    },
  ];
  const subscriptionRows = configuredSubscriptions.map((subscription) => ({
         id: asText(subscription.id, "unknown"),
         name: itemName(subscription),
         last: subscriptionIntervalText(subscription, locale),
         expiry: subscriptionMetadata[asText(subscription.id, "")]
           ? expiryText(asObject(subscriptionMetadata[asText(subscription.id, "")].provider).expires_at, locale)
           : subscriptionMetadataError ? tr("Повторная загрузка срока…") : tr("Загрузка срока…"),
         enabled: subscription.enabled !== false,
      }));
  const [tlsTransfer, setTlsTransfer] = useState<{ id: string; name: string } | "import" | null>(null);
  const tlsProfileRows = configuredTlsProfiles.map((profile) => {
    const id = asText(profile.id, "");
    const metadata = asObject(profile.certificate_metadata);
    const usedByLabels = configuredTransports.flatMap((transport) => {
      if (transport.enabled === false) return [];
      const kind = asText(transport.kind, "");
      if (["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)) {
        return cdnDeploymentsForTransport(transport)
          .filter((deployment) =>
            deployment.enabled !== false &&
            asText(
              deployment.tls_profile_id,
              asText(transport.tls_profile_id, ""),
            ) === id,
          )
          .map(
            (deployment) =>
              `${transportKindLabel(kind)} / ${asText(deployment.display_name, "CDN")}`,
          );
      }
      return asText(transport.tls_profile_id, "") === id
        ? [transportKindLabel(kind)]
        : [];
    });
    if (configuredCloudflareTlsProfileId === id && configuredStatusHostname) {
      usedByLabels.unshift(tr("Внешний status / health"));
    }
    if (configuredSubscriptionEndpointEnabled && configuredSubscriptionTlsProfileId === id) {
      usedByLabels.unshift(tr("Клиентская подписка"));
    }
    const ready = Boolean(
      asText(profile.certificate_secret_ref, "") &&
        asText(profile.private_key_secret_ref, ""),
    );
    return {
      id,
      name: itemName(profile),
      ready,
      expiry: tlsProfileExpiry(profile, locale),
      renewalFailed: asObject(certificateStatus[id]).enabled === true && asObject(certificateStatus[id]).state === "failed" && asText(profile.certificate_secret_ref, "").endsWith("/acme-bundle.pem"),
      dnsNames: asStringList(metadata.dns_names),
      usedByLabels,
    };
  });

  async function saveSubscriptionEndpoint() {
    if (!subscriptionEndpointEnabled) {
      setCloudflarePortBusy(true);
      setCloudflarePortMessage("");
      try {
        await saveCurrentDraft({
          config: disableSubscriptionPublication(config),
        });
        await onDraftChanged();
        setCloudflarePortMessage(tr("Публикация подписки отключена."));
        setSubscriptionEndpointDialogOpen(false);
      } catch (error) {
        setCloudflarePortMessage(prefixedErrorMessage(error));
      } finally {
        setCloudflarePortBusy(false);
      }
      return;
    }
    const nextSubscriptionDisplayName = subscriptionDisplayName.trim();
    if (!nextSubscriptionDisplayName) {
      setCloudflarePortMessage(tr("Укажите имя подписки для клиентского приложения."));
      return;
    }
    const usesDedicatedSubscriptionCdn = subscriptionUsesDedicatedCdn;
    if (
      subscriptionEndpointMode === "reuse-cdn" ||
      (subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn)
    ) {
      const selected = subscriptionDeploymentOptions.find(
        (option) => option.value === subscriptionDeploymentSelection,
      );
      if (!selected) {
        setCloudflarePortMessage(tr("Выберите включённое CDN-развёртывание."));
        return;
      }
      if (subscriptionEndpointMode === "reuse-cdn") {
        setCloudflarePortBusy(true);
        setCloudflarePortMessage("");
        try {
          await saveCurrentDraft({
            config: withDeploymentReadiness(
              {
                ...config,
                ingress: {
                  ...asObject(config.ingress),
                  status_hostname: "",
                  subscription_endpoint_enabled: true,
                  subscription_endpoint_mode: "reuse-cdn",
                  subscription_cdn_hostname: "",
                  subscription_origin_server_name: "",
                  subscription_primary_endpoint: "cdn",
                  subscription_transport_id: selected.transportId,
                  subscription_deployment_id: selected.deploymentId,
                },
                public_exposure: {
                  ...asObject(config.public_exposure),
                  subscription: {
                    ...asObject(asObject(config.public_exposure).subscription),
                    display_name: nextSubscriptionDisplayName,
                    happ_provider_id: happProviderId.trim(),
                  },
                },
              },
              false,
            ),
          });
          await onDraftChanged();
          setCloudflarePortMessage(tr("Подписка использует выбранный CDN-домен. Секретный путь отделён от пути подключения."));
          setSubscriptionEndpointDialogOpen(false);
        } catch (error) {
          setCloudflarePortMessage(prefixedErrorMessage(error));
        } finally {
          setCloudflarePortBusy(false);
        }
        return;
      }
    }
    if (subscriptionHasEditablePublicCdnPort && subscriptionCdnProvider === "cloudflare" && !CLOUDFLARE_HTTPS_PORTS.includes(
      subscriptionPublicPort as (typeof CLOUDFLARE_HTTPS_PORTS)[number],
    )) {
      setCloudflarePortMessage(tr("Выберите поддерживаемый Cloudflare HTTPS-порт подписки."));
      return;
    }
    if (
      subscriptionHasDedicatedHttpsEndpoint &&
      subscriptionTcpPortConflicts.length
    ) {
      setCloudflarePortMessage(
        tr("TCP/{value1} origin уже занят прямым входом: {value2}. Выберите другой origin-порт или настройте общий TCP 443 с разными SNI.", { value1: subscriptionOriginPort, value2: subscriptionTcpPortConflicts.join(
          ", ",
        ) }),
      );
      return;
    }
    if (!Number.isInteger(subscriptionOriginPort) || subscriptionOriginPort < 1 || subscriptionOriginPort > 65535) {
      setCloudflarePortMessage(tr("TCP-порт origin должен быть целым числом от 1 до 65535."));
      return;
    }
    if (subscriptionHasEditablePublicCdnPort && (!Number.isInteger(subscriptionPublicPort) || subscriptionPublicPort < 1 || subscriptionPublicPort > 65535)) {
      setCloudflarePortMessage(tr("Публичный HTTPS-порт должен быть целым числом от 1 до 65535."));
      return;
    }
    if (!configuredTlsProfiles.some((profile) => asText(profile.id, "") === subscriptionTlsProfileId)) {
      setCloudflarePortMessage(tr("Выберите существующий TLS-профиль клиентской подписки."));
      return;
    }
    const nextSubscriptionDirectHostname = subscriptionHostname.trim().replace(/\.$/, "").toLowerCase();
    const nextSubscriptionCdnHostname = subscriptionCdnHostname.trim().replace(/\.$/, "").toLowerCase();
    const nextSubscriptionHostname = subscriptionEndpointMode === "separate"
      ? nextSubscriptionCdnHostname
      : nextSubscriptionDirectHostname;
    if (!nextSubscriptionHostname) {
      setCloudflarePortMessage(
        subscriptionEndpointMode === "separate"
          ? tr("Укажите домен раздачи CDN.")
          : tr("Укажите прямой домен клиентской подписки."),
      );
      return;
    }
    if (usesDedicatedSubscriptionCdn && !nextSubscriptionCdnHostname) {
      setCloudflarePortMessage(tr("Выберите или укажите CDN-домен клиентской подписки."));
      return;
    }
    const nextSubscriptionOriginServerName = subscriptionOriginServerName
      .trim()
      .replace(/\.$/, "")
      .toLowerCase();
    if ((subscriptionEndpointMode === "separate" || usesDedicatedSubscriptionCdn) && !nextSubscriptionOriginServerName) {
      setCloudflarePortMessage(tr("Укажите DNS-имя origin."));
      return;
    }
    if (usesDedicatedSubscriptionCdn && nextSubscriptionDirectHostname !== nextSubscriptionOriginServerName) {
      setCloudflarePortMessage(tr("Для текущего CDN прямой домен должен совпадать с origin: {value1}.", { value1: nextSubscriptionOriginServerName }));
      return;
    }
    setCloudflarePortBusy(true);
    setCloudflarePortMessage("");
    try {
      await saveCurrentDraft({
        config: withDeploymentReadiness(
          {
            ...config,
            ingress: {
              ...asObject(config.ingress),
              status_hostname: "",
              subscription_endpoint_enabled: true,
              subscription_hostname: nextSubscriptionHostname,
              subscription_cdn_hostname:
                subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn
                  ? ""
                  : nextSubscriptionCdnHostname,
              subscription_origin_server_name:
                subscriptionEndpointMode === "separate" || usesDedicatedSubscriptionCdn
                  ? nextSubscriptionOriginServerName
                  : asText(asObject(config.ingress).subscription_origin_server_name, ""),
              subscription_listen_port: subscriptionOriginPort,
              subscription_public_port: subscriptionHasEditablePublicCdnPort
                ? subscriptionPublicPort
                : subscriptionEndpointMode === "direct"
                  ? subscriptionOriginPort
                  : asObject(config.ingress).subscription_public_port ?? subscriptionOriginPort,
              subscription_tls_profile_id: subscriptionTlsProfileId,
              subscription_cdn_provider: subscriptionCdnProvider,
              subscription_endpoint_mode: subscriptionEndpointMode,
              subscription_primary_endpoint:
                subscriptionEndpointMode === "direct-and-cdn"
                  ? subscriptionPrimaryEndpoint
                  : subscriptionEndpointMode === "direct"
                    ? "direct"
                    : "cdn",
              subscription_transport_id:
                subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn
                  ? subscriptionDeploymentSelection.split("::")[0] ?? ""
                  : "",
              subscription_deployment_id:
                subscriptionEndpointMode === "direct-and-cdn" && !usesDedicatedSubscriptionCdn
                  ? subscriptionDeploymentSelection.split("::")[1] ?? ""
                  : "",
              subscription_origin_protection_mode: subscriptionOriginProtectionMode,
              subscription_origin_header_name: "X-SB-Origin",
              subscription_origin_header_value:
                subscriptionEndpointMode === "separate" &&
                subscriptionOriginProtectionMode === "secret-header"
                  ? subscriptionOriginHeaderValue || undefined
                  : undefined,
            },
            public_exposure: {
              ...asObject(config.public_exposure),
              subscription: {
                ...asObject(asObject(config.public_exposure).subscription),
                display_name: nextSubscriptionDisplayName,
                happ_provider_id: happProviderId.trim(),
              },
            },
          },
          false,
        ),
      });
      await onDraftChanged();
      setCloudflarePortMessage(
        subscriptionEndpointMode === "direct"
          ? tr("Прямая HTTPS-ссылка сохранена на порту {value1}.", { value1: subscriptionOriginPort })
          : subscriptionEndpointMode === "direct-and-cdn"
            ? tr("Сохранены два адреса одной подписки: прямой HTTPS и выбранный CDN-домен.")
            : tr("Клиентская подписка сохранена: CDN {value1} → origin {value2}.", { value1: subscriptionPublicPort, value2: subscriptionOriginPort }),
      );
      setSubscriptionEndpointDialogOpen(false);
    } catch (error) {
      setCloudflarePortMessage(prefixedErrorMessage(error));
    } finally {
      setCloudflarePortBusy(false);
    }
  }

  async function checkSubscriptionTls() {
    const targets: Array<{ label: string; hostname: string; port: number; serverName: string }> = [];
    if (
      (subscriptionEndpointMode === "reuse-cdn" ||
        subscriptionEndpointMode === "direct-and-cdn") &&
      selectedSubscriptionDeployment
    ) {
      targets.push({
        label: "CDN",
        hostname: selectedSubscriptionDeployment.hostname,
        port: selectedSubscriptionDeployment.port,
        serverName: selectedSubscriptionDeployment.serverName,
      });
    }
    if (
      subscriptionEndpointMode === "direct-and-cdn" &&
      subscriptionDeploymentSelection === "subscription-cdn"
    ) {
      targets.push({
        label: "CDN",
        hostname: subscriptionCdnHostname.trim(),
        port: subscriptionPublicPort,
        serverName: subscriptionCdnHostname.trim(),
      });
    }
    if (subscriptionHasDedicatedHttpsEndpoint) {
      targets.push({
        label: subscriptionEndpointMode === "separate" ? tr("CDN-домен") : tr("Прямой адрес"),
        hostname: subscriptionEndpointMode === "separate"
          ? subscriptionCdnHostname.trim()
          : subscriptionHostname.trim(),
        port: subscriptionEndpointMode === "separate" ? subscriptionPublicPort : subscriptionOriginPort,
        serverName: subscriptionEndpointMode === "separate"
          ? subscriptionCdnHostname.trim()
          : subscriptionHostname.trim(),
      });
    }
    if (!targets.length || targets.some((target) => !target.hostname)) {
      setSubscriptionProbeResult(tr("Сначала укажите домен или выберите готовое CDN-развёртывание."));
      return;
    }
    setSubscriptionProbeBusy(true);
    setSubscriptionProbeResult("");
    try {
      const results = [];
      for (const target of targets) {
        const probe = await probeTlsEndpoint<JsonObject>(
          target.hostname,
          target.port,
          target.serverName,
        );
        results.push(
          tr("{value1}: {value2} · {value3} · сертификат: {value4}", { value1: target.label, value2: asStringList(probe.addresses).join(", "), value3: asText(probe.tls_version, "TLS"), value4: expiryText(probe.certificate_expires_at) }),
        );
      }
      setSubscriptionProbeResult(tr("{value1} Настройки аккаунта CDN проверяются отдельно через API провайдера.", { value1: results.join(" | ") }));
    } catch (error) {
      setSubscriptionProbeResult(prefixedErrorMessage(error));
    } finally {
      setSubscriptionProbeBusy(false);
    }
  }

  async function openNodeLocations(subscriptionId: string) {
    setNodeBusy(true);
    setSubscriptionMessage("");
    try {
      const result = await getSubscriptionNodes(subscriptionId);
      const rows = asObjectList(result.nodes);
      const values = Object.fromEntries(
        rows.map((node) => [asText(node.location_key, ""), asText(node.city, "")]),
      );
      setNodeSubscriptionId(subscriptionId);
      setNodeRows(rows);
      setNodeCities(values);
      setInitialNodeCities(values);
    } catch (error) {
      setSubscriptionMessage(prefixedErrorMessage(error));
    } finally {
      setNodeBusy(false);
    }
  }

  async function saveNodeLocations() {
    const subscription = configuredSubscriptions.find(
      (item) => asText(item.id, "") === nodeSubscriptionId,
    );
    if (!subscription) return;
    setNodeBusy(true);
    setSubscriptionMessage("");
    try {
      const overrides: JsonObject = { ...asObject(subscription.location_overrides) };
      for (const node of nodeRows) {
        const key = asText(node.location_key, "");
        if (!key || nodeCities[key] === initialNodeCities[key]) continue;
        const city = (nodeCities[key] ?? "").trim().replace(/\s+/g, " ");
        if (city) {
          overrides[key] = { ...asObject(overrides[key]), city };
        } else {
          delete overrides[key];
        }
      }
      await updateCollectionItem("subscriptions", nodeSubscriptionId, {
        ...subscription,
        location_overrides: overrides,
      });
      await onDraftChanged();
      setInitialNodeCities({ ...nodeCities });
      setSubscriptionMessage(tr("Города сохранены. Теперь их можно выбрать в маршрутном листе."));
    } catch (error) {
      setSubscriptionMessage(prefixedErrorMessage(error));
    } finally {
      setNodeBusy(false);
    }
  }

  function resetReserveEditor() {
    setEditingReserveId("");
    setReserveName("");
    setReserveLink("");
    setReserveMessage("");
    setReserveDialogOpen(false);
  }

  async function saveSubscriptionReserve(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const displayName = reserveName.trim();
    const link = reserveLink.trim();
    if (!displayName) {
      setReserveMessage(tr("Ошибка: укажите понятное имя резервного подключения."));
      return;
    }
    if (!editingReserveId && !link) {
      setReserveMessage(tr("Ошибка: вставьте одну ссылку VLESS."));
      return;
    }
    if (link && !link.toLowerCase().startsWith("vless://")) {
      setReserveMessage(tr("Ошибка: резерв должен быть одной ссылкой VLESS."));
      return;
    }
    if (!editingReserveId && configuredSubscriptionReserves.length >= 3) {
      setReserveMessage(tr("Ошибка: можно настроить не более трёх независимых резервов."));
      return;
    }
    const reserveId =
      editingReserveId ||
      entityIdFromName(
        displayName,
        new Set(
          configuredSubscriptionReserves.map((item) => asText(item.id, "")),
        ),
        "subscription-reserve",
      );
    const existing =
      configuredSubscriptionReserves.find(
        (item) => asText(item.id, "") === reserveId,
      ) ?? {};
    const item: JsonObject = {
      ...existing,
      id: reserveId,
      display_name: displayName,
      enabled: true,
      ...(link ? { link } : {}),
    };
    setReserveBusy(true);
    setReserveMessage("");
    try {
      if (editingReserveId) {
        await updateCollectionItem(
          "subscription-reserves",
          reserveId,
          item,
        );
      } else {
        await createCollectionItem("subscription-reserves", item);
      }
      await onDraftChanged();
      setReserveMessage(tr("Резервный VLESS сохранён. Для включения примените изменения."));
      setEditingReserveId("");
      setReserveName("");
      setReserveLink("");
      setReserveDialogOpen(false);
    } catch (error) {
      setReserveMessage(prefixedErrorMessage(error));
    } finally {
      setReserveBusy(false);
    }
  }

  async function removeSubscriptionReserve(reserveId: string) {
    setReserveBusy(true);
    setReserveMessage("");
    try {
      await deleteCollectionItem("subscription-reserves", reserveId);
      await onDraftChanged();
      if (editingReserveId === reserveId) resetReserveEditor();
      setReserveMessage(tr("Резервный VLESS удалён. Для включения примените изменения."));
    } catch (error) {
      setReserveMessage(prefixedErrorMessage(error));
    } finally {
      setReserveBusy(false);
    }
  }

  return (
    <>
      <SectionTitle
        title={tr("Подключения")}
      />

      <div className="transport-groups">
        {!configuredTransports.length ? (
          <aside className="notice notice-neutral">
            <span className="notice-icon">i</span>
            <div>
              <strong>{tr("Транспорты ещё не сохранены")}</strong>
              <p>{tr("Запустите мастер первого запуска, чтобы создать фактический набор серверных протоколов.")}</p>
            </div>
          </aside>
        ) : null}
        {transportGroups.map((group) => {
          const rows = transportRows.filter(
            (transport) => transport.group === group.id,
          );
          if (!rows.length && group.id !== "cdn") return null;
          return (
            <section className="transport-group" key={group.id}>
              <div className="transport-group-heading">
                <h3>{group.title}</h3>
              </div>
              {group.id === "cdn" ? (
                <article className="card transport-card settings-launch-card">
                  <div className="transport-summary">
                    <div className="transport-title">
                      <h3>{tr("HTTPS-ссылка клиентской подписки")}</h3>
                      <code>{subscriptionEndpointSummaryHost}</code>
                    </div>
                    <div className="transport-detail">
                      <span
                        className={`signal-dot signal-${configuredSubscriptionHostname ? "ok" : "warn"}`}
                        aria-hidden="true"
                      />
                      <span>
                        {configuredSubscriptionEndpointMode === "reuse-cdn"
                          ? tr("Домен существующего CDN-развёртывания")
                          : configuredSubscriptionEndpointMode === "direct"
                            ? tr("Прямая HTTPS-ссылка")
                            : configuredSubscriptionEndpointMode === "direct-and-cdn"
                              ? tr("Два адреса · CDN и прямой HTTPS")
                              : tr("Отдельный CDN-домен · {value1}", { value1: cdnProviderName(configuredSubscriptionCdnProvider) })}
                        {` · ${configuredSubscriptionDisplayName}`}
                      </span>
                    </div>
                  </div>
                  <div className="transport-actions">
                    <StatusPill tone={!subscriptionEndpointSummaryHost.includes(tr("не ")) && !subscriptionEndpointSummaryHost.includes(tr("не выбран")) ? "ok" : "warn"}>
                      {!subscriptionEndpointSummaryHost.includes(tr("не ")) && !subscriptionEndpointSummaryHost.includes(tr("не выбран")) ? tr("Настроено") : tr("Не настроено")}
                    </StatusPill>
                    <button
                      className="button button-tertiary"
                      type="button"
                      onClick={openSubscriptionEndpointDialog}
                    >
                       {tr("Настроить")} </button>
                  </div>
                </article>
              ) : null}
              <div className="transport-grid">
                {rows.map((transport) => (
                  <article
                    className="card transport-card"
                    key={transport.id}
                  >
                    <div className="transport-summary">
                      <div className="transport-title">
                        <h3>{transport.name}</h3>
                        <code>{transport.host}</code>
                      </div>
                      <div className="transport-detail">
                        <span
                          className={`signal-dot signal-${transport.tone}`}
                          aria-hidden="true"
                        />
                        <span>{transport.detail}</span>
                      </div>
                    </div>
                    <div className="transport-actions">
                      <StatusPill tone={transport.tone}>
                        {transport.status}
                      </StatusPill>
                      <button
                        className="button button-tertiary"
                        onClick={() => onConfigureTransport(transport.id)}
                      >
                        {transport.status === "Выключен"
                          ? tr("Подготовить")
                          : tr("Настроить")}
                      </button>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          );
        })}
      </div>

      <section className="tls-profile-panel">
        <div className="entity-section-heading">
          <div>
            <h3>{tr("TLS-профили")}</h3>
          </div>
          <div className="panel-heading-actions">
            <button className="button button-secondary button-compact" type="button" onClick={() => setTlsTransfer("import")}>
               {tr("Импорт")} </button>
            <button className="button button-secondary button-compact" type="button" onClick={onAddTlsProfile}>
               {tr("+ Добавить TLS-профиль")} </button>
          </div>
        </div>
        <div className="transport-grid">
          {tlsProfileRows.map((profile) => (
            <article className="card transport-card settings-launch-card" key={profile.id}>
              <div className="transport-summary">
                <div className="transport-title">
                  <h3>{profile.name}</h3>
                  <code>{profile.dnsNames.length ? profile.dnsNames.join(", ") : tr("Домены не определены")}</code>
                </div>
                <div className="transport-detail">
                  <span className={`signal-dot signal-${profile.ready ? "ok" : "warn"}`} aria-hidden="true" />
                  <span>
                    {profile.usedByLabels.length
                      ? tr("Используется: {value1}", { value1: russianCount(profile.usedByLabels.length, [tr("подключение"), tr("подключения"), tr("подключений")]) })
                      : tr("Не используется")}
                  </span>
                </div>
              </div>
              <div className="transport-actions">
                <StatusPill tone={profile.renewalFailed ? "danger" : profile.ready ? "ok" : "warn"}>
                  {profile.renewalFailed ? tr("Ошибка продления") : profile.ready
                    ? profile.expiry === "срок не определён"
                      ? tr("Срок не определён")
                      : tr("До {value1}", { value1: profile.expiry })
                    : tr("Нужна TLS-пара")}
                </StatusPill>
                <button className="button button-tertiary" type="button" onClick={() => onEditTlsProfile(profile.id)}>
                   {tr("Настроить")} </button>
              </div>
            </article>
          ))}
          {!tlsProfileRows.length ? <div className="empty-result">{tr("TLS-профилей пока нет.")}</div> : null}
        </div>
      </section>

      {tlsTransfer ? <TlsTransferDialog profile={tlsTransfer === "import" ? undefined : tlsTransfer} onClose={() => setTlsTransfer(null)} onImported={onDraftChanged} /> : null}
      <section className="subscriptions-grid">
        <article className="card panel-card">
          <div className="panel-heading">
            <div>
              <h3>{tr("Подписки")}</h3>
            </div>
            <div className="panel-heading-actions">
              <StatusPill tone={configuredSubscriptions.length ? "info" : "muted"}>
                {configuredSubscriptions.length
                  ? russianCount(configuredSubscriptions.length, [tr("подписка"), tr("подписки"), tr("подписок")])
                  : tr("Не настроено")}
              </StatusPill>
              <button
                className="button button-primary button-compact subscription-add-button"
                type="button"
                onClick={onAddSubscription}
              >
                 {tr("+ Добавить")} </button>
            </div>
          </div>
          {subscriptionRows.map((subscription) => (
            <div className="subscription-row" key={subscription.id}>
              <div className="subscription-logo">
                {subscription.name.slice(0, 1).toUpperCase()}
              </div>
              <div className="subscription-summary">
                <strong>{subscription.name}</strong>
                <small>{subscription.expiry}</small>
              </div>
              <div className="subscription-schedule">
                <small>{tr("Автопроверка")}</small>
                <strong>{subscription.last}</strong>
              </div>
              <details className="subscription-action-menu">
                <summary className="button button-secondary button-compact">
                   {tr("Действия")} </summary>
                <div className="subscription-action-popover">
                  <button
                  type="button"
                  disabled={
                    !subscription.enabled ||
                    Boolean(subscriptionBusy)
                  }
                  onClick={async (event) => {
                    event.currentTarget.closest("details")?.removeAttribute("open");
                    setSubscriptionBusy(subscription.id);
                    setSubscriptionMessage(
                      tr("Обновляю {value1}…", { value1: subscription.name }),
                    );
                    try {
                      const result = await refreshSubscription<JsonObject>(subscription.id);
                      setSubscriptionMetadata((current) => mergeSubscriptionMetadata(current, {
                        [subscription.id]: { provider: asObject(result.provider), refreshed_at: result.refreshed_at },
                      }, subscriptionIdsKey.split("|").filter(Boolean)));
                      await onDraftChanged();
                      setSubscriptionMessage(
                        resultMessage(
                          result,
                          tr("Candidate подписки проверен локальным control plane."),
                        ),
                      );
                    } catch (error) {
                      setSubscriptionMessage(prefixedErrorMessage(error));
                    } finally {
                      setSubscriptionBusy("");
                    }
                  }}
                >
                  {subscriptionBusy === subscription.id
                      ? tr("Проверяю…")
                      : subscription.enabled
                        ? tr("Проверить сейчас")
                        : tr("Подписка выключена")}
                  </button>
                  <button
                  type="button"
                  disabled={nodeBusy}
                  onClick={(event) => {
                    event.currentTarget.closest("details")?.removeAttribute("open");
                    openNodeLocations(subscription.id);
                  }}
                >
                   {tr("Узлы и города")} </button>
                  <button
                  type="button"
                  onClick={(event) => {
                    event.currentTarget.closest("details")?.removeAttribute("open");
                    onEditSubscription(subscription.id);
                  }}
                >
                   {tr("Настроить")} </button>
                </div>
              </details>
            </div>
          ))}
          {!subscriptionRows.length ? (
            <div className="empty-result">
               {tr("Подписок пока нет. Добавьте HTTPS-подписку кнопкой выше.")} </div>
          ) : null}
          {nodeSubscriptionId ? (
            <section className="node-location-editor">
              <div className="node-location-heading">
                <div>
                  <strong>{tr("Города узлов ·")} {nodeSubscriptionId}</strong>
                  <small>{tr("Исправьте только неизвестные или неверно определённые города.")}</small>
                </div>
                <button className="button button-tertiary" type="button" onClick={() => setNodeSubscriptionId("")}>{tr("Закрыть")}</button>
              </div>
              {nodeRows.map((node) => {
                const key = asText(node.location_key, "");
                return (
                  <label className="node-location-row" key={asText(node.id, key)}>
                    <span>
                      <strong>{asText(node.label, asText(node.id))}</strong>
                      <small>{asText(node.country, "??")} · {asText(node.transport, "tcp")}  {tr("· ключ")} {key}</small>
                    </span>
                    <input
                      value={nodeCities[key] ?? ""}
                      onChange={(event) => setNodeCities((current) => ({ ...current, [key]: event.target.value }))}
                      placeholder={tr("Город")}
                      maxLength={256}
                    />
                  </label>
                );
              })}
              {!nodeRows.length ? (
                <aside className="notice notice-neutral">
                  <span className="notice-icon">i</span>
                  <div><strong>{tr("Узлов пока нет")}</strong><p>{tr("Сначала нажмите «Проверить сейчас», затем откройте этот список снова.")}</p></div>
                </aside>
              ) : (
                <div className="node-location-actions">
                  <button className="button button-primary" type="button" onClick={saveNodeLocations} disabled={nodeBusy}>
                    {nodeBusy ? tr("Сохраняю…") : tr("Сохранить города")}
                  </button>
                </div>
              )}
            </section>
          ) : null}
          {subscriptionMessage ? (
            <div
              className={`inline-result ${
                isErrorMessage(subscriptionMessage)
                  ? "inline-result-error"
                  : ""
              }`}
              role={isErrorMessage(subscriptionMessage) ? "alert" : "status"}
            >
              <span>
                {subscriptionBusy
                  ? "↻"
                  : isErrorMessage(subscriptionMessage)
                    ? "!"
                    : "✓"}
              </span>
              {subscriptionMessage}
            </div>
          ) : null}
        </article>
        <article className="card panel-card subscription-reserve-panel">
          <div className="panel-heading">
            <div>
              <h3>{tr("Независимые VLESS")}</h3>
            </div>
            <div className="panel-heading-actions">
              <StatusPill tone={configuredSubscriptionReserves.length ? "info" : "muted"}>
                {configuredSubscriptionReserves.length}  {tr("из 3")} </StatusPill>
              <button
                className="button button-secondary button-compact"
                type="button"
                disabled={reserveBusy || configuredSubscriptionReserves.length >= 3}
                onClick={() => {
                  setEditingReserveId("");
                  setReserveName("");
                  setReserveLink("");
                  setReserveMessage("");
                  setReserveDialogOpen(true);
                }}
              >
                 {tr("+ Добавить резерв")} </button>
            </div>
          </div>
          <div className="subscription-reserve-list">
            {configuredSubscriptionReserves.map((reserve) => {
              const reserveId = asText(reserve.id, "");
              const node = asObject(reserve.node);
              const server = asText(node.server, tr("Сервер не определён"));
              const port = asText(node.server_port, "");
              return (
                <article className="card transport-card settings-launch-card" key={reserveId}>
                  <div className="transport-summary">
                    <div className="transport-title">
                      <h3>{itemName(reserve)}</h3>
                      <code>{server}{port ? `:${port}` : ""}</code>
                    </div>
                    <div className="transport-detail">
                      <span className="signal-dot signal-ok" aria-hidden="true" />
                      <span>{tr("Независимый VLESS · UUID скрыт")}</span>
                    </div>
                  </div>
                  <div className="transport-actions">
                    <StatusPill tone="ok">{tr("Настроено")}</StatusPill>
                    <button
                      className="button button-tertiary"
                      type="button"
                      disabled={reserveBusy}
                      onClick={() => {
                        setEditingReserveId(reserveId);
                        setReserveName(itemName(reserve));
                        setReserveLink("");
                        setReserveMessage("");
                        setReserveDialogOpen(true);
                      }}
                    >
                       {tr("Настроить")} </button>
                  </div>
                </article>
              );
            })}
            {!configuredSubscriptionReserves.length ? (
              <div className="empty-result">
                 {tr("Независимые резервные подключения пока не настроены.")} </div>
            ) : null}
          </div>
            {reserveMessage ? (
              <div
                className={`inline-result ${
                  isErrorMessage(reserveMessage) ? "inline-result-error" : ""
                }`}
                role={isErrorMessage(reserveMessage) ? "alert" : "status"}
              >
                <span>{isErrorMessage(reserveMessage) ? "!" : "✓"}</span>
                {reserveMessage}
              </div>
            ) : null}
        </article>
      </section>

      {subscriptionEndpointDialogOpen
        ? createPortal(
            <div className="modal-backdrop subscription-endpoint-backdrop" role="presentation" onMouseDown={() => setSubscriptionEndpointDialogOpen(false)}>
              <section className="modal subscription-endpoint-dialog" role="dialog" aria-modal="true" aria-labelledby="subscription-endpoint-title" onMouseDown={(event) => event.stopPropagation()}>
                <header className="subscription-dialog-header">
                  <h2 id="subscription-endpoint-title">{tr("Ссылка подписки")}</h2>
                  <button className="modal-close" type="button" onClick={() => setSubscriptionEndpointDialogOpen(false)} aria-label={tr("Закрыть")}>×</button>
                </header>

                <div className="subscription-dialog-body" ref={subscriptionEndpointBodyRef}>
                  <Toggle
                    className="subscription-publication-toggle"
                    checked={subscriptionEndpointEnabled}
                    onChange={(enabled) => {
                      setSubscriptionEndpointEnabled(enabled);
                      setCloudflarePortMessage("");
                    }}
                    label={tr("Публикация подписки")}
                  />
                  <fieldset className="subscription-publication-fields" disabled={!subscriptionEndpointEnabled}>
                  <div className="subscription-mode-menu" role="radiogroup" aria-label={tr("Способ публикации подписки")}>
                    {[
                      ["cdn", tr("Через CDN")],
                      ["direct", tr("Напрямую")],
                      ["direct-and-cdn", tr("Два адреса")],
                    ].map(([value, title]) => (
                      <label className={`subscription-mode-option ${value === "cdn" ? ["separate", "reuse-cdn"].includes(subscriptionEndpointMode) ? "is-selected" : "" : subscriptionEndpointMode === value ? "is-selected" : ""}`} key={value}>
                        <input
                          type="radio"
                          name="subscription-endpoint-mode"
                          value={value}
                          checked={value === "cdn" ? ["separate", "reuse-cdn"].includes(subscriptionEndpointMode) : subscriptionEndpointMode === value}
                          onChange={(event) => {
                            const nextMode = event.target.value;
                            if (nextMode === "cdn") {
                              if (subscriptionCdnHostname) {
                                setSubscriptionEndpointMode("separate");
                                setSubscriptionDeploymentSelection("subscription-cdn");
                              } else if (subscriptionDeploymentSelection && subscriptionDeploymentSelection !== "subscription-cdn") {
                                setSubscriptionEndpointMode("reuse-cdn");
                              } else {
                                setSubscriptionEndpointMode("separate");
                              }
                            } else {
                              setSubscriptionEndpointMode(nextMode);
                              if (nextMode === "direct-and-cdn" && !subscriptionDeploymentSelection && subscriptionCdnHostname) {
                                setSubscriptionDeploymentSelection("subscription-cdn");
                              }
                            }
                            setCloudflarePortMessage("");
                          }}
                        />
                        <span><strong>{title}</strong></span>
                      </label>
                    ))}
                  </div>

                  <div className="subscription-essential-grid">
                    <label className="field">
                       {tr("Имя в приложении")} <input value={subscriptionDisplayName} maxLength={96} placeholder="SB Gateway" onChange={(event) => { setSubscriptionDisplayName(event.target.value); setCloudflarePortMessage(""); }} />
                    </label>

                    {subscriptionEndpointMode === "separate" || subscriptionEndpointMode === "reuse-cdn" ? (
                      <label className="field">
                         {tr("CDN-домен")} <select
                          value={subscriptionEndpointMode === "reuse-cdn"
                            ? subscriptionDeploymentSelection
                            : subscriptionCdnHostname
                              ? "subscription-cdn"
                              : "new"}
                          onChange={(event) => {
                            if (event.target.value === "new") {
                              setSubscriptionEndpointMode("separate");
                              setSubscriptionCdnHostname("");
                              setSubscriptionDeploymentSelection("");
                            } else if (event.target.value === "subscription-cdn") {
                              setSubscriptionEndpointMode("separate");
                              setSubscriptionDeploymentSelection("subscription-cdn");
                            } else {
                              setSubscriptionEndpointMode("reuse-cdn");
                              setSubscriptionDeploymentSelection(event.target.value);
                            }
                            setCloudflarePortMessage("");
                          }}
                        >
                          <option value="new">{tr("Новый CDN-домен")}</option>
                          {subscriptionCdnHostname ? <option value="subscription-cdn">{`${cdnProviderName(subscriptionCdnProvider)} · ${subscriptionCdnHostname}`}</option> : null}
                          {subscriptionDeploymentOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
                        </select>
                      </label>
                    ) : null}

                    {subscriptionEndpointMode === "direct-and-cdn" ? (
                      <label className="field">
                         {tr("CDN-домен")} <select value={subscriptionDeploymentSelection} onChange={(event) => { setSubscriptionDeploymentSelection(event.target.value); if (event.target.value === "subscription-cdn" && subscriptionOriginServerName) setSubscriptionHostname(subscriptionOriginServerName); setCloudflarePortMessage(""); }} required>
                          <option value="">{tr("Выберите настроенный домен")}</option>
                          {subscriptionCdnHostname ? <option value="subscription-cdn">{`${cdnProviderName(subscriptionCdnProvider)} · ${subscriptionCdnHostname}`}</option> : null}
                          {subscriptionDeploymentOptions.map((option) => <option value={option.value} key={option.value}>{option.label}</option>)}
                        </select>
                      </label>
                    ) : null}
                  </div>

                  {subscriptionEndpointMode === "separate" ? (
                    <div className="subscription-address-grid subscription-address-grid-separate">
                      <label className="field">
                        CDN
                        <select value={subscriptionCdnProvider} onChange={(event) => {
                          setSubscriptionCdnProvider(event.target.value);
                          setSubscriptionOriginProtectionMode(supportsAutomaticCidr(event.target.value) ? "auto-cidr" : "secret-header");
                          if (!supportsAutomaticCidr(event.target.value)) setSubscriptionOriginHeaderValue((current) => current || generateOriginHeaderSecret());
                          setCloudflarePortMessage("");
                        }}>
                          {CDN_PROVIDERS.map((provider) => <option value={provider.id} key={provider.id}>{tr(provider.name)}</option>)}
                        </select>
                      </label>
                      <label className="field subscription-domain-field">
                         {tr("Домен раздачи CDN")} <input type="text" inputMode="url" value={subscriptionCdnHostname} placeholder="cdn.example.com" onChange={(event) => { setSubscriptionCdnHostname(event.target.value); setSubscriptionDeploymentSelection("subscription-cdn"); setCloudflarePortMessage(""); }} />
                      </label>
                      <label className="field">
                         {tr("TLS-профиль origin")} <select value={subscriptionTlsProfileId} onChange={(event) => selectSubscriptionTlsProfile(event.target.value)}>
                          {configuredTlsProfiles.map((profile) => <option value={asText(profile.id, "")} key={asText(profile.id, "")}>{itemName(profile)}</option>)}
                        </select>
                      </label>
                      <label className="field">
                         {tr("DNS-имя origin")} <input type="text" inputMode="url" list={subscriptionOriginDatalistId} value={subscriptionOriginServerName} placeholder={subscriptionOriginHostnameCandidates.length ? tr("Выберите или введите домен") : "origin.example.com"} onChange={(event) => { setSubscriptionOriginServerName(event.target.value); setCloudflarePortMessage(""); }} />
                        <datalist id={subscriptionOriginDatalistId}>
                          {subscriptionOriginHostnameCandidates.map((hostname) => <option value={hostname} key={hostname} />)}
                        </datalist>
                      </label>
                    </div>
                  ) : null}

                  {subscriptionEndpointMode === "direct" || subscriptionEndpointMode === "direct-and-cdn" ? (
                    <div className="subscription-address-grid subscription-address-grid-direct">
                      <label className="field subscription-domain-field">
                         {tr("Прямой домен")} <input type="text" inputMode="url" list={subscriptionHostnameDatalistId} value={subscriptionHostname} placeholder={subscriptionHostnameCandidates.length ? tr("Выберите или введите домен") : "sub.example.com"} onChange={(event) => { setSubscriptionHostname(event.target.value); setCloudflarePortMessage(""); }} />
                        <datalist id={subscriptionHostnameDatalistId}>
                          {subscriptionHostnameCandidates.map((hostname) => <option value={hostname} key={hostname} />)}
                        </datalist>
                      </label>
                      <label className="field">
                         {tr("TLS-профиль")} <select value={subscriptionTlsProfileId} onChange={(event) => selectSubscriptionTlsProfile(event.target.value)}>
                          {configuredTlsProfiles.map((profile) => <option value={asText(profile.id, "")} key={asText(profile.id, "")}>{itemName(profile)}</option>)}
                        </select>
                      </label>
                    </div>
                  ) : null}

                  <details className="subscription-advanced-settings">
                    <summary>{t("common.advanced")}</summary>
                    <div className="subscription-advanced-grid">
                      {subscriptionEndpointMode === "separate" ? (
                        <label className="field">
                           {tr("Защита origin")} <select value={subscriptionOriginProtectionMode} onChange={(event) => {
                            setSubscriptionOriginProtectionMode(event.target.value);
                            if (event.target.value === "secret-header") setSubscriptionOriginHeaderValue((current) => current || generateOriginHeaderSecret());
                            setCloudflarePortMessage("");
                          }}>
                            {supportsAutomaticCidr(subscriptionCdnProvider) ? <option value="auto-cidr">{tr("Официальные CIDR · автоматически")}</option> : null}
                            <option value="secret-header">{tr("Секретный HTTP-заголовок")}</option>
                          </select>
                          {subscriptionOriginProtectionMode === "auto-cidr" ? <small>{automaticCidrHint(subscriptionCdnProvider)}</small> : null}
                        </label>
                      ) : null}
                      {subscriptionHasEditablePublicCdnPort ? (
                        <label className="field">
                           {tr("Публичный HTTPS-порт")} {subscriptionCdnProvider === "cloudflare" ? (
                            <select value={subscriptionPublicPort} onChange={(event) => { setSubscriptionPublicPort(Number(event.target.value)); setCloudflarePortMessage(""); }}>
                              {CLOUDFLARE_HTTPS_PORTS.map((port) => <option value={port} key={port}>{port}</option>)}
                            </select>
                          ) : (
                            <input type="number" min="1" max="65535" value={subscriptionPublicPort} onChange={(event) => { setSubscriptionPublicPort(Number(event.target.value)); setCloudflarePortMessage(""); }} />
                          )}
                        </label>
                      ) : null}
                      {subscriptionHasDedicatedHttpsEndpoint ? (
                        <label className="field">
                          {subscriptionHasEditablePublicCdnPort ? tr("TCP-порт origin на MikroTik") : tr("HTTPS-порт")}
                          <input type="number" min="1" max="65535" value={subscriptionOriginPort} onChange={(event) => { setSubscriptionOriginPort(Number(event.target.value)); setCloudflarePortMessage(""); }} />
                        </label>
                      ) : null}
                      {subscriptionEndpointMode === "direct-and-cdn" ? (
                        <label className="field">
                           {tr("Основной адрес")} <select value={subscriptionPrimaryEndpoint} onChange={(event) => { setSubscriptionPrimaryEndpoint(event.target.value); setCloudflarePortMessage(""); }}>
                            <option value="cdn">{tr("CDN-домен")}</option>
                            <option value="direct">{tr("Прямой домен")}</option>
                          </select>
                        </label>
                      ) : null}
                      <label className="field">
                        Happ Provider ID
                        <input
                          value={happProviderId}
                          maxLength={127}
                          placeholder={tr("Не задан")}
                          onChange={(event) => {
                            setHappProviderId(event.target.value);
                            setCloudflarePortMessage("");
                          }}
                        />
                        <small>{tr("Нужен Happ для автоматического включения удалённых LAN-маршрутов на iOS. Без ID настройте Include all networks вручную.")}</small>
                      </label>
                      {subscriptionEndpointMode === "separate" && subscriptionOriginProtectionMode === "secret-header" ? (
                        <div className="field subscription-secret-field">
                           {tr("Секрет origin")} <code>X-SB-Origin</code>
                          <div className="inline-field-actions">
                            <input value={subscriptionOriginHeaderValue} readOnly placeholder={configuredSubscriptionOriginHeaderRef ? tr("Секрет сохранён") : tr("Создайте секрет")} />
                            <button className="button button-secondary" type="button" onClick={() => setSubscriptionOriginHeaderValue(generateOriginHeaderSecret())}>{tr("Создать")}</button>
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </details>

                  {subscriptionHasDedicatedHttpsEndpoint && subscriptionTcpPortConflicts.length ? (
                    <div className="subscription-port-conflict" role="alert">
                      <strong>TCP/{subscriptionOriginPort}  {tr("origin уже занят")}</strong>
                      <span>{subscriptionTcpPortConflicts.join(", ")}</span>
                    </div>
                  ) : null}
                  {subscriptionHasDedicatedHttpsEndpoint && /(^|\.)localhost$|\.local$/i.test((subscriptionEndpointMode === "separate" ? subscriptionCdnHostname : subscriptionHostname).trim()) ? <small className="subscription-host-warning">{tr("Для внешнего доступа нужен публичный DNS и действующий сертификат.")}</small> : null}
                  {subscriptionProbeResult ? <div className={`inline-result ${isErrorMessage(subscriptionProbeResult) ? "inline-result-error" : ""}`} role={isErrorMessage(subscriptionProbeResult) ? "alert" : "status"}><span>{isErrorMessage(subscriptionProbeResult) ? "!" : "✓"}</span>{subscriptionProbeResult}</div> : null}
                  </fieldset>
                  {cloudflarePortMessage ? <div className={`inline-result ${isErrorMessage(cloudflarePortMessage) ? "inline-result-error" : ""}`} role={isErrorMessage(cloudflarePortMessage) ? "alert" : "status"}><span>{isErrorMessage(cloudflarePortMessage) ? "!" : "✓"}</span>{cloudflarePortMessage}</div> : null}
                </div>

                <footer className="subscription-endpoint-actions">
                  <button className="button button-secondary" type="button" disabled={!subscriptionEndpointEnabled || subscriptionProbeBusy} onClick={() => void checkSubscriptionTls()}>{subscriptionProbeBusy ? tr("Проверяю…") : tr("Проверить DNS и TLS")}</button>
                  <div className="modal-actions">
                    <button className="button button-tertiary" type="button" disabled={cloudflarePortBusy} onClick={() => setSubscriptionEndpointDialogOpen(false)}>{tr("Отмена")}</button>
                    <button className="button button-primary" type="button" disabled={cloudflarePortBusy} onClick={saveSubscriptionEndpoint}>{cloudflarePortBusy ? tr("Сохраняю…") : tr("Сохранить")}</button>
                  </div>
                </footer>
              </section>
            </div>,
            document.body,
          )
        : null}

      {reserveDialogOpen ? (
        <div className="modal-backdrop" role="presentation" onMouseDown={resetReserveEditor}>
          <section className="modal" role="dialog" aria-modal="true" aria-labelledby="reserve-vless-title" onMouseDown={(event) => event.stopPropagation()}>
            <button className="modal-close" type="button" onClick={resetReserveEditor} aria-label={tr("Закрыть")}>×</button>
            <form onSubmit={saveSubscriptionReserve}>
              <p className="eyebrow">{tr("Резерв обновления")}</p>
              <h2 id="reserve-vless-title">{editingReserveId ? tr("Настроить резервный VLESS") : tr("Добавить резервный VLESS")}</h2>
              <p className="modal-lead">{tr("Узел используется только для обновления недоступных подписок и не участвует в пользовательском трафике.")}</p>
              <div className="form-grid form-grid-single">
                <label className="field">{tr("Понятное имя")}<input value={reserveName} maxLength={96} placeholder={tr("Резерв · Польша Reality")} onChange={(event) => setReserveName(event.target.value)} /></label>
                <label className="field">{tr("Ссылка VLESS")}<input type="password" autoComplete="off" value={reserveLink} placeholder={editingReserveId ? tr("Оставьте пустым, чтобы сохранить текущую") : "vless://…"} onChange={(event) => setReserveLink(event.target.value)} /><small>{tr("UUID хранится только в SecretStore и не возвращается в браузер.")}</small></label>
              </div>
              {reserveMessage ? <div className={`inline-result ${isErrorMessage(reserveMessage) ? "inline-result-error" : ""}`} role={isErrorMessage(reserveMessage) ? "alert" : "status"}><span>{isErrorMessage(reserveMessage) ? "!" : "✓"}</span>{reserveMessage}</div> : null}
              <div className="modal-actions modal-actions-split">
                {editingReserveId ? <button className="button button-danger" type="button" disabled={reserveBusy} onClick={() => void removeSubscriptionReserve(editingReserveId)}>{tr("Удалить")}</button> : <span />}
                <div><button className="button button-tertiary" type="button" disabled={reserveBusy} onClick={resetReserveEditor}>{tr("Отмена")}</button><button className="button button-primary" type="submit" disabled={reserveBusy || (!editingReserveId && configuredSubscriptionReserves.length >= 3)}>{reserveBusy ? tr("Сохраняю…") : tr("Сохранить")}</button></div>
              </div>
            </form>
          </section>
        </div>
      ) : null}
    </>
  );
}
