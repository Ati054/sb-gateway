"use client";

import { GatewayApiError, JsonObject, createCollectionItem, deleteCollectionItem, getSubscriptionNodes, getSubscriptionUrl, probeTlsEndpoint, refreshSubscription, revealTransportHttpPath, updateCollectionItem } from "../api-client";
import { automaticCidrHint, supportsAutomaticCidr } from "../cdn-capabilities";
import { useLanguage } from "../i18n";
import { cdnDeploymentAfterTLSProfileChange, cdnDeploymentForTLSInitialization, certificateCoversHostname, hostnameAfterTLSProfileChange, hostnameForTLSProfileInitialization, tlsConcreteHostnames, tlsProfileIdForHostname } from "../tls-hostnames";
import { CDN_PROVIDERS, CLOUDFLARE_HTTPS_PORTS, ConnectionAddressContext, TRANSPORT_RECOMMENDATIONS, Toggle, asObject, asObjectList, asOptionalPositiveText, asStringList, asText, cdnDeploymentScopeNote, cdnDeploymentsForTransport, cdnOriginNameNote, entityIdFromName, errorMessage, expiryText, formatBytes, generateOriginHeaderSecret, isErrorMessage, itemName, prefixedErrorMessage, subscriptionCdnProviderNote, transportChangeLead, transportKindLabel } from "./shared";
import { FormEvent, useContext, useEffect, useRef, useState } from "react";

export function ConnectionDialog({
  kind,
  transportId,
  subscriptionId,
  onClose,
  onSaved,
  config,
  certificateStatus,
}: {
  kind: "subscription" | "transport";
  transportId?: string;
  subscriptionId?: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
  config: JsonObject;
  certificateStatus: JsonObject;
}) {
  const { locale, t, tr } = useLanguage();
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [revealedHttpPath, setRevealedHttpPath] = useState("");
  const [httpPathBusy, setHttpPathBusy] = useState(false);
  const [httpPathMessage, setHttpPathMessage] = useState("");
  const [realityProbeBusy, setRealityProbeBusy] = useState(false);
  const [realityProbeResult, setRealityProbeResult] = useState("");
  const [realityProbeTone, setRealityProbeTone] = useState<
    "idle" | "success" | "warning" | "error"
  >("idle");
  const [realityProbeSignature, setRealityProbeSignature] = useState("");
  const [realityProbeEndpoints, setRealityProbeEndpoints] = useState<JsonObject[]>([]);
  const [realityProbeWildcards, setRealityProbeWildcards] = useState<string[]>([]);
  const [cdnProbeBusyId, setCdnProbeBusyId] = useState("");
  const [cdnProbeResults, setCdnProbeResults] = useState<Record<string, string>>({});
  const [pendingTransportActions, setPendingTransportActions] = useState<string[]>([]);
  const formRef = useRef<HTMLFormElement>(null);
  const transportParameterSnapshotRef = useRef<
    Record<string, { value: string; checked?: boolean }> | null
  >(null);
  const transportActionMenuRef = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    function closeTransportActionMenu(event: PointerEvent) {
      const menu = transportActionMenuRef.current;
      if (!menu?.open || menu.contains(event.target as Node)) return;
      menu.open = false;
    }
    function closeTransportActionMenuWithKeyboard(event: KeyboardEvent) {
      if (event.key !== "Escape" || !transportActionMenuRef.current?.open) return;
      transportActionMenuRef.current.open = false;
      transportActionMenuRef.current.querySelector<HTMLElement>("summary")?.focus();
    }
    document.addEventListener("pointerdown", closeTransportActionMenu);
    document.addEventListener("keydown", closeTransportActionMenuWithKeyboard);
    return () => {
      document.removeEventListener("pointerdown", closeTransportActionMenu);
      document.removeEventListener("keydown", closeTransportActionMenuWithKeyboard);
    };
  }, []);
  const [workingSubscriptionId, setWorkingSubscriptionId] = useState(
    subscriptionId ?? "",
  );
  const [subscriptionNodes, setSubscriptionNodes] = useState<JsonObject[]>([]);
  const [discoveryReady, setDiscoveryReady] = useState(false);
  const [discoveryMessage, setDiscoveryMessage] = useState("");
  const [subscriptionProvider, setSubscriptionProvider] = useState<JsonObject>({});
  const [persistedSubscription, setPersistedSubscription] = useState<JsonObject>({});
  const [subscriptionUrl, setSubscriptionUrl] = useState("");
  const [subscriptionUrlBusy, setSubscriptionUrlBusy] = useState(false);

  useEffect(() => {
    if (kind !== "subscription" || !subscriptionId) {
      setSubscriptionUrl("");
      setSubscriptionUrlBusy(false);
      return;
    }
    let active = true;
    setSubscriptionUrlBusy(true);
    getSubscriptionUrl<JsonObject>(subscriptionId)
      .then((result) => {
        if (active) setSubscriptionUrl(asText(result.url, ""));
      })
      .catch((error) => {
        if (active) {
          setSaveError(tr("Не удалось загрузить сохранённый URL: {value1}", { value1: errorMessage(error) }));
        }
      })
      .finally(() => {
        if (active) setSubscriptionUrlBusy(false);
      });
    return () => {
      active = false;
    };
  }, [kind, subscriptionId, tr]);

  const existingTransport =
    asObjectList(config.transports).find((item) => item.id === transportId) ?? {};
  const [transportEnabled, setTransportEnabled] = useState(
    existingTransport.enabled !== false,
  );
  const savedTransportKind = asText(existingTransport.kind, "").trim();
  const transportKind = savedTransportKind ||
    (transportId === "websocket"
      ? "ws"
      : transportId === "direct-reality"
        ? "reality"
        : transportId === "grpc-reality"
          ? "reality-grpc"
          : transportId === "grpc-tls-pin"
            ? "grpc-tls"
            : transportId === "xhttp-reality"
              ? "xhttp-reality"
              : transportId === "hysteria2"
                ? "hysteria2"
                : transportId ?? "ws");
  const transportRecommendation = TRANSPORT_RECOMMENDATIONS[transportKind];
  const directGRPCKind = ["reality-grpc", "grpc-tls"].includes(transportKind);
  const grpcIdleTimeoutDefault = directGRPCKind ? "60" : "0";
  const hostnamePlaceholder =
    ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(
      transportKind,
    )
      ? tr("IP-адрес или DNS-имя")
      : transportKind === "grpc"
      ? tr("Фактический gRPC hostname")
      : transportKind === "httpupgrade"
        ? tr("Фактический HTTPUpgrade hostname")
        : transportKind === "xhttp"
          ? tr("Фактический XHTTP hostname")
          : tr("Фактический WebSocket hostname");
  const connectionAddress = useContext(ConnectionAddressContext);
  const [hostnameMode, setHostnameMode] = useState(
    asText(existingTransport.hostname_mode, asText(existingTransport.hostname, "") ? "manual" : "auto"),
  );
  const [manualHostname, setManualHostname] = useState(asText(existingTransport.hostname, ""));
  const initialXHTTPMode = asText(
    existingTransport.mode,
    transportKind === "xhttp-reality" ? "auto" : "packet-up",
  );
  const [xhttpMode, setXHTTPMode] = useState(initialXHTTPMode);
  const [xhttpUplinkMethod, setXHTTPUplinkMethod] = useState(() => {
    const value = asText(existingTransport.uplink_http_method, initialXHTTPMode === "packet-up" ? "GET" : "POST").toUpperCase();
    return initialXHTTPMode !== "packet-up" && value === "GET" ? "POST" : value;
  });
  const [xhttpUplinkPlacement, setXHTTPUplinkPlacement] = useState(() => {
    const value = asText(existingTransport.uplink_data_placement, initialXHTTPMode === "packet-up" ? "header" : "auto");
    return initialXHTTPMode !== "packet-up" && ["header", "cookie"].includes(value) ? "auto" : value;
  });
  const [realityServerName, setRealityServerName] = useState(
    asText(existingTransport.server_name, ""),
  );
  const [realityCoverMode, setRealityCoverMode] = useState(
    asText(existingTransport.cover_mode, "external"),
  );
  const [realityHandshakeServer, setRealityHandshakeServer] = useState(
    asText(
      existingTransport.handshake_server,
      asText(existingTransport.server_name, ""),
    ),
  );
  const [realityHandshakeServerEdited, setRealityHandshakeServerEdited] =
    useState(false);
  const directInboundKind = [
    "reality",
    "reality-grpc",
    "grpc-tls",
    "xhttp-reality",
    "hysteria2",
  ].includes(transportKind);
  const directInboundProtocol = transportKind === "hysteria2" ? "UDP" : "TCP";
  const directInboundDefaultPort =
    transportKind === "hysteria2"
      ? "443"
      : transportKind === "reality-grpc"
        ? "2444"
        : transportKind === "grpc-tls"
          ? "2445"
          : transportKind === "xhttp-reality"
            ? "2446"
            : "2443";
  const [directListenPort, setDirectListenPort] = useState(
    asText(existingTransport.listen_port, directInboundDefaultPort),
  );
  const ownedWanAddresses = asObjectList(connectionAddress.wan_addresses);
  const selectedWanAddress = hostnameMode === "manual"
    ? ownedWanAddresses.find((row) => asText(row.address, "") === manualHostname.trim())
    : undefined;
  const wanDestinationAddress = selectedWanAddress ? manualHostname.trim() : "";
  const directPortConflict = directInboundKind
    ? asObjectList(config.transports).find((transport) => {
        const otherKind = asText(transport.kind, "");
        const otherProtocol = otherKind === "hysteria2" ? "UDP" : "TCP";
        const otherDestination = asText(
          transport.wan_destination_address,
          "",
        ).trim();
        return (
          asText(transport.id, "") !== asText(existingTransport.id, transportId ?? "") &&
          transport.enabled !== false &&
          ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(
            otherKind,
          ) &&
          otherProtocol === directInboundProtocol &&
          Number(transport.listen_port) === Number(directListenPort) &&
          (!wanDestinationAddress.trim() ||
            !otherDestination ||
            otherDestination === wanDestinationAddress.trim())
        );
      })
    : undefined;
  const savedRealityServerNames = asStringList(existingTransport.server_names)
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const [realitySniInput, setRealitySniInput] = useState(
    savedRealityServerNames.join(", "),
  );
  const [realitySniChecks, setRealitySniChecks] = useState<
    Array<{
      name: string;
      status: "pending" | "confirmed" | "certificate" | "rejected" | "failed";
      detail: string;
    }>
  >(
    savedRealityServerNames.map((name) => ({
      name,
      status: "pending",
      detail: tr("Сохранено · требуется повторная проверка"),
    })),
  );
  const [selectedRealitySnis, setSelectedRealitySnis] = useState<string[]>(
    savedRealityServerNames,
  );
  const [realitySniCheckPerformed, setRealitySniCheckPerformed] = useState(false);
  const existingXrayHysteria = asObject(existingTransport.xray_hysteria);
  const existingXrayMasquerade = asObject(existingXrayHysteria.masquerade);
  const existingXrayQuic = asObject(existingXrayHysteria.quic_params);
  const existingXrayUDPHop = asObject(existingXrayHysteria.udp_hop);
  const [hysteriaMasqueradeType, setHysteriaMasqueradeType] = useState(
    asText(existingXrayMasquerade.type, ""),
  );
  const [hysteriaWebsiteURL, setHysteriaWebsiteURL] = useState(
    asText(existingXrayMasquerade.type, "") === "website"
      ? asText(existingXrayMasquerade.url, "")
      : "",
  );
  const [hysteriaWebsiteBandwidth, setHysteriaWebsiteBandwidth] = useState(() => {
    if (asText(existingXrayMasquerade.type, "") !== "website") return "1";
    const value = Number(existingXrayMasquerade.bandwidth_mbps ?? 1);
    return Number.isFinite(value) && value >= 0.1 && value <= 100
      ? String(value)
      : "1";
  });
  const [hysteriaObfsEnabled, setHysteriaObfsEnabled] = useState(
    existingTransport.obfs_enabled === true,
  );
  const [hysteriaCongestion, setHysteriaCongestion] = useState(
    asText(existingXrayQuic.congestion, ""),
  );
  const [hysteriaUDPHopEnabled, setHysteriaUDPHopEnabled] = useState(
    existingXrayUDPHop.enabled === true,
  );
  const tlsProfiles = asObjectList(config.tls_profiles).map((profile) => {
    const status = asObject(certificateStatus[asText(profile.id, "")]);
    const certificateMetadata = asObject(status.metadata);
    return asStringList(certificateMetadata.dns_names).length
      ? { ...profile, certificate_metadata: certificateMetadata }
      : profile;
  });
  const [cdnDeployments, setCdnDeployments] = useState<JsonObject[]>(
    () =>
      cdnDeploymentsForTransport(existingTransport).map((deployment) => {
        const prepared =
          deployment.origin_protection_mode === "secret-header" &&
          !asText(deployment.origin_header_secret_ref, "")
            ? {
                ...deployment,
                origin_header_value: generateOriginHeaderSecret(),
              }
            : deployment;
        const profile = tlsProfiles.find(
          (item) =>
            asText(item.id, "") === asText(prepared.tls_profile_id, ""),
        );
        return cdnDeploymentForTLSInitialization(prepared, profile);
      }),
  );
  function updateCdnDeployment(index: number, patch: JsonObject) {
    setCdnDeployments((current) =>
      current.map((item, itemIndex) =>
        itemIndex === index ? { ...item, ...patch } : item,
      ),
    );
  }

  function syncRecommendedFieldState(
    name: string,
    value: string,
    checked?: boolean,
  ) {
    if (name === "mode") setXHTTPMode(value);
    if (name === "uplink_http_method") setXHTTPUplinkMethod(value);
    if (name === "uplink_data_placement") setXHTTPUplinkPlacement(value);
    if (name === "hysteria_congestion") setHysteriaCongestion(value);
    if (name === "hysteria_masquerade_type") setHysteriaMasqueradeType(value);
    if (name === "obfs_enabled") setHysteriaObfsEnabled(checked === true);
    if (name === "hysteria_udp_hop_enabled") {
      setHysteriaUDPHopEnabled(checked === true);
    }
  }

  function setRecommendedField(
    control: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement,
    value: string | boolean,
  ) {
    if (typeof value === "boolean" && control instanceof HTMLInputElement) {
      control.checked = value;
      syncRecommendedFieldState(control.name, control.value, value);
    } else if (typeof value === "string") {
      control.value = value;
      syncRecommendedFieldState(
        control.name,
        value,
        control instanceof HTMLInputElement ? control.checked : undefined,
      );
    }
    control.dispatchEvent(new Event("input", { bubbles: true }));
    control.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function applyTransportParameterDefaults() {
    const form = formRef.current;
    if (!form || !transportRecommendation) return;
    const snapshot: Record<string, { value: string; checked?: boolean }> = {};
    for (const field of transportRecommendation.fields) {
      const control = form.elements.namedItem(field.name);
      if (
        !(control instanceof HTMLInputElement) &&
        !(control instanceof HTMLSelectElement) &&
        !(control instanceof HTMLTextAreaElement)
      ) {
        continue;
      }
      snapshot[field.name] = {
        value: control.value,
        ...(control instanceof HTMLInputElement &&
        ["checkbox", "radio"].includes(control.type)
          ? { checked: control.checked }
          : {}),
      };
      setRecommendedField(control, field.value);
    }
    transportParameterSnapshotRef.current = snapshot;
  }

  function restoreTransportParameters() {
    const form = formRef.current;
    const snapshot = transportParameterSnapshotRef.current;
    if (!form || !snapshot) return;
    for (const [name, previous] of Object.entries(snapshot)) {
      const control = form.elements.namedItem(name);
      if (
        !(control instanceof HTMLInputElement) &&
        !(control instanceof HTMLSelectElement) &&
        !(control instanceof HTMLTextAreaElement)
      ) {
        continue;
      }
      setRecommendedField(
        control,
        typeof previous.checked === "boolean"
          ? previous.checked
          : previous.value,
      );
    }
    transportParameterSnapshotRef.current = null;
  }

  function cloneCdnDeployment(index: number, duplicate = true) {
    setCdnDeployments((current) => {
      const source = current[index] ?? current[0] ?? {};
      const usedIds = new Set(current.map((item) => asText(item.id, "")));
      let sequence = current.length + 1;
      let id = `cdn-${sequence}`;
      while (usedIds.has(id)) {
        sequence += 1;
        id = `cdn-${sequence}`;
      }
      const clone = {
        ...source,
        id,
        display_name: duplicate
          ? tr("{value1} · копия", { value1: asText(source.display_name, "CDN") })
          : `CDN ${sequence}`,
        hostname: "",
        tls_server_name: "",
        enabled: false,
        origin_header_secret_ref: undefined,
        origin_header_value:
          asText(source.origin_protection_mode, "") === "secret-header"
            ? generateOriginHeaderSecret()
            : undefined,
      };
      return [...current.slice(0, index + 1), clone, ...current.slice(index + 1)];
    });
  }
  async function showHttpPath() {
    if (!transportId) return;
    setHttpPathBusy(true);
    setHttpPathMessage("");
    try {
      const result = await revealTransportHttpPath<JsonObject>(transportId);
      setRevealedHttpPath(asText(result.path, ""));
    } catch (error) {
      setHttpPathMessage(errorMessage(error));
    } finally {
      setHttpPathBusy(false);
    }
  }

  async function copyHttpPath() {
    if (!revealedHttpPath) return;
    try {
      await navigator.clipboard.writeText(revealedHttpPath);
      setHttpPathMessage(tr("HTTP-путь скопирован."));
    } catch {
      setHttpPathMessage(tr("Браузер запретил копирование. Выделите путь вручную."));
    }
  }

  function invalidateRealityProbe() {
    setRealityProbeTone("idle");
    setRealityProbeSignature("");
    setRealityProbeResult("");
    setRealityProbeEndpoints([]);
    setRealityProbeWildcards([]);
    setRealitySniCheckPerformed(false);
  }

  function realityProbeFacts(probe: JsonObject): JsonObject[] {
    const endpoints = asObjectList(probe.endpoint_results);
    if (endpoints.length) return endpoints;
    return asStringList(probe.addresses).map((address) => ({
      address,
      ok: true,
      tls_version: asText(probe.tls_version, ""),
      alpn: asText(probe.alpn, ""),
    }));
  }

  function realityProbeProblem(probe: JsonObject): string {
    const endpoints = realityProbeFacts(probe);
    const failed = endpoints.filter((item) => item.ok !== true);
    const incompatible = failed.filter(
      (item) => asText(item.error_code, "") !== "tls_probe_handshake_failed",
    );
    if (incompatible.length) {
      return tr("Не все доступные адреса target принимают SNI: {value1}.", { value1: incompatible.map((item) => asText(item.address, tr("неизвестный IP"))).join(", ") });
    }
    const successful = endpoints.filter((item) => item.ok === true);
    const legacyTls = successful.filter(
      (item) => asText(item.tls_version, "") !== "TLSv1.3",
    );
    if (legacyTls.length) {
      return tr("REALITY требует TLS 1.3; несовместимые адреса: {value1}.", { value1: legacyTls.map((item) => asText(item.address, tr("неизвестный IP"))).join(", ") });
    }
    if (transportKind === "reality-grpc") {
      const withoutH2 = successful.filter((item) => asText(item.alpn, "") !== "h2");
      if (withoutH2.length) {
        return tr("Для gRPC нужен HTTP/2 (ALPN h2); несовместимые адреса: {value1}.", { value1: withoutH2.map((item) => `${asText(item.address, tr("неизвестный IP"))} — ${asText(item.alpn, tr("ALPN не согласован"))}`).join(", ") });
      }
    }
    return "";
  }

  function currentRealityProbeSignature() {
    const form = formRef.current;
    if (!form) return "";
    const serverNameInput = form.elements.namedItem("server_name");
    const handshakeServerInput = form.elements.namedItem("handshake_server");
    const handshakePortInput = form.elements.namedItem("handshake_port");
    const serverName =
      serverNameInput instanceof HTMLInputElement
        ? serverNameInput.value.trim().toLowerCase()
        : "";
    const handshakeServer =
      handshakeServerInput instanceof HTMLInputElement
        ? handshakeServerInput.value.trim().toLowerCase()
        : "";
    const handshakePort =
      handshakePortInput instanceof HTMLInputElement
        ? Number(handshakePortInput.value)
        : 443;
    const names = realitySniInput.split(/[\n,]/).map((value) => value.trim().toLowerCase()).filter(Boolean).sort();
    return `${transportKind}|${serverName}|${handshakeServer}|${handshakePort}|${names.join(",")}`;
  }

  async function checkRealityTarget(): Promise<boolean> {
    const form = formRef.current;
    if (!form) return false;
    const serverNameInput = form.elements.namedItem("server_name");
    const handshakeServerInput = form.elements.namedItem("handshake_server");
    const handshakePortInput = form.elements.namedItem("handshake_port");
    const serverName =
      serverNameInput instanceof HTMLInputElement
        ? serverNameInput.value.trim()
        : "";
    const handshakeServer =
      handshakeServerInput instanceof HTMLInputElement
        ? handshakeServerInput.value.trim()
        : "";
    const handshakePort =
      handshakePortInput instanceof HTMLInputElement
        ? Number(handshakePortInput.value)
        : 443;
    if (!serverName || !handshakeServer) {
      setRealityProbeResult(tr("Укажите SNI и сервер рукопожатия."));
      setRealityProbeTone("error");
      setRealityProbeSignature("");
      return false;
    }
    const manualNames = realitySniInput
      .split(/[\n,]/)
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean);
    const wildcardNames = manualNames.filter((value) => value.includes("*"));
    if (wildcardNames.length) {
      setRealityProbeResult(
        tr("Wildcard SAN нельзя сохранять напрямую: {value1}. Укажите конкретное имя хоста и проверьте его отдельно.", { value1: wildcardNames.join(", ") }),
      );
      setRealityProbeTone("error");
      setRealityProbeSignature(currentRealityProbeSignature());
      setRealityProbeEndpoints([]);
      setRealityProbeWildcards(wildcardNames);
      setRealitySniCheckPerformed(false);
      return false;
    }
    setRealityProbeBusy(true);
    setRealityProbeResult("");
    setRealityProbeTone("idle");
    setRealityProbeEndpoints([]);
    setRealityProbeWildcards([]);
    setRealitySniCheckPerformed(false);
    try {
      const probe = await probeTlsEndpoint<JsonObject>(
        handshakeServer,
        handshakePort,
        serverName,
        true,
      );
      const endpoints = realityProbeFacts(probe);
      setRealityProbeEndpoints(endpoints);
      const certificateNames = asStringList(probe.certificate_dns_names);
      const wildcardNames = certificateNames.filter((name) => name.includes("*"));
      setRealityProbeWildcards(wildcardNames);
      const mainProblem = realityProbeProblem(probe);
      if (mainProblem) {
        setRealityProbeTone("error");
        setRealityProbeSignature(currentRealityProbeSignature());
        setRealityProbeResult(mainProblem);
        return false;
      }
      const candidates = [...new Set([
        ...manualNames,
        ...certificateNames
          .map((value) => value.trim().toLowerCase())
          .filter((value) => value && !value.includes("*")),
      ])].filter((value) => value !== serverName.toLowerCase());
      const checks = await Promise.all(
        candidates.map(async (candidate) => {
          try {
            const candidateProbe = await probeTlsEndpoint<JsonObject>(
              handshakeServer,
              handshakePort,
              candidate,
              true,
            );
            const candidateProblem = realityProbeProblem(candidateProbe);
            if (candidateProblem) {
              return {
                name: candidate,
                status: "rejected" as const,
                detail: candidateProblem,
              };
            }
            return {
              name: candidate,
              status: "confirmed" as const,
              detail: `${asText(candidateProbe.tls_version, "TLS")} · ALPN ${asText(candidateProbe.alpn, tr("не согласован"))}`,
            };
          } catch (error) {
            const code = error instanceof GatewayApiError ? error.code : "";
            if (code === "tls_probe_certificate_mismatch") {
              return {
                name: candidate,
                status: "certificate" as const,
                detail: tr("Сертификат не подходит"),
              };
            }
            if (code === "tls_probe_sni_rejected" || code === "tls_probe_handshake_failed") {
              return {
                name: candidate,
                status: "rejected" as const,
                detail: tr("Target отклонил SNI"),
              };
            }
            return {
              name: candidate,
              status: "failed" as const,
              detail: errorMessage(error),
            };
          }
        }),
      );
      const confirmed = new Set(
        checks.filter((item) => item.status === "confirmed").map((item) => item.name),
      );
      setRealitySniChecks(checks);
      setSelectedRealitySnis((current) =>
        current.filter((name) => confirmed.has(name.toLowerCase())),
      );
      setRealitySniCheckPerformed(true);
      const successfulEndpoints = endpoints.filter((item) => item.ok === true);
      const unavailableEndpoints = endpoints.filter(
        (item) =>
          item.ok !== true &&
          asText(item.error_code, "") === "tls_probe_handshake_failed",
      );
      const nonH2 = successfulEndpoints.filter((item) => asText(item.alpn, "") !== "h2");
      const warnings: string[] = [];
      if (unavailableEndpoints.length) {
        warnings.push(
          tr("Часть DNS-адресов недоступна из контейнера ({value1}); успешный TLS через доступные адреса подтверждён.", { value1: unavailableEndpoints.map((item) => asText(item.address, tr("неизвестный IP"))).join(", ") }),
        );
      }
      if (transportKind === "reality" && nonH2.length > 0) {
        warnings.push(tr("Не все доступные адреса согласуют HTTP/2. Для Vision это допустимо; для gRPC такой target использовать нельзя."));
      }
      const warning = warnings.length > 0;
      setRealityProbeTone(warning ? "warning" : "success");
      setRealityProbeSignature(currentRealityProbeSignature());
      setRealityProbeResult(
        warning
          ? tr("SNI и target совместимы. {value1}", { value1: warnings.join(" ") })
          : tr("SNI и target совместимы с {value1}. Успешно проверено адресов: {value2}. Сертификат: {value3}.", { value1: transportKind === "reality-grpc" ? "gRPC + Reality" : transportKind === "xhttp-reality" ? "XHTTP + Reality" : "VLESS Reality", value2: successfulEndpoints.length, value3: expiryText(probe.certificate_expires_at) }),
      );
      return true;
    } catch (error) {
      setRealityProbeResult(prefixedErrorMessage(error));
      setRealityProbeTone("error");
      setRealityProbeSignature(currentRealityProbeSignature());
      setRealityProbeEndpoints([]);
      return false;
    } finally {
      setRealityProbeBusy(false);
    }
  }

  async function checkCdnDeployment(deploymentIndex: number) {
    const deployment = cdnDeployments[deploymentIndex] ?? {};
    const deploymentId = asText(
      deployment.id,
      `cdn-${deploymentIndex + 1}`,
    );
    const publicHostname = asText(deployment.hostname, "").trim();
    const publicPort = Number(deployment.listen_port ?? 443);
    const publicServerName =
      asText(deployment.tls_server_name, "").trim() || publicHostname;
    const originHostname = asText(deployment.origin_server_name, "").trim();
    const originPort = Number(
      deployment.origin_port ??
        existingTransport.origin_port ??
        existingTransport.listen_port ??
        legacyCloudflarePort,
    );
    if (!publicHostname || !originHostname) {
      setCdnProbeResults((current) => ({
        ...current,
        [deploymentId]: tr("Укажите домен раздачи CDN и DNS-имя origin."),
      }));
      return;
    }
    setCdnProbeBusyId(deploymentId);
    setCdnProbeResults((current) => ({ ...current, [deploymentId]: "" }));
    try {
      const publicProbe = await probeTlsEndpoint<JsonObject>(
        publicHostname,
        publicPort,
        publicServerName,
      );
      const originProbe = await probeTlsEndpoint<JsonObject>(
        originHostname,
        originPort,
        originHostname,
      );
      setCdnProbeResults((current) => ({
        ...current,
        [deploymentId]:
          tr("Домен CDN: {value1} · {value2} · {value3} | ", { value1: asStringList(publicProbe.addresses).join(", "), value2: asText(publicProbe.tls_version, "TLS"), value3: expiryText(publicProbe.certificate_expires_at) }) +
          `origin: ${asStringList(originProbe.addresses).join(", ")} · ${asText(originProbe.tls_version, "TLS")} · ${expiryText(originProbe.certificate_expires_at)} ` +
          "Proxy/CDN, Full strict и правила origin проверяются в аккаунте провайдера.",
      }));
    } catch (error) {
      setCdnProbeResults((current) => ({
        ...current,
        [deploymentId]: prefixedErrorMessage(error),
      }));
    } finally {
      setCdnProbeBusyId("");
    }
  }
  function selectCdnDeploymentTlsProfile(index: number, profileId: string) {
    const profile = tlsProfiles.find(
      (item) => asText(item.id, "") === profileId,
    );
    setCdnDeployments((current) =>
      current.map((deployment, deploymentIndex) =>
        deploymentIndex === index
          ? cdnDeploymentAfterTLSProfileChange(
              deployment,
              profileId,
              profile,
            )
          : deployment,
      ),
    );
  }
  const tlsManagedKind = [
    "ws",
    "grpc",
    "httpupgrade",
    "xhttp",
    "grpc-tls",
    "hysteria2",
  ].includes(transportKind);
  const cdnTransportKind = [
    "ws",
    "grpc",
    "httpupgrade",
    "xhttp",
  ].includes(transportKind);
  const realityKind = ["reality", "reality-grpc", "xhttp-reality"].includes(
    transportKind,
  );
  const realityAPICoverProfiles = realityKind
    ? tlsProfiles.filter((profile) =>
        certificateCoversHostname(profile, realityServerName),
      )
    : [];
  const realityAPICoverAvailable = realityAPICoverProfiles.length > 0;
  const effectiveRealityCoverMode =
    realityCoverMode === "api" && realityAPICoverAvailable ? "api" : "external";
  const sharedTlsManagedKind =
    (tlsManagedKind && !cdnTransportKind) ||
    (realityKind && effectiveRealityCoverMode === "api");
  const xhttpKind = ["xhttp", "xhttp-reality"].includes(transportKind);
  const tcpStabilityKind = realityKind || ["grpc", "grpc-tls"].includes(transportKind);
  const legacyCloudflarePort = Number(
    asObject(config.ingress).public_listen_port ?? 443,
  );
  const persistedDirectTlsServerName = asText(
    existingTransport.tls_server_name,
    asText(existingTransport.hostname, ""),
  );
  const savedTlsProfileId = asText(existingTransport.tls_profile_id, "");
  const initialTlsProfileId = savedTlsProfileId ||
    (["hysteria2", "grpc-tls"].includes(transportKind)
      ? tlsProfileIdForHostname(tlsProfiles, persistedDirectTlsServerName, "")
      : "");
  const [tlsProfileChoice, setTlsProfileChoice] = useState(
    initialTlsProfileId,
  );
  const selectedTlsProfile =
    tlsProfiles.find(
      (profile) => asText(profile.id, "") === tlsProfileChoice,
    ) ?? {};
  const [directTlsServerName, setDirectTlsServerName] = useState(() =>
    hostnameForTLSProfileInitialization(
      selectedTlsProfile,
      persistedDirectTlsServerName,
      ["hysteria2", "grpc-tls"].includes(transportKind),
    ),
  );
  const directTlsHostnameCandidates = tlsConcreteHostnames(selectedTlsProfile);
  function selectTransportTlsProfile(profileId: string) {
    setTlsProfileChoice(profileId);
    if (!["hysteria2", "grpc-tls"].includes(transportKind)) return;
    const profile =
      tlsProfiles.find((item) => asText(item.id, "") === profileId) ?? {};
    setDirectTlsServerName((current) =>
      hostnameAfterTLSProfileChange(profile, current),
    );
  }
  const existingSubscription =
    asObjectList(config.subscriptions).find(
      (item) => asText(item.id, "") === workingSubscriptionId,
    ) ?? persistedSubscription;
  const configuredSubscriptionReserves = asObjectList(
    config.subscription_reserves,
  ).filter((item) => item.enabled !== false);
  const editingSubscription = Boolean(
    kind === "subscription" && workingSubscriptionId,
  );
  const [refreshViaDirect, setRefreshViaDirect] = useState(
    existingSubscription.refresh_via_direct !== false,
  );
  const [refreshViaVpn, setRefreshViaVpn] = useState(
    existingSubscription.refresh_via_vpn !== false,
  );
  const [refreshViaActiveOutbounds, setRefreshViaActiveOutbounds] = useState(
    existingSubscription.refresh_via_active_outbounds !== false,
  );
  const [refreshViaIndependentReserves, setRefreshViaIndependentReserves] =
    useState(existingSubscription.refresh_via_independent_reserves === true);
  const configuredRefreshMinutes = Math.max(
    1,
    Number(
      existingSubscription.refresh_minutes ??
        Number(existingSubscription.refresh_hours ?? 6) * 60,
    ),
  );
  const defaultRefreshUnit =
    configuredRefreshMinutes % 60 === 0 ? "hours" : "minutes";
  const defaultRefreshValue =
    defaultRefreshUnit === "hours"
      ? configuredRefreshMinutes / 60
      : configuredRefreshMinutes;
  const existingSecretRefs = asObject(existingTransport.secret_refs);
  const selectedTlsProfileComplete = Boolean(
    asText(selectedTlsProfile.certificate_secret_ref, "") &&
      asText(selectedTlsProfile.private_key_secret_ref, ""),
  );

  function subscriptionItemFromForm(data: FormData): JsonObject {
    const displayName = String(data.get("display_name") ?? "").trim();
    const id =
      workingSubscriptionId ||
      entityIdFromName(
        displayName,
        new Set(
          asObjectList(config.subscriptions).map((item) => asText(item.id, "")),
        ),
        "provider",
      );
    if (!id || !/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/.test(id)) {
      throw new Error(
        tr("Идентификатор должен состоять из строчных латинских букв, цифр, точки, дефиса или подчёркивания."),
      );
    }
    const url = String(data.get("url") ?? "").trim();
    if (!workingSubscriptionId && !url) {
      throw new Error(tr("Введите HTTPS URL подписки."));
    }
    if (url && !url.startsWith("https://")) {
      throw new Error(tr("Подписка должна использовать HTTPS."));
    }
    const intervalValue = Number(data.get("refresh_value") ?? 6);
    const intervalUnit = String(data.get("refresh_unit") ?? "hours");
    const refreshMinutes =
      intervalUnit === "minutes" ? intervalValue : intervalValue * 60;
    if (
      !Number.isInteger(refreshMinutes) ||
      refreshMinutes < 1 ||
      refreshMinutes > 7 * 24 * 60
    ) {
      throw new Error(tr("Интервал проверки должен быть от 1 минуты до 7 суток."));
    }
    const vpnRouteReady =
      refreshViaVpn &&
      (refreshViaActiveOutbounds || refreshViaIndependentReserves);
    if (!refreshViaDirect && !vpnRouteReady) {
      throw new Error(
        tr("Оставьте хотя бы один путь обновления: прямой WAN или VPN-резерв."),
      );
    }
    if (
      !refreshViaDirect &&
      refreshViaVpn &&
      !refreshViaActiveOutbounds &&
      refreshViaIndependentReserves &&
      configuredSubscriptionReserves.length === 0
    ) {
      throw new Error(
        tr("Добавьте хотя бы один независимый резервный VLESS или включите рабочие VPN-каналы."),
      );
    }
    return {
      ...existingSubscription,
      ...persistedSubscription,
      id,
      display_name: displayName,
      ...(url ? { url } : {}),
      refresh_hours: undefined,
      refresh_minutes: refreshMinutes,
      // Location selection belongs to routing lists.  Keeping subscription
      // filters empty makes the complete provider catalogue available to
      // every independently configured list.
      allowed_countries: [],
      allowed_locations: [],
      enabled: data.get("enabled") === "on",
      refresh_via_direct: refreshViaDirect,
      refresh_via_vpn: refreshViaVpn,
      refresh_via_active_outbounds: refreshViaActiveOutbounds,
      refresh_via_independent_reserves: refreshViaIndependentReserves,
    };
  }

  async function persistAndDiscover(data: FormData) {
    const item = subscriptionItemFromForm(data);
    const id = asText(item.id, "");
    const savedItem = workingSubscriptionId
      ? await updateCollectionItem<JsonObject>(
          "subscriptions",
          workingSubscriptionId,
          item,
        )
      : await createCollectionItem<JsonObject>("subscriptions", item);
    const persisted = asObject(savedItem.item);
    const safeItem = { ...item };
    delete safeItem.url;
    setWorkingSubscriptionId(id);
    setPersistedSubscription({ ...safeItem, ...persisted, id });
    await onSaved();
    setDiscoveryMessage(tr("Подписка сохранена. Загружаю страны и города…"));
    const refreshed = await refreshSubscription<JsonObject>(id);
    const response = await getSubscriptionNodes<JsonObject>(id);
    const rows = asObjectList(response.nodes);
    const provider = asObject(response.provider);
    setSubscriptionNodes(rows);
    setSubscriptionProvider(provider);
    setDiscoveryReady(true);
    const refreshedNodeCount =
      typeof refreshed.nodes === "number" ? refreshed.nodes : rows.length;
    setDiscoveryMessage(
      tr("{value1} узл. загружено. Расположения доступны в маршрутных листах.", { value1: refreshedNodeCount }),
    );
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const submittedForm = event.currentTarget;
    if (kind === "transport" && directPortConflict) {
      setSaveError(
        tr("Этот WAN IP и {value1}-порт уже использует «{value2}».", { value1: directInboundProtocol, value2: transportKindLabel(directPortConflict.kind) }),
      );
      return;
    }
    if (kind === "transport" && realityKind && effectiveRealityCoverMode !== "api") {
      const signature = currentRealityProbeSignature();
      const savedSignature = `${transportKind}|${asText(existingTransport.server_name, "").trim().toLowerCase()}|${asText(existingTransport.handshake_server, "").trim().toLowerCase()}|${Number(existingTransport.handshake_port ?? 443)}|${[...savedRealityServerNames].sort().join(",")}`;
      const savedTargetUnchanged = existingTransport.enabled === true &&
        existingTransport.kind === transportKind && signature === savedSignature;
      const currentProbeAccepted =
        signature === realityProbeSignature &&
        ["success", "warning"].includes(realityProbeTone);
      if (!savedTargetUnchanged && !currentProbeAccepted) {
        const compatible = await checkRealityTarget();
        if (!compatible) {
          setSaveError(
            tr("Сохранение остановлено: исправьте SNI или target и повторите проверку."),
          );
          return;
        }
      }
    }
    setBusy(true);
    setSaveError("");
    const data = new FormData(submittedForm);
    try {
      if (kind === "subscription") {
        if (!discoveryReady) {
          await persistAndDiscover(data);
        } else {
          const item = subscriptionItemFromForm(data);
          await updateCollectionItem(
            "subscriptions",
            workingSubscriptionId,
            item,
          );
          await onSaved();
          setSaved(true);
        }
      } else {
        const id = transportId ?? "websocket";
        let tlsProfileId = "";
        if (sharedTlsManagedKind) {
          tlsProfileId = tlsProfileChoice;
          if (!tlsProfileId) {
            throw new Error(tr("Выберите TLS-профиль в форме транспорта."));
          }
        }
        const parseHttpHeaders = (fieldName: string, label: string): Record<string, string> => {
          const parsed: Record<string, string> = {};
          for (const rawLine of String(data.get(fieldName) ?? "").split("\n")) {
            const line = rawLine.trim();
            if (!line) continue;
            const separator = line.indexOf(":");
            if (separator <= 0) {
              throw new Error(tr("Каждый {value1}-заголовок задаётся как «Имя: значение».", { value1: label }));
            }
            const name = line.slice(0, separator).trim();
            const value = line.slice(separator + 1).trim();
            if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || !value) {
              throw new Error(tr("Некорректный {value1}-заголовок: {value2}", { value1: label, value2: line }));
            }
            parsed[name] = value;
          }
          return parsed;
        };
        const xhttpHeaders: Record<string, string> = {};
        const clientHttpHeaders = ["ws", "httpupgrade"].includes(transportKind)
          ? parseHttpHeaders("client_http_headers", "HTTP")
          : {};
        let xhttpDownloadSettings: JsonObject | undefined;
        if (xhttpKind) {
          Object.assign(xhttpHeaders, parseHttpHeaders("xhttp_headers", "XHTTP"));
          const rawDownloadSettings = String(
            data.get("download_settings_json") ?? "",
          ).trim();
          if (rawDownloadSettings) {
            const parsed = JSON.parse(rawDownloadSettings) as unknown;
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
              throw new Error(tr("downloadSettings должен быть JSON-объектом Xray StreamConfig."));
            }
            xhttpDownloadSettings = parsed as JsonObject;
          }
        }
        const submittedXHTTPMode = String(data.get("mode") ?? xhttpMode);
        const submittedXHTTPUplinkMethod = String(
          data.get("uplink_http_method") ?? xhttpUplinkMethod,
        ).toUpperCase();
        const submittedXHTTPUplinkPlacement = String(
          data.get("uplink_data_placement") ?? xhttpUplinkPlacement,
        );
        const submittedHysteriaMasqueradeType = String(
          data.get("hysteria_masquerade_type") ?? hysteriaMasqueradeType,
        );
        const submittedHysteriaCongestion = String(
          data.get("hysteria_congestion") ?? hysteriaCongestion,
        );
        const submittedHysteriaUDPHopEnabled =
          data.get("hysteria_udp_hop_enabled") === "on";
        let xrayHysteria: JsonObject | undefined;
        if (transportKind === "hysteria2") {
          const masqueradeHeaders: Record<string, string> = {};
          if (submittedHysteriaMasqueradeType === "string") {
            for (const rawLine of String(
              data.get("hysteria_masquerade_headers") ?? "",
            ).split("\n")) {
              const line = rawLine.trim();
              if (!line) continue;
              const separator = line.indexOf(":");
              if (separator <= 0) {
                throw new Error(
                  tr("Каждый заголовок ответа Hysteria задаётся как «Имя: значение»."),
                );
              }
              const name = line.slice(0, separator).trim();
              const value = line.slice(separator + 1).trim();
              if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || !value) {
                throw new Error(tr("Некорректный заголовок Hysteria: {value1}", { value1: line }));
              }
              masqueradeHeaders[name] = value;
            }
          }
          const optionalInteger = (name: string): number => {
            const raw = String(data.get(name) ?? "").trim();
            return raw ? Number(raw) : 0;
          };
          const websiteBandwidth = Number(
            String(data.get("hysteria_masquerade_bandwidth_mbps") ?? "").trim(),
          );
          if (
            submittedHysteriaMasqueradeType === "website" &&
            (!Number.isFinite(websiteBandwidth) ||
              websiteBandwidth < 0.1 ||
              websiteBandwidth > 100)
          ) {
            throw new Error(tr("Лимит сайта должен быть числом от 0.1 до 100 Мбит/с."));
          }
          xrayHysteria = {
            udp_idle_timeout: Number(data.get("hysteria_udp_idle_timeout") ?? 60),
            ...(submittedHysteriaUDPHopEnabled
              ? {
                  udp_hop: {
                    enabled: true,
                    port_start: Number(data.get("hysteria_udp_hop_port_start")),
                    port_end: Number(data.get("hysteria_udp_hop_port_end")),
                    interval_min: Number(data.get("hysteria_udp_hop_interval_min")),
                    interval_max: Number(data.get("hysteria_udp_hop_interval_max")),
                    excluded_ports: String(data.get("hysteria_udp_hop_excluded_ports") ?? "").trim(),
                  },
                }
              : {}),
            masquerade:
              submittedHysteriaMasqueradeType === "string"
                ? {
                    type: "string",
                    content: String(data.get("hysteria_masquerade_content") ?? ""),
                    status_code: Number(
                      data.get("hysteria_masquerade_status_code") ?? 200,
                    ),
                    headers: masqueradeHeaders,
                  }
                  : submittedHysteriaMasqueradeType === "api"
                    ? { type: "api" }
                  : submittedHysteriaMasqueradeType === "proxy" ||
                    submittedHysteriaMasqueradeType === "website"
                    ? {
                        type: submittedHysteriaMasqueradeType,
                        url: String(data.get("hysteria_masquerade_url") ?? "").trim(),
                        ...(submittedHysteriaMasqueradeType === "website"
                          ? { bandwidth_mbps: websiteBandwidth }
                          : {}),
                        rewrite_host:
                          data.get("hysteria_masquerade_rewrite_host") === "on",
                        ...(submittedHysteriaMasqueradeType === "proxy" &&
                        data.get("hysteria_masquerade_x_forwarded") === "on"
                          ? { x_forwarded: true }
                          : {}),
                    }
                  : { type: "" },
            quic_params: {
              congestion: submittedHysteriaCongestion,
              brutal_up_mbps: optionalInteger("hysteria_brutal_up_mbps"),
              brutal_down_mbps: optionalInteger("hysteria_brutal_down_mbps"),
              init_stream_receive_window: optionalInteger(
                "hysteria_init_stream_receive_window",
              ),
              max_stream_receive_window: optionalInteger(
                "hysteria_max_stream_receive_window",
              ),
              init_connection_receive_window: optionalInteger(
                "hysteria_init_connection_receive_window",
              ),
              max_connection_receive_window: optionalInteger(
                "hysteria_max_connection_receive_window",
              ),
              max_idle_timeout: optionalInteger("hysteria_max_idle_timeout"),
              keep_alive_period: optionalInteger("hysteria_keep_alive_period"),
              max_incoming_streams: optionalInteger(
                "hysteria_max_incoming_streams",
              ),
              disable_path_mtu_discovery:
                data.get("hysteria_disable_path_mtu_discovery") === "on",
              ...(submittedHysteriaCongestion === "brutal" &&
              data.get("hysteria_brutal_disable_loss_compensation") === "on"
                ? { brutal_disable_loss_compensation: true }
                : {}),
              ...(data.get("hysteria_disable_gso") === "on"
                ? { disable_gso: true }
                : {}),
              ...(data.get("hysteria_disable_stateless_reset") === "on"
                ? { disable_stateless_reset: true }
                : {}),
            },
          };
        }
        const normalizedCdnDeployments = cdnTransportKind
          ? cdnDeployments.map((deployment, deploymentIndex) => ({
              id: asText(deployment.id, `cdn-${deploymentIndex + 1}`)
                .trim()
                .toLowerCase(),
              display_name: asText(
                deployment.display_name,
                `CDN ${deploymentIndex + 1}`,
              ).trim(),
              enabled: deployment.enabled !== false,
              cdn_provider: asText(deployment.cdn_provider, "cloudflare"),
              hostname: asText(deployment.hostname, "").trim(),
              listen_port: Number(deployment.listen_port ?? 443),
              tls_server_name: asText(
                deployment.tls_server_name,
                asText(deployment.hostname, ""),
              ).trim(),
              http_host: asText(deployment.http_host, "").trim(),
              grpc_authority: asText(deployment.grpc_authority, "").trim(),
              origin_port: Number(
                deployment.origin_port ??
                  existingTransport.origin_port ??
                  existingTransport.listen_port ??
                  legacyCloudflarePort,
              ),
              origin_server_name: asText(
                deployment.origin_server_name,
                asText(existingTransport.origin_server_name, ""),
              ).trim(),
              tls_profile_id: asText(
                deployment.tls_profile_id,
                asText(existingTransport.tls_profile_id, ""),
              ),
              origin_allowed_cidrs: asStringList(
                deployment.origin_allowed_cidrs,
              ),
              origin_protection_mode: asText(
                deployment.origin_protection_mode,
                asText(deployment.cdn_provider, "cloudflare") === "cloudflare"
                  ? "auto-cidr"
                  : "secret-header",
              ),
              origin_header_name: asText(
                deployment.origin_header_name,
                "X-SB-Origin",
              ),
              origin_header_secret_ref: asText(
                deployment.origin_header_secret_ref,
                "",
              ) || undefined,
              origin_header_value: asText(
                deployment.origin_header_value,
                "",
              ) || undefined,
            }))
          : [];
        const primaryCdnDeployment =
          normalizedCdnDeployments.find((deployment) => deployment.enabled) ??
          normalizedCdnDeployments[0];
        const backend =
          id === "grpc"
            ? "127.0.0.1:11002"
            : id === "httpupgrade"
              ? "127.0.0.1:11003"
              : id === "xhttp"
                ? "127.0.0.1:11004"
              : ["direct-reality", "grpc-reality", "grpc-tls-pin", "xhttp-reality", "hysteria2"].includes(id)
                ? undefined
                : "127.0.0.1:11001";
        await updateCollectionItem("transports", id, {
          ...existingTransport,
          wan_destination_address: undefined,
          id,
          kind: transportKind,
          cdn_deployments: cdnTransportKind
            ? normalizedCdnDeployments
            : undefined,
          cdn_provider: cdnTransportKind
            ? asText(primaryCdnDeployment?.cdn_provider, "cloudflare")
            : undefined,
          tls_profile_id: tlsManagedKind
            ? cdnTransportKind
              ? asText(primaryCdnDeployment?.tls_profile_id, "")
              : tlsProfileId
            : realityKind && effectiveRealityCoverMode === "api"
              ? tlsProfileId
              : undefined,
          enabled: data.get("enabled") === "on",
          recommended: existingTransport.recommended === true,
          hostname: cdnTransportKind
            ? asText(primaryCdnDeployment?.hostname, "")
            : directInboundKind ? manualHostname : String(data.get("hostname") ?? ""),
          hostname_mode: directInboundKind ? hostnameMode : undefined,
          backend,
          listen_port:
            cdnTransportKind
              ? Number(primaryCdnDeployment?.listen_port ?? legacyCloudflarePort)
              : ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(transportKind)
              ? Number(
                  data.get("listen_port") ??
                    (transportKind === "reality" ? 2443 : transportKind === "reality-grpc" ? 2444 : transportKind === "grpc-tls" ? 2445 : transportKind === "xhttp-reality" ? 2446 : 443),
                )
                : undefined,
          origin_port: cdnTransportKind
            ? Number(primaryCdnDeployment?.origin_port ?? legacyCloudflarePort)
            : undefined,
          origin_server_name: cdnTransportKind
            ? asText(primaryCdnDeployment?.origin_server_name, "")
            : undefined,
          origin_allowed_cidrs:
            cdnTransportKind
              ? normalizedCdnDeployments.flatMap((deployment) =>
                  asStringList(deployment.origin_allowed_cidrs),
                )
              : [],
          handshake_server:
            realityKind
              ? String(data.get("handshake_server") ?? "")
              : undefined,
          handshake_port:
            realityKind
              ? Number(data.get("handshake_port") ?? 443)
              : undefined,
          server_name:
            realityKind
              ? String(data.get("server_name") ?? "")
              : undefined,
          cover_mode: realityKind ? effectiveRealityCoverMode : undefined,
          fingerprint:
            undefined,
          up_mbps:
            undefined,
          down_mbps:
            undefined,
          ignore_client_bandwidth:
            undefined,
          xray_hysteria:
            transportKind === "hysteria2" ? xrayHysteria : undefined,
          obfs_enabled:
            transportKind === "hysteria2"
              ? data.get("obfs_enabled") === "on"
              : undefined,
          tls_server_name:
            ["hysteria2", "grpc-tls"].includes(transportKind)
              ? String(data.get("tls_server_name") ?? "").trim()
              : undefined,
          tls_pin_certificate:
            transportKind === "hysteria2"
              ? data.get("tls_pin_certificate") === "on"
              : undefined,
          tcp_keep_alive_enabled: tcpStabilityKind
            ? data.get("tcp_keep_alive_enabled") === "on"
            : undefined,
          tcp_keep_alive_idle: tcpStabilityKind
            ? Number(data.get("tcp_keep_alive_idle") ?? 30)
            : undefined,
          tcp_keep_alive_interval: tcpStabilityKind
            ? Number(data.get("tcp_keep_alive_interval") ?? 10)
            : undefined,
          tcp_user_timeout: tcpStabilityKind
            ? Number(data.get("tcp_user_timeout") ?? 60000)
            : undefined,
          client_http_headers: ["ws", "httpupgrade"].includes(transportKind)
            ? clientHttpHeaders
            : undefined,
          early_data: ["ws", "httpupgrade"].includes(transportKind)
            ? Number(data.get("early_data") ?? 0)
            : undefined,
          ws_heartbeat_period: transportKind === "ws"
            ? Number(data.get("ws_heartbeat_period") ?? 0)
            : undefined,
          grpc_multi_mode: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? data.get("grpc_multi_mode") === "on"
            : undefined,
          grpc_user_agent: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? String(data.get("grpc_user_agent") ?? "").trim()
            : undefined,
          grpc_idle_timeout: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? Number(data.get("grpc_idle_timeout") ?? grpcIdleTimeoutDefault)
            : undefined,
          grpc_health_check_timeout: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? Number(data.get("grpc_health_check_timeout") ?? 20)
            : undefined,
          grpc_permit_without_stream: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? data.get("grpc_permit_without_stream") === "on"
            : undefined,
          grpc_initial_windows_size: ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind)
            ? Number(data.get("grpc_initial_windows_size") ?? 0)
            : undefined,
          mode:
            xhttpKind
              ? submittedXHTTPMode
              : undefined,
          x_padding_bytes:
            xhttpKind
              ? String(data.get("x_padding_bytes") ?? "100-1000")
              : undefined,
          vless_encryption_enabled: xhttpKind
            ? data.get("vless_encryption_enabled") === "on"
            : undefined,
          vless_encryption_authentication: xhttpKind
            ? String(data.get("vless_encryption_authentication") ?? "mlkem768")
            : undefined,
          x_padding_obfs_mode: xhttpKind
            ? data.get("x_padding_obfs_mode") === "on"
            : undefined,
          x_padding_placement: xhttpKind
            ? String(data.get("x_padding_placement") ?? "query")
            : undefined,
          x_padding_key: xhttpKind
            ? String(data.get("x_padding_key") ?? "_v").trim()
            : undefined,
          x_padding_header: xhttpKind
            ? String(data.get("x_padding_header") ?? "X-Padding").trim()
            : undefined,
          x_padding_method: xhttpKind
            ? String(data.get("x_padding_method") ?? "tokenish")
            : undefined,
          uplink_http_method: xhttpKind
            ? submittedXHTTPMode !== "packet-up" && submittedXHTTPUplinkMethod === "GET"
              ? "POST"
              : submittedXHTTPUplinkMethod
            : undefined,
          uplink_data_placement: xhttpKind
            ? submittedXHTTPMode !== "packet-up" && ["header", "cookie"].includes(submittedXHTTPUplinkPlacement)
              ? "auto"
              : submittedXHTTPUplinkPlacement
            : undefined,
          uplink_data_key: xhttpKind
            ? String(data.get("uplink_data_key") ?? "X-Data").trim()
            : undefined,
          uplink_chunk_size: xhttpKind
            ? String(data.get("uplink_chunk_size") ?? "2048-3072").trim()
            : undefined,
          session_id_placement: xhttpKind
            ? String(data.get("session_id_placement") ?? "cookie")
            : undefined,
          session_id_key: xhttpKind
            ? String(data.get("session_id_key") ?? "_sid").trim()
            : undefined,
          session_id_table: xhttpKind
            ? String(data.get("session_id_table") ?? "").trim()
            : undefined,
          session_id_length:
            xhttpKind && String(data.get("session_id_length") ?? "").trim()
              ? Number(data.get("session_id_length"))
              : undefined,
          seq_placement: xhttpKind
            ? String(data.get("seq_placement") ?? "query")
            : undefined,
          seq_key: xhttpKind
            ? String(data.get("seq_key") ?? "_seq").trim()
            : undefined,
          server_max_header_bytes: xhttpKind
            ? Number(data.get("server_max_header_bytes") ?? 16384)
            : undefined,
          no_grpc_header: xhttpKind
            ? data.get("no_grpc_header") === "on"
            : undefined,
          no_sse_header: xhttpKind
            ? data.get("no_sse_header") === "on"
            : undefined,
          sc_max_each_post_bytes: xhttpKind
            ? String(data.get("sc_max_each_post_bytes") ?? "").trim()
            : undefined,
          sc_min_posts_interval_ms: xhttpKind
            ? String(data.get("sc_min_posts_interval_ms") ?? "").trim()
            : undefined,
          sc_max_buffered_posts:
            xhttpKind && String(data.get("sc_max_buffered_posts") ?? "").trim()
              ? Number(data.get("sc_max_buffered_posts"))
              : undefined,
          sc_stream_up_server_secs: xhttpKind
            ? String(data.get("sc_stream_up_server_secs") ?? "").trim()
            : undefined,
          headers: xhttpKind ? xhttpHeaders : undefined,
          download_settings: xhttpKind ? xhttpDownloadSettings : undefined,
          xmux_max_connections: xhttpKind
            ? String(data.get("xmux_max_connections") ?? "").trim()
            : undefined,
          xmux_max_concurrency: xhttpKind
            ? String(data.get("xmux_max_concurrency") ?? "").trim()
            : undefined,
          xmux_h_max_request_times: xhttpKind
            ? String(data.get("xmux_h_max_request_times") ?? "").trim()
            : undefined,
          xmux_h_max_reusable_secs: xhttpKind
            ? String(data.get("xmux_h_max_reusable_secs") ?? "").trim()
            : undefined,
          xmux_c_max_reuse_times: xhttpKind
            ? String(data.get("xmux_c_max_reuse_times") ?? "").trim()
            : undefined,
          xmux_h_keep_alive_period: xhttpKind
            ? String(data.get("xmux_h_keep_alive_period") ?? "").trim()
            : undefined,
          server_names: realityKind
            ? String(data.get("server_names") ?? "")
                .split(/[\n,]/)
                .map((value) => value.trim())
                .filter(Boolean)
            : undefined,
          min_client_ver: realityKind
            ? String(data.get("min_client_ver") ?? "").trim()
            : undefined,
          max_client_ver: realityKind
            ? String(data.get("max_client_ver") ?? "").trim()
            : undefined,
          max_time_diff: realityKind
            ? Number(data.get("max_time_diff") ?? 0)
            : undefined,
          xver: realityKind ? Number(data.get("xver") ?? 0) : undefined,
          reality_show: realityKind
            ? data.get("reality_show") === "on"
            : undefined,
          reality_fallback_upload_after_bytes: realityKind
            ? Number(data.get("reality_fallback_upload_after_bytes") ?? 0)
            : undefined,
          reality_fallback_upload_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_upload_bytes_per_sec") ?? 0)
            : undefined,
          reality_fallback_upload_burst_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_upload_burst_bytes_per_sec") ?? 0)
            : undefined,
          reality_fallback_download_after_bytes: realityKind
            ? Number(data.get("reality_fallback_download_after_bytes") ?? 0)
            : undefined,
          reality_fallback_download_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_download_bytes_per_sec") ?? 0)
            : undefined,
          reality_fallback_download_burst_bytes_per_sec: realityKind
            ? Number(data.get("reality_fallback_download_burst_bytes_per_sec") ?? 0)
            : undefined,
          spider_x: realityKind
            ? String(data.get("spider_x") ?? "").trim()
            : undefined,
          reality_mldsa65_enabled: realityKind
            ? data.get("reality_mldsa65_enabled") === "on"
            : undefined,
          require_public_address: ["reality", "reality-grpc", "grpc-tls", "xhttp-reality", "hysteria2"].includes(transportKind),
          grpc_service_name:
            ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind) &&
            String(data.get("grpc_service_name") ?? "").trim()
              ? String(data.get("grpc_service_name") ?? "").trim()
              : undefined,
          generate_http_path:
            ["ws", "httpupgrade", "xhttp", "xhttp-reality"].includes(transportKind) &&
            (!existingTransport.path_secret_ref || data.get("regenerate_http_path") === "on"),
          generate_grpc_service_name:
            ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind) &&
            (!existingTransport.service_name_secret_ref || data.get("regenerate_grpc_service_name") === "on"),
          generate_reality_keys:
            realityKind &&
            (!existingSecretRefs.reality_private_key ||
              !existingTransport.public_key ||
              data.get("regenerate_reality_keys") === "on"),
          generate_vless_encryption:
            xhttpKind &&
            data.get("vless_encryption_enabled") === "on" &&
            (!existingSecretRefs.vless_decryption ||
              !existingSecretRefs.vless_encryption ||
              data.get("regenerate_vless_encryption") === "on"),
          generate_reality_mldsa65:
            realityKind &&
            data.get("reality_mldsa65_enabled") === "on" &&
            (!existingSecretRefs.reality_mldsa65_seed ||
              !existingTransport.mldsa65_verify ||
              data.get("regenerate_reality_mldsa65") === "on"),
          generate_hysteria2_obfs:
            transportKind === "hysteria2" &&
            data.get("obfs_enabled") === "on" &&
            (!existingSecretRefs.hysteria2_obfs_password ||
              data.get("regenerate_hysteria2_obfs") === "on"),
        });
      }
      if (kind !== "subscription") {
        await onSaved();
        setSaved(true);
      }
    } catch (error) {
      setSaveError(errorMessage(error));
    } finally {
      setBusy(false);
    }
  }

  const grpcClientTuningFields = (
    <>
      <div className="transport-client-profile-scope form-span">
        <strong>{tr("Только клиентский профиль")}</strong>
        <span>{tr("Попадает в Xray/Reverse; совместимые поля — в Mihomo.")}</span>
      </div>
      <label className="checkbox-field">
        <input name="grpc_multi_mode" type="checkbox" defaultChecked={existingTransport.grpc_multi_mode === true} />
        <span><strong>{tr("gRPC multiMode · экспериментально")}</strong><small>{tr("Только клиентский профиль. Может повысить скорость, но совместимость между версиями Xray не гарантируется.")}</small></span>
      </label>
      <label className="field">
         {tr("User-Agent выдаваемого gRPC-клиента · необязательно")} <input name="grpc_user_agent" defaultValue={asText(existingTransport.grpc_user_agent, "")} placeholder={tr("Пусто · стандарт Xray")} />
      </label>
      <label className="field">
         {tr("Проверка простоя, сек.")} <input name="grpc_idle_timeout" type="number" min="0" max="86400" defaultValue={asText(existingTransport.grpc_idle_timeout, grpcIdleTimeoutDefault)} />
        <small>{directGRPCKind ? tr("60 — для прямого подключения; 0 отключает проверку.") : tr("0 отключает health-check; Xray применяет минимум 10 секунд.")}</small>
      </label>
      <label className="field">
         {tr("Таймаут health-check, сек.")} <input name="grpc_health_check_timeout" type="number" min="1" max="86400" defaultValue={asText(existingTransport.grpc_health_check_timeout, "20")} />
      </label>
      <label className="checkbox-field">
        <input
          name="grpc_permit_without_stream"
          type="checkbox"
          defaultChecked={
            existingTransport.grpc_permit_without_stream === true ||
            (directGRPCKind && !("grpc_permit_without_stream" in existingTransport))
          }
        />
        <span><strong>{tr("Проверять без активных stream")}</strong><small>{tr("Только клиент: разрешает gRPC health-check без дочерних соединений.")}</small></span>
      </label>
      <label className="field">
         {tr("Начальное окно HTTP/2")} <input name="grpc_initial_windows_size" type="number" min="0" max="2147483647" defaultValue={asText(existingTransport.grpc_initial_windows_size, "0")} />
        <small>
          {directGRPCKind
            ? tr("0 — автоматический размер. Большее окно может повысить скорость на канале с высокой задержкой, но требует больше памяти.")
            : tr("0 — авто. Для Cloudflare обычно проверяют 65536 и выше.")}
        </small>
      </label>
    </>
  );

  const tcpStabilityFields = (
    <>
      <label className="checkbox-field form-span">
        <input
          name="tcp_keep_alive_enabled"
          type="checkbox"
          defaultChecked={existingTransport.tcp_keep_alive_enabled !== false}
        />
        <span>
          <strong>TCP Keep-Alive</strong>
          <small>
            {transportKind === "grpc"
              ? tr("Xray JSON · клиент → CDN.")
              : tr("Сервер и Xray JSON, включая Reverse VLESS.")}
          </small>
        </span>
      </label>
      <label className="field">
         {tr("Начать проверку после простоя · сек.")} <input name="tcp_keep_alive_idle" type="number" min="1" max="86400" defaultValue={asText(existingTransport.tcp_keep_alive_idle, "30")} required />
      </label>
      <label className="field">
         {tr("Интервал проверок · сек.")} <input name="tcp_keep_alive_interval" type="number" min="1" max="86400" defaultValue={asText(existingTransport.tcp_keep_alive_interval, "10")} required />
      </label>
      <label className="field">
         {tr("Таймаут TCP · мс · Linux")} <input name="tcp_user_timeout" type="number" min="0" max="2147483647" defaultValue={asText(existingTransport.tcp_user_timeout, "60000")} required />
        <small>{tr("0 — без принудительного таймаута. Не зависит от Keep-Alive.")}</small>
      </label>
    </>
  );

  const regenerationOptions = [
    {
      name: "regenerate_http_path",
      label: t("regenerate.httpPath"),
      visible:
        ["ws", "httpupgrade", "xhttp", "xhttp-reality"].includes(
          transportKind,
        ) && Boolean(existingTransport.path_secret_ref),
    },
    {
      name: "regenerate_vless_encryption",
      label: "VLESS Encryption",
      visible:
        xhttpKind &&
        (Boolean(existingSecretRefs.vless_decryption) ||
          Boolean(existingSecretRefs.vless_encryption)),
    },
    {
      name: "regenerate_grpc_service_name",
      label: t("regenerate.grpc"),
      visible:
        ["grpc", "reality-grpc", "grpc-tls"].includes(transportKind) &&
        Boolean(existingTransport.service_name_secret_ref),
    },
    {
      name: "regenerate_reality_keys",
      label: tr("X25519 и Short ID"),
      visible: realityKind && Boolean(existingTransport.public_key),
    },
    {
      name: "regenerate_reality_mldsa65",
      label: "ML-DSA-65",
      visible:
        realityKind &&
        (Boolean(existingSecretRefs.reality_mldsa65_seed) ||
          Boolean(existingTransport.mldsa65_verify)),
    },
    {
      name: "regenerate_hysteria2_obfs",
      label: t("regenerate.salamander"),
      visible:
        transportKind === "hysteria2" &&
        Boolean(existingSecretRefs.hysteria2_obfs_password),
    },
  ].filter((option) => option.visible);

  const transportActionOptions = [
    {
      name: "reset_transport_parameters",
      label: t("transport.reset"),
    },
    ...regenerationOptions,
  ];
  const selectedTransportActionLabels = transportActionOptions
    .filter((option) => pendingTransportActions.includes(option.name))
    .map((option) => option.label);
  const transportActionCount = selectedTransportActionLabels.length;
  function selectTransportAction(name: string, selected: boolean) {
    if (name === "reset_transport_parameters") {
      if (selected) applyTransportParameterDefaults();
      else restoreTransportParameters();
    }
    setPendingTransportActions((current) =>
      selected
        ? current.includes(name)
          ? current
          : [...current, name]
        : current.filter((value) => value !== name),
    );
  }

  const transportActionMenu = transportActionOptions.length ? (
    <details ref={transportActionMenuRef} className="transport-regeneration-menu">
      <summary
        className={`button button-compact ${transportActionCount ? "button-primary" : "button-tertiary"}`}
        title={t("regenerate.title")}
      >
        {t("regenerate.action")}
        {transportActionCount ? ` (${transportActionCount})` : ""}
      </summary>
      <div
        className="transport-regeneration-options"
        role="group"
        aria-label={t("regenerate.group")}
      >
        {transportActionOptions.map((option) => (
          <label key={option.name}>
            <input
              name={option.name}
              type="checkbox"
              checked={pendingTransportActions.includes(option.name)}
              onChange={(event) =>
                selectTransportAction(option.name, event.target.checked)
              }
            />
            <span>{option.label}</span>
          </label>
        ))}
      </div>
    </details>
  ) : null;

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        className={`modal modal-wide ${kind === "subscription" ? "subscription-editor-modal" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="connection-title"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <button className="modal-close" onClick={onClose} aria-label={tr("Закрыть")}>
          ×
        </button>
        {saved ? (
          <div className="modal-success" role="status">
            <span>✓</span>
            <h2 id="connection-title">{tr("Настройки сохранены")}</h2>
            <p>
              {kind === "subscription"
                ? tr("Подписка сохранена. URL доступен авторизованному администратору в настройках.")
                : tr("Секретное значение записано отдельно и не возвращается в браузер.")}{" "}
               {tr("Рабочая конфигурация изменится только после применения.")} </p>
            <button className="button button-primary" onClick={onClose}>
               {tr("Готово")} </button>
          </div>
        ) : (
          <form ref={formRef} onSubmit={submit}>
            {kind === "transport" ? <p className="eyebrow">{tr("Удалённый вход")}</p> : null}
            <h2 id="connection-title">
              {kind === "subscription"
                ? editingSubscription
                  ? tr("Настроить · {value1}", { value1: itemName(existingSubscription) })
                  : tr("Добавить подписку")
                : tr("Настроить {value1}", { value1: transportKindLabel(transportKind) })}
            </h2>
            {kind !== "subscription" ? (
              <p className="modal-lead">{tr(transportChangeLead(transportKind))}</p>
            ) : null}
            {kind === "subscription" ? (
              <div className="form-grid">
                <label className="field">
                   {tr("Имя подписки")} <input
                    name="display_name"
                    required
                    defaultValue={asText(existingSubscription.display_name, "")}
                    placeholder={tr("Основной провайдер")}
                  />
                </label>
                <label className="field">
                   {tr("Проверять каждые")} <div className="field-with-unit field-with-select">
                    <input name="refresh_value" type="number" min="1" max="10080" defaultValue={defaultRefreshValue} required />
                    <select name="refresh_unit" defaultValue={defaultRefreshUnit} aria-label={tr("Единица интервала проверки")}>
                      <option value="minutes">{tr("минут")}</option>
                      <option value="hours">{tr("часов")}</option>
                    </select>
                  </div>
                </label>
                <label className="field form-span">
                   {tr("URL подписки")} <textarea
                    name="url"
                    required
                    autoComplete="url"
                    rows={1}
                    wrap="off"
                    spellCheck={false}
                    className="subscription-url-input"
                    value={subscriptionUrl}
                    placeholder={subscriptionUrlBusy ? tr("Загружаю сохранённый URL…") : "https://…"}
                    onChange={(event) => {
                      setSubscriptionUrl(event.target.value);
                      if (workingSubscriptionId) {
                        setDiscoveryReady(false);
                        setDiscoveryMessage(
                          tr("URL изменён. Загрузите список заново перед сохранением выбора."),
                        );
                      }
                    }}
                  />
                  {subscriptionUrlBusy ? <small role="status">{tr("Загрузка ссылки…")}</small> : null}
                </label>
                <fieldset className="subscription-refresh-routing form-span">
                  <legend>{tr("Пути обновления")}</legend>
                  <div className="subscription-refresh-modes">
                    {[
                      { id: "wan", label: "WAN", direct: true, vpn: false, title: tr("Только прямой WAN") },
                      { id: "wan-vpn", label: "WAN → VPN", direct: true, vpn: true, title: tr("Прямой WAN, затем VPN-резерв") },
                      { id: "vpn", label: "VPN", direct: false, vpn: true, title: tr("Только VPN") },
                    ].map((mode) => (
                      <label key={mode.id} title={mode.title}>
                        <input
                          type="radio"
                          name="refresh_route_mode"
                          value={mode.id}
                          checked={refreshViaDirect === mode.direct && refreshViaVpn === mode.vpn}
                          onChange={() => {
                            setRefreshViaDirect(mode.direct);
                            setRefreshViaVpn(mode.vpn);
                          }}
                        />
                        <span>{mode.label}</span>
                      </label>
                    ))}
                  </div>
                  {refreshViaVpn ? (
                    <div className="subscription-refresh-children">
                      <Toggle className="subscription-refresh-toggle" label={tr("Рабочие каналы")} checked={refreshViaActiveOutbounds} onChange={setRefreshViaActiveOutbounds} />
                      <Toggle className="subscription-refresh-toggle" label={tr("Резервные VLESS")} description={tr("{value1} из 3 настроено", { value1: configuredSubscriptionReserves.length })} checked={refreshViaIndependentReserves} onChange={setRefreshViaIndependentReserves} />
                    </div>
                  ) : null}
                </fieldset>
                 <section className="subscription-location-picker form-span" aria-live="polite">
                   <div className="subscription-location-heading">
                     <div>
                       <strong>{tr("Данные подписки")}</strong>
                     </div>
                     {workingSubscriptionId ? (
                       <button
                         type="button"
                         className="button button-tertiary"
                         disabled={busy}
                         onClick={async () => {
                           if (!formRef.current) return;
                           setBusy(true);
                           setSaveError("");
                           try {
                             setDiscoveryReady(false);
                             await persistAndDiscover(new FormData(formRef.current));
                           } catch (error) {
                             setSaveError(errorMessage(error));
                           } finally {
                             setBusy(false);
                           }
                         }}
                       >
                          {tr("Обновить список")} </button>
                     ) : null}
                   </div>
                   {discoveryMessage ? (
                     <p className="subscription-discovery-message">{discoveryMessage}</p>
                   ) : null}
                   {discoveryReady ? (
                     <div className="subscription-provider-meta">
                       <span>
                         <strong>{tr("Срок")}</strong>
                         <small>{expiryText(subscriptionProvider.expires_at, locale)}</small>
                       </span>
                       <span>
                         <strong>{tr("Трафик")}</strong>
                         <small>
                           {Object.keys(asObject(subscriptionProvider.usage)).length
                             ? locale === "en"
                               ? `${formatBytes(asObject(subscriptionProvider.usage).used_bytes, locale)} of ${formatBytes(asObject(subscriptionProvider.usage).total_bytes, locale)} · ${formatBytes(asObject(subscriptionProvider.usage).remaining_bytes, locale)} remaining`
                               : tr("{value1} из {value2} · осталось {value3}", { value1: formatBytes(asObject(subscriptionProvider.usage).used_bytes, locale), value2: formatBytes(asObject(subscriptionProvider.usage).total_bytes, locale), value3: formatBytes(asObject(subscriptionProvider.usage).remaining_bytes, locale) })
                             : tr("Лимит не указан провайдером")}
                         </small>
                       </span>
                     </div>
                   ) : null}
                   {discoveryReady ? (
                     <div className="subscription-discovery-ready">
                       <strong>{subscriptionNodes.length}  {tr("узл. готовы к использованию")}</strong>
                     </div>
                   ) : (
                     <div className="subscription-discovery-empty">
                        {tr("Список узлов ещё не загружен.")} </div>
                   )}
                 </section>
                 <Toggle
                   className="form-span subscription-enabled-toggle"
                   name="enabled"
                   defaultChecked={existingSubscription.enabled !== false}
                   tone="state"
                   label={tr("Подписка включена")}
                 />
               </div>
            ) : (
              <div className="form-grid">
                {!cdnTransportKind ? (
                  <div className={directInboundKind ? "field form-span" : "field"}>
                    <label htmlFor="transport-hostname">{tr("Адрес подключения")}</label>
                    <div className={directInboundKind ? "connection-address-row" : undefined}>
                    <input
                      id="transport-hostname"
                      name="hostname"
                      required={!directInboundKind || hostnameMode === "manual"}
                      readOnly={directInboundKind && hostnameMode === "auto"}
                      value={directInboundKind && hostnameMode === "auto" ? asText(connectionAddress.address, "") : manualHostname}
                      onChange={(event) => setManualHostname(event.target.value)}
                      placeholder={hostnamePlaceholder}
                      list={directInboundKind && hostnameMode === "manual" ? "connection-wan-addresses" : undefined}
                    />
                    {directInboundKind ? (
                      <select aria-label={tr("Режим адреса подключения")} name="hostname_mode" value={hostnameMode} onChange={(event) => setHostnameMode(event.target.value)}>
                        <option value="auto">{tr("Автоматически")}</option>
                        <option value="manual">{tr("Вручную")}</option>
                      </select>
                    ) : null}
                    </div>
                    {directInboundKind && hostnameMode === "manual" ? (
                      <>
                        <datalist id="connection-wan-addresses">
                          {ownedWanAddresses.map((row) => <option key={asText(row.address, "")} value={asText(row.address, "")}>{asText(row.interface, "")}</option>)}
                        </datalist>
                      </>
                    ) : null}
                    {directInboundKind && hostnameMode === "auto" ? (
                      <small role="status">{connectionAddress.state === "ready"
                        ? `WAN: ${asText(connectionAddress.interface, "")}`
                        : connectionAddress.state === "ambiguous" ? tr("Несколько WAN-адресов — выберите адрес вручную.")
                        : tr("Адрес WAN пока недоступен.")}</small>
                    ) : null}
                  </div>
                ) : null}
                {cdnTransportKind ? (
                  <>
                    <section className="cdn-deployments-editor form-span" aria-labelledby="cdn-deployments-title">
                      <div className="cdn-deployments-heading">
                        <span>
                          <strong id="cdn-deployments-title">{tr("CDN-развёртывания")}</strong>
                          <small>{tr(cdnDeploymentScopeNote(transportKind))}</small>
                        </span>
                        <button
                          className="button button-secondary cdn-add-button"
                          type="button"
                          onClick={() => cloneCdnDeployment(Math.max(0, cdnDeployments.length - 1), false)}
                        >
                           {tr("+ Ещё один CDN")} </button>
                      </div>
                      <div className="cdn-deployments-list">
                        {cdnDeployments.map((deployment, deploymentIndex) => {
                          const deploymentProvider = asText(
                            deployment.cdn_provider,
                            "cloudflare",
                          );
                          const deploymentId = asText(
                            deployment.id,
                            `cdn-${deploymentIndex + 1}`,
                          );
                          const deploymentHostname = asText(
                            deployment.hostname,
                            "",
                          );
                          const configuredTlsServerName = asText(
                            deployment.tls_server_name,
                            "",
                          );
                          const customTlsServerName =
                            configuredTlsServerName &&
                            configuredTlsServerName.toLowerCase() !==
                              deploymentHostname.toLowerCase()
                              ? configuredTlsServerName
                              : "";
                          const hasClientHostOverride = Boolean(
                            customTlsServerName ||
                              asText(deployment.http_host, "") ||
                              asText(deployment.grpc_authority, ""),
                          );
                          const originHostnameCandidates = tlsConcreteHostnames(
                            tlsProfiles.find(
                              (profile) =>
                                asText(profile.id, "") ===
                                asText(deployment.tls_profile_id, ""),
                            ),
                          );
                          const originHostnameDatalistId = `cdn-origin-dns-${deploymentIndex}`;
                          return (
                            <fieldset className="cdn-deployment-row" key={deploymentId}>
                              <legend>{asText(deployment.display_name, `CDN ${deploymentIndex + 1}`)}</legend>
                              <div className="form-grid">
                                <label className="field">
                                   {tr("Название")} <input
                                    value={asText(deployment.display_name, "")}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        display_name: event.target.value,
                                      })
                                    }
                                    required
                                  />
                                  <small>ID: {deploymentId}</small>
                                </label>
                                <label className="field">
                                  CDN
                                  <select
                                    value={deploymentProvider}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        cdn_provider: event.target.value,
                                        listen_port:
                                          event.target.value === "cloudflare" && transportKind === "grpc"
                                            ? 443
                                            : deployment.listen_port ?? 443,
                                        origin_protection_mode:
                                          supportsAutomaticCidr(event.target.value)
                                            ? "auto-cidr"
                                            : "secret-header",
                                        origin_header_value:
                                          supportsAutomaticCidr(event.target.value)
                                            ? undefined
                                            : asText(deployment.origin_header_value, "") ||
                                              generateOriginHeaderSecret(),
                                      })
                                    }
                                  >
                                    {CDN_PROVIDERS.map((provider) => (
                                      <option value={provider.id} key={provider.id}>{tr(provider.name)}</option>
                                    ))}
                                  </select>
                                  <small>{tr(subscriptionCdnProviderNote(deploymentProvider))}</small>
                                </label>
                                <label className="field">
                                   {tr("Домен раздачи CDN")} <input
                                    value={asText(deployment.hostname, "")}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        hostname: event.target.value,
                                        ...(customTlsServerName
                                          ? {}
                                          : { tls_server_name: "" }),
                                      })
                                    }
                                    placeholder="edge.example.com"
                                    required={transportEnabled && deployment.enabled !== false}
                                  />
                                  <small>{tr("Собственный CNAME или технический домен именно этого CDN-ресурса.")}</small>
                                </label>
                                <details className="cdn-client-overrides form-span" open={hasClientHostOverride}>
                                  <summary>
                                    <span><strong>{tr("SNI и Host клиента")}</strong><small>{hasClientHostOverride ? tr("Переопределено") : tr("Автоматически · домен раздачи CDN")}</small></span>
                                  </summary>
                                  <div className="form-grid">
                                    <label className="field">
                                       {tr("TLS SNI клиента")} <input
                                        value={customTlsServerName}
                                        onChange={(event) =>
                                          updateCdnDeployment(deploymentIndex, {
                                            tls_server_name: event.target.value,
                                          })
                                        }
                                        placeholder={tr("Авто: {value1}", { value1: deploymentHostname || "edge.example.com" })}
                                      />
                                      <small>{tr("Оставьте пустым, чтобы использовать публичный домен CDN.")}</small>
                                    </label>
                                    {["ws", "httpupgrade"].includes(transportKind) ? (
                                      <label className="field">
                                         {tr("HTTP Host клиента")} <input
                                          value={asText(deployment.http_host, "")}
                                          onChange={(event) => updateCdnDeployment(deploymentIndex, { http_host: event.target.value })}
                                          placeholder={tr("Авто: {value1}", { value1: deploymentHostname || "edge.example.com" })}
                                        />
                                        <small>{tr("Меняйте только если CDN требует отдельный Host.")}</small>
                                      </label>
                                    ) : null}
                                    {transportKind === "grpc" ? (
                                      <label className="field">
                                        gRPC authority
                                        <input
                                          value={asText(deployment.grpc_authority, "")}
                                          onChange={(event) => updateCdnDeployment(deploymentIndex, { grpc_authority: event.target.value })}
                                          placeholder={tr("Авто: не добавляется")}
                                        />
                                        <small>{tr("Меняйте только если CDN требует отдельный :authority.")}</small>
                                      </label>
                                    ) : null}
                                  </div>
                                </details>
                                <label className="field">
                                   {tr("Публичный HTTPS-порт")} {deploymentProvider === "cloudflare" ? (
                                    <select
                                      value={Number(deployment.listen_port ?? 443)}
                                      onChange={(event) =>
                                        updateCdnDeployment(deploymentIndex, {
                                          listen_port: Number(event.target.value),
                                        })
                                      }
                                    >
                                      {(transportKind === "grpc" ? [443] : CLOUDFLARE_HTTPS_PORTS).map((port) => (
                                        <option value={port} key={port}>{port}</option>
                                      ))}
                                    </select>
                                  ) : (
                                    <input
                                      type="number"
                                      min="1"
                                      max="65535"
                                      value={Number(deployment.listen_port ?? 443)}
                                      onChange={(event) =>
                                        updateCdnDeployment(deploymentIndex, {
                                          listen_port: Number(event.target.value),
                                        })
                                      }
                                      required
                                    />
                                  )}
                                  <small>{deploymentProvider === "cloudflare" && transportKind === "grpc" ? tr("Cloudflare gRPC использует TCP 443.") : tr("Проверьте поддержку порта у выбранного CDN.")}</small>
                                </label>
                                <label className="field">
                                   {tr("TCP-порт origin на MikroTik")} <input
                                    type="number"
                                    min="1"
                                    max="65535"
                                    value={Number(
                                      deployment.origin_port ??
                                        existingTransport.origin_port ??
                                        existingTransport.listen_port ??
                                        legacyCloudflarePort,
                                    )}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        origin_port: Number(event.target.value),
                                      })
                                    }
                                    required={transportEnabled && deployment.enabled !== false}
                                  />
                                  <small>{tr("Порт, на который этот CDN обращается к origin шлюза. Разные классы защиты, например Cloudflare CIDR и Yandex secret-header, используют разные origin-порты.")}</small>
                                </label>
                                <label className="field">
                                   {tr("DNS-имя origin")} <input
                                    value={asText(deployment.origin_server_name, "")}
                                    list={originHostnameDatalistId}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        origin_server_name: event.target.value,
                                      })
                                    }
                                    placeholder={originHostnameCandidates.length ? tr("Выберите или введите домен") : "origin.example.com"}
                                    required={transportEnabled && deployment.enabled !== false}
                                  />
                                  <datalist id={originHostnameDatalistId}>
                                    {originHostnameCandidates.map((hostname) => <option value={hostname} key={hostname} />)}
                                  </datalist>
                                  <small>{tr(cdnOriginNameNote(transportKind))}</small>
                                </label>
                                <label className="field">
                                   {tr("TLS-профиль origin")} <select
                                    value={asText(deployment.tls_profile_id, "")}
                                    onChange={(event) =>
                                      selectCdnDeploymentTlsProfile(
                                        deploymentIndex,
                                        event.target.value,
                                      )
                                    }
                                    required={transportEnabled && deployment.enabled !== false}
                                  >
                                    <option value="">{tr("Выберите сертификат origin")}</option>
                                    {tlsProfiles.map((profile) => (
                                      <option
                                        value={asText(profile.id, "")}
                                        key={asText(profile.id, "")}
                                      >
                                        {itemName(profile)}
                                        {asText(profile.certificate_secret_ref, "")
                                          ? tr(" · настроен")
                                          : tr(" · нужна пара")}
                                      </option>
                                    ))}
                                  </select>
                                  <small>{tr("Сертификат соединения CDN → origin.")}</small>
                                </label>
                                <label className="field">
                                   {tr("Защита origin")} <select
                                    value={asText(
                                      deployment.origin_protection_mode,
                                      deploymentProvider === "cloudflare"
                                        ? "auto-cidr"
                                        : "secret-header",
                                    )}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        origin_protection_mode: event.target.value,
                                        origin_header_value:
                                          event.target.value === "secret-header"
                                            ? asText(deployment.origin_header_value, "") ||
                                              generateOriginHeaderSecret()
                                            : undefined,
                                      })
                                    }
                                  >
                                    {supportsAutomaticCidr(deploymentProvider) ? (
                                      <option value="auto-cidr">{tr("Официальные CIDR · авто")}</option>
                                    ) : null}
                                    <option value="secret-header">{tr("Секретный HTTP-заголовок")}</option>
                                    <option value="manual-cidr">{tr("IPv4 CIDR · вручную")}</option>
                                  </select>
                                  <small>
                                    {asText(deployment.origin_protection_mode, "") === "auto-cidr"
                                      ? automaticCidrHint(deploymentProvider)
                                      : asText(deployment.origin_protection_mode, "") === "manual-cidr"
                                        ? tr("Расширенный fallback, если провайдер не умеет добавлять секретный header и не публикует машинный feed.")
                                        : tr("Добавьте этот header в настройках CDN-запроса к origin. Прямой запрос без секрета получит 404.")}
                                  </small>
                                </label>
                                {asText(deployment.origin_protection_mode, "") === "secret-header" ? (
                                  <div className="field">
                                     {tr("Секрет origin-header")} <div className="inline-field-actions">
                                      <input
                                        value={asText(deployment.origin_header_value, "")}
                                        readOnly
                                        placeholder={
                                          asText(deployment.origin_header_secret_ref, "")
                                            ? tr("Секрет уже сохранён и скрыт")
                                            : tr("Нажмите «Создать новый»")
                                        }
                                        aria-label={tr("Секрет origin-header")}
                                      />
                                      <button
                                        className="button button-secondary"
                                        type="button"
                                        onClick={() =>
                                          updateCdnDeployment(deploymentIndex, {
                                            origin_header_value: generateOriginHeaderSecret(),
                                          })
                                        }
                                      >
                                         {tr("Создать новый")} </button>
                                    </div>
                                    <small>
                                       {tr("Имя заголовка:")} <code>{asText(deployment.origin_header_name, "X-SB-Origin")}</code>{tr(". Новый секрет покажется до сохранения — скопируйте его в CDN.")} </small>
                                  </div>
                                ) : null}
                                {asText(deployment.origin_protection_mode, "") === "manual-cidr" ? (
                                  <label className="field">
                                     {tr("Разрешённые IPv4-сети CDN")} <textarea
                                      value={asStringList(deployment.origin_allowed_cidrs).join("\n")}
                                      onChange={(event) =>
                                        updateCdnDeployment(deploymentIndex, {
                                          origin_allowed_cidrs: event.target.value
                                            .split(/[\n,]/)
                                            .map((value) => value.trim())
                                            .filter(Boolean),
                                        })
                                      }
                                      placeholder={"203.0.113.0/24\n198.51.100.0/24"}
                                      rows={3}
                                    />
                                    <small>{tr("Панель валидирует список; меняйте его только по официальным данным CDN.")}</small>
                                  </label>
                                ) : null}
                                <label className="checkbox-field">
                                  <input
                                    type="checkbox"
                                    checked={deployment.enabled !== false}
                                    onChange={(event) =>
                                      updateCdnDeployment(deploymentIndex, {
                                        enabled: event.target.checked,
                                      })
                                    }
                                  />
                                  <span><strong>{tr("Отдавать клиентам")}</strong><small>{tr("Выключенное развёртывание сохраняется, но не попадает в подписку.")}</small></span>
                                </label>
                                <div className="cdn-deployment-actions">
                                  <button className="button button-tertiary" type="button" onClick={() => cloneCdnDeployment(deploymentIndex)}>{tr("Дублировать")}</button>
                                  <button
                                    className="button button-tertiary"
                                    type="button"
                                    disabled={cdnDeployments.length <= 1}
                                    onClick={() => setCdnDeployments((current) => current.filter((_, itemIndex) => itemIndex !== deploymentIndex))}
                                  >
                                     {tr("Удалить")} </button>
                                </div>
                                <div className="reality-target-check form-span">
                                  <div>
                                    <strong>{tr("Проверка домена CDN и origin")}</strong>
                                    <small>{tr("Проверяет DNS, TLS/SNI и срок сертификатов без сохранения и Apply.")}</small>
                                  </div>
                                  <button
                                    className="button button-secondary button-compact"
                                    type="button"
                                    disabled={cdnProbeBusyId === deploymentId}
                                    onClick={() => void checkCdnDeployment(deploymentIndex)}
                                  >
                                    {cdnProbeBusyId === deploymentId ? tr("Проверяю…") : tr("Проверить")}
                                  </button>
                                  {cdnProbeResults[deploymentId] ? (
                                    <small
                                      className={isErrorMessage(cdnProbeResults[deploymentId]) ? "field-error" : ""}
                                      role={isErrorMessage(cdnProbeResults[deploymentId]) ? "alert" : "status"}
                                    >
                                      {cdnProbeResults[deploymentId]}
                                    </small>
                                  ) : null}
                                </div>
                              </div>
                            </fieldset>
                          );
                        })}
                      </div>
                    </section>
                  </>
                ) : null}
                {!directInboundKind && !cdnTransportKind ? (
                  <Toggle
                    className="form-span"
                    name="enabled"
                    checked={transportEnabled}
                    onChange={setTransportEnabled}
                    tone="state"
                    label={tr("Транспорт включён")}
                    description={tr("Изменение вступит в силу только после проверки и Apply.")}
                  />
                ) : null}
                {directInboundKind ? (
                  <>
                    <label className="field direct-inbound-port">
                      {directInboundProtocol}{tr("-порт прямого входа")} <input
                        name="listen_port"
                        type="number"
                        min="1"
                        max="65535"
                        value={directListenPort}
                        onChange={(event) => setDirectListenPort(event.target.value)}
                        required
                      />
                    </label>
                    {["hysteria2", "grpc-tls"].includes(transportKind) ? (
                      <label className="field">
                        TLS SNI
                        <input
                          name="tls_server_name"
                          list="direct-tls-server-names"
                          value={directTlsServerName}
                          onChange={(event) => {
                            const nextServerName = event.target.value;
                            setDirectTlsServerName(nextServerName);
                            const matchingProfileId = tlsProfileIdForHostname(
                              tlsProfiles,
                              nextServerName,
                              tlsProfileChoice,
                            );
                            if (matchingProfileId !== tlsProfileChoice) {
                              setTlsProfileChoice(matchingProfileId);
                            }
                          }}
                          placeholder="www.example.com"
                          required
                        />
                        <datalist id="direct-tls-server-names">
                          {directTlsHostnameCandidates.map((hostname) => (
                            <option value={hostname} key={hostname} />
                          ))}
                        </datalist>
                      </label>
                    ) : null}
                    {directPortConflict ? (
                      <div className="direct-inbound-conflict form-span" role="alert">
                         {tr("Порт")} {directListenPort}  {tr("уже используется входом «")} {transportKindLabel(directPortConflict.kind)}{tr("». Выберите другой WAN IP или порт.")} </div>
                    ) : null}
                  </>
                ) : null}
                {["ws", "httpupgrade"].includes(transportKind) ? (
                  <details className="policy-check-advanced form-span">
                    <summary>{tr("Дополнительно")}</summary>
                    <div className="form-grid">
                      <div className="transport-http-path form-span">
                        <div className="transport-http-path-heading">
                          <span>
                            <strong>{tr("HTTP-путь транспорта")}</strong>
                            <small>{existingTransport.path_secret_ref ? tr("Хранится в SecretStore и показывается только по запросу.") : tr("Будет создан автоматически при сохранении.")}</small>
                          </span>
                          {existingTransport.path_secret_ref ? (
                            <div className="transport-http-path-actions">
                              <button className="button button-tertiary button-compact" type="button" disabled={httpPathBusy} onClick={() => void showHttpPath()}>{httpPathBusy ? tr("Открываю…") : revealedHttpPath ? tr("Обновить") : tr("Показать")}</button>
                              <button className="button button-tertiary button-compact" type="button" disabled={!revealedHttpPath} onClick={() => void copyHttpPath()}>{tr("Скопировать")}</button>
                            </div>
                          ) : null}
                        </div>
                        {revealedHttpPath ? <input className="transport-http-path-value" value={revealedHttpPath} readOnly aria-label={tr("Текущий HTTP-путь")} /> : null}
                        {httpPathMessage ? <small className="transport-http-path-message" role="status">{httpPathMessage}</small> : null}
                      </div>
                      <label className="field">
                         {tr("Early Data, байт")} <input name="early_data" type="number" min="0" max="8192" defaultValue={asText(existingTransport.early_data, "0")} />
                        <small>{tr("0 — выключено; рекомендуемый порог Xray — 2560.")}</small>
                      </label>
                      {transportKind === "ws" ? (
                        <label className="field">
                           {tr("WebSocket heartbeat, сек.")} <input name="ws_heartbeat_period" type="number" min="0" max="86400" defaultValue={asText(existingTransport.ws_heartbeat_period, "0")} />
                          <small>{tr("0 — Ping keepalive отключён.")}</small>
                        </label>
                      ) : null}
                      <label className="field form-span">
                         {tr("Заголовки клиентского запроса · необязательно")} <textarea
                          name="client_http_headers"
                          rows={3}
                          defaultValue={Object.entries(asObject(existingTransport.client_http_headers)).map(([name, value]) => `${name}: ${asText(value, "")}`).join("\n")}
                          placeholder={tr("Оставьте пустым, если CDN не требует специальных заголовков")}
                        />
                        <small>{tr("Только Xray / Sing-box / Mihomo. Обычная VLESS-ссылка недоступна с дополнительными заголовками.")}</small>
                      </label>
                    </div>
                  </details>
                ) : null}
                {xhttpKind ? (
                  <>
                    <label className="field">
                       {tr("Режим XHTTP")} <select
                        name="mode"
                        value={xhttpMode}
                        onChange={(event) => {
                          const nextMode = event.target.value;
                          setXHTTPMode(nextMode);
                          if (nextMode !== "packet-up") {
                            if (xhttpUplinkMethod === "GET") setXHTTPUplinkMethod("POST");
                            if (["header", "cookie"].includes(xhttpUplinkPlacement)) setXHTTPUplinkPlacement("auto");
                          }
                        }}
                      >
                        <option value="packet-up">
                          {transportKind === "xhttp"
                            ? tr("packet-up · основной режим через CDN")
                            : tr("packet-up · принудительный пакетный uplink")}
                        </option>
                        <option value="stream-up">stream-up</option>
                        <option value="stream-one">stream-one</option>
                        <option value="auto">
                          {transportKind === "xhttp-reality"
                            ? tr("auto · рекомендуется для Reality")
                            : tr("auto · клиент выбирает")}
                        </option>
                      </select>
                      <small>{tr("Vision для XHTTP включается только вместе с VLESS Encryption в расширенном профиле Xray.")}</small>
                    </label>
                    <label className="field">
                       {tr("XHTTP padding, байты")} <input
                        name="x_padding_bytes"
                        pattern="[1-9][0-9]{0,5}(-[1-9][0-9]{0,5})?"
                        defaultValue={asText(existingTransport.x_padding_bytes, "100-1000")}
                        required
                      />
                      <small>{tr("Обязательный диапазон форка; безопасное значение по умолчанию — 100-1000.")}</small>
                    </label>
                    <details className="policy-check-advanced form-span">
                      <summary>{t("common.advanced")} · XHTTP</summary>
                      <div className="form-grid">
                        <label className="checkbox-field form-span">
                          <input name="vless_encryption_enabled" type="checkbox" defaultChecked={existingTransport.vless_encryption_enabled !== false} />
                          <span><strong>VLESS Encryption + XTLS Vision</strong><small>{tr("Серверный decryption и клиентский encryption генерируются парой через `xray vlessenc` и хранятся в SecretStore.")}</small></span>
                        </label>
                        <label className="field">
                           {tr("Аутентификация VLESS Encryption")} <select name="vless_encryption_authentication" defaultValue={asText(existingTransport.vless_encryption_authentication, "mlkem768")}>
                            <option value="mlkem768">{tr("ML-KEM-768 · постквантовая")}</option>
                            <option value="x25519">X25519</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Метод uplink")} <select name="uplink_http_method" value={xhttpUplinkMethod} onChange={(event) => setXHTTPUplinkMethod(event.target.value)}>
                            <option value="GET">{tr("GET · только packet-up")}</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="PATCH">PATCH</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Где передавать uplink data")} <select name="uplink_data_placement" value={xhttpUplinkPlacement} onChange={(event) => setXHTTPUplinkPlacement(event.target.value)}>
                            <option value="header">{tr("header · для GET packet-up")}</option>
                            <option value="cookie">{tr("cookie · для GET packet-up")}</option>
                            <option value="body">body</option>
                            <option value="auto">auto</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ uplink data")} <input name="uplink_data_key" defaultValue={asText(existingTransport.uplink_data_key, "X-Data")} required />
                        </label>
                        <label className="field">
                           {tr("Размер чанка uplink")} <input name="uplink_chunk_size" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.uplink_chunk_size, "2048-3072")} required />
                          <small>
                             {tr("Для header/cookie учитывайте Base64 и")} {transportKind === "xhttp"
                              ? tr(" лимит заголовков выбранного CDN.")
                              : tr(" заданный максимум HTTP-заголовков.")}
                          </small>
                        </label>
                        <label className="checkbox-field form-span">
                          <input name="x_padding_obfs_mode" type="checkbox" defaultChecked={existingTransport.x_padding_obfs_mode !== false} />
                          <span><strong>{tr("Новый padding obfs mode")}</strong><small>{tr("Включает управляемые placement, key, header и method.")}</small></span>
                        </label>
                        <label className="field">
                           {tr("Размещение padding")} <select name="x_padding_placement" defaultValue={asText(existingTransport.x_padding_placement, "query")}>
                            <option value="query">query</option>
                            <option value="queryInHeader">queryInHeader</option>
                            <option value="header">header</option>
                            <option value="cookie">cookie</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Вид padding")} <select name="x_padding_method" defaultValue={asText(existingTransport.x_padding_method, "tokenish")}>
                            <option value="tokenish">tokenish</option>
                            <option value="repeat-x">repeat-x</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ padding")} <input name="x_padding_key" defaultValue={asText(existingTransport.x_padding_key, "_v")} required />
                        </label>
                        <label className="field">
                           {tr("Заголовок padding")} <input name="x_padding_header" defaultValue={asText(existingTransport.x_padding_header, "X-Padding")} required />
                        </label>
                        <label className="field">
                           {tr("Размещение session ID")} <select name="session_id_placement" defaultValue={asText(existingTransport.session_id_placement, "cookie")}>
                            <option value="path">path</option><option value="cookie">cookie</option><option value="header">header</option><option value="query">query</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ session ID")} <input name="session_id_key" defaultValue={asText(existingTransport.session_id_key, "_sid")} required />
                        </label>
                        <label className="field">
                           {tr("Таблица символов session ID")} <input name="session_id_table" defaultValue={asText(existingTransport.session_id_table, "")} placeholder={tr("Пусто · таблица Xray")} />
                        </label>
                        <label className="field">
                           {tr("Длина session ID")} <input name="session_id_length" type="number" min="1" max="1048576" defaultValue={asText(existingTransport.session_id_length, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                           {tr("Размещение seq")} <select name="seq_placement" defaultValue={asText(existingTransport.seq_placement, "query")}>
                            <option value="path">path</option><option value="cookie">cookie</option><option value="header">header</option><option value="query">query</option>
                          </select>
                        </label>
                        <label className="field">
                           {tr("Ключ seq")} <input name="seq_key" defaultValue={asText(existingTransport.seq_key, "_seq")} required />
                        </label>
                        <label className="field">
                           {tr("Максимум заголовков сервера, байт")} <input name="server_max_header_bytes" type="number" min="1024" max="1048576" defaultValue={asText(existingTransport.server_max_header_bytes, "16384")} required />
                        </label>
                        <label className="field form-span">
                           {tr("Дополнительные HTTP-заголовки")} <textarea
                            name="xhttp_headers"
                            rows={4}
                            defaultValue={Object.entries(asObject(existingTransport.headers)).map(([name, value]) => `${name}: ${asText(value, "")}`).join("\n")}
                            placeholder={"Accept: */*\nCache-Control: no-cache"}
                          />
                          <small>{tr("По одному «Имя: значение» на строке. Не копируйте чужой фиксированный User-Agent без причины.")}</small>
                        </label>
                        <label className="field form-span">
                           {tr("downloadSettings · JSON StreamConfig клиента")} <textarea
                            name="download_settings_json"
                            rows={6}
                            defaultValue={Object.keys(asObject(existingTransport.download_settings)).length ? JSON.stringify(asObject(existingTransport.download_settings), null, 2) : ""}
                            placeholder={'{"address":"download.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"download.example.com"},"xhttpSettings":{"path":"/down"}}'}
                            spellCheck={false}
                          />
                          <small>{tr("Отдельный downlink Xray. Сохраняется в JSON и ссылке XHTTP; экспорт Mihomo недоступен.")}</small>
                        </label>
                        <label className="checkbox-field">
                          <input name="no_grpc_header" type="checkbox" defaultChecked={existingTransport.no_grpc_header === true} />
                          <span><strong>noGRPCHeader</strong><small>{tr("Не добавлять gRPC-подобный заголовок.")}</small></span>
                        </label>
                        <label className="checkbox-field">
                          <input name="no_sse_header" type="checkbox" defaultChecked={existingTransport.no_sse_header === true} />
                          <span><strong>noSSEHeader</strong><small>{tr("Не добавлять SSE-заголовок downlink.")}</small></span>
                        </label>
                        <label className="field">
                          scMaxEachPostBytes
                          <input name="sc_max_each_post_bytes" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.sc_max_each_post_bytes, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          scMinPostsIntervalMs
                          <input name="sc_min_posts_interval_ms" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.sc_min_posts_interval_ms, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          scMaxBufferedPosts
                          <input name="sc_max_buffered_posts" type="number" min="1" max="1048576" defaultValue={asText(existingTransport.sc_max_buffered_posts, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          scStreamUpServerSecs
                          <input name="sc_stream_up_server_secs" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.sc_stream_up_server_secs, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          XMUX maxConnections
                          <input name="xmux_max_connections" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_max_connections, "3")} />
                        </label>
                        <label className="field">
                          XMUX maxConcurrency
                          <input name="xmux_max_concurrency" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_max_concurrency, "0")} />
                          <small>{tr("Для стабильной работы на мобильных сетях: maxConnections 3, maxConcurrency 0.")}</small>
                        </label>
                        <label className="field">
                          XMUX hMaxRequestTimes
                          <input name="xmux_h_max_request_times" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_h_max_request_times, "600-900")} />
                        </label>
                        <label className="field">
                          XMUX hMaxReusableSecs
                          <input name="xmux_h_max_reusable_secs" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_h_max_reusable_secs, "1800-3000")} />
                        </label>
                        <label className="field">
                          XMUX cMaxReuseTimes
                          <input name="xmux_c_max_reuse_times" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_c_max_reuse_times, "")} placeholder={tr("Авто")} />
                        </label>
                        <label className="field">
                          XMUX hKeepAlivePeriod
                          <input name="xmux_h_keep_alive_period" pattern="[0-9]{1,10}(-[0-9]{1,10})?" defaultValue={asText(existingTransport.xmux_h_keep_alive_period, "")} placeholder={tr("Авто")} />
                        </label>
                      </div>
                    </details>
                  </>
                ) : null}
                {["grpc", "grpc-tls"].includes(transportKind) ? (
                  <details className="policy-check-advanced form-span">
                    <summary>{t("common.advanced")} · gRPC</summary>
                    <div className="form-grid">
                      {grpcClientTuningFields}
                      {tcpStabilityFields}
                    </div>
                  </details>
                ) : null}
                {realityKind ? (
                  <>
                    <label className="field">
                       {tr("SNI для маскировки")} <input
                        name="server_name"
                        value={realityServerName}
                        onChange={(event) => {
                          const nextServerName = event.target.value;
                          setRealityServerName(nextServerName);
                          if (
                            realityCoverMode === "api" &&
                            !tlsProfiles.some((profile) =>
                              certificateCoversHostname(profile, nextServerName),
                            )
                          ) {
                            setRealityCoverMode("external");
                          }
                          invalidateRealityProbe();
                          if (!realityHandshakeServerEdited) {
                            setRealityHandshakeServer(nextServerName);
                          }
                        }}
                        placeholder="www.microsoft.com"
                        required
                      />
                    </label>
                    {realityAPICoverAvailable ? (
                      <label className="field">
                         {tr("Ответ без действительного ключа")} <select
                          name="cover_mode"
                          value={effectiveRealityCoverMode}
                          onChange={(event) => {
                            const nextMode = event.target.value;
                            setRealityCoverMode(nextMode);
                            if (nextMode === "api") {
                              const selectedStillMatches = realityAPICoverProfiles.some(
                                (profile) => asText(profile.id, "") === tlsProfileChoice,
                              );
                              if (!selectedStillMatches) {
                                selectTransportTlsProfile(
                                  asText(realityAPICoverProfiles[0]?.id, ""),
                                );
                              }
                            }
                            invalidateRealityProbe();
                          }}
                        >
                          <option value="api">{tr("API JSON на своём домене")}</option>
                          <option value="external">{tr("Внешний REALITY target")}</option>
                        </select>
                        <small>{tr("Доступно, потому что выбранный SNI покрыт собственным TLS-сертификатом.")}</small>
                      </label>
                    ) : null}
                    {effectiveRealityCoverMode === "external" ? (
                      <>
                        <label className="field">
                           {tr("Сервер рукопожатия")} <input
                            name="handshake_server"
                            value={realityHandshakeServer}
                            onChange={(event) => {
                              setRealityHandshakeServer(event.target.value);
                              setRealityHandshakeServerEdited(true);
                              invalidateRealityProbe();
                            }}
                            placeholder={tr("Подставляется из SNI")}
                            required
                          />
                          <small>{tr("Автоматически повторяет SNI, пока вы не измените target вручную.")}</small>
                        </label>
                        <label className="field">
                           {tr("Порт рукопожатия")} <input name="handshake_port" type="number" min="1" max="65535" defaultValue={asText(existingTransport.handshake_port, "443")} onChange={invalidateRealityProbe} required />
                        </label>
                        <div className="reality-target-check form-span">
                      <div>
                        <strong>{tr("Проверка target и SNI")}</strong>
                        <small>{tr("Основной SNI проверяется первым; затем каждое конкретное имя из SAN и введённого списка проверяется отдельным TLS-handshake.")}</small>
                      </div>
                      <button className="button button-secondary button-compact" type="button" disabled={realityProbeBusy} onClick={() => void checkRealityTarget()}>{realityProbeBusy ? tr("Проверяю…") : tr("Проверить target и SNI")}</button>
                      {realityProbeResult ? (
                        <div
                          className={`reality-probe-result is-${realityProbeTone}`}
                          role={realityProbeTone === "error" ? "alert" : "status"}
                        >
                          <strong>
                            {realityProbeTone === "error"
                              ? tr("Исправьте target")
                              : realityProbeTone === "warning"
                                ? tr("Совместимо с ограничением")
                                : tr("Проверка пройдена")}
                          </strong>
                          <small>{realityProbeResult}</small>
                          {realityProbeEndpoints.length ? (
                            <div className="reality-probe-endpoints" aria-label={tr("Проверенные адреса target")}>
                              {realityProbeEndpoints.map((endpoint, endpointIndex) => (
                                <span
                                  key={`${asText(endpoint.address, "endpoint")}-${endpointIndex}`}
                                  className={
                                    endpoint.ok === true
                                      ? "is-ok"
                                      : asText(endpoint.error_code, "") === "tls_probe_handshake_failed"
                                        ? "is-warning"
                                        : "is-error"
                                  }
                                >
                                  <code>{asText(endpoint.address, tr("IP не определён"))}</code>
                                  <small>
                                    {endpoint.ok === true
                                      ? `${asText(endpoint.tls_version, tr("TLS не определён"))} · ${asText(endpoint.alpn, tr("ALPN не согласован"))}`
                                      : asText(endpoint.error_message, tr("TLS-handshake не выполнен"))}
                                  </small>
                                </span>
                              ))}
                            </div>
                          ) : null}
                          {realityProbeWildcards.length ? (
                            <small>
                              Wildcard {realityProbeWildcards.join(", ")}  {tr("не добавляется автоматически. Введите конкретный поддомен и проверьте его.")} </small>
                          ) : null}
                        </div>
                      ) : null}
                        </div>
                      </>
                    ) : (
                      <aside className="notice notice-neutral form-span">
                        <span className="notice-icon">i</span>
                        <div>
                          <strong>{tr("Локальная API-маскировка")}</strong>
                          <p>{tr("Выберите ниже TLS-профиль, сертификат которого покрывает SNI. Внешний сайт для рукопожатия не используется.")}</p>
                        </div>
                      </aside>
                    )}
                    <div className="reality-sni-panel form-span">
                      <label className="field">
                         {tr("Дополнительные допустимые SNI")} <input
                          value={realitySniInput}
                          onChange={(event) => {
                            setRealitySniInput(event.target.value);
                            setRealitySniCheckPerformed(false);
                            setRealitySniChecks([]);
                          }}
                          placeholder="www.example.com, cdn.example.com"
                        />
                        <input
                          type="hidden"
                          name="server_names"
                          value={(effectiveRealityCoverMode === "api"
                            ? realitySniInput.split(/[\n,]/).map((value) => value.trim().toLowerCase()).filter(Boolean)
                            : realitySniCheckPerformed ? selectedRealitySnis : savedRealityServerNames).join(",")}
                        />
                        <small>{effectiveRealityCoverMode === "api" ? tr("Каждое имя должно входить в SAN выбранного сертификата.") : tr("Wildcard SAN не сохраняется: введите конкретное имя и запустите проверку.")}</small>
                      </label>
                      {realitySniChecks.length ? (
                        <div className="reality-sni-checks" aria-label={tr("Проверенные дополнительные SNI")}>
                          {realitySniChecks.map((item) => {
                            const confirmed = item.status === "confirmed";
                            const selected = selectedRealitySnis.includes(item.name);
                            return (
                              <label key={item.name} className={`reality-sni-option is-${item.status}`}>
                                <input
                                  type="checkbox"
                                  disabled={!confirmed}
                                  checked={confirmed && selected}
                                  onChange={() => setSelectedRealitySnis((current) =>
                                    current.includes(item.name)
                                      ? current.filter((name) => name !== item.name)
                                      : [...current, item.name]
                                  )}
                                />
                                <span>
                                  <strong>{item.name}</strong>
                                  <small>{confirmed ? tr("Подтверждено") : item.detail}</small>
                                </span>
                              </label>
                            );
                          })}
                        </div>
                      ) : null}
                    </div>
                    <details className="policy-check-advanced form-span">
                      <summary>{t("common.advanced")} · REALITY</summary>
                      <div className="form-grid">
                        {tcpStabilityFields}
                        <label className="field">
                           {tr("Минимальная версия клиента")} <input name="min_client_ver" defaultValue={asText(existingTransport.min_client_ver, "")} placeholder={tr("Без ограничения версии")} />
                        </label>
                        <label className="checkbox-field form-span">
                          <input name="reality_show" type="checkbox" defaultChecked={existingTransport.reality_show === true} />
                          <span><strong>{tr("Отладочный вывод REALITY")}</strong><small>{tr("Обычно выключен; включает подробные сообщения Xray для диагностики.")}</small></span>
                        </label>
                        <fieldset className="form-span nested-settings-group">
                          <legend>{tr("Ограничение непроверенного fallback · необязательно")}</legend>
                          <div className="form-grid">
                            <label className="field">{tr("Upload: после байт")}<input name="reality_fallback_upload_after_bytes" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_upload_after_bytes, "0")} /></label>
                            <label className="field">{tr("Upload: байт/сек.")}<input name="reality_fallback_upload_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_upload_bytes_per_sec, "0")} /></label>
                            <label className="field">{tr("Upload: burst байт/сек.")}<input name="reality_fallback_upload_burst_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_upload_burst_bytes_per_sec, "0")} /></label>
                            <label className="field">{tr("Download: после байт")}<input name="reality_fallback_download_after_bytes" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_download_after_bytes, "0")} /></label>
                            <label className="field">{tr("Download: байт/сек.")}<input name="reality_fallback_download_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_download_bytes_per_sec, "0")} /></label>
                            <label className="field">{tr("Download: burst байт/сек.")}<input name="reality_fallback_download_burst_bytes_per_sec" type="number" min="0" defaultValue={asText(existingTransport.reality_fallback_download_burst_bytes_per_sec, "0")} /></label>
                          </div>
                          <small>{tr("Ограничивает только подключения, не прошедшие проверку REALITY. Скорость 0 отключает ограничение.")}</small>
                        </fieldset>
                        <label className="field">
                           {tr("Максимальная версия клиента")} <input name="max_client_ver" defaultValue={asText(existingTransport.max_client_ver, "")} placeholder={tr("Оставьте пустым")} />
                        </label>
                        <label className="field">
                           {tr("Допуск времени, мс")} <input name="max_time_diff" type="number" min="0" max="86400000" defaultValue={asText(existingTransport.max_time_diff, "0")} />
                        </label>
                        <label className="field">
                           {tr("PROXY protocol для fallback")} <select name="xver" defaultValue={asText(existingTransport.xver, "0")}>
                            <option value="0">{tr("Не передавать")}</option>
                            <option value="1">{tr("v1 · текстовый заголовок")}</option>
                            <option value="2">{tr("v2 · бинарный заголовок")}</option>
                          </select>
                          <small>{tr("Нужно только если fallback-сервис умеет принимать PROXY protocol.")}</small>
                        </label>
                        <label className="field">
                           {tr("spiderX клиента · необязательно")} <input name="spider_x" defaultValue={asText(existingTransport.spider_x, "")} placeholder="/" />
                          <small>{tr("Попадает в экспорт Xray-клиента. Пустое значение не добавляется.")}</small>
                        </label>
                        <label className="checkbox-field form-span">
                          <input name="reality_mldsa65_enabled" type="checkbox" defaultChecked={existingTransport.reality_mldsa65_enabled === true} />
                          <span><strong>{tr("ML-DSA-65 для REALITY")}</strong><small>{tr("Seed хранится в SecretStore, verify попадает клиенту. Target должен отдавать достаточно крупный сертификат; сначала проверьте его через `xray tls ping`.")}</small></span>
                        </label>
                      </div>
                    </details>
                    {transportKind === "reality-grpc" ? (
                      <details className="policy-check-advanced form-span">
                        <summary>{t("common.advanced")} · gRPC</summary>
                        <div className="form-grid">
                          {grpcClientTuningFields}
                        </div>
                      </details>
                    ) : null}
                  </>
                ) : null}
                {transportKind === "hysteria2" ? (
                  <>
                    <>
                        <details className="policy-check-advanced form-span">
                          <summary>{t("common.advanced")} · QUIC / masquerade</summary>
                          <div className="form-grid">
                            <label className="field">
                               {tr("UDP idle timeout, секунд")} <input name="hysteria_udp_idle_timeout" type="number" min="2" max="600" defaultValue={asText(existingXrayHysteria.udp_idle_timeout, "60")} required />
                              <small>{tr("Таймаут неактивной UDP-сессии Hysteria.")}</small>
                            </label>
                            <label className="field">
                               {tr("Управление перегрузкой QUIC")} <select
                                name="hysteria_congestion"
                                value={hysteriaCongestion}
                                onChange={(event) => setHysteriaCongestion(event.target.value)}
                              >
                                <option value="">{tr("Автоматически · Xray")}</option>
                                <option value="bbr">BBR</option>
                                <option value="brutal">Brutal</option>
                              </select>
                            </label>
                            {hysteriaCongestion === "brutal" ? (
                              <>
                                <label className="field">
                                   {tr("Brutal upload, Мбит/с")} <input name="hysteria_brutal_up_mbps" type="number" min="1" max="100000" defaultValue={asText(existingXrayQuic.brutal_up_mbps, "100")} required />
                                </label>
                                <label className="field">
                                   {tr("Brutal download, Мбит/с")} <input name="hysteria_brutal_down_mbps" type="number" min="1" max="100000" defaultValue={asText(existingXrayQuic.brutal_down_mbps, "100")} required />
                                </label>
                                <label className="checkbox-field form-span">
                                  <input name="hysteria_brutal_disable_loss_compensation" type="checkbox" defaultChecked={existingXrayQuic.brutal_disable_loss_compensation === true} />
                                  <span><strong>{tr("Brutal без компенсации потерь")}</strong><small>{tr("Не увеличивать скорость отправки для компенсации потерь.")}</small></span>
                                </label>
                              </>
                            ) : null}
                            <label className="field">
                               {tr("Max idle timeout QUIC, секунд")} <input name="hysteria_max_idle_timeout" type="number" min="4" max="120" defaultValue={asOptionalPositiveText(existingXrayQuic.max_idle_timeout)} placeholder={tr("Авто · 30")} />
                            </label>
                            <label className="field">
                               {tr("Keepalive QUIC, секунд")} <input name="hysteria_keep_alive_period" type="number" min="2" max="60" defaultValue={asOptionalPositiveText(existingXrayQuic.keep_alive_period) || (Object.keys(existingTransport).length ? "" : "15")} placeholder={tr("Пусто · выключено")} />
                            </label>
                            <label className="field">
                               {tr("Максимум входящих потоков")} <input name="hysteria_max_incoming_streams" type="number" min="8" max="1000000" defaultValue={asOptionalPositiveText(existingXrayQuic.max_incoming_streams)} placeholder={tr("Пусто · значение Xray")} />
                            </label>
                            <label className="checkbox-field">
                              <input name="hysteria_disable_path_mtu_discovery" type="checkbox" defaultChecked={existingXrayQuic.disable_path_mtu_discovery === true} />
                              <span><strong>{tr("Отключить Path MTU Discovery")}</strong><small>{tr("Используйте только при проблемах с MTU на маршруте.")}</small></span>
                            </label>
                            <label className="checkbox-field">
                              <input name="hysteria_disable_gso" type="checkbox" defaultChecked={existingXrayQuic.disable_gso === true} />
                              <span><strong>{tr("Отключить GSO")}</strong><small>{tr("Для несовместимых сетевых драйверов.")}</small></span>
                            </label>
                            <label className="checkbox-field">
                              <input name="hysteria_disable_stateless_reset" type="checkbox" defaultChecked={existingXrayQuic.disable_stateless_reset === true} />
                              <span><strong>{tr("Отключить Stateless Reset")}</strong><small>{tr("Не отправлять сброс для неизвестных QUIC-соединений.")}</small></span>
                            </label>
                            <label className="field">
                               {tr("Начальное окно потока, байты")} <input name="hysteria_init_stream_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.init_stream_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="field">
                               {tr("Максимальное окно потока, байты")} <input name="hysteria_max_stream_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.max_stream_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="field">
                               {tr("Начальное окно соединения, байты")} <input name="hysteria_init_connection_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.init_connection_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="field">
                               {tr("Максимальное окно соединения, байты")} <input name="hysteria_max_connection_receive_window" type="number" min="0" max="4294967295" defaultValue={asText(existingXrayQuic.max_connection_receive_window, "")} placeholder={tr("0 · значение Xray")} />
                            </label>
                            <label className="checkbox-field form-span">
                              <input
                                name="hysteria_udp_hop_enabled"
                                type="checkbox"
                                checked={hysteriaUDPHopEnabled}
                                onChange={(event) => setHysteriaUDPHopEnabled(event.target.checked)}
                              />
                              <span><strong>UDP port hopping</strong><small>{tr("Клиент меняет внешний порт, RouterOS перенаправляет диапазон на Hysteria.")}</small></span>
                            </label>
                            {hysteriaUDPHopEnabled ? (
                              <>
                                <label className="field">
                                   {tr("Первый UDP-порт")} <input name="hysteria_udp_hop_port_start" type="number" min="1024" max="65535" defaultValue={asText(existingXrayUDPHop.port_start, "20000")} required />
                                </label>
                                <label className="field">
                                   {tr("Последний UDP-порт")} <input name="hysteria_udp_hop_port_end" type="number" min="1024" max="65535" defaultValue={asText(existingXrayUDPHop.port_end, "20100")} required />
                                </label>
                                <label className="field">
                                   {tr("Минимальный интервал, секунд")} <input name="hysteria_udp_hop_interval_min" type="number" min="5" max="3600" defaultValue={asText(existingXrayUDPHop.interval_min, "15")} required />
                                </label>
                                <label className="field">
                                   {tr("Максимальный интервал, секунд")} <input name="hysteria_udp_hop_interval_max" type="number" min="5" max="3600" defaultValue={asText(existingXrayUDPHop.interval_max, "45")} required />
                                </label>
                                <label className="field form-span">
                                   {tr("Исключить занятые UDP-порты")} <input name="hysteria_udp_hop_excluded_ports" type="text" defaultValue={asText(existingXrayUDPHop.excluded_ports, "")} placeholder="20053, 20080" />
                                </label>
                              </>
                            ) : null}
                            <label className="field">
                               {tr("Masquerade для неизвестных запросов")} <select
                                name="hysteria_masquerade_type"
                                value={hysteriaMasqueradeType}
                                onChange={(event) => {
                                  setHysteriaMasqueradeType(event.target.value);
                                  if (event.target.value === "website") {
                                    setHysteriaWebsiteURL("");
                                    setHysteriaWebsiteBandwidth("1");
                                  }
                                }}
                              >
                                <option value="api">{tr("API JSON · рекомендуется")}</option>
                                <option value="">{tr("Стандартный ответ Xray")}</option>
                                <option value="string">{tr("Статический HTTP-ответ")}</option>
                                <option value="proxy">{tr("Локальный HTTP-сервис")}</option>
                                <option value="website">{tr("Проксировать сайт")}</option>
                              </select>
                              <small>{tr("API JSON отдаёт нейтральный 404 без данных о панели и Xray.")}</small>
                            </label>
                            {hysteriaMasqueradeType === "string" ? (
                              <>
                                <label className="field">
                                  HTTP status
                                  <input name="hysteria_masquerade_status_code" type="number" min="100" max="599" defaultValue={asText(existingXrayMasquerade.status_code, "200")} required />
                                </label>
                                <label className="field form-span">
                                   {tr("Тело ответа")} <textarea name="hysteria_masquerade_content" rows={4} maxLength={8192} defaultValue={asText(existingXrayMasquerade.content, "")} placeholder="Not found" />
                                </label>
                                <label className="field form-span">
                                   {tr("HTTP-заголовки · по одному на строку")} <textarea
                                    name="hysteria_masquerade_headers"
                                    rows={3}
                                    defaultValue={Object.entries(asObject(existingXrayMasquerade.headers)).map(([name, value]) => `${name}: ${asText(value, "")}`).join("\n")}
                                    placeholder={"Content-Type: text/plain\nCache-Control: no-store"}
                                  />
                                </label>
                              </>
                            ) : null}
                            {hysteriaMasqueradeType === "proxy" ? (
                              <>
                                <label className="field form-span">
                                   {tr("URL локального HTTP-сервиса")} <input name="hysteria_masquerade_url" type="url" pattern="http://(127\\.0\\.0\\.1|localhost|\\[::1\\])(:[0-9]{1,5})?(/.*)?" defaultValue={asText(existingXrayMasquerade.url, "")} placeholder="http://127.0.0.1:8080/" required />
                                  <small>{tr("Разрешён только loopback HTTP; внешний URL здесь намеренно запрещён.")}</small>
                                </label>
                                <label className="checkbox-field form-span">
                                  <input name="hysteria_masquerade_rewrite_host" type="checkbox" defaultChecked={existingXrayMasquerade.rewrite_host === true} />
                                  <span><strong>{tr("Переписать Host на адрес локального сервиса")}</strong><small>{tr("Иначе исходный Host запроса будет сохранён.")}</small></span>
                                </label>
                                <label className="checkbox-field form-span">
                                  <input name="hysteria_masquerade_x_forwarded" type="checkbox" defaultChecked={existingXrayMasquerade.x_forwarded === true} />
                                  <span><strong>{tr("Передавать X-Forwarded-*")}</strong><small>{tr("Только доверенному локальному HTTP-сервису.")}</small></span>
                                </label>
                              </>
                            ) : null}
                            {hysteriaMasqueradeType === "website" ? (
                              <>
                                <label className="field">
                                   {tr("Адрес сайта")} <input
                                    name="hysteria_masquerade_url"
                                    type="url"
                                    value={hysteriaWebsiteURL}
                                    onChange={(event) => setHysteriaWebsiteURL(event.target.value)}
                                    placeholder="https://example.com/"
                                    required
                                  />
                                </label>
                                <label className="field">
                                   {tr("Лимит скорости, Мбит/с")} <input
                                    name="hysteria_masquerade_bandwidth_mbps"
                                    type="number"
                                    min="0.1"
                                    max="100"
                                    step="0.1"
                                    value={hysteriaWebsiteBandwidth}
                                    onChange={(event) => setHysteriaWebsiteBandwidth(event.target.value)}
                                    required
                                  />
                                </label>
                                {hysteriaObfsEnabled ? (
                                  <small className="form-span">{tr("С Salamander сайт недоступен обычным HTTP/3-клиентам.")}</small>
                                ) : null}
                              </>
                            ) : null}
                          </div>
                        </details>
                    </>
                    <label className="checkbox-field form-span">
                      <input name="obfs_enabled" type="checkbox" checked={hysteriaObfsEnabled} onChange={(event) => setHysteriaObfsEnabled(event.target.checked)} />
                      <span><strong>Salamander obfuscation</strong><small>{tr("Пароль создаётся автоматически и хранится отдельно.")}</small></span>
                    </label>
                    <label className="checkbox-field form-span">
                      <input name="tls_pin_certificate" type="checkbox" defaultChecked={existingTransport.tls_pin_certificate === true} />
                      <span><strong>{tr("Закрепить выбранный TLS-сертификат")}</strong><small>{tr("Для самоподписанного сертификата профиль получит точный pin вместо небезопасного отключения проверки.")}</small></span>
                    </label>
                  </>
                ) : null}
                {sharedTlsManagedKind ? (
                  <>
                    <label className="field form-span">
                       {tr("TLS-профиль")} <select
                        name="tls_profile_id"
                        value={tlsProfileChoice}
                        onChange={(event) =>
                          selectTransportTlsProfile(event.target.value)
                        }
                        required
                      >
                        <option value="" disabled>{tr("Выберите TLS-профиль")}</option>
                        {tlsProfiles.map((profile) => (
                          <option
                            value={asText(profile.id, "")}
                            key={asText(profile.id, "")}
                          >
                            {itemName(profile)}
                            {asText(profile.certificate_secret_ref, "")
                              ? tr(" · настроен")
                              : tr(" · нужна пара")}
                          </option>
                        ))}
                      </select>
                    </label>
                    {tlsProfileChoice && !selectedTlsProfileComplete ? (
                      <small className="form-span">{tr("Настройте сертификат в TLS-профилях.")}</small>
                    ) : null}
                    {!tlsProfileChoice && tlsProfiles.length === 0 ? (
                      <small className="form-span">{tr("Создайте TLS-профиль в разделе TLS-профили.")}</small>
                    ) : null}
                  </>
                ) : cdnTransportKind ? (
                  <aside className="notice notice-neutral form-span">
                    <span className="notice-icon">i</span>
                    <div>
                      <strong>{tr("TLS origin настраивается в карточке каждого CDN")}</strong>
                      <p>
                         {tr("Так Cloudflare, Yandex и другие CDN могут использовать разные origin-домены, порты и сертификаты в одном транспортном профиле.")} </p>
                    </div>
                  </aside>
                ) : null}
                {transportRecommendation ? (
                  <section
                    className="transport-recommendations form-span"
                    aria-label={tr("Сброс параметров транспорта")}
                  >
                    <div className="transport-recommendations-heading">
                      <div>
                        <strong>{t("transport.base")}</strong>
                        <small>{t("transport.baseSafe")}</small>
                      </div>
                      <div className="transport-recommendations-actions">
                        {transportActionMenu}
                      </div>
                    </div>
                    {transportActionCount ? (
                      <div
                        className="transport-reset-summary"
                        role="status"
                        aria-live="polite"
                      >
                        <strong>{t("transport.resetStatus")}</strong>
                        <span>{selectedTransportActionLabels.join(" · ")}</span>
                      </div>
                    ) : null}
                  </section>
                ) : null}
                {directInboundKind || cdnTransportKind ? (
                  <Toggle
                    className="form-span direct-transport-enabled"
                    name="enabled"
                    checked={transportEnabled}
                    onChange={(enabled) => {
                      setTransportEnabled(enabled);
                      if (!enabled && cdnTransportKind) {
                        setCdnDeployments((current) =>
                          current.map((deployment) => ({ ...deployment, enabled: false })),
                        );
                      }
                    }}
                    tone="state"
                    label={tr("Транспорт включён")}
                    description={tr("Изменение вступит в силу только после проверки и Apply.")}
                  />
                ) : null}
              </div>
            )}
            {saveError ? (
              <div className="inline-result inline-result-error" role="alert">
                <span>!</span>
                {saveError}
              </div>
            ) : null}
            <div className="modal-actions">
              {Boolean(subscriptionId) ? (
                <button
                  className="button button-danger"
                  type="button"
                  disabled={busy}
                  onClick={async () => {
                    if (!deleteArmed) {
                      setDeleteArmed(true);
                      setSaveError(
                        tr("Нажмите «Удалить подписку» ещё раз. Секретный URL останется в защищённом хранилище."),
                      );
                      return;
                    }
                    setBusy(true);
                    setSaveError("");
                    try {
                      await deleteCollectionItem(
                        "subscriptions",
                        workingSubscriptionId,
                      );
                      await onSaved();
                      onClose();
                    } catch (error) {
                      setSaveError(errorMessage(error));
                      setBusy(false);
                    }
                  }}
                >
                  {deleteArmed ? tr("Удалить подписку") : tr("Подготовить удаление")}
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
                  ? discoveryReady
                    ? tr("Сохраняю…")
                    : tr("Загружаю список…")
                  : kind === "subscription"
                    ? discoveryReady
                      ? tr("Сохранить выбор")
                      : tr("Проверить подписку и продолжить")
                    : tr("Сохранить изменения")}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
