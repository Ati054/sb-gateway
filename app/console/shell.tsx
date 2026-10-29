"use client";

import { GatewayApiError, JsonObject, createCollectionItem, deleteCollectionItem, getBootstrapState, getClientTelemetry, getCurrentDraft, getOverview, getRouterOsContainerStatus, getSelectorStatus, getStatus, isUncertainOperationError, logout, runDraftOperation, saveCurrentDraft, updateCollectionItem } from "../api-client";
import { DraftAutosave } from "../draft-autosave";
import { useLanguage } from "../i18n";
import { mergeRuntimeStatus } from "../runtime-status";
import { mergeOverviewState } from "../overview-state";
import { ApplyDialog, ResetDraftDialog } from "./apply-dialog";
import { AddDialog } from "./client-dialog";
import { Clients } from "./clients";
import { ConnectionDialog } from "./connection-dialog";
import { Connections } from "./connections";
import { Operations } from "./operations";
import { Overview } from "./overview";
import { PolicyDialog } from "./policy-dialog";
import { Routing } from "./routing";
import { Settings } from "./settings";
import { SetupWizard } from "./setup-wizard";
import { ConnectionAddressContext, DraftEnvelope, ROUTING_EXPANDED_POLICY_STORAGE_KEY, ROUTING_SAVE_MESSAGE_STORAGE_KEY, RevisionState, Screen, ViewTransitionDocument, asObject, asObjectList, asStringList, asText, draftConfigsMatchIgnoringReadiness, errorMessage, hasPublicTlsPair, importReviewCounts, loadRouterOSDiscovery, markCurrentDraftUnready, navigation, pendingChangeText, screenFromHash, screenHash, withDeploymentReadiness } from "./shared";
import { TlsProfileDialog } from "./tls-profile-dialog";
import { useCallback, useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";

export function GatewayConsole({
  username,
  onSessionEnded,
}: {
  username: string;
  onSessionEnded: () => void;
}) {
  const { locale, setLocale, t, tr } = useLanguage();
  const [screen, setScreen] = useState<Screen>("overview");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [applyMode, setApplyMode] = useState<"check" | "apply" | null>(null);
  const [resetDraftOpen, setResetDraftOpen] = useState(false);
  const [addKind, setAddKind] = useState<"local" | "remote" | null>(null);
  const [editingLocalId, setEditingLocalId] = useState("");
  const [editingRemoteId, setEditingRemoteId] = useState("");
  const [setupOpen, setSetupOpen] = useState(false);
  const [policyDialog, setPolicyDialog] = useState<{
    policyId?: string;
  } | null>(null);
  const [connectionDialog, setConnectionDialog] = useState<{
    kind: "subscription" | "transport";
    transportId?: string;
    subscriptionId?: string;
  } | null>(null);
  const [tlsProfileDialog, setTlsProfileDialog] = useState<{
    profileId?: string;
  } | null>(null);
  const [runtimeStatus, setRuntimeStatus] = useState<JsonObject>();
  const [subscriptionMetadata, setSubscriptionMetadata] = useState<Record<string, JsonObject>>({});
  const [runtimeDetailsReady, setRuntimeDetailsReady] = useState(false);
  const [overviewData, setOverviewData] = useState<JsonObject>();
  const [liveRouteros, setLiveRouteros] = useState<JsonObject>({});
  const [clientTelemetry, setClientTelemetry] = useState<JsonObject>();
  const [runtimeError, setRuntimeError] = useState("");
  const [draftEnvelope, setDraftEnvelope] = useState<DraftEnvelope>();
  const [draftError, setDraftError] = useState("");
  const routingAutosave = useRef<DraftAutosave | null>(null);
  const routingReset = useRef<(() => void) | undefined>(undefined);
  const [routingFormPending, setRoutingFormPending] = useState(false);
  const [routingFormSaving, setRoutingFormSaving] = useState(false);
  const [routingMountVersion, setRoutingMountVersion] = useState(0);
  const [preparingApply, setPreparingApply] = useState(false);
  const preparingApplyRef = useRef(false);
  const navigationRequest = useRef(0);
  const committedScreen = useRef(screen);
  const registerRoutingAutosave = useCallback(
    (autosave: DraftAutosave | null, reset?: () => void) => {
      routingAutosave.current = autosave;
      routingReset.current = reset;
    }, [],
  );

  useEffect(() => {
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!routingAutosave.current?.pending) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, []);
  const [pendingChangePopoverOpen, setPendingChangePopoverOpen] =
    useState(false);
  const runtimeRefreshInFlight = useRef(false);
  const detailedStatusRefreshInFlight = useRef(false);
  const clientTelemetryRefreshInFlight = useRef(false);
  const draftRefreshInFlight = useRef(false);
  const routerosRefreshInFlight = useRef(false);
  const routerosContainerRefreshInFlight = useRef(false);
  const routerosRefreshedAt = useRef(0);

  const navigateToScreen = useCallback(async (nextScreen: Screen) => {
    const request = ++navigationRequest.current;
    const currentScreen = screenFromHash(window.location.hash);
    if (currentScreen === nextScreen) return;
    try {
      await routingAutosave.current?.flush();
    } catch (error) {
      if (request !== navigationRequest.current) return;
      setDraftError(errorMessage(error));
      return;
    }
    const commitNavigation = () => {
      if (request !== navigationRequest.current) return;
      if (currentScreen === "routing" && nextScreen !== "routing") {
        window.sessionStorage.removeItem(ROUTING_EXPANDED_POLICY_STORAGE_KEY);
        window.sessionStorage.removeItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY);
      }
      flushSync(() => setScreen(nextScreen));
      committedScreen.current = nextScreen;
      window.history.pushState(null, "", screenHash(nextScreen));
    };
    const transitionDocument = document as ViewTransitionDocument;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reduceMotion && transitionDocument.startViewTransition) {
      try {
        const transition = transitionDocument.startViewTransition(commitNavigation);
        // Chromium rejects `ready` when a newer lateral navigation supersedes
        // an in-flight transition. The state update still completes, so consume
        // that expected rejection instead of surfacing a false page error.
        void transition.ready?.catch(() => undefined);
        void transition.updateCallbackDone?.catch(() => undefined);
        void transition.finished?.catch(() => undefined);
      } catch {
        commitNavigation();
      }
    } else {
      commitNavigation();
    }
  }, []);

  useEffect(() => {
    const syncScreenFromLocation = async () => {
      const request = ++navigationRequest.current;
      const previousScreen = committedScreen.current;
      const nextScreen = screenFromHash(window.location.hash);
      try {
        await routingAutosave.current?.flush();
      } catch (error) {
        if (request !== navigationRequest.current) return;
        setDraftError(errorMessage(error));
        window.history.replaceState(null, "", screenHash(previousScreen));
        return;
      }
      if (request !== navigationRequest.current) return;
      if (previousScreen === "routing" && nextScreen !== "routing") {
        window.sessionStorage.removeItem(ROUTING_EXPANDED_POLICY_STORAGE_KEY);
        window.sessionStorage.removeItem(ROUTING_SAVE_MESSAGE_STORAGE_KEY);
      }
      committedScreen.current = nextScreen;
      setScreen(nextScreen);
    };

    if (window.location.hash) {
      syncScreenFromLocation();
    } else {
      window.history.replaceState(null, "", screenHash("overview"));
    }

    window.addEventListener("hashchange", syncScreenFromLocation);
    window.addEventListener("popstate", syncScreenFromLocation);
    return () => {
      window.removeEventListener("hashchange", syncScreenFromLocation);
      window.removeEventListener("popstate", syncScreenFromLocation);
    };
  }, []);

  const current = navigation.find((item) => item.id === screen)!;
  const routerosSummary: JsonObject = {
    ...asObject(overviewData?.routeros),
    ...liveRouteros,
  };
  const displayedOverview = overviewData
    ? { ...overviewData, routeros: routerosSummary }
    : undefined;
  const draftConfig = asObject(draftEnvelope?.config);
  const reverseTelemetryNeeded = screen === "routing"
    && asObjectList(draftConfig.reverse_vless_exits).some(exit => exit.enabled !== false);
  const draftRevision = asText(draftEnvelope?.revision, "");
  const activeRevision = asText(overviewData?.active_revision, "");
  // A periodic overview for an older draft must not hide a just-saved change.
  const overviewForDraft = asText(overviewData?.draft_revision, "") === draftRevision
    ? overviewData : undefined;
  const overviewPendingChangeCount = overviewForDraft?.pending_change_count;
  const configurationHydrated = Boolean(overviewData && draftEnvelope);
  const reportedPendingChangeCount =
    typeof overviewPendingChangeCount === "number"
      ? overviewPendingChangeCount
      : draftEnvelope?.pending_change_count;
  const pendingChangeCount =
    typeof reportedPendingChangeCount === "number"
      ? Math.max(0, Math.trunc(reportedPendingChangeCount))
      : activeRevision && activeRevision === draftRevision
        ? 0
        : 0;
  const overviewConfigChangeCount = overviewForDraft?.pending_config_change_count;
  const reportedConfigChangeCount =
    typeof overviewConfigChangeCount === "number"
      ? overviewConfigChangeCount
      : draftEnvelope?.pending_config_change_count;
  const revisionsMatch = Boolean(
    activeRevision && draftRevision && activeRevision === draftRevision,
  );
  const pendingConfigChangeCount =
    typeof reportedConfigChangeCount === "number"
      ? Math.max(0, Math.trunc(reportedConfigChangeCount))
      : revisionsMatch
        ? 0
        : pendingChangeCount;
  const pendingConfigChanges = asObjectList(
    draftEnvelope?.pending_config_changes ??
      overviewForDraft?.pending_config_changes,
  );
  const reportedRuntimeUpdateRequired =
    overviewForDraft?.runtime_update_required ??
    draftEnvelope?.runtime_update_required;
  const reportedRuntimeUpdateOnly =
    overviewForDraft?.runtime_update_only ?? draftEnvelope?.runtime_update_only;
  const runtimeUpdateOnly =
    configurationHydrated &&
    (reportedRuntimeUpdateOnly === true ||
      (reportedRuntimeUpdateRequired === true && pendingConfigChangeCount === 0) ||
      (revisionsMatch &&
        pendingChangeCount > 0 &&
        pendingConfigChangeCount === 0));
  const hasPendingAction =
    configurationHydrated &&
    (pendingConfigChangeCount > 0 || runtimeUpdateOnly || routingFormPending);
  const displayedChangeCount = pendingConfigChangeCount + Number(routingFormPending);
  const hasActiveConfiguration = Boolean(
    activeRevision || draftEnvelope?.has_active_configuration,
  );
  const revisionState: RevisionState =
    !configurationHydrated
      ? "loading"
      : hasActiveConfiguration && pendingConfigChangeCount === 0 && !routingFormPending
        ? "applied"
        : "draft";
  const draftReviewCounts = importReviewCounts(draftConfig);
  const draftManagement = asObject(asObject(draftConfig.system).management);
  const selectedManagementIngress = asStringList(
    draftManagement.allowed_ingress_interfaces,
  );
  const managementIngressReady = selectedManagementIngress.length > 0;

  const refreshLiveRouterOS = useCallback(async () => {
    if (
      routerosRefreshInFlight.current ||
      Date.now() - routerosRefreshedAt.current < 30_000
    ) {
      return;
    }
    routerosRefreshInFlight.current = true;
    try {
      const response = await loadRouterOSDiscovery();
      setLiveRouteros(response);
      routerosRefreshedAt.current = Date.now();
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
      // The saved RouterOS summary remains usable when live REST is unavailable.
    } finally {
      routerosRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshLiveRouterOSContainer = useCallback(async () => {
    if (routerosContainerRefreshInFlight.current) return;
    routerosContainerRefreshInFlight.current = true;
    try {
      const response = await getRouterOsContainerStatus<JsonObject>();
      const container = asObject(response.container);
      setLiveRouteros((current) => ({ ...current, container }));
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
      // Keep the last confirmed value when the lightweight REST read fails.
    } finally {
      routerosContainerRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshRuntime = useCallback(async () => {
    if (runtimeRefreshInFlight.current) return;
    runtimeRefreshInFlight.current = true;
    try {
      const response = await getOverview<JsonObject>();
      setOverviewData((current) => mergeOverviewState(current, response));
      setRuntimeStatus((current) =>
        mergeRuntimeStatus(current, asObject(response.status)),
      );
      setRuntimeError("");
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
        return;
      }
      setRuntimeError(errorMessage(error));
    } finally {
      runtimeRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshDraft = useCallback(async () => {
    if (draftRefreshInFlight.current) return;
    draftRefreshInFlight.current = true;
    try {
      const response = await getCurrentDraft<DraftEnvelope>();
      setDraftEnvelope(response);
      setDraftError("");
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
        return;
      }
      setDraftError(errorMessage(error));
    } finally {
      draftRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshInitialState = useCallback(async () => {
    if (runtimeRefreshInFlight.current || draftRefreshInFlight.current) return;
    runtimeRefreshInFlight.current = true;
    draftRefreshInFlight.current = true;
    try {
      const [response, detailedStatus] = await Promise.all([
        getBootstrapState<JsonObject>(),
        getStatus<JsonObject>().catch((error) => {
          if (error instanceof GatewayApiError && error.status === 401) throw error;
          return undefined;
        }),
      ]);
      const overview = asObject(response.overview);
      const draft = asObject(response.draft) as DraftEnvelope;
      setOverviewData((current) => mergeOverviewState(current, overview));
      setRuntimeStatus((current) =>
        detailedStatus
          ? mergeRuntimeStatus(
              mergeRuntimeStatus(current, asObject(overview.status)),
              detailedStatus,
            )
          : mergeRuntimeStatus(current, asObject(overview.status)),
      );
      setRuntimeDetailsReady(Boolean(detailedStatus));
      setDraftEnvelope(draft);
      setRuntimeError("");
      setDraftError("");
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
        return;
      }
      const message = errorMessage(error);
      setRuntimeError(message);
      setDraftError(message);
    } finally {
      runtimeRefreshInFlight.current = false;
      draftRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshDetailedStatus = useCallback(async () => {
    if (detailedStatusRefreshInFlight.current) return;
    detailedStatusRefreshInFlight.current = true;
    try {
      const detailedStatus = await getStatus<JsonObject>();
      setRuntimeStatus((current) => mergeRuntimeStatus(current, detailedStatus));
      setRuntimeDetailsReady(true);
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
      // Overview already contains the compact runtime status. A delayed
      // selector-history refresh must never blank or block the main screen.
    } finally {
      detailedStatusRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshClientTelemetry = useCallback(async () => {
    if (clientTelemetryRefreshInFlight.current) return;
    clientTelemetryRefreshInFlight.current = true;
    try {
      const nextTelemetry = await getClientTelemetry<JsonObject>();
      setClientTelemetry((current) => {
        const currentSample = asText(current?.sampled_at, "");
        const nextSample = asText(nextTelemetry.sampled_at, "");
        return current && currentSample === nextSample ? current : nextTelemetry;
      });
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) {
        onSessionEnded();
      }
    } finally {
      clientTelemetryRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const selectorRefreshInFlight = useRef(false);
  const refreshSelectorStatus = useCallback(async () => {
    if (selectorRefreshInFlight.current) return;
    selectorRefreshInFlight.current = true;
    try {
      const status = await getSelectorStatus<JsonObject>();
      setRuntimeStatus((current) => mergeRuntimeStatus(current, status));
      setRuntimeDetailsReady(true);
    } catch (error) {
      if (error instanceof GatewayApiError && error.status === 401) onSessionEnded();
    } finally {
      selectorRefreshInFlight.current = false;
    }
  }, [onSessionEnded]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshRuntime(), refreshDraft(), refreshDetailedStatus(), refreshSelectorStatus()]);
  }, [refreshDetailedStatus, refreshDraft, refreshRuntime, refreshSelectorStatus]);

  async function prepareApply() {
    if (preparingApplyRef.current) return;
    preparingApplyRef.current = true;
    setPreparingApply(true);
    try {
      await routingAutosave.current?.flush();
      setDraftError("");
      setApplyMode("apply");
    } catch (error) {
      setDraftError(errorMessage(error));
    } finally {
      preparingApplyRef.current = false;
      setPreparingApply(false);
    }
  }

  useEffect(() => {
    if (screen !== "routing") return;
    const refresh = () => {
      if (document.visibilityState === "visible") void refreshSelectorStatus();
    };
    const initial = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 5_000);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, [screen, refreshSelectorStatus]);

  useEffect(() => {
    const initial = window.setTimeout(() => {
      void refreshInitialState();
      void refreshLiveRouterOS();
    }, 0);
    const timer = window.setInterval(refreshRuntime, 60_000);
    const routerosTimer = window.setInterval(refreshLiveRouterOS, 300_000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      window.clearInterval(routerosTimer);
    };
  }, [refreshInitialState, refreshLiveRouterOS, refreshRuntime]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (screen !== "overview") void refreshLiveRouterOS();
      if (screen === "routing" || screen === "operations") {
        void refreshDetailedStatus();
      }
    }, 0);
    return () => window.clearTimeout(timer);
  }, [refreshDetailedStatus, refreshLiveRouterOS, screen]);

  useEffect(() => {
    const refreshVisibleState = () => {
      if (document.visibilityState !== "visible") return;
      void refreshRuntime();
      void refreshDetailedStatus();
      void refreshLiveRouterOS();
    };
    document.addEventListener("visibilitychange", refreshVisibleState);
    return () => document.removeEventListener("visibilitychange", refreshVisibleState);
  }, [refreshDetailedStatus, refreshLiveRouterOS, refreshRuntime]);

  useEffect(() => {
    if (!overviewData) return;
    const initial = window.setTimeout(() => void refreshDetailedStatus(), 3_000);
    const timer = window.setInterval(
      refreshDetailedStatus,
      screen === "overview" ? 30_000 : 60_000,
    );
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, [overviewData, refreshDetailedStatus, screen]);

  useEffect(() => {
    if ((screen !== "overview" && !reverseTelemetryNeeded) || !overviewData) return;
    const refreshVisible = () => {
      if (document.visibilityState === "visible") void refreshClientTelemetry();
    };
    const initial = window.setTimeout(refreshVisible, 750);
    // Poll between the agent's 30-second samples. Identical sampled_at values
    // are discarded above, so the table is not repainted for duplicate data.
    const timer = window.setInterval(refreshVisible, 15_000);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, [overviewData, refreshClientTelemetry, screen, reverseTelemetryNeeded]);

  useEffect(() => {
    if (screen !== "overview" || !overviewData) return;
    const refreshVisible = () => {
      if (document.visibilityState === "visible") {
        void refreshLiveRouterOSContainer();
      }
    };
    const initial = window.setTimeout(refreshVisible, 500);
    const timer = window.setInterval(refreshVisible, 30_000);
    document.addEventListener("visibilitychange", refreshVisible);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshVisible);
    };
  }, [overviewData, refreshLiveRouterOSContainer, screen]);

  return (
    <ConnectionAddressContext.Provider value={asObject(overviewData?.connection_address)}>
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        {t("shell.skip")}
      </a>
      <aside className={`sidebar ${sidebarOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <span className="brand-mark">SB</span>
          <div>
            <strong>Gateway</strong>
            <small>VLESS · MikroTik</small>
          </div>
          <button
            className="sidebar-close"
            onClick={() => setSidebarOpen(false)}
            aria-label={t("shell.closeMenu")}
          >
            ×
          </button>
        </div>

        <nav aria-label={t("shell.navigation")}>
          {navigation.map((item) => (
            <button
              key={item.id}
              className={screen === item.id ? "nav-active" : ""}
              onClick={() => {
                navigateToScreen(item.id);
                setSidebarOpen(false);
              }}
            >
              <span className="nav-icon">{t(item.short)}</span>
              <span>
                <strong>{t(item.label)}</strong>
                <small>{t(item.description)}</small>
              </span>
            </button>
          ))}
        </nav>

        <div className="sidebar-system">
          <div className="system-title">
            <span
              className={
                runtimeStatus?.state === "healthy" ? "pulse-dot" : "status-dot"
              }
            />
            <strong>
              {runtimeError
                ? t("status.error")
                : runtimeStatus?.state === "healthy"
                  ? t("status.healthy")
                  : runtimeStatus?.state === "unconfigured"
                    ? t("status.unconfigured")
                    : t("status.checking")}
            </strong>
          </div>
          {(() => {
            const build = asObject(overviewData?.build);
            const containerVersion = asText(build.container_version, "");
            return (
          <dl>
            <div>
              <dt>RouterOS</dt>
              <dd>{asText(routerosSummary.detected_version, t("status.fromExport"))}</dd>
            </div>
            <div>
              <dt>{t("status.channel")}</dt>
              <dd>{asText(routerosSummary.channel, t("status.notDetected"))}</dd>
            </div>
            <div>
              <dt>{t("status.core")}</dt>
              <dd title={`${asText(build.active_core_name, t("status.notDefined"))} ${asText(build.active_core_version, "")}`}>
                {asText(build.active_core_name, t("status.notDefined"))} {asText(build.active_core_version, "")}
              </dd>
            </div>
            <div>
              <dt>{t("status.container")}</dt>
              <dd>{containerVersion ? `v${containerVersion}` : "—"}</dd>
            </div>
          </dl>
            );
          })()}
        </div>

        <div className="profile">
          <span className="avatar avatar-small">A</span>
          <div>
            <strong>{username}</strong>
            <small>{t("shell.localNetwork")}</small>
          </div>
          <button
            className="language-toggle"
            type="button"
            title={
              locale === "ru"
                ? t("language.switchToEnglish")
                : t("language.switchToRussian")
            }
            aria-label={
              locale === "ru"
                ? t("language.switchToEnglish")
                : t("language.switchToRussian")
            }
            onClick={() => setLocale(locale === "ru" ? "en" : "ru")}
          >
            {locale.toUpperCase()}
          </button>
          <button
            className="icon-button"
            aria-label={t("shell.logout")}
            onClick={async () => {
              try {
                await logout();
              } finally {
                onSessionEnded();
              }
            }}
          >
            ↪
          </button>
        </div>
      </aside>

      {sidebarOpen ? (
        <button
          className="sidebar-scrim"
          aria-label={t("shell.closeMenu")}
          onClick={() => setSidebarOpen(false)}
        />
      ) : null}

      <div className={`workspace screen-${screen}-workspace`}>
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu"
              onClick={() => setSidebarOpen(true)}
              aria-label={t("shell.openMenu")}
            >
              ☰
            </button>
            <div>
              <span>SB Gateway</span>
              <i>/</i>
              <strong>{t(current.label)}</strong>
            </div>
          </div>
          <div className="draft-actions">
            <div
              className={`draft-change-disclosure ${
                pendingChangePopoverOpen ? "is-open" : ""
              }`}
              onMouseEnter={() => {
                if (pendingConfigChangeCount > 0) setPendingChangePopoverOpen(true);
              }}
              onMouseLeave={() => setPendingChangePopoverOpen(false)}
              onBlur={(event) => {
                if (!event.currentTarget.contains(event.relatedTarget)) {
                  setPendingChangePopoverOpen(false);
                }
              }}
            >
              {displayedChangeCount > 0 && !draftError ? (
                <button
                  type="button"
                  className={`draft-label revision-${revisionState}`}
                  aria-expanded={pendingChangePopoverOpen}
                  aria-controls="pending-change-popover"
                  onFocus={() => setPendingChangePopoverOpen(true)}
                  onClick={() =>
                    setPendingChangePopoverOpen((currentValue) => !currentValue)
                  }
                >
                  <i aria-hidden="true" />
                  {tr("Изменения · {value1}", { value1: displayedChangeCount })}
                </button>
              ) : (
                <span
                  className={`draft-label ${
                    runtimeUpdateOnly
                      ? "revision-runtime"
                      : `revision-${revisionState}`
                  }`}
                >
                  <i aria-hidden="true" />
                  {draftError
                    ? tr("Ошибка загрузки изменений")
                    : runtimeUpdateOnly
                      ? tr("Есть обновление шлюза")
                      : revisionState === "applied"
                        ? tr("Применено")
                        : tr("Загружаю изменения")}
                </span>
              )}
              {pendingConfigChangeCount > 0 ? (
                <div
                  className="draft-change-popover"
                  id="pending-change-popover"
                  role="tooltip"
                >
                  <strong>{tr("Что изменилось")}</strong>
                  <ul>
                    {(pendingConfigChanges.length
                      ? pendingConfigChanges.slice(0, 8)
                      : [{
                          collection: "configuration",
                          op: "replace",
                        }]
                    ).map((change, index) => (
                      <li key={`${asText(change.path, "change")}-${index}`}>
                        {pendingConfigChanges.length
                          ? pendingChangeText(change, locale)
                          : tr("{value1} изменений конфигурации", { value1: pendingConfigChangeCount })}
                      </li>
                    ))}
                  </ul>
                  {pendingConfigChanges.length > 8 ? (
                    <small>{tr("Ещё")} {pendingConfigChanges.length - 8}</small>
                  ) : null}
                </div>
              ) : null}
            </div>
            <button
              className="button button-secondary"
              onClick={() => {
                try {
                  routingReset.current?.();
                  setDraftError("");
                  if (pendingConfigChangeCount > 0) setResetDraftOpen(true);
                } catch (error) {
                  setDraftError(errorMessage(error));
                }
              }}
              disabled={routingFormSaving || preparingApply || (displayedChangeCount === 0 || !hasActiveConfiguration)}
              title={
                !hasActiveConfiguration
                  ? tr("Сначала примените первую конфигурацию")
                  : pendingConfigChangeCount === 0
                    ? runtimeUpdateOnly
                      ? tr("Черновик не изменён — доступно обновление компонентов шлюза")
                      : tr("Несохранённых изменений нет")
                    : tr("Вернуть черновик к последней применённой конфигурации")
              }
            >
               {tr("Сбросить")} </button>
            <button
              className="button button-primary"
              onClick={() => void prepareApply()}
              disabled={preparingApply || revisionState === "loading" || !hasPendingAction}
              title={
                runtimeUpdateOnly
                  ? tr("Проверить, затрагивает ли обновление runtime или управляемые правила RouterOS")
                  : revisionState === "loading"
                    ? tr("Сначала дождитесь загрузки ревизий")
                    : revisionState === "applied"
                      ? tr("Текущая ревизия уже применена")
                    : tr("Безопасно применить проверенный черновик")
              }
            >
              {preparingApply
                ? tr("Сохраняю…")
                : runtimeUpdateOnly && !routingFormPending
                ? tr("Применить обновление")
                : revisionState === "applied"
                  ? tr("Применено")
                  : tr("Применить ({value1})", { value1: displayedChangeCount })}
            </button>
          </div>
        </header>

        <main id="main-content" className={`main-content screen-${screen}`}>
          {screen === "overview" ? (
            <Overview
              onNavigate={navigateToScreen}
              onOpenSetup={() => setSetupOpen(true)}
              onAddClient={() => navigateToScreen("clients")}
              onEditClient={(kind, id) => {
                if (kind === "remote") setEditingRemoteId(id);
                else setEditingLocalId(id);
              }}
              runtime={runtimeStatus}
              runtimeError={runtimeError}
              overview={displayedOverview}
              clientTelemetry={clientTelemetry}
              config={draftConfig}
            />
          ) : null}
          {screen === "clients" ? (
            <Clients
              onAdd={setAddKind}
              onEditLocal={setEditingLocalId}
              onEditRemote={setEditingRemoteId}
              config={draftConfig}
              revisionState={revisionState}
            />
          ) : null}
          {screen === "routing" ? (
            configurationHydrated ? (
              <Routing
                key={routingMountVersion}
                onAddPolicy={() => setPolicyDialog({})}
                onEditPolicy={(policyId) => setPolicyDialog({ policyId })}
                config={draftConfig}
                runtime={{ ...runtimeStatus, reverse_telemetry: clientTelemetry }}
                runtimeDetailsReady={runtimeDetailsReady}
                revisionState={revisionState}
                routeros={routerosSummary}
                onDraftChanged={refreshDraft}
                onAutosaveChange={registerRoutingAutosave}
                onPendingChange={setRoutingFormPending}
                onSavingChange={setRoutingFormSaving}
              />
            ) : (
              <section className="card screen-hydration-state" role="status">
                 {tr("Загружаю настройки маршрутизации…")} </section>
            )
          ) : null}
          {screen === "connections" ? (
            configurationHydrated ? (
              <Connections
                certificateStatus={asObject(asObject(runtimeStatus).acme)}
                subscriptionMetadata={subscriptionMetadata}
                setSubscriptionMetadata={setSubscriptionMetadata}
                onAddSubscription={() =>
                  setConnectionDialog({ kind: "subscription" })
                }
                onEditSubscription={(subscriptionId) =>
                  setConnectionDialog({ kind: "subscription", subscriptionId })
                }
                onConfigureTransport={(transportId) =>
                  setConnectionDialog({ kind: "transport", transportId })
                }
                onAddTlsProfile={() => setTlsProfileDialog({})}
                onEditTlsProfile={(profileId) => setTlsProfileDialog({ profileId })}
                onDraftChanged={refreshDraft}
                config={draftConfig}
                revisionState={revisionState}
              />
            ) : (
              <section className="card screen-hydration-state" role="status">
                 {tr("Загружаю настройки подключений…")} </section>
            )
          ) : null}
          {screen === "operations" ? (
            <Operations
              onRefresh={refreshAll}
              onDraftChanged={refreshDraft}
              onNavigate={navigateToScreen}
              overview={displayedOverview}
              runtime={runtimeStatus}
              config={draftConfig}
            />
          ) : null}
          {screen === "settings" ? (
            <Settings
              key={draftRevision || "draft-loading"}
              config={draftConfig}
              routeros={routerosSummary}
              onDraftChanged={refreshDraft}
              onRouterOSChanged={refreshLiveRouterOSContainer}
            />
          ) : null}
        </main>
      </div>

      {applyMode ? (
        <ApplyDialog
          mode={applyMode}
          publicTlsReady={hasPublicTlsPair(draftConfig)}
          networkReviewPending={draftReviewCounts.pending}
          managementIngressReady={managementIngressReady}
          onPlan={() =>
            runDraftOperation("plan", {
              config: withDeploymentReadiness(draftConfig, true),
            })
          }
          onClose={() => setApplyMode(null)}
          onRun={async (operation) => {
            let targetRevision = "";
            try {
              if (operation === "apply") {
                const saved = await saveCurrentDraft<DraftEnvelope>({
                  config: withDeploymentReadiness(draftConfig, true),
                });
                targetRevision = asText(saved.revision, "");
              }
              try {
                return await runDraftOperation(operation);
              } catch (error) {
                if (operation === "apply") {
                  const uncertain = isUncertainOperationError(error);
                  if (uncertain && targetRevision) {
                    for (let attempt = 0; attempt < 12; attempt += 1) {
                      await new Promise((resolve) => window.setTimeout(resolve, 5000));
                      try {
                        const status = await getStatus<JsonObject>();
                        const appliedRevision = asText(
                          status.active_revision,
                          asText(asObject(status.last_apply).revision, ""),
                        );
                        if (appliedRevision === targetRevision) {
                          return {
                            ok: true,
                            operation: "applied_after_reconnect",
                            revision: targetRevision,
                            message:
                              tr("Связь с запросом прерывалась, но control plane подтвердил, что именно эта ревизия успешно применена."),
                          };
                        }
                      } catch {
                        // The next bounded status attempt may succeed while the
                        // already-running Safe Mode operation continues.
                      }
                    }
                    throw new GatewayApiError(
                      tr("Ответ Apply потерян, а итог пока не подтверждён. Не запускайте применение повторно: обновите статус через минуту."),
                      { code: "apply_status_unknown" },
                    );
                  }
                  await markCurrentDraftUnready();
                }
                throw error;
              }
            } finally {
              // Apply already confirms the committed revision and readiness.
              // Slow history/telemetry reads must not prolong its busy state.
              void refreshAll();
            }
          }}
        />
      ) : null}
      {resetDraftOpen ? (
        <ResetDraftDialog
          changeCount={pendingConfigChangeCount}
          onClose={() => setResetDraftOpen(false)}
          onReset={async () => {
            try {
              const result = await runDraftOperation("reset");
              setDraftEnvelope(await getCurrentDraft<DraftEnvelope>());
              setRoutingMountVersion((current) => current + 1);
              return result;
            } finally {
              await refreshAll();
            }
          }}
        />
      ) : null}
      {addKind ? (
        <AddDialog
          kind={addKind}
          onClose={() => setAddKind(null)}
          config={draftConfig}
          onSave={async (kind, item, servicePacks) => {
            try {
              if (kind === "local") {
                return await saveCurrentDraft({
                  config: withDeploymentReadiness({
                    ...draftConfig,
                    service_packs: servicePacks,
                    local_clients: [
                      ...asObjectList(draftConfig.local_clients),
                      item,
                    ],
                  }, false),
                });
              }
              await saveCurrentDraft({
                config: withDeploymentReadiness(
                  { ...draftConfig, service_packs: servicePacks },
                  false,
                ),
              });
              return await createCollectionItem("remote-users", item);
            } finally {
              await refreshDraft();
            }
          }}
        />
      ) : null}
      {editingLocalId ? (
        <AddDialog
          kind="local"
          existingItem={
            asObjectList(draftConfig.local_clients).find(
              (item) => asText(item.id, "") === editingLocalId,
            ) ?? {}
          }
          config={draftConfig}
          onClose={() => setEditingLocalId("")}
          onSave={async (_kind, item, servicePacks) => {
            const nextConfig: JsonObject = {
              ...draftConfig,
              service_packs: servicePacks,
              local_clients: asObjectList(draftConfig.local_clients).map((client) =>
                client.id === editingLocalId ? item : client,
              ),
            };
            if (draftConfigsMatchIgnoringReadiness(draftConfig, nextConfig)) {
              return { ok: true, unchanged: true };
            }
            try {
              return await saveCurrentDraft({
                config: withDeploymentReadiness(
                  nextConfig,
                  false,
                ),
              });
            } finally {
              await refreshDraft();
            }
          }}
          onDelete={async () => {
            try {
              await saveCurrentDraft({
                config: withDeploymentReadiness(
                  {
                    ...draftConfig,
                    local_clients: asObjectList(draftConfig.local_clients).filter(
                      (client) => client.id !== editingLocalId,
                    ),
                  },
                  false,
                ),
              });
              setEditingLocalId("");
            } finally {
              await refreshDraft();
            }
          }}
        />
      ) : null}
      {editingRemoteId ? (
        <AddDialog
          kind="remote"
          existingItem={
            asObjectList(draftConfig.remote_users).find(
              (item) => asText(item.id, "") === editingRemoteId,
            ) ?? {}
          }
          onClose={() => setEditingRemoteId("")}
          config={draftConfig}
          onSave={async (_kind, item, servicePacks) => {
            try {
              await saveCurrentDraft({
                config: withDeploymentReadiness(
                  { ...draftConfig, service_packs: servicePacks },
                  false,
                ),
              });
              return await updateCollectionItem(
                "remote-users",
                editingRemoteId,
                item,
              );
            } finally {
              await refreshDraft();
            }
          }}
          onDelete={async () => {
            try {
              await deleteCollectionItem("remote-users", editingRemoteId);
              setEditingRemoteId("");
            } finally {
              await refreshDraft();
            }
          }}
        />
      ) : null}
      {setupOpen ? (
        <SetupWizard
          onClose={() => setSetupOpen(false)}
          onDraftChanged={refreshAll}
          config={draftConfig}
        />
      ) : null}
      {connectionDialog ? (
        <ConnectionDialog
          kind={connectionDialog.kind}
          transportId={connectionDialog.transportId}
          subscriptionId={connectionDialog.subscriptionId}
          onClose={() => setConnectionDialog(null)}
          onSaved={refreshDraft}
          config={draftConfig}
          certificateStatus={asObject(asObject(runtimeStatus).acme)}
        />
      ) : null}
      {tlsProfileDialog ? (
        <TlsProfileDialog
          profileId={tlsProfileDialog.profileId}
          onClose={() => setTlsProfileDialog(null)}
          onSaved={refreshDraft}
          config={draftConfig}
        />
      ) : null}
      {policyDialog ? (
        <PolicyDialog
          policyId={policyDialog.policyId}
          onClose={() => setPolicyDialog(null)}
          onSaved={refreshDraft}
          config={draftConfig}
        />
      ) : null}
    </div>
    </ConnectionAddressContext.Provider>
  );
}
