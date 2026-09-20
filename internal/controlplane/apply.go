package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type routerOSApplyOutput struct {
	Backup   routeros.BackupRef
	Result   routeros.TransactionResult
	Kind     string
	Sections []string
}

type applyValidationError struct{ result configValidation }

func (failure applyValidationError) Error() string { return "configuration validation failed" }

type routerOSApplyFunc func(
	context.Context,
	map[string]any,
	string,
	string,
	func(context.Context) error,
	func(context.Context, routeros.BackupRef) error,
) (routerOSApplyOutput, error)

const (
	applyOperationTimeout = 5 * time.Minute
	applyResponseTimeout  = applyOperationTimeout + time.Minute
)

// An authenticated Apply is a transaction, not a streaming request. Restarting
// Xray can briefly interrupt the management client's network path; coupling the
// transaction to that socket would cancel activation and force an unnecessary
// rollback. Keep the accepted operation bounded, but let it finish its atomic
// commit or rollback after the client disconnects.
func applyOperationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), applyOperationTimeout)
}

func (server *Server) applyDraft(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body := map[string]any{}
	if request.Body != http.NoBody && request.ContentLength != 0 {
		body, ok = server.readObject(response, request, maxRequestBytes)
		if !ok {
			return
		}
	}
	config, supplied := body["config"].(map[string]any)
	if _, exists := body["config"]; exists && !supplied {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_config", "Config must be an object.")
		return
	}
	if !supplied {
		var err error
		config, err = server.getDraft()
		if err != nil {
			server.internalStateError(response, request, err)
			return
		}
	}
	if server.runtime == nil {
		server.writeErrorResponse(response, request, http.StatusServiceUnavailable, "native_runtime_unavailable", "Native runtime process control is unavailable.")
		return
	}

	server.configMu.Lock()
	defer server.configMu.Unlock()
	actor := fmt.Sprint(payload["sub"])
	operationContext, cancelOperation := applyOperationContext(request.Context())
	defer cancelOperation()
	result, status, err := server.applyConfiguration(operationContext, config, actor)
	if err != nil {
		var validationFailure applyValidationError
		if errors.As(err, &validationFailure) {
			server.writeValidationError(response, request, validationFailure.result)
			return
		}
		// Keep the public response deliberately generic, but preserve the exact
		// internal cause locally. errors.Join otherwise makes validation,
		// restart, probe, and rollback failures indistinguishable in the audit.
		log.Printf("control-plane: apply failed request_id=%v: %v", request.Context().Value(requestIDKey{}), err)
		server.audit(request, actor, "apply", "failed", map[string]any{"error_type": fmt.Sprintf("%T", err)})
		server.writeErrorResponse(response, request, status, "apply_failed", "The candidate failed validation or health checks; the previous generation remains active.")
		return
	}
	server.audit(request, actor, "apply", fmt.Sprint(result["operation"]), map[string]any{
		"revision": result["revision"], "apply_mode": result["apply_mode"],
		"routeros_apply_kind": result["routeros_apply_kind"],
	})
	server.writeJSON(response, http.StatusOK, result)
}

func (server *Server) applyConfiguration(ctx context.Context, config map[string]any, actor string) (map[string]any, int, error) {
	normalizeXHTTPModeCompatibility(config)
	check := validateCurrentConfig(config)
	if !check.Valid {
		return nil, http.StatusUnprocessableEntity, applyValidationError{result: check}
	}
	activeRevision, err := server.repository.activeRevision()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	var active map[string]any
	if activeRevision != "" {
		active, err = server.repository.loadGeneration(activeRevision)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}
	metadata, err := server.repository.metadata()
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	previousRuntimeRevision, _ := metadata["runtime_revision"].(string)
	nodes, err := server.routerOSPlanNodes(config)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	desiredNodes := server.routerOSNodesForRevision(check.Revision, nodes)
	candidate, err := server.runtime.prepare(config, desiredNodes)
	if err != nil {
		return nil, http.StatusUnprocessableEntity, err
	}
	desiredRouterOS, err := runtimeconfig.RenderRouterOSTrafficCandidate(config, desiredNodes, server.opts.Runtime.RuleSetDir)
	if err != nil {
		return nil, http.StatusUnprocessableEntity, err
	}
	committedRouterOS, _ := metadata["routeros_source"].(string)
	previousRouterOS := committedRouterOS
	if previousRouterOS == "" && active != nil {
		previousNodes := server.routerOSNodesForRevision(activeRevision, nodes)
		previousRouterOS, err = runtimeconfig.RenderRouterOSTrafficCandidate(active, previousNodes, server.opts.Runtime.RuleSetDir)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	} else if previousRouterOS == "" {
		// A fresh installation has no committed generation yet. Build a bounded
		// rollback candidate from the operator-confirmed topology, but remove
		// every traffic-diversion and public-exposure decision. RouterOS Safe
		// Mode remains the exact primary rollback; this source is the independent
		// scheduler fallback and deliberately restores fail-open reachability.
		previousRouterOS, err = runtimeconfig.RenderRouterOSTrafficCandidate(firstApplyRollbackConfig(config), nil, server.opts.Runtime.RuleSetDir)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("render first-apply fail-open rollback: %w", err)
		}
	}
	// Compare against what was actually committed, not the old configuration
	// re-rendered by the new binary (which conceals renderer fixes on upgrade).
	routerOSChanged := committedRouterOS == "" || desiredRouterOS != previousRouterOS
	if activeRevision == check.Revision && previousRuntimeRevision == candidate.Revision && !routerOSChanged {
		result := applyResponse("unchanged", check.Revision, activeRevision, candidate.Revision, false, "none", nil, nil, false)
		result["check"] = check.payload()
		return result, http.StatusOK, nil
	}
	stagedRevision, err := server.repository.stageGeneration(config)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	// Freeze the latest operational node snapshot under the old configuration
	// before switching configurations, so explicit rollback restores it too.
	if activeRevision != check.Revision && safeRevision(subscriptionText(metadata["node_snapshot_revision"])) {
		if err := server.saveSubscriptionSnapshot(activeRevision, server.routerOSNodesForRevision(activeRevision, nil)); err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}

	var receipt runtimeconfig.ActivationReceipt
	var activated bool
	var stateCommitted bool
	runtimeCleanupPending := false
	runtimeReady := false
	activate := func(operationContext context.Context) error {
		if runtimeReady {
			return nil
		}
		if err := server.ensureCDNFeeds(operationContext, config); err != nil {
			return err
		}
		var activateErr error
		receipt, activateErr = server.runtime.activate(operationContext, candidate)
		activated = len(receipt.Changed()) > 0
		runtimeReady = activateErr == nil
		return activateErr
	}
	rollbackRuntime := func() error {
		if !activated || stateCommitted {
			return nil
		}
		rollbackContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := server.runtime.rollback(rollbackContext, receipt)
		if err == nil {
			activated = false
		}
		return err
	}
	commit := func(backup any) error {
		if err := server.saveSubscriptionSnapshot(stagedRevision, desiredNodes); err != nil {
			return err
		}
		if err := server.repository.commitActive(commitMetadata{
			RouterOSSource: desiredRouterOS,
			Revision:       stagedRevision, PreviousRevision: activeRevision,
			RuntimeRevision: candidate.Revision, PreviousRuntimeRevision: previousRuntimeRevision,
			BackupRef: backup, Actor: actor, CommittedAt: server.now(),
		}); err != nil {
			return err
		}
		stateCommitted = true
		if err := server.runtime.commit(candidate); err != nil {
			runtimeCleanupPending = true
		}
		return nil
	}

	var backup any = metadata["backup_ref"]
	applyKind := "none"
	sections := []string{}
	guardMode := "none"
	cleanupPending := false
	if routerOSChanged {
		output, applyErr := server.applyRouterOS(ctx, config, desiredRouterOS, previousRouterOS, activate, func(_ context.Context, reference routeros.BackupRef) error {
			backup = reference
			return commit(reference)
		})
		applyKind, sections, cleanupPending = output.Kind, output.Sections, output.Result.CleanupPending
		guardMode = output.Result.GuardMode
		if applyErr != nil {
			return nil, http.StatusConflict, errors.Join(applyErr, rollbackRuntime())
		}
	} else {
		if err := activate(ctx); err != nil {
			return nil, http.StatusConflict, errors.Join(err, rollbackRuntime())
		}
		if err := commit(backup); err != nil {
			return nil, http.StatusInternalServerError, errors.Join(err, rollbackRuntime())
		}
	}
	if _, err := server.repository.saveDraft(config); err != nil {
		runtimeCleanupPending = true
	}
	server.noteXrayLoggingApplied(config, stagedRevision)
	result := applyResponse("applied", stagedRevision, activeRevision, candidate.Revision, routerOSChanged, applyKind, sections, backup, cleanupPending || runtimeCleanupPending)
	result["routeros_guard_mode"] = guardMode
	result["check"] = check.payload()
	return result, http.StatusOK, nil
}

func firstApplyRollbackConfig(config map[string]any) map[string]any {
	baseline := cloneJSONObject(config)
	for _, collection := range []string{
		"local_clients", "policies", "remote_users", "reverse_vless_exits",
		"service_packs", "subscription_reserves", "transports",
	} {
		baseline[collection] = []any{}
	}
	ingress := objectAt(baseline, "ingress")
	ingress["status_hostname"] = ""
	ingress["subscription_endpoint_enabled"] = false
	ingress["subscription_hostname"] = ""
	ingress["subscription_cdn_hostname"] = ""
	ingress["subscription_deployment_id"] = ""
	ingress["subscription_transport_id"] = ""
	publicExposure := objectAt(baseline, "public_exposure")
	publicExposure["shared_tcp_443"] = false
	networking := objectAt(objectAt(baseline, "system"), "networking")
	networking["wireguard_egress_enabled"] = false
	networking["wireguard_egress_exits"] = []any{}
	return baseline
}

func (server *Server) runRouterOSApply(
	ctx context.Context,
	config map[string]any,
	desired, previous string,
	health func(context.Context) error,
	finalize func(context.Context, routeros.BackupRef) error,
) (routerOSApplyOutput, error) {
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		return routerOSApplyOutput{}, err
	}
	defer stack.REST.CloseIdleConnections()
	schedulerGuardOnly, err := stack.REST.SchedulerGuardRequired(ctx)
	if err != nil {
		return routerOSApplyOutput{}, err
	}
	name := "SB-GATEWAY-" + server.now().UTC().Format("20060102T150405Z") + "-" + mustRevisionPrefix(desired)
	backup, err := stack.REST.CreateBackup(ctx, name, stack.BackupPassword)
	if err != nil {
		return routerOSApplyOutput{}, err
	}
	transaction, err := routeros.NewTransaction(stack.REST, stack.SSH)
	if err != nil {
		return routerOSApplyOutput{Backup: backup}, err
	}
	options := routeros.TransactionOptions{
		RollbackDelay: 10 * time.Minute, SettleTimeout: 2 * time.Minute,
		SchedulerGuardOnly: schedulerGuardOnly,
		HealthCheck: func(probeContext context.Context) error {
			if err := health(probeContext); err != nil {
				return err
			}
			return stack.REST.Health(probeContext)
		},
		Finalize: func(finalizeContext context.Context) error { return finalize(finalizeContext, backup) },
	}
	if len(runtimeconfig.SharedOriginPorts(config)) > 0 || runtimeconfig.Shared443(config) {
		// Arm rollback first, install origin guards next, only then widen NAT.
		options.BeforeApply = health
	}
	output := routerOSApplyOutput{Backup: backup, Kind: "full", Sections: []string{}}
	if delta := runtimeconfig.BuildRouterOSDelta(previous, desired, 0.8); delta != nil {
		output.Kind, output.Sections = "delta", append([]string(nil), delta.Sections...)
		output.Result, err = transaction.ApplyDelta(ctx, delta.ApplyScript, delta.RollbackScript, options)
	} else {
		output.Result, err = transaction.ApplyCandidate(ctx, desired, previous, options)
	}
	if err == nil {
		storageRoot, rootErr := validateLifecycleStorageRoot(text(objectAt(config, "storage")["root"]))
		if rootErr == nil {
			cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, cleanupErr := stack.REST.PruneManagedFiles(cleanupContext, storageRoot)
			cancel()
			if cleanupErr != nil {
				output.Result.CleanupPending = true
				log.Printf("control-plane: RouterOS managed file retention pending: %v", cleanupErr)
			}
		}
	}
	return output, err
}

func mustRevisionPrefix(source string) string {
	revision := artifactRevision(map[string][]byte{"routeros.rsc": []byte(source)})
	return revision[:12]
}

func (server *Server) routerOSNodesForRevision(revision string, fallback []map[string]any) []map[string]any {
	if revision == "" {
		return fallback
	}
	metadata, _ := server.repository.metadata()
	if metadata["revision"] == revision && safeRevision(subscriptionText(metadata["node_snapshot_revision"])) {
		snapshotRevision := subscriptionText(metadata["node_snapshot_revision"])
		snapshot, err := server.repository.auxiliary("subscription-nodes-" + snapshotRevision)
		if err != nil || snapshot["revision"] != snapshotRevision {
			return nil
		}
		return objectNodes(snapshot["nodes"])
	}
	state, err := server.repository.auxiliary("subscription-nodes-" + revision)
	if err != nil {
		return fallback
	}
	if savedRevision, _ := state["revision"].(string); savedRevision == revision {
		if _, ok := state["nodes"].([]any); ok {
			return objectNodes(state["nodes"])
		}
	}
	return fallback
}

func (server *Server) saveSubscriptionSnapshot(revision string, nodes []map[string]any) error {
	values := make([]any, len(nodes))
	for index := range nodes {
		values[index] = cloneJSONObject(nodes[index])
	}
	return server.repository.saveAuxiliary("subscription-nodes-"+revision, map[string]any{
		"revision": revision, "nodes": values,
	})
}

func objectNodes(value any) []map[string]any {
	raw, _ := value.([]any)
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if node, ok := item.(map[string]any); ok {
			result = append(result, node)
		}
	}
	return result
}

func applyResponse(operation, revision, previousRevision, runtimeRevision string, routerOSChanged bool, kind string, sections []string, backup any, cleanupPending bool) map[string]any {
	if sections == nil {
		sections = []string{}
	}
	mode := "runtime_fast"
	if operation == "unchanged" {
		mode = "unchanged"
	} else if routerOSChanged {
		mode = "routeros_safe_mode"
	}
	return map[string]any{
		"ok": true, "operation": operation, "revision": revision,
		"previous_revision": nullableString(previousRevision), "runtime_revision": runtimeRevision,
		"backup_ref": cloneJSONValue(backup), "rolled_back": false,
		"apply_mode": mode, "routeros_changed": routerOSChanged,
		"routeros_apply_kind": kind, "routeros_delta_sections": sections,
		"routeros_guard_mode": "none",
		"cleanup_pending":     cleanupPending,
	}
}
