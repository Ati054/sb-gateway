package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type subscriptionRuntimeError struct {
	stage string
	cause error
}

const (
	subscriptionRuntimeActivationTimeout = 5 * time.Minute
	subscriptionRuntimeRollbackTimeout   = 2 * time.Minute
)

func (err subscriptionRuntimeError) Error() string { return "subscription runtime: " + err.stage }
func (err subscriptionRuntimeError) Unwrap() error { return err.cause }

func mustSubscriptionSourceRevision(subscription map[string]any) string {
	revision, _ := revisionFor(subscription)
	return revision
}

// Publication holds mutationMu -> subscriptionMu -> configMu. A download that
// owns subscriptionMu must remain able to acquire mutationMu for its commit.
// This never applies a draft. RouterOS changes cover owned loop-bypass hosts
// and the existing planned-restart gate when the startup Xray graph changes.
func (server *Server) activatePendingSubscription(ctx context.Context) (bool, error) {
	if server.runtime == nil {
		return false, nil
	}
	server.mutationMu.Lock()
	defer server.mutationMu.Unlock()
	if conflict, err := server.stateMutationConflict(mutationSubscription); err != nil {
		return false, err
	} else if conflict != "" {
		return false, nil
	}
	if !server.subscriptionMu.TryLock() {
		// Do not monopolize mutation admission while a download finishes. The
		// normal scheduler wake retries after the inventory has been committed.
		return false, nil
	}
	defer server.subscriptionMu.Unlock()
	server.configMu.Lock()
	defer server.configMu.Unlock()
	now := server.now()
	if server.subscriptionRuntimeIdle.unchanged(now) {
		return false, nil
	}
	server.subscriptionRuntimeIdle = subscriptionRuntimeIdle{}
	sources, cacheable := server.repository.subscriptionRuntimePointers()
	if err := server.repository.reconcileCommitPointers(); err != nil {
		return false, err
	}
	metadata, err := server.repository.metadata()
	if err != nil {
		return false, err
	}
	revision := subscriptionText(metadata["revision"])
	if !safeRevision(revision) {
		return false, nil
	}
	snapshotRevision := stringDefault(metadata["node_snapshot_revision"], revision)
	if cacheable && safeRevision(snapshotRevision) {
		extra, ok := subscriptionRuntimeSources(filepath.Join(server.repository.generations, revision+".json"), filepath.Join(server.repository.root, "subscription-nodes-"+snapshotRevision+".json"))
		cacheable = ok
		sources = append(sources, extra...)
	} else {
		cacheable = false
	}
	active, err := server.repository.loadGeneration(revision)
	if err != nil {
		return false, err
	}
	snapshot, err := server.repository.auxiliary("subscription-nodes-" + snapshotRevision)
	if err != nil {
		return false, err
	}
	if snapshot["revision"] != snapshotRevision {
		return false, errors.New("committed subscription snapshot missing")
	}
	previousNodes := objectNodes(snapshot["nodes"])
	if snapshotRevision != revision {
		checksum, err := revisionFor(previousNodes)
		if err != nil || checksum != snapshotRevision {
			return false, errors.New("subscription snapshot checksum mismatch")
		}
	}
	journal, err := server.repository.auxiliary("subscription-runtime-operation")
	if err != nil {
		return false, err
	}
	if journal["pending"] == true {
		recovery, cancel := context.WithTimeout(ctx, subscriptionRuntimeActivationTimeout)
		defer cancel()
		// A crash/failed rollback left activation unconfirmed. Reconstruct the
		// committed model, never the newest fetched model or the user's draft.
		candidate, err := server.runtime.prepare(active, previousNodes)
		if err != nil {
			return true, err
		}
		var endpoints []string
		if journal["endpoints_changed"] == true {
			endpoints, err = server.subscriptionEndpointBypass(active, previousNodes)
			if err != nil {
				return true, err
			}
			if err = server.syncSubscriptionEndpoints(recovery, active, endpoints, false); err != nil {
				return true, err
			}
		}
		if _, _, err := server.activateSubscriptionCandidate(recovery, active, candidate); err != nil {
			return true, err
		}
		if journal["endpoints_changed"] == true {
			if err = server.syncSubscriptionEndpoints(recovery, active, endpoints, true); err != nil {
				return true, err
			}
		}
		if err := server.runtime.commit(candidate); err != nil {
			return true, err
		}
		if err := server.updateRecoveredRuntimeRevision(candidate.Revision); err != nil {
			return true, err
		}
		if err := server.repository.saveAuxiliary("subscription-runtime-operation", map[string]any{}); err != nil {
			return true, err
		}
		return true, nil
	}
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return false, err
	}
	statuses, err := server.repository.auxiliary("subscription-runtime-status")
	if err != nil {
		return false, err
	}
	var retryAt time.Time
	for _, raw := range collectionArray(active["subscriptions"]) {
		subscription, ok := raw.(map[string]any)
		if !ok || subscription["enabled"] == false {
			continue
		}
		id := subscriptionText(subscription["id"])
		entry, _ := state[id].(map[string]any)
		fingerprint := subscriptionText(entry["fingerprint"])
		// A manually refreshed draft with a new URL/options is not approved yet.
		if fingerprint == "" || entry["source_revision"] != mustSubscriptionSourceRevision(subscription) {
			continue
		}
		inventory := entry["nodes"]
		if reference, exists := entry["catalog_ref"]; exists {
			inventory = reference
		}
		nodesRevision, err := revisionFor(inventory)
		if err != nil {
			return false, err
		}
		status, _ := statuses[id].(map[string]any)
		if status["active_revision"] == revision && status["nodes_revision"] == nodesRevision {
			if status["state"] == "active" {
				continue
			}
			if status["state"] == "blocked" && status["reason"] == "catalog_planning_budget" && status["node_snapshot_revision"] == snapshotRevision {
				storedBudget, valid := jsonInteger(status["planning_budget_bytes"])
				if valid && storedBudget > 0 && runtimeconfig.CatalogPlanningBudgetBytes() <= int64(storedBudget) {
					// Recheck only the cheap budget/identity predicate after this
					// idle-cache TTL; unchanged oversized plans are not prepared.
					next := now.Add(30 * time.Second)
					if retryAt.IsZero() || next.Before(retryAt) {
						retryAt = next
					}
					continue
				}
			}
			next, _ := time.Parse(time.RFC3339Nano, subscriptionText(status["next_attempt"]))
			if server.now().Before(next) {
				if retryAt.IsZero() || next.Before(retryAt) {
					retryAt = next
				}
				continue
			}
		}
		// Other subscriptions may contain unapplied drafts; retain their applied
		// snapshots and replace only this approved provider's inventory.
		providerNodes := runtimeSubscriptionNodes(active, map[string]any{id: entry})
		desired := make([]map[string]any, 0, len(previousNodes)+len(providerNodes))
		previousProvider := make([]map[string]any, 0, len(providerNodes))
		inserted := false
		for _, node := range previousNodes {
			if subscriptionText(node["subscription_id"]) == id {
				previousProvider = append(previousProvider, node)
				if !inserted {
					// Group expansion follows catalog order. Replacing a provider
					// must not move its block behind unrelated priority candidates.
					desired = append(desired, providerNodes...)
					inserted = true
				}
				continue
			}
			desired = append(desired, node)
		}
		if !inserted {
			desired = append(desired, providerNodes...)
		}
		// Apply already committed these nodes under the new configuration. Only
		// acknowledge that generation; do not republish/reorder the same handlers.
		if equalJSONObject(map[string]any{"nodes": previousProvider}, map[string]any{"nodes": providerNodes}) {
			statuses[id] = map[string]any{"active_revision": revision, "fingerprint": fingerprint, "nodes_revision": nodesRevision, "last_attempt": now.UTC().Format(time.RFC3339Nano), "state": "active"}
			return true, server.repository.saveAuxiliary("subscription-runtime-status", statuses)
		}
		operation, cancel := context.WithTimeout(ctx, subscriptionRuntimeActivationTimeout)
		activationErr := server.installSubscriptionRuntime(operation, active, metadata, previousNodes, desired)
		cancel()
		status = map[string]any{
			"active_revision": revision, "fingerprint": fingerprint, "nodes_revision": nodesRevision,
			"last_attempt": server.now().UTC().Format(time.RFC3339Nano), "state": "active",
		}
		if activationErr != nil {
			if errors.Is(activationErr, runtimeconfig.ErrCatalogPlanningBudget) {
				status["state"] = "blocked"
				status["reason"] = "catalog_planning_budget"
				status["planning_budget_bytes"] = runtimeconfig.CatalogPlanningBudgetBytes()
				status["node_snapshot_revision"] = snapshotRevision
				status["message"] = "Выбранный набор превышает бюджет памяти. Сузьте выбор узлов или увеличьте память контейнера. Каталог сохранён; действующая конфигурация не изменена."
			} else {
				status["state"] = "retrying"
				status["message"] = "Runtime не обновлён; повтор через 30 секунд."
				status["next_attempt"] = server.now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano)
			}
			var failure subscriptionRuntimeError
			if errors.As(activationErr, &failure) {
				status["failure_stage"] = failure.stage
			}
		}
		statuses[id] = status
		saveErr := server.repository.saveAuxiliary("subscription-runtime-status", statuses)
		server.auditBackground("subscriptions.runtime", map[string]any{"id": id, "ok": activationErr == nil, "failure_stage": status["failure_stage"]})
		return true, errors.Join(activationErr, saveErr)
	}
	if cacheable && subscriptionRuntimeSourcesUnchanged(sources) {
		server.subscriptionRuntimeIdle = subscriptionRuntimeIdle{sources: sources, checked: now.UTC(), retryAt: retryAt}
	}
	return false, nil
}

func (server *Server) installSubscriptionRuntime(ctx context.Context, active, metadata map[string]any, previousNodes, nodes []map[string]any) (result error) {
	stage := "endpoint_model"
	defer func() {
		if result != nil {
			result = subscriptionRuntimeError{stage: stage, cause: result}
		}
	}()
	previousEndpoints, err := server.subscriptionEndpointBypass(active, previousNodes)
	if err != nil {
		return err
	}
	desiredEndpoints, err := server.subscriptionEndpointBypass(active, nodes)
	if err != nil {
		return err
	}
	stage = "endpoint_source"
	source, err := runtimeconfig.UpdateRouterOSEndpointSource(subscriptionText(metadata["routeros_source"]), previousEndpoints, desiredEndpoints)
	if err != nil {
		return err
	}
	endpointsChanged := source != subscriptionText(metadata["routeros_source"])
	if endpointsChanged && server.syncSubscriptionEndpoints == nil {
		return errors.New("subscription endpoint sync unavailable")
	}
	stage = "runtime_prepare"
	candidate, err := server.runtime.prepare(active, nodes)
	if err != nil {
		return err
	}
	stage = "snapshot_save"
	nodesRevision, err := revisionFor(nodes)
	if err != nil {
		return err
	}
	if err := server.saveSubscriptionSnapshot(nodesRevision, nodes); err != nil {
		return err
	}
	if err := server.repository.saveAuxiliary("subscription-runtime-operation", map[string]any{"pending": true, "endpoints_changed": endpointsChanged}); err != nil {
		return err
	}
	var receipt runtimeconfig.ActivationReceipt
	coldRuntime := false
	rollback := func(cause error) error {
		timeout := subscriptionRuntimeRollbackTimeout
		native, isNative := server.runtime.(*nativeRuntime)
		if isNative && (coldRuntime || native.subscriptionRestartPending.Load()) {
			// Core readiness alone may take 210s for large GeoIP sets. Keep the
			// previous shorter deadline for ordinary hot endpoint rollbacks.
			timeout = subscriptionRuntimeActivationTimeout
		}
		recovery, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		var rollbackErr error
		if isNative {
			rollbackErr = native.rollbackSubscriptionWithXrayRestartHook(recovery, receipt, server.subscriptionXrayRestartHook(active))
		} else {
			rollbackErr = server.runtime.rollbackSubscription(recovery, receipt)
		}
		if endpointsChanged {
			rollbackErr = errors.Join(rollbackErr, server.syncSubscriptionEndpoints(recovery, active, previousEndpoints, true))
		}
		if rollbackErr == nil {
			rollbackErr = server.repository.saveAuxiliary("subscription-runtime-operation", map[string]any{})
		}
		return errors.Join(cause, rollbackErr)
	}
	if endpointsChanged {
		// Add-only until the new runtime has passed its local readiness checks.
		stage = "endpoint_prepare"
		if err := server.syncSubscriptionEndpoints(ctx, active, desiredEndpoints, false); err != nil {
			return rollback(err)
		}
	}
	stage = "runtime_activate"
	receipt, coldRuntime, err = server.activateSubscriptionCandidate(ctx, active, candidate)
	if err != nil {
		return rollback(err)
	}
	if endpointsChanged {
		stage = "endpoint_cleanup"
		if err := server.syncSubscriptionEndpoints(ctx, active, desiredEndpoints, true); err != nil {
			return rollback(err)
		}
	}
	stage = "metadata_commit"
	err = server.repository.commitActive(commitMetadata{
		Revision: subscriptionText(metadata["revision"]), PreviousRevision: subscriptionText(metadata["previous_revision"]),
		RuntimeRevision: candidate.Revision, PreviousRuntimeRevision: subscriptionText(metadata["runtime_revision"]),
		NodeSnapshotRevision: nodesRevision, PreviousNodeSnapshotRevision: subscriptionText(metadata["node_snapshot_revision"]),
		RouterOSSource: source, BackupRef: metadata["backup_ref"], Actor: "subscription-refresh", CommittedAt: server.now(),
	})
	if err != nil {
		// active.json is the commit point even if a derivative write failed.
		committed, readErr := server.repository.readJSON(filepath.Join(server.repository.root, "active.json"))
		if readErr != nil || committed["node_snapshot_revision"] != nodesRevision || committed["runtime_revision"] != candidate.Revision {
			return rollback(err)
		}
		if err := server.repository.reconcileCommitPointers(); err != nil {
			return err
		}
	}
	stage = "runtime_commit"
	if err := server.runtime.commit(candidate); err != nil {
		return err
	}
	return server.repository.saveAuxiliary("subscription-runtime-operation", map[string]any{})
}

func (server *Server) activateSubscriptionCandidate(ctx context.Context, active map[string]any, candidate runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, bool, error) {
	if native, ok := server.runtime.(*nativeRuntime); ok {
		cold := false
		hook := server.subscriptionXrayRestartHook(active)
		receipt, err := native.activateSubscriptionWithXrayRestartHook(ctx, candidate, func(ctx context.Context) error {
			cold = true
			return hook(ctx)
		})
		return receipt, cold, err
	}
	receipt, err := server.runtime.activateSubscription(ctx, candidate)
	return receipt, false, err
}

func (server *Server) subscriptionXrayRestartHook(active map[string]any) func(context.Context) error {
	return func(ctx context.Context) error {
		client, _, err := server.newRouterOSRESTClient(active)
		if err != nil {
			return err
		}
		defer client.CloseIdleConnections()
		return client.EnterPlannedApplyFailOpen(ctx)
	}
}

func (server *Server) runSubscriptionEndpointSync(ctx context.Context, config map[string]any, values []string, prune bool) error {
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		return err
	}
	defer stack.REST.CloseIdleConnections()
	return stack.REST.SyncSubscriptionEndpoints(ctx, values, prune)
}
