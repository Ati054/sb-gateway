package controlplane

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"time"
)

const xrayLoggingStateName = "xray-logging"

func configuredXrayLogLevel(config map[string]any) string {
	level := strings.ToLower(strings.TrimSpace(subscriptionText(nestedValue(config, "system", "logging", "xray_level"))))
	switch level {
	case "debug", "info", "warning", "error", "none":
		return level
	default:
		return "warning"
	}
}

func xrayDebugTimeout(config map[string]any) time.Duration {
	minutes := boundedJSONInt(nestedValue(config, "system", "logging", "xray_debug_timeout_minutes"), 15, 1, 60)
	return time.Duration(minutes) * time.Minute
}

func setConfiguredXrayLogLevel(config map[string]any, level string) {
	system := objectAt(config, "system")
	logging := objectAt(system, "logging")
	logging["xray_level"] = level
	if _, exists := logging["xray_debug_timeout_minutes"]; !exists {
		logging["xray_debug_timeout_minutes"] = 15
	}
}

func (server *Server) noteXrayLoggingApplied(config map[string]any, revision string) {
	level := configuredXrayLogLevel(config)
	now := server.now()
	state := map[string]any{
		"level": level, "revision": revision,
		"updated_at": now.UTC().Format(time.RFC3339Nano),
	}
	if level == "debug" {
		expiresAt := now.Add(xrayDebugTimeout(config))
		if previous, err := server.repository.auxiliary(xrayLoggingStateName); err == nil && previous["level"] == "debug" {
			if preserved, parseErr := time.Parse(time.RFC3339Nano, subscriptionText(previous["debug_expires_at"])); parseErr == nil {
				expiresAt = preserved
			}
		}
		state["debug_expires_at"] = expiresAt.UTC().Format(time.RFC3339Nano)
	}
	if err := server.repository.saveAuxiliary(xrayLoggingStateName, state); err != nil {
		log.Printf("control-plane: persist Xray logging state: %v", err)
	}
	select {
	case server.xrayLoggingWake <- struct{}{}:
	default:
	}
}

func (server *Server) runXrayLoggingScheduler(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if err := server.reconcileXrayDebugTimeout(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("control-plane: reconcile Xray debug timeout: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-server.xrayLoggingWake:
		}
	}
}

func (server *Server) reconcileXrayDebugTimeout(ctx context.Context) error {
	activeRevision, err := server.repository.activeRevision()
	if err != nil || activeRevision == "" {
		return err
	}
	active, err := server.repository.loadGeneration(activeRevision)
	if err != nil {
		return err
	}
	if configuredXrayLogLevel(active) != "debug" {
		return nil
	}
	state, err := server.repository.auxiliary(xrayLoggingStateName)
	if err != nil {
		return err
	}
	expiresAt, parseErr := time.Parse(time.RFC3339Nano, subscriptionText(state["debug_expires_at"]))
	if state["revision"] != activeRevision || parseErr != nil {
		server.noteXrayLoggingApplied(active, activeRevision)
		return nil
	}
	if server.now().Before(expiresAt) {
		return nil
	}
	return server.resetExpiredXrayDebug(ctx, activeRevision)
}

func (server *Server) resetExpiredXrayDebug(parent context.Context, expectedRevision string) error {
	server.configMu.Lock()
	defer server.configMu.Unlock()
	activeRevision, err := server.repository.activeRevision()
	if err != nil || activeRevision != expectedRevision {
		return err
	}
	active, err := server.repository.loadGeneration(activeRevision)
	if err != nil {
		return err
	}
	if configuredXrayLogLevel(active) != "debug" {
		return nil
	}
	draft, draftErr := server.getDraft()
	if draftErr != nil && !errors.Is(draftErr, os.ErrNotExist) {
		return draftErr
	}
	draftRevision, _ := revisionFor(draft)
	pendingDraft := draftRevision != "" && draftRevision != activeRevision
	next := cloneJSONObject(active)
	setConfiguredXrayLogLevel(next, "warning")
	operationContext, cancel := context.WithTimeout(context.WithoutCancel(parent), applyOperationTimeout)
	defer cancel()
	result, _, applyErr := server.applyConfiguration(operationContext, next, "system:xray-debug-timeout")
	if applyErr != nil {
		server.auditBackground("xray.logging.debug_timeout", map[string]any{"ok": false})
		return applyErr
	}
	if pendingDraft {
		if configuredXrayLogLevel(draft) == "debug" {
			setConfiguredXrayLogLevel(draft, "warning")
		}
		if _, err := server.repository.saveDraft(draft); err != nil {
			return err
		}
	}
	server.auditBackground("xray.logging.debug_timeout", map[string]any{
		"ok": true, "revision": result["revision"], "level": "warning",
	})
	return nil
}
