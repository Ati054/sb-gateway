package controlplane

import (
	"context"
	"errors"
	"log"
	"time"
)

const (
	subscriptionSchedulerIdle  = 5 * time.Minute
	subscriptionSchedulerBatch = 10 * time.Second
)

func (server *Server) runSubscriptionScheduler(ctx context.Context) {
	initial := time.Duration(boundedEnvInt("SB_BACKGROUND_INITIAL_DELAY_SECONDS", 5, 5, 300)) * time.Second
	timer := time.NewTimer(initial)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-server.subscriptionWake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		worked, err := server.activatePendingSubscription(ctx)
		delay := subscriptionSchedulerBatch
		if !worked {
			var refreshErr error
			delay, refreshErr = server.refreshOneDueSubscription(ctx)
			err = errors.Join(err, refreshErr)
		}
		if err != nil {
			log.Printf("subscription-refresh: scheduled attempt failed safely; previous nodes retained")
		}
		if delay < subscriptionSchedulerBatch {
			delay = subscriptionSchedulerBatch
		}
		// Pending runtime retries and crash recovery must not wait for a
		// provider's multi-hour download interval. No fetch when not due.
		timer.Reset(min(delay, 30*time.Second))
	}
}

func (server *Server) refreshOneDueSubscription(ctx context.Context) (time.Duration, error) {
	now := server.now().UTC()
	activeRevision, err := server.repository.activeRevision()
	if err != nil || activeRevision == "" {
		return subscriptionSchedulerIdle, err
	}
	active, err := server.repository.loadGeneration(activeRevision)
	if err != nil {
		return subscriptionSchedulerIdle, err
	}
	nodesState, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return subscriptionSchedulerIdle, err
	}
	statusState, err := server.repository.auxiliary("subscription-refresh-status")
	if err != nil {
		return subscriptionSchedulerIdle, err
	}
	var due map[string]any
	remaining := 7 * 24 * time.Hour
	enabled := 0
	for _, raw := range collectionArray(active["subscriptions"]) {
		subscription, ok := raw.(map[string]any)
		if !ok || subscription["enabled"] == false {
			continue
		}
		enabled++
		id := subscriptionText(subscription["id"])
		last := latestSubscriptionAttempt(nodesState[id], statusState[id])
		interval := subscriptionRefreshInterval(subscription)
		if last.IsZero() || !now.Before(last.Add(interval)) {
			if due == nil {
				due = subscription
			}
			remaining = subscriptionSchedulerBatch
			continue
		}
		until := last.Add(interval).Sub(now)
		if until < remaining {
			remaining = until
		}
	}
	if enabled == 0 {
		return subscriptionSchedulerIdle, nil
	}
	if due == nil {
		return remaining, nil
	}
	id := subscriptionText(due["id"])
	attemptedAt := now.Format(time.RFC3339Nano)
	server.subscriptionMu.Lock()
	result, refreshErr := server.refreshSubscriptionNow(ctx, due)
	server.subscriptionMu.Unlock()
	status := map[string]any{"state": "failed", "last_attempt_at": attemptedAt}
	if refreshErr == nil {
		status["state"] = "ok"
		status["last_success_at"] = attemptedAt
		status["update_channel"] = result["update_channel"]
	}
	statusState[id] = status
	if err := server.repository.saveAuxiliary("subscription-refresh-status", statusState); err != nil {
		return subscriptionSchedulerBatch, err
	}
	server.auditBackground("subscriptions.refresh", map[string]any{"id": id, "scheduled": true, "ok": refreshErr == nil})
	return subscriptionSchedulerBatch, refreshErr
}

func subscriptionRefreshInterval(subscription map[string]any) time.Duration {
	if minutes, ok := jsonInteger(subscription["refresh_minutes"]); ok {
		minutes = max(1, min(minutes, 7*24*60))
		return time.Duration(minutes) * time.Minute
	}
	hours := boundedSubscriptionInteger(subscription["refresh_hours"], 24, 1, 7*24)
	return time.Duration(hours) * time.Hour
}

func latestSubscriptionAttempt(nodeValue, statusValue any) time.Time {
	latest := time.Time{}
	for _, pair := range []struct {
		value any
		field string
	}{{nodeValue, "refreshed_at"}, {statusValue, "last_attempt_at"}} {
		entry, _ := pair.value.(map[string]any)
		parsed, err := time.Parse(time.RFC3339Nano, subscriptionText(entry[pair.field]))
		if err == nil && parsed.After(latest) {
			latest = parsed
		}
	}
	return latest
}

func (server *Server) auditBackground(action string, details map[string]any) {
	outcome := "rejected"
	if details["ok"] == true {
		outcome = "ok"
	}
	_ = server.repository.appendAudit(map[string]any{
		"timestamp": server.now().UTC().Format(time.RFC3339Nano), "actor": "system",
		"action": action, "outcome": outcome,
		"request_id": "", "details": details,
	})
}
