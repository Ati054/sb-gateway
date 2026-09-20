package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type cdnSourceSync func(context.Context, map[string]any, string, []string) error

const (
	cdnFeedFetchTimeout = 45 * time.Second
	// A first RouterOS sync writes hundreds of individual address-list rows.
	// Keep it separately bounded so a successful fetch cannot consume the time
	// needed to write and verify the complete provider list.
	cdnFeedSyncTimeout = 2 * time.Minute
)

// No Apply, Xray restart, conntrack flush, or client-route change. Mixed
// virtual-host boundaries gracefully reload Nginx only when CIDRs change.
// Only committed listeners are selected.
func (server *Server) runCDNFeedScheduler(ctx context.Context) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := server.refreshOneCDNFeed(ctx); err != nil {
				log.Printf("cdn-feeds: update failed safely: %v", err)
			}
			timer.Reset(15 * time.Second)
		}
	}
}

func (server *Server) refreshOneCDNFeed(ctx context.Context) error {
	if !server.configMu.TryLock() {
		return nil
	}
	defer server.configMu.Unlock()
	revision, err := server.repository.activeRevision()
	if err != nil || revision == "" {
		return err
	}
	config, err := server.repository.loadGeneration(revision)
	if err != nil {
		return err
	}
	providers, err := runtimeconfig.RequiredCDNFeeds(config)
	if err != nil {
		return err
	}
	state, err := server.repository.auxiliary("cdn-feeds")
	if err != nil {
		return err
	}
	due := ""
	var oldest time.Time
	for _, provider := range providers {
		record, _ := state[provider].(map[string]any)
		last, _ := time.Parse(time.RFC3339Nano, subscriptionText(record["last_attempt_at"]))
		delay := cdnfeed.Interval
		if record["state"] != "ok" {
			delay = time.Minute
		}
		if !last.IsZero() && server.now().Before(last.Add(delay)) {
			continue
		}
		// An unavailable early provider must not starve later providers when
		// fetches consume most of their retry interval.
		if due == "" || last.Before(oldest) {
			due, oldest = provider, last
		}
	}
	if due != "" {
		return server.refreshCDNFeed(ctx, config, due, false)
	}
	return nil
}

// Called inside the Apply health phase, before the new runtime is accepted.
// The first activation requires a validated feed; subsequent failures can use
// the persisted validated last-known-good snapshot, never an unrestricted rule.
func (server *Server) ensureCDNFeeds(ctx context.Context, config map[string]any) error {
	providers, err := runtimeconfig.RequiredCDNFeeds(config)
	if err != nil {
		return err
	}
	for _, provider := range providers {
		if err := server.refreshCDNFeed(ctx, config, provider, true); err != nil {
			return err
		}
	}
	return nil
}

func (server *Server) refreshCDNFeed(ctx context.Context, config map[string]any, provider string, apply bool) error {
	state, err := server.repository.auxiliary("cdn-feeds")
	if err != nil {
		return err
	}
	record, _ := state[provider].(map[string]any)
	if record == nil {
		record = map[string]any{}
	}
	cached, cacheErr := cdnfeed.Validate(cdnCachedValues(record["cidrs"]))
	last, _ := time.Parse(time.RFC3339Nano, subscriptionText(record["last_success_at"]))
	values := cached
	var fetchErr error
	fetched := false
	refresh := cacheErr != nil || !apply || last.IsZero() || !server.now().Before(last.Add(cdnfeed.Interval))
	if refresh {
		fetchContext, cancelFetch := context.WithTimeout(ctx, cdnFeedFetchTimeout)
		values, fetchErr = server.fetchCDNFeed(fetchContext, provider)
		cancelFetch()
		if fetchErr == nil {
			values, fetchErr = cdnfeed.Validate(values)
		}
		fetched = fetchErr == nil
		if fetchErr != nil {
			values = cached
		}
	}
	if refresh {
		record["last_attempt_at"] = server.now().UTC().Format(time.RFC3339Nano)
	}
	if fetchErr != nil && (!apply || cacheErr != nil) {
		record["state"] = "failed"
		state[provider] = record
		_ = server.repository.saveAuxiliary("cdn-feeds", state)
		server.auditBackground("cdn-feeds.refresh", map[string]any{"provider": provider, "ok": false})
		return fmt.Errorf("%s official origin feed unavailable; previous addresses retained: %w", provider, fetchErr)
	}
	syncContext, cancelSync := context.WithTimeout(ctx, cdnFeedSyncTimeout)
	defer cancelSync()
	if err := server.syncCDNFeed(syncContext, config, provider, values); err != nil {
		record["state"] = "failed"
		state[provider] = record
		_ = server.repository.saveAuxiliary("cdn-feeds", state)
		return fmt.Errorf("%s RouterOS origin allowlist update: %w", provider, err)
	}
	shared := runtimeconfig.SharedOriginPorts(config)
	needsACL := false
	for _, p := range runtimeconfig.OriginPolicies(config) {
		if shared[p.Port] && p.Mode == "auto-cidr" && p.Provider == provider {
			needsACL = true
		}
	}
	if native, ok := server.runtime.(*nativeRuntime); ok && needsACL {
		if err := native.updateOriginCIDRs(syncContext, provider, values); err != nil {
			record["state"] = "failed"
			state[provider] = record
			_ = server.repository.saveAuxiliary("cdn-feeds", state)
			return fmt.Errorf("%s Nginx origin allowlist update: %w", provider, err)
		}
	}
	if fetched {
		record["cidrs"] = values
		record["last_success_at"] = server.now().UTC().Format(time.RFC3339Nano)
	}
	record["state"] = "ok"
	if fetchErr != nil {
		record["state"] = "stale"
		log.Printf("cdn-feeds: %s using last-known-good origin addresses", provider)
	}
	state[provider] = record
	if err := server.repository.saveAuxiliary("cdn-feeds", state); err != nil {
		return err
	}
	server.auditBackground("cdn-feeds.refresh", map[string]any{"provider": provider, "ok": fetchErr == nil, "count": len(values), "cached": !fetched})
	return nil
}

func (server *Server) syncRouterOSCDNFeed(ctx context.Context, config map[string]any, provider string, values []string) error {
	if len(values) == 0 {
		return errors.New("refusing empty origin allowlist")
	}
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		return err
	}
	defer stack.REST.CloseIdleConnections()
	return stack.REST.SyncCDNSources(ctx, provider, values)
}

func cdnCachedValues(value any) []string {
	if values, ok := value.([]string); ok {
		return values
	}
	values, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value, ok := raw.(string)
		if !ok {
			return nil
		}
		result = append(result, value)
	}
	return result
}
