package controlplane

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func TestCDNFeedLastKnownGoodAndRestart(t *testing.T) {
	server := newTestServer(t)
	now := time.Now().UTC()
	server.now = func() time.Time { return now }
	fetches, syncs := 0, 0
	failing := false
	server.fetchCDNFeed = func(context.Context, string) ([]string, error) {
		fetches++
		if failing {
			return nil, errors.New("offline")
		}
		return []string{"8.8.8.0/24"}, nil
	}
	server.syncCDNFeed = func(_ context.Context, _ map[string]any, _ string, values []string) error {
		syncs++
		if !reflect.DeepEqual(values, []string{"8.8.8.0/24"}) {
			t.Fatal(values)
		}
		return nil
	}
	ctx := context.Background()
	if err := server.refreshCDNFeed(ctx, nil, "gcore", true); err != nil {
		t.Fatal(err)
	}
	if err := server.refreshCDNFeed(ctx, nil, "gcore", true); err != nil {
		t.Fatal(err)
	}
	if fetches != 1 || syncs != 2 {
		t.Fatalf("fresh Apply did not reuse cache: %d %d", fetches, syncs)
	}
	// Reopen repository to prove that the fallback is persistent, not in-memory.
	repository, err := newStateRepository(server.opts.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	server.repository = repository
	now = now.Add(cdnfeed.Interval + time.Second)
	failing = true
	if err := server.refreshCDNFeed(ctx, nil, "gcore", false); err == nil {
		t.Fatal("background failure hidden")
	}
	if syncs != 2 {
		t.Fatal("failed fetch changed RouterOS")
	}
	if err := server.refreshCDNFeed(ctx, nil, "gcore", true); err != nil {
		t.Fatal("Apply did not use LKG:", err)
	}
	state, _ := server.repository.auxiliary("cdn-feeds")
	if state["gcore"].(map[string]any)["state"] != "stale" {
		t.Fatal(state)
	}
	if err := server.refreshCDNFeed(ctx, nil, "yandex", true); err == nil {
		t.Fatal("first use accepted missing feed")
	}
	if syncs != 3 {
		t.Fatal("first failed feed mutated allowlist")
	}
}

func TestCDNFeedRejectsBadResponseAndSyncFailureWithoutReplacingCache(t *testing.T) {
	server := newTestServer(t)
	server.fetchCDNFeed = func(context.Context, string) ([]string, error) { return []string{"0.0.0.0/0"}, nil }
	server.syncCDNFeed = func(context.Context, map[string]any, string, []string) error {
		t.Fatal("unsafe sync called")
		return nil
	}
	if err := server.refreshCDNFeed(context.Background(), nil, "gcore", true); err == nil {
		t.Fatal("unsafe feed accepted")
	}
	server.fetchCDNFeed = func(context.Context, string) ([]string, error) { return []string{"8.8.8.0/24"}, nil }
	server.syncCDNFeed = func(context.Context, map[string]any, string, []string) error { return errors.New("RouterOS offline") }
	if err := server.refreshCDNFeed(context.Background(), nil, "gcore", true); err == nil {
		t.Fatal("sync failure hidden")
	}
	state, _ := server.repository.auxiliary("cdn-feeds")
	if state["gcore"].(map[string]any)["cidrs"] != nil {
		t.Fatal("uncommitted cache saved")
	}
}

func TestCDNFeedSeparatesFetchAndRouterOSSyncDeadlines(t *testing.T) {
	server := newTestServer(t)
	server.fetchCDNFeed = func(ctx context.Context, _ string) ([]string, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > cdnFeedFetchTimeout+time.Second {
			t.Fatal("official feed fetch is not independently bounded")
		}
		return []string{"8.8.8.0/24"}, nil
	}
	server.syncCDNFeed = func(ctx context.Context, _ map[string]any, _ string, _ []string) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < cdnFeedSyncTimeout-time.Second {
			t.Fatal("RouterOS sync inherited the shorter feed fetch deadline")
		}
		return nil
	}
	if err := server.refreshCDNFeed(context.Background(), nil, "gcore", true); err != nil {
		t.Fatal(err)
	}
}

func TestCDNFeedFirstApplyCannotActivateWithoutVerifiedSources(t *testing.T) {
	server := newTestServer(t)
	active := routerOSReadyConfig(t)
	revision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, RuntimeRevision: strings.Repeat("1", 64), Actor: "test", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	desired := cloneJSONObject(active)
	desired["ingress"].(map[string]any)["subscription_cdn_provider"] = "gcore"
	desired["ingress"].(map[string]any)["subscription_listen_port"] = 18443
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("2", 64)}
	server.runtime = runtime
	server.fetchCDNFeed = func(context.Context, string) ([]string, error) { return nil, errors.New("offline") }
	server.syncCDNFeed = func(context.Context, map[string]any, string, []string) error {
		t.Fatal("empty list sent to router")
		return nil
	}
	server.applyRouterOS = func(ctx context.Context, _ map[string]any, _, _ string, health func(context.Context) error, finalize func(context.Context, routeros.BackupRef) error) (routerOSApplyOutput, error) {
		if err := health(ctx); err != nil {
			return routerOSApplyOutput{}, err
		}
		t.Fatal("health succeeded with no origin feed")
		return routerOSApplyOutput{}, nil
	}
	if _, _, err := server.applyConfiguration(context.Background(), desired, "test"); err == nil {
		t.Fatal("first Apply accepted missing feed")
	}
	if runtime.activateCalls != 0 || runtime.commitCalls != 0 {
		t.Fatal("runtime activated before source verification")
	}
	current, _ := server.repository.activeRevision()
	if current != revision {
		t.Fatal("failed Apply advanced revision")
	}
}

func TestCDNFeedSchedulerDoesNotStarveLaterProvidersOrReadDraft(t *testing.T) {
	server := newTestServer(t)
	now := time.Now().UTC()
	server.now = func() time.Time { return now }
	config := map[string]any{"transports": []any{map[string]any{"id": "cdn", "kind": "ws", "cdn_deployments": []any{
		map[string]any{"id": "b", "cdn_provider": "beeline", "origin_protection_mode": "auto-cidr", "origin_port": 8443},
		map[string]any{"id": "g", "cdn_provider": "gcore", "origin_protection_mode": "auto-cidr", "origin_port": 8444},
		map[string]any{"id": "y", "cdn_provider": "yandex", "origin_protection_mode": "auto-cidr", "origin_port": 8445},
	}}}}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	if _, err := server.repository.saveDraft(map[string]any{}); err != nil {
		t.Fatal(err)
	}
	order := []string{}
	server.fetchCDNFeed = func(_ context.Context, id string) ([]string, error) {
		order = append(order, id)
		now = now.Add(50 * time.Second)
		return nil, errors.New("offline")
	}
	for i := 0; i < 6; i++ {
		_ = server.refreshOneCDNFeed(context.Background())
		now = now.Add(15 * time.Second)
	}
	if !reflect.DeepEqual(order, []string{"beeline", "gcore", "yandex", "beeline", "gcore", "yandex"}) {
		t.Fatalf("starved provider: %v", order)
	}
	server.configMu.Lock()
	defer server.configMu.Unlock()
	if err := server.refreshOneCDNFeed(context.Background()); err != nil || len(order) != 6 {
		t.Fatal("scheduler ran during Apply")
	}
}
