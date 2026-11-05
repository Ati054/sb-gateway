package controlplane

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type blockedPlanningRuntime struct{ subscriptionRuntimeFake }

func (r *blockedPlanningRuntime) prepare(map[string]any, []map[string]any) (runtimeconfig.RuntimeCandidate, error) {
	r.prepareCalls++
	return runtimeconfig.RuntimeCandidate{}, fmt.Errorf("wrapped planning rejection: %w", runtimeconfig.ErrCatalogPlanningBudget)
}

func TestSubscriptionRuntimePlanningBudgetBlocksOnlyIdenticalSelection(t *testing.T) {
	for _, change := range []string{"source", "active-config", "applied-snapshot"} {
		t.Run(change, func(t *testing.T) {
			s, _, entry, revision := subscriptionRuntimeFixture(t)
			r := &blockedPlanningRuntime{}
			s.runtime = r
			now := s.now()
			s.now = func() time.Time { return now }
			before, _ := s.repository.metadata()
			beforeInventory, _ := s.repository.auxiliary("subscription-nodes")
			worked, err := s.activatePendingSubscription(context.Background())
			if !worked || !errors.Is(err, runtimeconfig.ErrCatalogPlanningBudget) {
				t.Fatal("planning failure not reported")
			}
			statuses, _ := s.repository.auxiliary("subscription-runtime-status")
			status, _ := statuses["one"].(map[string]any)
			if status["state"] != "blocked" || status["reason"] != "catalog_planning_budget" || status["next_attempt"] != nil || status["message"] == "" {
				t.Fatal("deterministic rejection scheduled a transient retry")
			}
			if stored, valid := jsonInteger(status["planning_budget_bytes"]); !valid || int64(stored) != runtimeconfig.CatalogPlanningBudgetBytes() {
				t.Fatal("planning budget not bound to rejection")
			}
			for range 2 {
				now = now.Add(time.Minute)
				if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
					t.Fatal("unchanged blocked selection was retried")
				}
			}
			if r.prepareCalls != 1 || r.activateCalls != 0 || r.commitCalls != 0 {
				t.Fatal("unchanged rejection consumed another prepare or changed runtime")
			}
			after, _ := s.repository.metadata()
			inventory, _ := s.repository.auxiliary("subscription-nodes")
			if !equalJSONObject(before, after) || !equalJSONObject(beforeInventory, inventory) {
				t.Fatal("rejected plan changed runtime or full source inventory")
			}
			if change == "source" {
				objectNodes(entry["nodes"])[0]["server"] = "changed.example.test"
				if err := s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": entry}); err != nil {
					t.Fatal(err)
				}
			} else if change == "active-config" {
				config, err := s.repository.loadGeneration(revision)
				if err != nil {
					t.Fatal(err)
				}
				interval, _ := jsonInteger(objectAt(config, "watchdog")["interval_seconds"])
				objectAt(config, "watchdog")["interval_seconds"] = float64(interval + 1)
				next, err := s.repository.stageGeneration(config)
				if err != nil {
					t.Fatal(err)
				}
				snapshot, _ := s.repository.auxiliary("subscription-nodes-" + revision)
				if err := s.saveSubscriptionSnapshot(next, objectNodes(snapshot["nodes"])); err != nil {
					t.Fatal(err)
				}
				if err := s.repository.commitActive(commitMetadata{Revision: next, RuntimeRevision: subscriptionText(before["runtime_revision"]), NodeSnapshotRevision: next, RouterOSSource: subscriptionText(before["routeros_source"]), Actor: "synthetic", CommittedAt: s.now()}); err != nil {
					t.Fatal(err)
				}
			} else {
				// Another provider has applied a new generation; the blocked
				// provider's own source and active configuration are unchanged.
				snapshot, _ := s.repository.auxiliary("subscription-nodes-" + revision)
				nodes := objectNodes(snapshot["nodes"])
				for _, node := range nodes {
					if subscriptionText(node["subscription_id"]) == "two" {
						node["server"] = "other-applied.example.test"
					}
				}
				next, err := revisionFor(nodes)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.saveSubscriptionSnapshot(next, nodes); err != nil {
					t.Fatal(err)
				}
				config, err := s.repository.loadGeneration(revision)
				if err != nil {
					t.Fatal(err)
				}
				source, err := runtimeconfig.RenderRouterOSTrafficCandidate(config, nodes)
				if err != nil {
					t.Fatal(err)
				}
				if err := s.repository.commitActive(commitMetadata{Revision: revision, RuntimeRevision: strings.Repeat("3", 64), NodeSnapshotRevision: next, RouterOSSource: source, Actor: "synthetic-other-provider", CommittedAt: s.now()}); err != nil {
					t.Fatal(err)
				}
			}
			if worked, err := s.activatePendingSubscription(context.Background()); !worked || !errors.Is(err, runtimeconfig.ErrCatalogPlanningBudget) {
				t.Fatal("changed selection did not become eligible")
			}
			if r.prepareCalls != 2 {
				t.Fatal("changed config/source did not get one fresh prepare")
			}
			now = now.Add(time.Minute)
			if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
				t.Fatal("unchanged reconsidered generation was retried")
			}
			if r.prepareCalls != 2 {
				t.Fatal("reconsideration was not bounded to one prepare")
			}
		})
	}
}

func TestSubscriptionRuntimeBlockedBudgetRiseRechecksAfterIdleTTL(t *testing.T) {
	previous := debug.SetMemoryLimit(112 << 20)
	defer debug.SetMemoryLimit(previous)
	s, _, _, _ := subscriptionRuntimeFixture(t)
	r := &blockedPlanningRuntime{}
	s.runtime = r
	now := s.now()
	s.now = func() time.Time { return now }
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || !errors.Is(err, runtimeconfig.ErrCatalogPlanningBudget) {
		t.Fatal("initial rejection missing")
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatal("blocked recheck repeated prepare")
	}
	if s.subscriptionRuntimeIdle.retryAt.IsZero() {
		t.Fatal("blocked idle cache has no budget recheck deadline")
	}
	debug.SetMemoryLimit(128 << 20)
	now = now.Add(31 * time.Second)
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || !errors.Is(err, runtimeconfig.ErrCatalogPlanningBudget) {
		t.Fatal("larger budget did not permit reconsideration")
	}
	if r.prepareCalls != 2 {
		t.Fatal("budget rise did not get one fresh prepare")
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatal("rejection at larger budget retried unchanged")
	}
}

func TestSubscriptionRuntimeTransientPlanningFailureStillRetriesAfter30Seconds(t *testing.T) {
	s, r, _, _ := subscriptionRuntimeFixture(t)
	r.fail = "prepare"
	now := s.now()
	s.now = func() time.Time { return now }
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err == nil {
		t.Fatal("transient failure missing")
	}
	statuses, _ := s.repository.auxiliary("subscription-runtime-status")
	status, _ := statuses["one"].(map[string]any)
	if status["state"] != "retrying" || !strings.Contains(subscriptionText(status["message"]), "30") || status["planning_budget_bytes"] != nil {
		t.Fatal("transient failure was permanently blocked")
	}
	now = now.Add(29 * time.Second)
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatal("transient retry ran early")
	}
	now = now.Add(2 * time.Second)
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err == nil {
		t.Fatal("due transient retry was suppressed")
	}
	if r.prepareCalls != 2 {
		t.Fatal("transient retry frequency changed")
	}
}
