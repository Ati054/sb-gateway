package controlplane

import (
	"context"
	"reflect"
	"testing"
)

func TestSubscriptionRuntimeKeepsProviderPositionAcrossRefreshes(t *testing.T) {
	s, runtime, first, revision := subscriptionRuntimeFixture(t)
	active, err := s.repository.loadGeneration(revision)
	if err != nil {
		t.Fatal(err)
	}
	second := collectionArray(active["subscriptions"])[1].(map[string]any)
	state, err := s.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}

	check := func(want []string) {
		t.Helper()
		worked, err := s.activatePendingSubscription(context.Background())
		if !worked || err != nil {
			t.Fatalf("activation: worked=%v err=%v", worked, err)
		}
		got := make([]string, 0, len(runtime.nodes))
		for _, node := range runtime.nodes {
			got = append(got, subscriptionText(node["id"]))
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("catalog order=%v, want %v", got, want)
		}
	}
	check([]string{"one-new", "two-stay"})
	firstApplied := cloneJSONObject(runtime.nodes[0])
	state["two"] = map[string]any{
		"source_revision": mustSubscriptionSourceRevision(second), "fingerprint": "second-refresh",
		"nodes": []any{map[string]any{"id": "stay", "label": "FI updated", "protocol": "vless", "server": "second.example.test", "server_port": 443}},
	}
	if err := s.repository.saveAuxiliary("subscription-nodes", state); err != nil {
		t.Fatal(err)
	}
	check([]string{"one-new", "two-stay"})
	if !equalJSONObject(firstApplied, runtime.nodes[0]) {
		t.Fatal("refresh changed another provider's applied node")
	}
	secondApplied := cloneJSONObject(runtime.nodes[1])
	updatedFirst := cloneJSONObject(first)
	updatedFirst["fingerprint"] = "first-grown"
	updatedFirst["nodes"] = []any{
		map[string]any{"id": "next", "label": "DE next", "protocol": "vless", "server": "next.example.test", "server_port": 443},
		map[string]any{"id": "new", "label": "DE updated", "protocol": "vless", "server": "new.example.test", "server_port": 443},
	}
	state["one"] = updatedFirst
	if err := s.repository.saveAuxiliary("subscription-nodes", state); err != nil {
		t.Fatal(err)
	}
	check([]string{"one-next", "one-new", "two-stay"})
	if !equalJSONObject(secondApplied, runtime.nodes[2]) {
		t.Fatal("growing the first provider changed another provider's node")
	}
	if runtime.activateCalls != 3 || runtime.rollbackCalls != 0 {
		t.Fatalf("activations=%d rollbacks=%d", runtime.activateCalls, runtime.rollbackCalls)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatalf("unchanged refresh performed work: worked=%v err=%v", worked, err)
	}
}

func TestSubscriptionRuntimeKeepsLocalNodesAndAppendsNewProvider(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before []string
		want   []string
	}{
		{"middle", []string{"local-node", "one-old", "two-stay"}, []string{"local-node", "one-new", "two-stay"}},
		{"last", []string{"two-stay", "local-node", "one-old"}, []string{"two-stay", "local-node", "one-new"}},
		{"new-provider", []string{"local-node", "two-stay"}, []string{"local-node", "two-stay", "one-new"}},
		{"interleaved", []string{"one-old", "local-node", "one-extra", "two-stay"}, []string{"one-new", "local-node", "two-stay"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, runtime, _, revision := subscriptionRuntimeFixture(t)
			applied := s.routerOSNodesForRevision(revision, nil)
			byID := map[string]map[string]any{}
			for _, node := range applied {
				byID[subscriptionText(node["id"])] = node
			}
			byID["local-node"] = map[string]any{"id": "local-node", "label": "Local", "protocol": "vless", "server": "local.example.test", "server_port": 443}
			byID["one-extra"] = cloneJSONObject(byID["one-old"])
			byID["one-extra"]["id"] = "one-extra"
			previous := make([]map[string]any, 0, len(tc.before))
			for _, id := range tc.before {
				previous = append(previous, byID[id])
			}
			if err := s.saveSubscriptionSnapshot(revision, previous); err != nil {
				t.Fatal(err)
			}
			worked, err := s.activatePendingSubscription(context.Background())
			if !worked || err != nil {
				t.Fatalf("activation: worked=%v err=%v", worked, err)
			}
			got := make([]string, 0, len(runtime.nodes))
			for _, node := range runtime.nodes {
				id := subscriptionText(node["id"])
				got = append(got, id)
				if id == "local-node" || id == "two-stay" {
					if !equalJSONObject(node, byID[id]) {
						t.Fatalf("refresh changed unrelated node %s", id)
					}
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("catalog order=%v, want %v", got, tc.want)
			}
		})
	}
}
