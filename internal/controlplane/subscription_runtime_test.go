package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type subscriptionRuntimeFake struct {
	fakeRuntimeApplier
	nodes  []map[string]any
	config map[string]any
	fail   string
}

func (r *subscriptionRuntimeFake) prepare(c map[string]any, n []map[string]any) (runtimeconfig.RuntimeCandidate, error) {
	r.prepareCalls++
	r.config = cloneJSONObject(c)
	r.nodes = n
	if r.fail == "prepare" {
		return runtimeconfig.RuntimeCandidate{}, errors.New("validation failure")
	}
	revision, _ := revisionFor(n)
	return runtimeconfig.RuntimeCandidate{Revision: revision}, nil
}
func (r *subscriptionRuntimeFake) activate(context.Context, runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error) {
	r.activateCalls++
	if r.fail == "activate" || r.fail == "rollback" {
		return runtimeconfig.ActivationReceipt{}, errors.New("activation failure")
	}
	return runtimeconfig.ActivationReceipt{}, nil
}
func (r *subscriptionRuntimeFake) activateSubscription(ctx context.Context, candidate runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error) {
	return r.activate(ctx, candidate)
}
func (r *subscriptionRuntimeFake) rollback(context.Context, runtimeconfig.ActivationReceipt) error {
	r.rollbackCalls++
	if r.fail == "rollback" {
		return errors.New("rollback failure")
	}
	return nil
}
func (r *subscriptionRuntimeFake) rollbackSubscription(ctx context.Context, receipt runtimeconfig.ActivationReceipt) error {
	return r.rollback(ctx, receipt)
}
func (r *subscriptionRuntimeFake) commit(runtimeconfig.RuntimeCandidate) error {
	r.commitCalls++
	if r.fail == "commit" {
		return errors.New("commit interrupted")
	}
	return nil
}

func subscriptionRuntimeFixture(t *testing.T) (*Server, *subscriptionRuntimeFake, map[string]any, string) {
	t.Helper()
	s := newTestServer(t)
	c := routerOSReadyConfig(t)
	sub := map[string]any{"id": "one", "enabled": true, "display_name": "One", "url_secret_ref": "subscriptions/one.url"}
	c["subscriptions"] = []any{sub, map[string]any{"id": "two", "enabled": true, "url_secret_ref": "subscriptions/two.url"}}
	old := []map[string]any{{"id": "one-old", "subscription_id": "one", "label": "DE", "protocol": "vless", "server": "old.example.test", "server_port": 443}, {"id": "two-stay", "subscription_id": "two", "label": "FI", "protocol": "vless", "server": "stay.example.test", "server_port": 443}}
	revision, err := s.repository.stageGeneration(c)
	if err != nil {
		t.Fatal(err)
	}
	source, err := runtimeconfig.RenderRouterOSTrafficCandidate(c, old)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.saveSubscriptionSnapshot(revision, old); err != nil {
		t.Fatal(err)
	}
	if err = s.repository.commitActive(commitMetadata{Revision: revision, RuntimeRevision: strings.Repeat("1", 64), RouterOSSource: source, Actor: "test", CommittedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	draft := cloneJSONObject(c)
	draft["display_name"] = "UNAPPLIED"
	if _, err = s.repository.saveDraft(draft); err != nil {
		t.Fatal(err)
	}
	entry := map[string]any{"source_revision": mustSubscriptionSourceRevision(sub), "fingerprint": "fresh", "nodes": []any{map[string]any{"id": "new", "label": "DE", "protocol": "vless", "server": "new.example.test", "server_port": 443}}}
	if err = s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": entry, "two": map[string]any{"source_revision": "draft-only", "fingerprint": "unapproved", "nodes": []any{map[string]any{"id": "DRAFT"}}}}); err != nil {
		t.Fatal(err)
	}
	r := &subscriptionRuntimeFake{}
	s.runtime = r
	return s, r, entry, revision
}

func TestSubscriptionRuntimeAutomaticActivationKeepsDraftAndOtherProviders(t *testing.T) {
	s, r, _, revision := subscriptionRuntimeFixture(t)
	before, _ := s.getDraft()
	worked, err := s.activatePendingSubscription(context.Background())
	if !worked || err != nil {
		t.Fatalf("worked=%v err=%v", worked, err)
	}
	after, _ := s.getDraft()
	if !equalJSONObject(before, after) || r.config["display_name"] == "UNAPPLIED" {
		t.Fatal("draft was applied or modified")
	}
	if got, _ := s.repository.activeRevision(); got != revision {
		t.Fatal("configuration revision changed")
	}
	ids := []string{}
	for _, n := range r.nodes {
		ids = append(ids, subscriptionText(n["id"]))
	}
	if !reflect.DeepEqual(ids, []string{"two-stay", "one-new"}) {
		t.Fatalf("nodes=%v", ids)
	}
	if len(s.routerOSNodesForRevision(revision, nil)) != 2 {
		t.Fatal("operational snapshot missing")
	}
	if worked, err = s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatalf("unchanged update repeated: %v %v", worked, err)
	}
	if r.activateCalls != 1 || r.rollbackCalls != 0 {
		t.Fatal("unexpected runtime restarts")
	}
	metadata, _ := s.repository.metadata()
	snapshot := subscriptionText(metadata["node_snapshot_revision"])
	found := false
	revisions, err := s.subscriptionRetentionRevisions()
	if err != nil {
		t.Fatal(err)
	}
	for _, rev := range revisions {
		found = found || rev == snapshot
	}
	if !found {
		t.Fatal("active node secrets not retained")
	}
}

func TestSubscriptionRuntimeActivatesWithoutWaitingForIdleTraffic(t *testing.T) {
	s, r, _, _ := subscriptionRuntimeFixture(t)
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("hot runtime was not activated: worked=%v err=%v", worked, err)
	}
	if r.activateCalls != 1 {
		t.Fatalf("hot runtime activations=%d", r.activateCalls)
	}
}

func TestSubscriptionRuntimeReactivatesChangedParsedNodesWithSameSourceFingerprint(t *testing.T) {
	s, r, entry, _ := subscriptionRuntimeFixture(t)
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("initial activation: worked=%v err=%v", worked, err)
	}
	node := objectNodes(entry["nodes"])[0]
	node["tls"] = map[string]any{
		"enabled": true, "server_name": "provider.example.test",
		"pinned_peer_cert_sha256": strings.Repeat("a", 64),
	}
	if err := s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": entry}); err != nil {
		t.Fatal(err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("changed parsed nodes were skipped: worked=%v err=%v", worked, err)
	}
	if r.activateCalls != 2 {
		t.Fatalf("runtime activations=%d", r.activateCalls)
	}
	latest := r.nodes[len(r.nodes)-1]
	if objectCopy(latest["tls"])["pinned_peer_cert_sha256"] != strings.Repeat("a", 64) {
		t.Fatal("updated per-node TLS metadata did not reach runtime")
	}
}

func TestSubscriptionRuntimeFailureRetriesWithoutLosingCommittedState(t *testing.T) {
	for _, phase := range []string{"prepare", "activate"} {
		t.Run(phase, func(t *testing.T) {
			s, r, _, revision := subscriptionRuntimeFixture(t)
			r.fail = phase
			now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
			s.now = func() time.Time { return now }
			before, _ := s.repository.metadata()
			if worked, err := s.activatePendingSubscription(context.Background()); !worked || err == nil {
				t.Fatal("failure not reported")
			}
			after, _ := s.repository.metadata()
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failure changed commit point")
			}
			if s.routerOSNodesForRevision(revision, nil)[0]["id"] != "one-old" {
				t.Fatal("old runtime nodes lost")
			}
			if phase == "activate" && r.rollbackCalls != 1 {
				t.Fatal("activation not rolled back")
			}
			if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
				t.Fatal("retry deadline ignored")
			}
			now = now.Add(31 * time.Second)
			r.fail = ""
			if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
				t.Fatalf("recovery failed: %v", err)
			}
		})
	}
}

func TestSubscriptionRuntimeCrashRecoveryUsesCommitPoint(t *testing.T) {
	for _, phase := range []string{"rollback", "commit"} {
		t.Run(phase, func(t *testing.T) {
			s, r, _, revision := subscriptionRuntimeFixture(t)
			r.fail = phase
			if _, err := s.activatePendingSubscription(context.Background()); err == nil {
				t.Fatal("missing injected failure")
			}
			journal, _ := s.repository.auxiliary("subscription-runtime-operation")
			if journal["pending"] != true {
				t.Fatal("missing recovery journal")
			}
			committed := s.routerOSNodesForRevision(revision, nil)
			r.fail = ""
			if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
				t.Fatalf("recovery: %v", err)
			}
			committedRevision, committedErr := revisionFor(committed)
			recoveredRevision, recoveredErr := revisionFor(r.nodes)
			if committedErr != nil || recoveredErr != nil || committedRevision != recoveredRevision {
				t.Fatalf("recovery used uncommitted/latest nodes: committed=%s recovered=%s errors=%v/%v", committedRevision, recoveredRevision, committedErr, recoveredErr)
			}
			journal, _ = s.repository.auxiliary("subscription-runtime-operation")
			if journal["pending"] == true {
				t.Fatal("recovery journal not cleared")
			}
		})
	}
}

func TestSubscriptionRuntimeRejectsDraftSourceAndMissingSnapshot(t *testing.T) {
	s, r, entry, _ := subscriptionRuntimeFixture(t)
	entry["source_revision"] = "unapproved"
	if err := s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": entry}); err != nil {
		t.Fatal(err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil || r.prepareCalls != 0 {
		t.Fatal("draft URL activated")
	}
	metadata, _ := s.repository.metadata()
	metadata["node_snapshot_revision"] = strings.Repeat("f", 64)
	if err := s.repository.writeJSON(s.repository.root+"/active.json", metadata); err != nil {
		t.Fatal(err)
	}
	if _, err := s.activatePendingSubscription(context.Background()); err == nil || r.prepareCalls != 0 {
		t.Fatal("missing snapshot silently applied empty runtime")
	}
}

func TestSubscriptionRuntimeIPChangeStagesBypassBeforeActivation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			s, r, entry, revision := subscriptionRuntimeFixture(t)
			objectNodes(entry["nodes"])[0]["server"] = "9.9.9.9"
			if err := s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": entry}); err != nil {
				t.Fatal(err)
			}
			phases := []bool{}
			s.syncSubscriptionEndpoints = func(_ context.Context, _ map[string]any, values []string, prune bool) error {
				phases = append(phases, prune)
				if !prune && r.activateCalls != 0 {
					t.Fatal("bypass preparation too late")
				}
				if prune && r.activateCalls == 0 {
					t.Fatal("bypass pruned before runtime validation")
				}
				if !fail && len(values) != 1 {
					t.Fatal("missing new IP")
				}
				return nil
			}
			if fail {
				r.fail = "activate"
			}
			worked, err := s.activatePendingSubscription(context.Background())
			if !worked || (err != nil) != fail {
				t.Fatalf("%v", err)
			}
			if !reflect.DeepEqual(phases, []bool{false, true}) {
				t.Fatalf("phases=%v", phases)
			}
			nodes := s.routerOSNodesForRevision(revision, nil)
			if fail && nodes[0]["id"] != "one-old" {
				t.Fatal("failed new endpoint committed")
			}
		})
	}
}

func TestSubscriptionRuntimeRefreshSurvivesUnappliedRendererChanges(t *testing.T) {
	for _, endpointChange := range []bool{false, true} {
		t.Run(fmt.Sprint(endpointChange), func(t *testing.T) {
			s, r, entry, _ := subscriptionRuntimeFixture(t)
			metadata, _ := s.repository.metadata()
			committed := subscriptionText(metadata["routeros_source"]) + "# earlier renderer guard rules\n"
			metadata["routeros_source"] = committed
			if err := s.repository.writeJSON(s.repository.root+"/active.json", metadata); err != nil {
				t.Fatal(err)
			}
			if endpointChange {
				objectNodes(entry["nodes"])[0]["server"] = "192.0.2.5"
				if err := s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": entry}); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			s.syncSubscriptionEndpoints = func(context.Context, map[string]any, []string, bool) error { calls++; return nil }
			if _, err := s.activatePendingSubscription(context.Background()); err != nil {
				t.Fatal(err)
			}
			after, _ := s.repository.metadata()
			if !strings.HasSuffix(subscriptionText(after["routeros_source"]), "# earlier renderer guard rules\n") || r.activateCalls != 1 {
				t.Fatal("refresh blocked or unrelated rules marked applied")
			}
			if (endpointChange && calls != 2) || (!endpointChange && calls != 0) {
				t.Fatal("unexpected endpoint mutation")
			}
		})
	}
}

func TestSubscriptionRuntimeFailureStageDoesNotExposeCause(t *testing.T) {
	s, r, _, _ := subscriptionRuntimeFixture(t)
	r.fail = "prepare"
	_, err := s.activatePendingSubscription(context.Background())
	if err == nil || strings.Contains(err.Error(), "validation failure") {
		t.Fatal("unsafe or missing failure")
	}
	statuses, _ := s.repository.auxiliary("subscription-runtime-status")
	status := statuses["one"].(map[string]any)
	if status["failure_stage"] != "runtime_prepare" || status["state"] != "retrying" {
		t.Fatal("failure stage missing")
	}
}

func TestSubscriptionRefreshReusesLegacyIdentityOnEndpointChange(t *testing.T) {
	s := newTestServer(t)
	sub := map[string]any{"id": "one", "enabled": true}
	body := []byte("vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@old.example.test:443?security=tls&type=ws#Warsaw")
	nodes, err := parseProxySubscription(body, 10)
	if err != nil {
		t.Fatal(err)
	}
	old := cloneJSONObject(nodes[0])
	old["id"] = "legacy-position-id"
	old["selection_identity"] = "legacy-choice"
	delete(old, "_uuid")
	if err = s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": map[string]any{"nodes": []any{old}}}); err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.ReplaceAll(string(body), "old.example.test", "new.example.test"))
	nodes, err = parseProxySubscription(body, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.commitSubscriptionNodes(sub, body, http.Header{}, nodes, subscriptionRefreshChannel{}); err != nil {
		t.Fatal(err)
	}
	state, _ := s.repository.auxiliary("subscription-nodes")
	updated := objectNodes(state["one"].(map[string]any)["nodes"])[0]
	if updated["id"] != "legacy-position-id" || updated["selection_identity"] != "legacy-choice" || updated["server"] != "new.example.test" {
		t.Fatalf("identity migration failed: id=%v", updated["id"])
	}
}

func TestSubscriptionRefreshPreservesIdentityAcrossUnambiguousProviderEdits(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{
			name: "cosmetic rename",
			old:  "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@edge.example.test:443?security=tls&type=ws#Old%20Name",
			new:  "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@edge.example.test:443?security=tls&type=ws#%F0%9F%87%AB%F0%9F%87%B7%20New%20Name",
		},
		{
			name: "credential rotation",
			old:  "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@edge.example.test:443?security=tls&type=ws#Stable%20Name",
			new:  "vless://83a9897d-65e6-49c3-9ffd-c13bdc8e2189@edge.example.test:443?security=tls&type=ws#Stable%20Name",
		},
		{
			name: "city metadata removed",
			old:  "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@edge.example.test:443?security=tls&type=ws&city=Paris#Stable%20Name",
			new:  "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@edge.example.test:443?security=tls&type=ws#Stable%20Name",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t)
			sub := map[string]any{"id": "one", "enabled": true}
			commit := func(link string) map[string]any {
				nodes, err := parseProxySubscription([]byte(link), 10)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.commitSubscriptionNodes(sub, []byte(link), http.Header{}, nodes, subscriptionRefreshChannel{}); err != nil {
					t.Fatal(err)
				}
				state, err := s.repository.auxiliary("subscription-nodes")
				if err != nil {
					t.Fatal(err)
				}
				return objectNodes(state["one"].(map[string]any)["nodes"])[0]
			}
			before := commit(test.old)
			after := commit(test.new)
			if after["id"] != before["id"] || after["selection_identity"] != before["selection_identity"] {
				t.Fatalf("identity changed after %s: before=%v/%v after=%v/%v", test.name, before["id"], before["selection_identity"], after["id"], after["selection_identity"])
			}
		})
	}
}

func TestSubscriptionRefreshDoesNotGuessAmbiguousEndpointRename(t *testing.T) {
	s := newTestServer(t)
	sub := map[string]any{"id": "one", "enabled": true}
	oldBody := []byte(strings.Join([]string{
		"vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@shared.example.test:443?security=tls&type=ws#First",
		"vless://83a9897d-65e6-49c3-9ffd-c13bdc8e2189@shared.example.test:443?security=tls&type=ws#Second",
	}, "\n"))
	nodes, err := parseProxySubscription(oldBody, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.commitSubscriptionNodes(sub, oldBody, http.Header{}, nodes, subscriptionRefreshChannel{}); err != nil {
		t.Fatal(err)
	}
	state, _ := s.repository.auxiliary("subscription-nodes")
	oldNodes := objectNodes(state["one"].(map[string]any)["nodes"])
	oldIDs := map[string]bool{}
	oldSelections := map[string]bool{}
	for _, node := range oldNodes {
		oldIDs[subscriptionText(node["id"])] = true
		oldSelections[subscriptionText(node["selection_identity"])] = true
	}

	newBody := []byte("vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@shared.example.test:443?security=tls&type=ws#Renamed")
	nodes, err = parseProxySubscription(newBody, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.commitSubscriptionNodes(sub, newBody, http.Header{}, nodes, subscriptionRefreshChannel{}); err != nil {
		t.Fatal(err)
	}
	state, _ = s.repository.auxiliary("subscription-nodes")
	updated := objectNodes(state["one"].(map[string]any)["nodes"])[0]
	if oldIDs[subscriptionText(updated["id"])] || oldSelections[subscriptionText(updated["selection_identity"])] {
		t.Fatalf("ambiguous endpoint rename reused an old identity: %#v", updated)
	}
}
