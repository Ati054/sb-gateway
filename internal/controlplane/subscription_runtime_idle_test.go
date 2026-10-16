package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func warmedSubscriptionRuntime(t *testing.T) (*Server, *subscriptionRuntimeFake, map[string]any, string) {
	t.Helper()
	s, runtime, entry, revision := subscriptionRuntimeFixture(t)
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("initial activation: %v %v", worked, err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatalf("idle scan: %v %v", worked, err)
	}
	if !s.subscriptionRuntimeIdle.unchanged(s.now()) {
		t.Fatal("unchanged successful scan was not cached")
	}
	return s, runtime, entry, revision
}

func TestSubscriptionRuntimeIdleSkipsUnchangedCatalog(t *testing.T) {
	s, runtime, _, _ := warmedSubscriptionRuntime(t)
	before := s.subscriptionRuntimeIdle.checked
	for range 3 {
		if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
			t.Fatalf("idle call: %v %v", worked, err)
		}
	}
	if runtime.prepareCalls != 1 || runtime.activateCalls != 1 || !s.subscriptionRuntimeIdle.checked.Equal(before) {
		t.Fatal("idle catalog was reprocessed")
	}
}

func TestSubscriptionRuntimeIdleInvalidatesChangedParsedNodes(t *testing.T) {
	s, runtime, entry, _ := warmedSubscriptionRuntime(t)
	objectNodes(entry["nodes"])[0]["server"] = "changed.example.test"
	if err := s.repository.saveAuxiliary("subscription-nodes", map[string]any{"one": entry}); err != nil {
		t.Fatal(err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("changed nodes: %v %v", worked, err)
	}
	if runtime.activateCalls != 2 {
		t.Fatal("changed source with the same fingerprint was skipped")
	}
}

func TestSubscriptionRuntimeIdleDetectsReplacementWithSameSizeAndTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, ok := subscriptionRuntimeSources(path)
	if !ok {
		t.Fatal("stat failed")
	}
	replacement := path + ".next"
	if err := os.WriteFile(replacement, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, before[0].info.ModTime(), before[0].info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if subscriptionRuntimeSourcesUnchanged(before) {
		t.Fatal("replacement was mistaken for the old file")
	}
}

func TestSubscriptionRuntimeIdleReadsReplacementWithSameSizeAndTime(t *testing.T) {
	s, runtime, _, _ := warmedSubscriptionRuntime(t)
	path := filepath.Join(s.repository.root, "subscription-nodes.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replaced := strings.Replace(string(body), "new.example.test", "alt.example.test", 1)
	if replaced == string(body) || len(replaced) != len(body) {
		t.Fatal("test must preserve the source size")
	}
	replacement := path + ".next"
	if err := os.WriteFile(replacement, []byte(replaced), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("atomic replacement: %v %v", worked, err)
	}
	if runtime.activateCalls != 2 || runtime.nodes[len(runtime.nodes)-1]["server"] != "alt.example.test" {
		t.Fatal("the document cache concealed the new catalog")
	}
}

func TestSubscriptionRuntimeIdleDoesNotHideGenerationCorruption(t *testing.T) {
	s, runtime, _, revision := warmedSubscriptionRuntime(t)
	if err := os.WriteFile(filepath.Join(s.repository.generations, revision+".json"), []byte(`{"changed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.activatePendingSubscription(context.Background()); err == nil {
		t.Fatal("generation corruption was hidden")
	}
	if runtime.activateCalls != 1 {
		t.Fatal("corrupted generation reached runtime")
	}
}

func TestSubscriptionRuntimeIdleRepairsChangedCommitPointers(t *testing.T) {
	for _, name := range []string{"last-known-good.json", "apply-metadata.json"} {
		t.Run(name, func(t *testing.T) {
			s, runtime, _, _ := warmedSubscriptionRuntime(t)
			if err := os.WriteFile(filepath.Join(s.repository.root, name), []byte("broken"), 0o600); err != nil {
				t.Fatal(err)
			}
			if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
				t.Fatalf("pointer repair: %v %v", worked, err)
			}
			active, _ := s.repository.readJSON(filepath.Join(s.repository.root, "active.json"))
			pointer, err := s.repository.readJSON(filepath.Join(s.repository.root, name))
			if err != nil || !equalJSONObject(active, pointer) || runtime.activateCalls != 1 {
				t.Fatal("derived pointer was not repaired from the commit point")
			}
		})
	}
}

func TestSubscriptionRuntimeIdleObservesNewRecoveryJournal(t *testing.T) {
	s, runtime, _, _ := warmedSubscriptionRuntime(t)
	path := filepath.Join(s.repository.root, "subscription-runtime-operation.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatalf("missing optional journal: %v %v", worked, err)
	}
	if err := s.repository.saveAuxiliary("subscription-runtime-operation", map[string]any{"pending": true}); err != nil {
		t.Fatal(err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("recovery: %v %v", worked, err)
	}
	journal, _ := s.repository.auxiliary("subscription-runtime-operation")
	if journal["pending"] == true || runtime.activateCalls != 2 {
		t.Fatal("new journal was ignored")
	}
}

func TestSubscriptionRuntimeIdlePreservesRetryDeadline(t *testing.T) {
	s, runtime, _, _ := subscriptionRuntimeFixture(t)
	now := s.now()
	s.now = func() time.Time { return now }
	runtime.fail = "prepare"
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err == nil {
		t.Fatal("injected failure was not reported")
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatal("retry deadline was ignored")
	}
	runtime.fail = ""
	now = now.Add(5 * time.Second)
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatal("cached retry ran too early")
	}
	now = now.Add(26 * time.Second)
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("due retry was skipped: %v %v", worked, err)
	}
}

func TestSubscriptionRuntimeIdleRejectsClockRollback(t *testing.T) {
	s, _, _, _ := warmedSubscriptionRuntime(t)
	now := s.subscriptionRuntimeIdle.checked.Add(-time.Second)
	s.now = func() time.Time { return now }
	if s.subscriptionRuntimeIdle.unchanged(now) {
		t.Fatal("clock rollback retained the idle decision")
	}
	if worked, err := s.activatePendingSubscription(context.Background()); worked || err != nil {
		t.Fatalf("rescan after clock rollback: %v %v", worked, err)
	}
	if !s.subscriptionRuntimeIdle.checked.Equal(now) {
		t.Fatal("clock rollback did not force a scan")
	}
}

func TestSubscriptionRuntimeUnchangedInventoryAfterApplyDoesNotReactivate(t *testing.T) {
	s, runtime, _, revision := warmedSubscriptionRuntime(t)
	active, _ := s.repository.loadGeneration(revision)
	active["display_name"] = "Updated panel title"
	next, err := s.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := s.repository.metadata()
	if err := s.repository.commitActive(commitMetadata{Revision: next, RuntimeRevision: subscriptionText(metadata["runtime_revision"]), NodeSnapshotRevision: subscriptionText(metadata["node_snapshot_revision"]), RouterOSSource: subscriptionText(metadata["routeros_source"]), Actor: "test", CommittedAt: s.now()}); err != nil {
		t.Fatal(err)
	}
	if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
		t.Fatalf("acknowledge Apply: %v %v", worked, err)
	}
	statuses, _ := s.repository.auxiliary("subscription-runtime-status")
	status := objectCopy(statuses["one"])
	if status["active_revision"] != next || status["state"] != "active" || runtime.prepareCalls != 1 || runtime.activateCalls != 1 {
		t.Fatal("unchanged committed provider was reactivated")
	}
	after, _ := s.repository.metadata()
	if after["node_snapshot_revision"] != metadata["node_snapshot_revision"] {
		t.Fatal("unchanged inventory was reordered")
	}
}
