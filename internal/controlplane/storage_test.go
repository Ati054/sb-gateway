package controlplane

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCanonicalRevisionIsStable(t *testing.T) {
	value := map[string]any{"z": "Европа", "a": []any{1, true, nil}}
	revision, err := revisionFor(value)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "a2a962809edf83fce9f0701f5445c356b8fe40d185837619a480b42351d2b575"
	if revision != expected {
		t.Fatalf("canonical revision drifted: %s", revision)
	}
}

func TestIdenticalJSONSkipsRewrite(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"pending": false}
	if err := repository.saveAuxiliary("maintenance-state", value); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "maintenance-state.json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := repository.saveAuxiliary("maintenance-state", value); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("identical state was durably rewritten")
	}
}

func TestReadJSONCacheReturnsIndependentCopies(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.saveAuxiliary("runtime-status", map[string]any{
		"container": map[string]any{"healthy": true},
	}); err != nil {
		t.Fatal(err)
	}
	first, err := repository.auxiliary("runtime-status")
	if err != nil {
		t.Fatal(err)
	}
	first["container"].(map[string]any)["healthy"] = false
	second, err := repository.auxiliary("runtime-status")
	if err != nil {
		t.Fatal(err)
	}
	if second["container"].(map[string]any)["healthy"] != true {
		t.Fatal("caller mutation escaped into the cached state")
	}
}

func TestStateDocumentCacheIsBounded(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < stateDocumentCacheLimit+20; index++ {
		name := fmt.Sprintf("state-%03d", index)
		if err := repository.saveAuxiliary(name, map[string]any{"index": index}); err != nil {
			t.Fatal(err)
		}
	}
	if len(repository.cache) != stateDocumentCacheLimit {
		t.Fatalf("state cache grew beyond its bound: %d", len(repository.cache))
	}
}

func TestRecentAuditReadsBoundedTail(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "audit.jsonl")
	prefix := make([]byte, 600<<10)
	for index := range prefix {
		prefix[index] = 'x'
	}
	prefix = append(prefix, '\n')
	prefix = append(prefix, []byte("{\"action\":\"old\"}\n{\"action\":\"latest\"}\n")...)
	if err := os.WriteFile(path, prefix, 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := repository.recentAudit(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0]["action"] != "latest" {
		t.Fatalf("unexpected audit tail: %#v", events)
	}
}

func TestCommitActiveUsesActivePointerAsCrashSafeCommitPoint(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"schema_version": 1, "name": "candidate"}
	revision, err := repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	previous := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runtimeRevision := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	committedAt := time.Date(2026, 9, 3, 12, 30, 0, 0, time.UTC)
	if err := repository.commitActive(commitMetadata{
		Revision: revision, PreviousRevision: previous, RuntimeRevision: runtimeRevision,
		Actor: "admin", BackupRef: map[string]any{"name": "backup"}, CommittedAt: committedAt,
	}); err != nil {
		t.Fatal(err)
	}
	active, err := repository.readJSON(filepath.Join(repository.root, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if active["revision"] != revision || active["previous_revision"] != previous || active["runtime_revision"] != runtimeRevision || active["committed_at"] != "2026-09-03T12:30:00Z" {
		t.Fatalf("active pointer = %#v", active)
	}
	for _, name := range []string{"last-known-good.json", "apply-metadata.json"} {
		derived, readErr := repository.readJSON(filepath.Join(repository.root, name))
		if readErr != nil || !equalJSONObject(active, derived) {
			t.Fatalf("%s does not match commit point: %#v, %v", name, derived, readErr)
		}
	}
}

func TestCommitActiveDetailedReportsPublishedCommitWhenDerivativeWriteFails(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	revision, err := repository.stageGeneration(map[string]any{"schema_version": 1})
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the derivative path makes that write fail on every
	// supported OS without affecting the authoritative active.json write.
	derivativePath := filepath.Join(repository.root, "last-known-good.json")
	if err := os.Mkdir(derivativePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(derivativePath, "block"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	published, commitErr := repository.commitActiveDetailed(commitMetadata{
		Revision: revision, Actor: "admin", CommittedAt: time.Now().UTC(),
	})
	if !published || commitErr == nil {
		t.Fatalf("published=%t err=%v", published, commitErr)
	}
	active, readErr := repository.activeRevision()
	if readErr != nil || active != revision {
		t.Fatalf("active revision=%q err=%v", active, readErr)
	}
}

func TestReconcileCommitPointersRepairsOnlyFromVerifiedActive(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"schema_version": 1}
	revision, err := repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	active := map[string]any{"revision": revision, "actor": "admin"}
	if err := repository.writeJSON(filepath.Join(repository.root, "active.json"), active); err != nil {
		t.Fatal(err)
	}
	if err := repository.writeJSON(filepath.Join(repository.root, "last-known-good.json"), map[string]any{"revision": "bad"}); err != nil {
		t.Fatal(err)
	}
	if err := repository.reconcileCommitPointers(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"last-known-good.json", "apply-metadata.json"} {
		value, readErr := repository.readJSON(filepath.Join(repository.root, name))
		if readErr != nil || !equalJSONObject(active, value) {
			t.Fatalf("%s was not repaired: %#v, %v", name, value, readErr)
		}
	}
}
