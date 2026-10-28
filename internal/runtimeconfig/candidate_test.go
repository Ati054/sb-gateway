package runtimeconfig

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCandidateStorePublishesRollsBackAndKeepsOneCandidate(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { _ = removeManagedTree(filepath.Dir(root), root) })
	destinationRoot := filepath.Join(root, "runtime")
	destinations := map[string]string{
		"policy-dns.json": filepath.Join(destinationRoot, "policy-dns.json"),
		"xray.json":       filepath.Join(destinationRoot, "xray.json"),
	}
	store, err := NewCandidateStore(filepath.Join(root, "state"), destinations)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(destinationRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destinations["xray.json"], []byte("old-xray\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := store.Prepare(strings.Repeat("a", 64), map[string][]byte{
		"policy-dns.json": []byte("new-dns\n"),
		"xray.json":       []byte("new-xray\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(first.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded.Files, first.Files) {
		t.Fatalf("loaded candidate differs: %#v != %#v", loaded, first)
	}
	receipt, err := store.Activate(first)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := receipt.Changed(), []string{"policy-dns.json", "xray.json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("changed artifacts = %v, want %v", got, want)
	}
	assertFileBody(t, destinations["policy-dns.json"], "new-dns\n")
	assertFileBody(t, destinations["xray.json"], "new-xray\n")
	prepareErr := errors.New("rollback scope was not captured")
	if err := store.RollbackAfter(receipt, func(restoring map[string]string) error {
		assertFileBody(t, destinations["xray.json"], "new-xray\n")
		assertFileBody(t, restoring["xray.json"], "old-xray\n")
		if path, exists := restoring["policy-dns.json"]; !exists || path != "" {
			t.Fatalf("previously absent artifact = %q, exists=%t", path, exists)
		}
		return prepareErr
	}); !errors.Is(err, prepareErr) {
		t.Fatalf("rollback ignored preparation error: %v", err)
	}
	assertFileBody(t, destinations["xray.json"], "new-xray\n")
	if err := store.RollbackAfter(receipt, func(restoring map[string]string) error {
		assertFileBody(t, destinations["xray.json"], "new-xray\n")
		assertFileBody(t, restoring["xray.json"], "old-xray\n")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(destinations["policy-dns.json"]); !os.IsNotExist(err) {
		t.Fatalf("new destination survived rollback: %v", err)
	}
	assertFileBody(t, destinations["xray.json"], "old-xray\n")

	second, err := store.Prepare(strings.Repeat("b", 64), map[string][]byte{
		"policy-dns.json": []byte("final-dns\n"),
		"xray.json":       []byte("final-xray\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(first.Directory); !os.IsNotExist(err) {
		t.Fatalf("older reproducible candidate was retained: %v", err)
	}
	if _, err := store.Activate(second); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitLastKnownGood(second); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, filepath.Join(root, "state", "runtime-lkg", "policy-dns.json"), "final-dns\n")
	if _, err := os.Stat(filepath.Join(second.Directory, ".previous-runtime")); !os.IsNotExist(err) {
		t.Fatalf("activation rollback copy was retained after LKG commit: %v", err)
	}

	unchanged, err := store.Activate(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.Changed()) != 0 {
		t.Fatalf("unchanged activation rewrote files: %v", unchanged.Changed())
	}
}

func TestCandidateStoreLoadRejectsTamperedArtifact(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { _ = removeManagedTree(filepath.Dir(root), root) })
	store, err := NewCandidateStore(filepath.Join(root, "state"), map[string]string{
		"xray.json": filepath.Join(root, "runtime", "xray.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("c", 64)
	candidate, err := store.Prepare(revision, map[string][]byte{"xray.json": []byte("trusted\n")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate.Files["xray.json"], []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(revision); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered artifact was accepted: %v", err)
	}
}

func TestCandidateStoreRejectsPartialAndUnsafeCandidates(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { _ = removeManagedTree(filepath.Dir(root), root) })
	store, err := NewCandidateStore(filepath.Join(root, "state"), map[string]string{
		"xray.json": filepath.Join(root, "runtime", "xray.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Prepare("not-a-revision", map[string][]byte{"xray.json": []byte("x")}); err == nil {
		t.Fatal("unsafe revision was accepted")
	}
	if _, err := store.Prepare(strings.Repeat("a", 64), map[string][]byte{}); err == nil {
		t.Fatal("partial candidate was accepted")
	}
	if _, err := NewCandidateStore(filepath.Join(root, "state"), map[string]string{"../xray.json": "x"}); err == nil {
		t.Fatal("unsafe artifact name was accepted")
	}
	if _, err := NewCandidateStore(filepath.Join(root, "state"), map[string]string{"manifest.json": "x"}); err == nil {
		t.Fatal("reserved manifest name was accepted")
	}
}

func TestCandidateStoreValidatesExactChangedSetBeforePublishing(t *testing.T) {
	root := t.TempDir()
	destinations := map[string]string{
		"same":    filepath.Join(root, "live", "same"),
		"changed": filepath.Join(root, "live", "changed"),
	}
	store, err := NewCandidateStore(filepath.Join(root, "state"), destinations)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destinations["same"]), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destinations["same"], []byte("same\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destinations["changed"], []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := store.Prepare(strings.Repeat("a", 64), map[string][]byte{
		"same": []byte("same\n"), "changed": []byte("new\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	wantFailure := errors.New("reject candidate")
	_, err = store.ActivateAfter(candidate, func(changed []string) error {
		if !reflect.DeepEqual(changed, []string{"changed"}) {
			t.Fatalf("changed set = %v", changed)
		}
		return wantFailure
	})
	if !errors.Is(err, wantFailure) {
		t.Fatalf("validation error = %v", err)
	}
	assertFileBody(t, destinations["changed"], "old\n")
}

func assertFileBody(t *testing.T, path, want string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(body); got != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}

func TestCandidatePrepareReusesVerifiedFilesAndPreservesRollback(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live.json")
	store, err := NewCandidateStore(filepath.Join(root, "state"), map[string]string{"xray.json": live})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	revision := strings.Repeat("c", 64)
	artifacts := map[string][]byte{"xray.json": []byte("new")}
	first, err := store.Prepare(revision, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Activate(first)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(946684800, 0)
	if err := os.Chtimes(first.Files["xray.json"], stamp, stamp); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(first.Files["xray.json"])
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Prepare(revision, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(second.Files["xray.json"])
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("identical verified candidate was rewritten")
	}
	if err := store.Rollback(receipt); err != nil {
		t.Fatal(err)
	}
	assertFileBody(t, live, "old")
}

func TestCandidatePrepareRepairsCorruptionAndRejectsStaleContents(t *testing.T) {
	for _, kind := range []string{"artifact", "manifest", "rendered"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			store, err := NewCandidateStore(filepath.Join(root, "state"), map[string]string{"xray.json": filepath.Join(root, "live.json")})
			if err != nil {
				t.Fatal(err)
			}
			revision := strings.Repeat("d", 64)
			artifacts := map[string][]byte{"xray.json": []byte("expected")}
			candidate, err := store.Prepare(revision, artifacts)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "artifact":
				if err := os.WriteFile(candidate.Files["xray.json"], []byte("corrupt"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "manifest":
				if err := os.WriteFile(filepath.Join(candidate.Directory, "manifest.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "rendered":
				artifacts["xray.json"] = []byte("changed")
			}
			fixed, err := store.Prepare(revision, artifacts)
			if err != nil {
				t.Fatal(err)
			}
			assertFileBody(t, fixed.Files["xray.json"], string(artifacts["xray.json"]))
			if _, err := store.Load(revision); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkCandidatePrepareUnchanged(b *testing.B) {
	root := b.TempDir()
	artifacts := make(map[string][]byte)
	destinations := make(map[string]string)
	for _, name := range []string{"xray.json", "urltest-pool.json", "policy-dns.json", "nginx.conf", "watchdog.env", "client-telemetry.nft", "transparent-exclusions.txt"} {
		artifacts[name] = make([]byte, 64<<10)
		destinations[name] = filepath.Join(root, "live", name)
	}
	store, err := NewCandidateStore(filepath.Join(root, "state"), destinations)
	if err != nil {
		b.Fatal(err)
	}
	revision := strings.Repeat("b", 64)
	if _, err := store.Prepare(revision, artifacts); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := store.Prepare(revision, artifacts); err != nil {
			b.Fatal(err)
		}
	}
}
