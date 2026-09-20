package controlplane

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestUpdateRetentionAcceptsOnlyZeroOrOne(t *testing.T) {
	for _, value := range []any{0, 1, 2, -1, true, "1", 0.5} {
		config := currentConfigFixture(t)
		config["updates"] = map[string]any{"retain_previous_images": value}
		want := value == 0 || value == 1
		if result := validateCurrentConfig(config); result.Valid != want {
			t.Fatalf("retention %v validation=%v", value, result.Valid)
		}
		if keepPreviousImage(config) != (value == 1) {
			t.Fatalf("retention %v misread", value)
		}
	}
}

func TestPruneLocalUpdateBackupsRejectsUnreadableOrInvalidPolicy(t *testing.T) {
	root := t.TempDir()
	if removed, err := PruneLocalUpdateBackups(Options{StateDir: root}); err == nil || removed != 0 {
		t.Fatal("missing policy must not trigger cleanup")
	}
	repository, err := newStateRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.saveDraft(map[string]any{"updates": map[string]any{"retain_previous_images": 2}}); err != nil {
		t.Fatal(err)
	}
	if removed, err := PruneLocalUpdateBackups(Options{StateDir: root}); err == nil || removed != 0 {
		t.Fatal("invalid policy must not trigger cleanup")
	}
	for _, keep := range []int{0, 1} {
		if _, err := repository.saveDraft(map[string]any{"updates": map[string]any{"retain_previous_images": keep}}); err != nil {
			t.Fatal(err)
		}
		if got, err := localUpdateBackupRetention(root); err != nil || got != keep {
			t.Fatalf("persisted retention=%d, err=%v", got, err)
		}
	}
}

func TestUpdateBackupPruningKeepsOneOrNoneAndPreservesUnrelatedData(t *testing.T) {
	for _, keep := range []int{0, 1} {
		directory := t.TempDir()
		pattern := regexp.MustCompile(`^\.ui-backup-[0-9]{8}T[0-9]{6}Z-[0-9]+$`)
		old, latest := ".ui-backup-20260906T120000Z-1", ".ui-backup-20260907T120000Z-2"
		for _, name := range []string{old, latest, "out", ".ui-stage-pending", "last-known-good", "user-backup"} {
			if err := os.MkdirAll(filepath.Join(directory, name), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, name, "index.html"), []byte("keep me"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		removed, err := pruneUpdateBackupGroup(directory, pattern, keep)
		if err != nil || removed != 2-keep {
			t.Fatalf("removed=%d err=%v", removed, err)
		}
		for _, name := range []string{"out", ".ui-stage-pending", "last-known-good", "user-backup"} {
			if _, err := os.Stat(filepath.Join(directory, name, "index.html")); err != nil {
				t.Fatalf("unrelated %s removed", name)
			}
		}
		if _, err := os.Stat(filepath.Join(directory, latest)); (err == nil) != (keep == 1) {
			t.Fatal("wrong retained version")
		}
		if _, err := os.Stat(filepath.Join(directory, old)); !os.IsNotExist(err) {
			t.Fatal("old version survived")
		}
		if removed, err := pruneUpdateBackupGroup(directory, pattern, keep); err != nil || removed != 0 {
			t.Fatal("cleanup is not idempotent")
		}
	}
}

func TestFailedBinaryBackupPruningRemovesEveryOwnedFailure(t *testing.T) {
	directory := t.TempDir()
	failed := []string{
		"sb-gateway.failed-20260910T143622Z",
		"sb-gateway.failed-20260910T155346Z",
	}
	preserved := []string{
		"sb-gateway",
		"sb-gateway.before-20260910T172411Z",
		"sb-gateway.failed-current",
		"sb-gateway.failed-20260910T155346Z.extra",
	}
	for _, name := range append(append([]string{}, failed...), preserved...) {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("binary"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := pruneUpdateBackupGroup(
		directory,
		regexp.MustCompile(sbGatewayFailedBackupPattern),
		0,
	)
	if err != nil || removed != len(failed) {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	for _, name := range failed {
		if _, err := os.Stat(filepath.Join(directory, name)); !os.IsNotExist(err) {
			t.Fatalf("failed binary survived: %s", name)
		}
	}
	for _, name := range preserved {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("unrelated binary removed: %s", name)
		}
	}
}

func TestUpdateBackupPruningDoesNotFollowSymlinks(t *testing.T) {
	directory := t.TempDir()
	outside := t.TempDir()
	protected := filepath.Join(outside, "protected")
	if err := os.WriteFile(protected, []byte("safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "backup-link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Mkdir(filepath.Join(directory, "backup-real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "backup-real", "nested")); err != nil {
		t.Fatal(err)
	}
	if removed, err := pruneUpdateBackupGroup(directory, regexp.MustCompile(`^backup-`), 0); err != nil || removed != 1 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatal("symlink target was removed")
	}
}
