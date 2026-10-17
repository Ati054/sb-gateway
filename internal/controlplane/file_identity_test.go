package controlplane

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileIdentitySnapshotSurvivesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := statFileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := path + ".next"
	if err := os.WriteFile(replacement, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	after, err := statFileIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("replacement must preserve size and modification time")
	}
	if os.SameFile(before, after) {
		t.Fatal("file identity was resolved from the replacement path")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(after, after) {
		t.Fatal("captured identity depends on a path that no longer exists")
	}
	if _, err := statFileIdentity(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}
