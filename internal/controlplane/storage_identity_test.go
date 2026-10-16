package controlplane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadJSONCacheInvalidatesAtomicReplacement(t *testing.T) {
	for _, readWarmup := range []bool{false, true} {
		name := "write-cache"
		if readWarmup {
			name = "read-cache"
		}
		t.Run(name, func(t *testing.T) {
			repository, err := newStateRepository(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := repository.saveAuxiliary("runtime-status", map[string]any{"value": "old"}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(repository.root, "runtime-status.json")
			if readWarmup {
				repository.mu.Lock()
				delete(repository.cache, path)
				repository.mu.Unlock()
				if _, err := repository.readJSON(path); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			replacement := path + ".next"
			body := []byte("{\"value\":\"new\"}\n")
			if int64(len(body)) != before.Size() {
				t.Fatal("replacement must preserve size")
			}
			if err := os.WriteFile(replacement, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(replacement, before.ModTime(), before.ModTime()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatal(err)
			}
			after, err := repository.readJSON(path)
			if err != nil || after["value"] != "new" {
				t.Fatalf("stale state after replacement: %v %v", after, err)
			}
		})
	}
}
