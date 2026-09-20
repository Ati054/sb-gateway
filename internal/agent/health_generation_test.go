package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerationWaitWakesForHealthPoolPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "urltest-pool.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan bool, 1)
	started := time.Now()
	go func() {
		done <- waitForGenerationChange(context.Background(), 2*time.Second, []string{path}, 5*time.Millisecond)
	}()
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("new-generation"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !<-done {
		t.Fatal("generation wait stopped before publication")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("health pool publication was not reconciled promptly: %v", elapsed)
	}
}
