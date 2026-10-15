package diagnosticlog

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExternalAppendRotationKeepsWriterAndBoundsArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.log")
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	before, _ := writer.Stat()
	r := ExternalRotator{AppendPaths: []string{path}, Maximum: 1024}
	for pass := 0; pass < 3; pass++ {
		_, _ = writer.WriteString(strings.Repeat("old", 2000) + strings.Repeat("z", 1024))
		if err := r.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(path + ".1"); err != nil || string(b) != strings.Repeat("z", 1024) {
			t.Fatalf("archive: %d %v", len(b), err)
		}
		if _, err := writer.WriteString("still alive\n"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(path)
		after, _ := os.Stat(path)
		if string(b) != "still alive\n" || !os.SameFile(before, after) {
			t.Fatal("append descriptor lost or sparse data created")
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatalf("unexpected retained files: %v", entries)
	}
}

func TestExternalReopenRetriesWithoutReplacingLiveArchive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires Linux rename semantics for an open Nginx log descriptor")
	}
	path := filepath.Join(t.TempDir(), "nginx.log")
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { writer.Close() }()
	_, _ = writer.WriteString(strings.Repeat("x", 2048))
	calls := 0
	reopen := func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("temporary reopen failure")
		}
		writer.Close()
		var err error
		writer, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		return err
	}
	r := ExternalRotator{ReopenPaths: []string{path}, Maximum: 1024, Reopen: reopen}
	if err := r.Check(context.Background()); err == nil {
		t.Fatal("lost reopen failure")
	}
	_, _ = writer.WriteString("written before reopen")
	archive, _ := os.ReadFile(path + ".1")
	if !strings.HasSuffix(string(archive), "written before reopen") {
		t.Fatal("live descriptor did not retain archive")
	}
	// Recreate the maintenance owner as if only the controller restarted.
	r = ExternalRotator{ReopenPaths: []string{path}, Maximum: 1024, Reopen: reopen}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.WriteString("new log")
	b, _ := os.ReadFile(path)
	archive, _ = os.ReadFile(path + ".1")
	if string(b) != "new log" || len(archive) != 1024 || !strings.HasSuffix(string(archive), "written before reopen") || calls != 2 {
		t.Fatal("reopen retry lost data or failed to bound archive")
	}
}

func TestExternalRotationRejectsLinksAndPreservesFailedSources(t *testing.T) {
	for _, mode := range []string{"append", "reopen"} {
		for _, link := range []bool{false, true} {
			t.Run(mode+"/"+map[bool]string{false: "archive", true: "source"}[link], func(t *testing.T) {
				root := t.TempDir()
				path, victim := filepath.Join(root, "managed.log"), filepath.Join(root, "unrelated")
				original := strings.Repeat("secret", 1024)
				if err := os.WriteFile(victim, []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
				if link {
					if err := os.Symlink(victim, path); err != nil {
						t.Skip(err)
					}
				} else {
					if err := os.WriteFile(path, []byte(original), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(victim, path+".1"); err != nil {
						t.Skip(err)
					}
				}
				r := ExternalRotator{Maximum: 1024}
				if mode == "append" {
					r.AppendPaths = []string{path}
				} else {
					r.ReopenPaths = []string{path}
				}
				if err := r.Check(context.Background()); err == nil {
					t.Fatal("accepted symlink")
				}
				for _, name := range []string{victim, path} {
					b, _ := os.ReadFile(name)
					if string(b) != original {
						t.Fatal("modified unsafe target")
					}
				}
			})
		}
	}
	path := filepath.Join(t.TempDir(), "log")
	_ = os.WriteFile(path, []byte(strings.Repeat("x", 2048)), 0600)
	_ = os.Mkdir(path+".1", 0700)
	r := ExternalRotator{AppendPaths: []string{path}, Maximum: 1024}
	if err := r.Check(context.Background()); err == nil {
		t.Fatal("archive failure ignored")
	}
	if info, _ := os.Stat(path); info.Size() != 2048 {
		t.Fatal("source truncated after archive failure")
	}
}

func TestExternalRotationMissingSmallAndCancelled(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "log")
	_ = os.WriteFile(path, []byte("small"), 0600)
	r := ExternalRotator{AppendPaths: []string{path, filepath.Join(root, "missing")}, ReopenPaths: []string{filepath.Join(root, "missing-nginx")}, Maximum: 1024}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = os.WriteFile(path, []byte(strings.Repeat("x", 2048)), 0600)
	if err := r.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if info, _ := os.Stat(path); info.Size() != 2048 {
		t.Fatal("cancelled pass changed file")
	}
}

func TestExternalRotationBoundsLegacyArchiveWithoutChangingSmallLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte("small"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1", []byte(strings.Repeat("old", 2048)+strings.Repeat("z", 1024)), 0600); err != nil {
		t.Fatal(err)
	}
	r := ExternalRotator{AppendPaths: []string{path}, Maximum: 1024}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	archive, _ := os.ReadFile(path + ".1")
	if string(b) != "small" || string(archive) != strings.Repeat("z", 1024) {
		t.Fatal("legacy archive remains unbounded or current log changed")
	}
}

func BenchmarkExternalLogIdle(b *testing.B) {
	root := b.TempDir()
	r := ExternalRotator{Maximum: 4 << 20}
	for _, name := range []string{"xray-error", "xray-process", "nginx-error", "nginx-public"} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("small"), 0600); err != nil {
			b.Fatal(err)
		}
		if strings.HasPrefix(name, "xray") {
			r.AppendPaths = append(r.AppendPaths, path)
		} else {
			r.ReopenPaths = append(r.ReopenPaths, path)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := r.Check(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func TestExternalRotationWithConcurrentAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.log")
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 1024; i++ {
			if _, err := writer.WriteString(strings.Repeat("x", 2048) + "\n"); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	r := ExternalRotator{AppendPaths: []string{path}, Maximum: 1024}
	var rotationErr error
	for i := 0; i < 10; i++ {
		rotationErr = errors.Join(rotationErr, r.Check(context.Background()))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if rotationErr != nil {
		t.Fatal(rotationErr)
	}
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = writer.WriteString("final record\n")
	b, readErr := os.ReadFile(path)
	if err != nil || readErr != nil || !strings.HasSuffix(string(b), "final record\n") || strings.ContainsRune(string(b), 0) {
		t.Fatalf("append stream damaged: %v %v", err, readErr)
	}
}
