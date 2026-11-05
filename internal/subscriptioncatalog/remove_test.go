package subscriptioncatalog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func assertCatalogFilesIntact(t *testing.T, path string, ref Ref) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(path, ref.Generation))
	if err != nil || len(entries) != len(generationFiles) {
		t.Fatalf("generation changed before deletion: count=%d err=%v", len(entries), err)
	}
	reader, err := Open(path, ref)
	if err != nil {
		t.Fatalf("retained generation is unreadable: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogRemoveRespectsEveryReaderLease(t *testing.T) {
	path := privateRoot(t)
	ref := buildSynthetic(t, path, DefaultLimits(), syntheticRecord(1))
	first, err := Open(path, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := RemoveGeneration(context.Background(), path, ref); !errors.Is(err, ErrBusy) {
		t.Fatalf("two readers: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RemoveGeneration(context.Background(), path, ref); !errors.Is(err, ErrBusy) {
		t.Fatalf("independent second reader: %v", err)
	}
	assertCatalogFilesIntact(t, path, ref)
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := RemoveGeneration(context.Background(), path, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(path, ref.Generation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generation survived complete removal: %v", err)
	}
}

func TestCatalogRemoveRefusesUnknownAndCorruptFiles(t *testing.T) {
	for _, kind := range []string{"extra", "corrupt", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := privateRoot(t)
			ref := buildSynthetic(t, path, DefaultLimits(), syntheticRecord(1))
			directory := filepath.Join(path, ref.Generation)
			switch kind {
			case "extra":
				if err := os.WriteFile(filepath.Join(directory, "foreign"), []byte("unowned"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(filepath.Join(directory, "metadata.bin"), []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(filepath.Join(directory, "metadata.bin")); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(t.TempDir(), "unowned")
				if err := os.WriteFile(target, []byte("unowned"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(directory, "metadata.bin")); err != nil {
					t.Skip("symlink unavailable")
				}
			}
			before, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			if err := RemoveGeneration(context.Background(), path, ref); err == nil {
				t.Fatal("unsafe generation was removed")
			}
			after, err := os.ReadDir(directory)
			if err != nil || len(before) != len(after) {
				t.Fatalf("validation deleted a file: %v", err)
			}
		})
	}
}

type catalogCountingContext struct {
	context.Context
	calls    int
	cancelAt int
}

func (ctx *catalogCountingContext) Err() error {
	ctx.calls++
	if ctx.cancelAt > 0 && ctx.calls >= ctx.cancelAt {
		return context.Canceled
	}
	return ctx.Context.Err()
}

func TestCatalogRemoveCancellationBoundary(t *testing.T) {
	path := privateRoot(t)
	ref := buildSynthetic(t, path, DefaultLimits(), syntheticRecord(1))
	// Discover the final context check without unlinking anything; this keeps
	// the test independent of the number of streaming checksum reads.
	counted := &catalogCountingContext{Context: context.Background()}
	if err := removeGeneration(counted, path, ref, func(*os.Root, string) error { return errors.New("stop before unlink") }); err == nil {
		t.Fatal("dry removal unexpectedly succeeded")
	}
	cancelled := &catalogCountingContext{Context: context.Background(), cancelAt: counted.calls}
	if err := RemoveGeneration(cancelled, path, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel before first unlink: %v", err)
	}
	assertCatalogFilesIntact(t, path, ref)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	err := removeGeneration(ctx, path, ref, func(root *os.Root, name string) error {
		if err := root.Remove(name); err != nil {
			return err
		}
		calls++
		if calls == 1 {
			cancel()
		}
		return nil
	})
	if err != nil || calls != len(generationFiles) {
		t.Fatalf("committed removal interrupted: calls=%d err=%v", calls, err)
	}
}

func TestCatalogLeaseProcessHelper(t *testing.T) {
	if os.Getenv("SB_CATALOG_LEASE_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	var ref Ref
	if err := json.Unmarshal([]byte(os.Getenv("SB_CATALOG_LEASE_REF")), &ref); err != nil {
		t.Fatal(err)
	}
	reader, err := Open(os.Getenv("SB_CATALOG_LEASE_ROOT"), ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	fmt.Fprintln(os.Stdout, "lease-ready")
	var release [1]byte
	if _, err := os.Stdin.Read(release[:]); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogRemoveRespectsOtherProcessLease(t *testing.T) {
	path := privateRoot(t)
	ref := buildSynthetic(t, path, DefaultLimits(), syntheticRecord(1))
	encoded, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCatalogLeaseProcessHelper$")
	command.Env = append(os.Environ(), "SB_CATALOG_LEASE_HELPER=1", "SB_CATALOG_LEASE_ROOT="+path, "SB_CATALOG_LEASE_REF="+string(encoded))
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "lease-ready\n" {
		t.Fatalf("reader subprocess not ready: %v %s", err, stderr.String())
	}
	if err := RemoveGeneration(context.Background(), path, ref); !errors.Is(err, ErrBusy) {
		t.Fatalf("cross-process reader was not protected: %v", err)
	}
	if _, err := input.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	if err := command.Wait(); err != nil {
		t.Fatalf("reader subprocess: %v %s", err, stderr.String())
	}
	if err := RemoveGeneration(context.Background(), path, ref); err != nil {
		t.Fatal(err)
	}
}
