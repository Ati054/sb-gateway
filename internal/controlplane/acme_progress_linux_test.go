//go:build linux

package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"golang.org/x/sys/unix"
)

func TestRunACMEWorkerProgressUsesNonblockingFD3AndKeepsJSONStdout(t *testing.T) {
	original := acmeWorkerCommand
	acmeWorkerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACMEWorkerProgressProcessHelper$")
	}
	defer func() { acmeWorkerCommand = original }()

	var mu sync.Mutex
	var got []acmejob.ProgressStage
	result, err := runACMEWorkerWithProgress(context.Background(), acmejob.Request{}, func(event acmejob.ProgressEvent) {
		mu.Lock()
		got = append(got, event.Stage)
		mu.Unlock()
	})
	if err != nil || result.Certificate != "synthetic-certificate" || result.PrivateKey != "synthetic-key" {
		t.Fatalf("worker result changed by progress pipe: %#v %v", result, err)
	}
	want := []acmejob.ProgressStage{acmejob.ProgressPreparing, acmejob.ProgressDNSPrecheck, acmejob.ProgressCertificateReceived}
	if !slices.Equal(got, want) {
		t.Fatalf("progress = %#v, want %#v", got, want)
	}
}

func TestRunACMEWorkerProgressClosedReaderDoesNotBreakResult(t *testing.T) {
	originalCommand := acmeWorkerCommand
	originalPipe := openACMEProgressPipe
	acmeWorkerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACMEWorkerProgressProcessHelper$")
	}
	openACMEProgressPipe = func() (*os.File, *os.File, bool) {
		reader, writer, ok := newACMEProgressPipe()
		if ok {
			_ = reader.Close()
		}
		return reader, writer, ok
	}
	defer func() {
		acmeWorkerCommand = originalCommand
		openACMEProgressPipe = originalPipe
	}()

	result, err := runACMEWorkerWithProgress(context.Background(), acmejob.Request{}, func(acmejob.ProgressEvent) {
		t.Fatal("closed progress reader accepted an event")
	})
	if err != nil || result.Certificate != "synthetic-certificate" {
		t.Fatalf("closed telemetry pipe changed worker result: %#v %v", result, err)
	}
}

func TestRunACMEWorkerProgressDoesNotWaitForInheritedDescriptor(t *testing.T) {
	original := acmeWorkerCommand
	acmeWorkerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACMEWorkerProgressInheritedFDHelper$")
	}
	defer func() { acmeWorkerCommand = original }()

	started := time.Now()
	result, err := runACMEWorkerWithProgress(context.Background(), acmejob.Request{}, func(acmejob.ProgressEvent) {})
	if err != nil || result.Certificate != "synthetic-certificate" {
		t.Fatalf("worker result: %#v %v", result, err)
	}
	if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
		t.Fatalf("telemetry reader waited for inherited FD3: %v", elapsed)
	}
}

// TestACMEWorkerProgressProcessHelper is a real child process for FD3
// inheritance. It sends one precheck event before simulating hundreds of
// repeat prechecks without writes, then still reaches certificate_received.
func TestACMEWorkerProgressProcessHelper(t *testing.T) {
	if !testChild("TestACMEWorkerProgressProcessHelper") {
		return
	}
	// exec.Cmd.ExtraFiles obtains its descriptor through File.Fd(), which can
	// clear O_NONBLOCK in the child copy. The real sb-acme reporter restores it
	// during reporter initialization; the helper must exercise that path.
	if syscall.SetNonblock(3, true) != nil {
		os.Exit(31)
	}
	flags, err := unix.FcntlInt(uintptr(3), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 || os.Getenv("SB_ACME_PROGRESS_FD") != "3" {
		os.Exit(31)
	}
	for _, stage := range []acmejob.ProgressStage{acmejob.ProgressPreparing, acmejob.ProgressDNSPrecheck} {
		writeProgressChild(stage)
	}
	for range 200 {
		// A real worker deduplicates repeated precheck callbacks per job.
	}
	writeProgressChild(acmejob.ProgressCertificateReceived)
	_ = json.NewEncoder(os.Stdout).Encode(acmejob.Result{Certificate: "synthetic-certificate", PrivateKey: "synthetic-key"})
	os.Exit(0)
}

// TestACMEWorkerProgressInheritedFDHelper deliberately leaves a descendant
// holding FD3 after its own JSON result is complete.
func TestACMEWorkerProgressInheritedFDHelper(t *testing.T) {
	if !testChild("TestACMEWorkerProgressInheritedFDHelper") {
		return
	}
	// ExtraFiles gives the descendant its own explicit FD3. Without the
	// bounded parent-side drain, this known one-second holder would delay the
	// result even after this test helper has exited.
	progress := os.NewFile(uintptr(3), "progress")
	if progress == nil {
		os.Exit(33)
	}
	child := exec.Command("sh", "-c", "sleep 1")
	child.Stdout = io.Discard
	child.Stderr = io.Discard
	child.ExtraFiles = []*os.File{progress}
	if child.Start() != nil {
		os.Exit(32)
	}
	_ = progress.Close()
	_ = json.NewEncoder(os.Stdout).Encode(acmejob.Result{Certificate: "synthetic-certificate", PrivateKey: "synthetic-key"})
	os.Exit(0)
}

func testChild(name string) bool {
	for _, argument := range os.Args[1:] {
		if argument == "-test.run=^"+name+"$" {
			return true
		}
	}
	return false
}

func writeProgressChild(stage acmejob.ProgressStage) {
	body, err := acmejob.EncodeProgress(acmejob.ProgressEvent{Version: 1, Stage: stage})
	if err == nil {
		_, _ = syscall.Write(3, append(body, '\n'))
	}
}
