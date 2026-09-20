//go:build linux

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

func TestWorkerProgressReporterRequiresExplicitFD3AndNeverBlocks(t *testing.T) {
	t.Run("missing opt-in", func(t *testing.T) {
		reader, writer := workerProgressPipe(t)
		defer reader.Close()
		output, err := runWorkerProgressChild(writer, "missing")
		if err != nil || output != "{\"result\":\"ok\"}\n" {
			t.Fatalf("worker stdout changed: %q %v", output, err)
		}
		if bytesRead, err := io.ReadAll(reader); err != nil || len(bytesRead) != 0 {
			t.Fatalf("worker enabled ambient FD3: %q %v", bytesRead, err)
		}
	})
	t.Run("closed reader", func(t *testing.T) {
		reader, writer := workerProgressPipe(t)
		_ = reader.Close()
		started := time.Now()
		output, err := runWorkerProgressChild(writer, "closed")
		if err != nil || output != "{\"result\":\"ok\"}\n" {
			t.Fatalf("closed pipe changed worker stdout: %q %v", output, err)
		}
		if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
			t.Fatalf("closed telemetry reader blocked worker: %v", elapsed)
		}
	})
	t.Run("full pipe", func(t *testing.T) {
		reader, writer := workerProgressPipe(t)
		defer reader.Close() // Deliberately never drain it before the child exits.
		fd := workerProgressRawFD(t, writer)
		if err := syscall.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
		for {
			_, err := syscall.Write(fd, make([]byte, 4096))
			if err == nil {
				continue
			}
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				break
			}
			t.Fatalf("fill pipe: %v", err)
		}
		started := time.Now()
		output, err := runWorkerProgressChild(writer, "full")
		if err != nil || output != "{\"result\":\"ok\"}\n" {
			t.Fatalf("full pipe changed worker stdout: %q %v", output, err)
		}
		if elapsed := time.Since(started); elapsed > 750*time.Millisecond {
			t.Fatalf("full telemetry pipe blocked worker: %v", elapsed)
		}
	})
	t.Run("actual event", func(t *testing.T) {
		reader, writer := workerProgressPipe(t)
		defer reader.Close()
		output, err := runWorkerProgressChild(writer, "event")
		if err != nil || output != "{\"result\":\"ok\"}\n" {
			t.Fatalf("worker stdout changed: %q %v", output, err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		event, ok := acmejob.DecodeProgress(bytes.TrimSpace(body))
		if !ok || event.Stage != acmejob.ProgressPreparing {
			t.Fatalf("actual reporter event: %q %#v", body, event)
		}
	})
}

func workerProgressRawFD(t *testing.T, file *os.File) int {
	t.Helper()
	connection, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	if err := connection.Control(func(value uintptr) { fd = int(value) }); err != nil || fd < 0 {
		t.Fatalf("progress pipe descriptor: %d %v", fd, err)
	}
	return fd
}

func workerProgressPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	return reader, writer
}

func runWorkerProgressChild(writer *os.File, mode string) (string, error) {
	command := exec.Command(os.Args[0], "-test.run=^TestWorkerProgressReporterProcessHelper$")
	command.Env = workerProgressChildEnv(mode)
	if mode != "missing" {
		command.Env = append(command.Env, "SB_ACME_PROGRESS_FD=3")
	}
	command.ExtraFiles = []*os.File{writer}
	var output bytes.Buffer
	command.Stdout = &output
	if err := command.Start(); err != nil {
		_ = writer.Close()
		return output.String(), err
	}
	_ = writer.Close()
	err := command.Wait()
	return output.String(), err
}

func workerProgressChildEnv(mode string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "SB_ACME_PROGRESS_FD=") || strings.HasPrefix(value, "SB_ACME_PROGRESS_TEST_MODE=") {
			continue
		}
		environment = append(environment, value)
	}
	return append(environment, "SB_ACME_PROGRESS_TEST_MODE="+mode)
}

func TestWorkerProgressReporterProcessHelper(t *testing.T) {
	if !workerProgressChild() {
		return
	}
	reporter := newWorkerProgressReporter()
	reporter.report(acmejob.ProgressPreparing)
	_, _ = os.Stdout.WriteString("{\"result\":\"ok\"}\n")
	os.Exit(0)
}

func workerProgressChild() bool {
	for _, argument := range os.Args[1:] {
		if argument == "-test.run=^TestWorkerProgressReporterProcessHelper$" {
			return true
		}
	}
	return false
}
