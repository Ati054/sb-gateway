package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestAgentWorkersJoinOnParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	release := make(chan struct{})
	finishCleanup := sync.OnceFunc(func() { close(release) })
	t.Cleanup(finishCleanup)
	started := []chan struct{}{make(chan struct{}), make(chan struct{})}
	canceled := []chan struct{}{make(chan struct{}), make(chan struct{})}
	cleaned := []chan struct{}{make(chan struct{}), make(chan struct{})}
	worker := func(index int) func(context.Context) error {
		return func(child context.Context) error {
			close(started[index])
			<-child.Done()
			close(canceled[index])
			<-release
			close(cleaned[index])
			return nil
		}
	}
	done := make(chan error, 1)
	go func() { done <- runAgentWorkers(ctx, worker(0), worker(1)) }()
	for _, signal := range started {
		waitAgentWorkerSignal(t, signal)
	}
	cancel()
	for _, signal := range canceled {
		waitAgentWorkerSignal(t, signal)
	}
	assertAgentWorkersStillJoining(t, done)
	finishCleanup()
	if err := waitAgentWorkersResult(t, done); err != nil {
		t.Fatal(err)
	}
	for _, signal := range cleaned {
		waitAgentWorkerSignal(t, signal)
	}
}

func TestAgentWorkersCancelSiblingOnExit(t *testing.T) {
	failure := errors.New("worker failed")
	for _, failedHealth := range []bool{false, true} {
		for _, workerError := range []error{nil, failure} {
			name := "telemetry"
			if failedHealth {
				name = "health"
			}
			if workerError == nil {
				name += "/normal exit"
			} else {
				name += "/error"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(cancel)
				release := make(chan struct{})
				finishCleanup := sync.OnceFunc(func() { close(release) })
				t.Cleanup(finishCleanup)
				canceled := make(chan struct{})
				cleaned := make(chan struct{})
				exiting := func(context.Context) error { return workerError }
				sibling := func(child context.Context) error {
					<-child.Done()
					close(canceled)
					<-release
					close(cleaned)
					return nil
				}
				telemetry, health := exiting, sibling
				if failedHealth {
					telemetry, health = sibling, exiting
				}
				done := make(chan error, 1)
				go func() { done <- runAgentWorkers(ctx, telemetry, health) }()
				waitAgentWorkerSignal(t, canceled)
				assertAgentWorkersStillJoining(t, done)
				finishCleanup()
				if err := waitAgentWorkersResult(t, done); !errors.Is(err, workerError) {
					t.Fatalf("Run error=%v want=%v", err, workerError)
				}
				waitAgentWorkerSignal(t, cleaned)
				if ctx.Err() != nil {
					t.Fatal("worker exit canceled the caller context")
				}
			})
		}
	}
}

func TestAgentWorkersReleaseFailureSocketBeforeRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unixgram is validated on Linux")
	}
	path := filepath.Join(t.TempDir(), "failure.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	release := make(chan struct{})
	finishCleanup := sync.OnceFunc(func() { close(release) })
	t.Cleanup(finishCleanup)
	ready := make(chan error, 1)
	canceled := make(chan struct{})
	health := func(child context.Context) error {
		_, closeSocket, err := listenXrayFailureSignals(child, path)
		ready <- err
		if err != nil {
			return err
		}
		defer closeSocket()
		<-child.Done()
		close(canceled)
		<-release
		return nil
	}
	telemetry := func(child context.Context) error {
		<-child.Done()
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- runAgentWorkers(ctx, telemetry, health) }()
	if err := waitAgentWorkersResult(t, ready); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitAgentWorkerSignal(t, canceled)
	assertAgentWorkersStillJoining(t, done)
	finishCleanup()
	if err := waitAgentWorkersResult(t, done); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("previous worker retained its socket path: %v", err)
	}

	next, stop := context.WithCancel(context.Background())
	defer stop()
	signals, closeSocket, err := listenXrayFailureSignals(next, path)
	if err != nil {
		t.Fatalf("next generation cannot own the socket: %v", err)
	}
	defer closeSocket()
	sender, err := net.DialTimeout("unixgram", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if err := sender.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Write([]byte(`{"v":1,"pid":123,"tag":"next-generation","stage":"dial"}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case signal, ok := <-signals:
		if !ok || signal.Tag != "next-generation" {
			t.Fatalf("new receiver got %+v, open=%t", signal, ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("new receiver did not receive its datagram")
	}
}

func waitAgentWorkerSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("agent worker did not reach the expected lifecycle phase")
	}
}

func waitAgentWorkersResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("agent workers did not finish")
		return nil
	}
}

func assertAgentWorkersStillJoining(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("agent returned before worker cleanup: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
}
