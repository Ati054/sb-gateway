package appliance

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"testing"
	"time"
)

func TestRunCommandStopsWithContext(t *testing.T) {
	previousStopTimeout := commandStopTimeout
	previousKillTimeout := commandKillTimeout
	commandStopTimeout = 50 * time.Millisecond
	commandKillTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		commandStopTimeout = previousStopTimeout
		commandKillTimeout = previousKillTimeout
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runCommand(ctx, os.Args[0], []string{"-test.run=TestCommandHelper", "--", "wait"})
	}()
	time.Sleep(25 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runCommand error = %v", err)
		}
	// Starting another copy of the test binary can take more than a second on
	// a loaded Windows host. The production stop deadlines above remain 50 ms;
	// this outer bound only prevents a slow process launch from making the test
	// flaky while the rest of the packages run in parallel.
	case <-time.After(5 * time.Second):
		t.Fatal("command did not stop after context cancellation")
	}
}

func TestTCPProbeMakesOneConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := TCPProbe(listener.Addr().String(), time.Second)(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("probe did not reach listener")
	}
}

func TestWaitProbeStopsAtFirstSuccess(t *testing.T) {
	attempts := 0
	probe := WaitProbe(func(context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("not ready")
		}
		return nil
	}, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probe(ctx); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("probe attempts = %d", attempts)
	}
}

func TestCommandHelper(t *testing.T) {
	if flag.Arg(0) != "wait" {
		return
	}
	// A bare select{} lets the Linux runtime report an artificial global
	// deadlock before the parent can cancel the helper. A timer keeps this
	// process genuinely alive while preserving the cancellation contract.
	time.Sleep(time.Hour)
}
