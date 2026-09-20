package appliance

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestSupervisorRestartsOnlySelectedProgram(t *testing.T) {
	var firstRuns atomic.Int32
	var secondRuns atomic.Int32
	first := blockingProgram("first", &firstRuns)
	second := blockingProgram("second", &secondRuns)
	supervisor, err := NewSupervisor([]Program{first, second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitRuns(t, &firstRuns, 1)
	waitRuns(t, &secondRuns, 1)

	restartCtx, restartCancel := context.WithTimeout(context.Background(), time.Second)
	defer restartCancel()
	if err := supervisor.Restart(restartCtx, []string{"first", "first"}); err != nil {
		t.Fatal(err)
	}
	waitRuns(t, &firstRuns, 2)
	if secondRuns.Load() != 1 {
		t.Fatalf("unselected program restarted %d times", secondRuns.Load())
	}

	if err := supervisor.Probe(restartCtx, []string{"first", "second"}); err != nil {
		t.Fatal(err)
	}
	status := supervisor.Status()
	if len(status) != 2 || status[0].Name != "first" || status[0].Generation != 2 || !status[0].Running {
		t.Fatalf("unexpected status: %#v", status)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorRejectsUnknownProgramWithoutRestarting(t *testing.T) {
	var runs atomic.Int32
	supervisor, err := NewSupervisor([]Program{blockingProgram("known", &runs)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitRuns(t, &runs, 1)
	requestCtx, requestCancel := context.WithTimeout(context.Background(), time.Second)
	defer requestCancel()
	if err := supervisor.Restart(requestCtx, []string{"missing"}); err == nil {
		t.Fatal("unknown program was accepted")
	}
	if runs.Load() != 1 {
		t.Fatal("known program was disturbed")
	}
	cancel()
	<-done
}

func TestSupervisorUsesRunningStateForInProcessProgramProbe(t *testing.T) {
	var runs atomic.Int32
	program := blockingProgram("worker", &runs)
	program.Probe = nil
	supervisor, err := NewSupervisor([]Program{program})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitRuns(t, &runs, 1)
	probeCtx, probeCancel := context.WithTimeout(context.Background(), time.Second)
	defer probeCancel()
	if err := supervisor.Probe(probeCtx, []string{"worker"}); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
}

func TestSupervisorRestartsUnexpectedExitWithBoundedBackoff(t *testing.T) {
	var runs atomic.Int32
	supervisor, err := NewSupervisor([]Program{{
		Name: "failing",
		Run: func(context.Context) error {
			runs.Add(1)
			return errors.New("boom")
		},
		Probe: func(context.Context) error { return nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := supervisor.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if count := runs.Load(); count != 2 {
		t.Fatalf("unexpected restart count: %d", count)
	}
	status := supervisor.Status()
	if len(status) != 1 || status[0].Running || status[0].LastError == "" {
		t.Fatalf("unexpected failure status: %#v", status)
	}
}

func blockingProgram(name string, runs *atomic.Int32) Program {
	return Program{
		Name: name,
		Run: func(ctx context.Context) error {
			runs.Add(1)
			<-ctx.Done()
			return ctx.Err()
		},
		Probe: func(context.Context) error { return nil },
	}
}

func waitRuns(t *testing.T, runs *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for runs.Load() < want && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runs.Load() < want {
		t.Fatalf("program ran %d times, want %d", runs.Load(), want)
	}
}
