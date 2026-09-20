package appliance

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"
)

type Program struct {
	Name  string
	Run   func(context.Context) error
	Probe func(context.Context) error
}

type programState struct {
	program    Program
	restart    chan restartRequest
	generation uint64
	running    bool
	lastError  error
}

type restartRequest struct {
	ack chan error
}

type Supervisor struct {
	mu       sync.RWMutex
	programs map[string]*programState
	started  bool
	ready    chan struct{}
}

type Status struct {
	Name       string
	Generation uint64
	Running    bool
	LastError  string
}

func NewSupervisor(programs []Program) (*Supervisor, error) {
	states := make(map[string]*programState, len(programs))
	for _, program := range programs {
		if program.Name == "" || program.Run == nil {
			return nil, errors.New("appliance program requires name and runner")
		}
		if _, exists := states[program.Name]; exists {
			return nil, fmt.Errorf("duplicate appliance program %q", program.Name)
		}
		states[program.Name] = &programState{
			program: program,
			restart: make(chan restartRequest),
		}
	}
	if len(states) == 0 {
		return nil, errors.New("appliance supervisor requires at least one program")
	}
	return &Supervisor{programs: states, ready: make(chan struct{})}, nil
}

// Run owns all supervised programs until ctx is cancelled. Each program uses
// one long-lived goroutine and one short-lived result goroutine; no polling or
// per-program ticker is retained while the program is healthy.
func (supervisor *Supervisor) Run(ctx context.Context) error {
	supervisor.mu.Lock()
	if supervisor.started {
		supervisor.mu.Unlock()
		return errors.New("appliance supervisor is already running")
	}
	supervisor.started = true
	supervisor.mu.Unlock()

	var wait sync.WaitGroup
	for _, state := range supervisor.programs {
		wait.Add(1)
		go func(state *programState) {
			defer wait.Done()
			supervisor.runProgram(ctx, state)
		}(state)
	}
	close(supervisor.ready)
	<-ctx.Done()
	wait.Wait()
	return nil
}

func (supervisor *Supervisor) runProgram(ctx context.Context, state *programState) {
	var failures int
	var restarted chan error
	for ctx.Err() == nil {
		child, cancel := context.WithCancel(ctx)
		result := make(chan error, 1)
		supervisor.setStarted(state)
		go func() { result <- state.program.Run(child) }()
		if restarted != nil {
			restarted <- nil
			restarted = nil
		}

		select {
		case request := <-state.restart:
			log.Printf("appliance: planned restart requested for %s", state.program.Name)
			cancel()
			err := <-result
			if ctx.Err() != nil {
				request.ack <- ctx.Err()
				return
			}
			supervisor.setStopped(state, expectedStopError(err))
			failures = 0
			restarted = request.ack
			continue
		case err := <-result:
			cancel()
			if ctx.Err() != nil {
				supervisor.setStopped(state, nil)
				return
			}
			failures++
			supervisor.setStopped(state, unexpectedStopError(err))
			delay := restartDelay(failures)
			log.Printf("appliance: %s stopped unexpectedly: %v; restart in %s", state.program.Name, unexpectedStopError(err), delay)
			if !waitContext(ctx, delay) {
				return
			}
		case <-ctx.Done():
			cancel()
			<-result
			supervisor.setStopped(state, nil)
			if restarted != nil {
				restarted <- ctx.Err()
			}
			return
		}
	}
}

func (supervisor *Supervisor) Restart(ctx context.Context, names []string) error {
	if err := supervisor.waitReady(ctx); err != nil {
		return err
	}
	states, err := supervisor.selected(names)
	if err != nil {
		return err
	}
	for _, state := range states {
		request := restartRequest{ack: make(chan error, 1)}
		select {
		case state.restart <- request:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case err := <-request.ack:
			if err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (supervisor *Supervisor) Probe(ctx context.Context, names []string) error {
	if err := supervisor.waitReady(ctx); err != nil {
		return err
	}
	states, err := supervisor.selected(names)
	if err != nil {
		return err
	}
	for _, state := range states {
		if state.program.Probe == nil {
			supervisor.mu.RLock()
			running := state.running
			lastError := state.lastError
			supervisor.mu.RUnlock()
			if !running {
				if lastError != nil {
					return fmt.Errorf("probe %s: %w", state.program.Name, lastError)
				}
				return fmt.Errorf("probe %s: program is not running", state.program.Name)
			}
			continue
		}
		if err := state.program.Probe(ctx); err != nil {
			return fmt.Errorf("probe %s: %w", state.program.Name, err)
		}
	}
	return nil
}

func (supervisor *Supervisor) Status() []Status {
	supervisor.mu.RLock()
	defer supervisor.mu.RUnlock()
	result := make([]Status, 0, len(supervisor.programs))
	for _, state := range supervisor.programs {
		lastError := ""
		if state.lastError != nil {
			lastError = state.lastError.Error()
		}
		result = append(result, Status{
			Name: state.program.Name, Generation: state.generation,
			Running: state.running, LastError: lastError,
		})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}

func (supervisor *Supervisor) selected(names []string) ([]*programState, error) {
	seen := make(map[string]struct{}, len(names))
	result := make([]*programState, 0, len(names))
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		state, exists := supervisor.programs[name]
		if !exists {
			return nil, fmt.Errorf("unknown appliance program %q", name)
		}
		seen[name] = struct{}{}
		result = append(result, state)
	}
	return result, nil
}

func (supervisor *Supervisor) waitReady(ctx context.Context) error {
	select {
	case <-supervisor.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (supervisor *Supervisor) setStarted(state *programState) {
	supervisor.mu.Lock()
	state.generation++
	state.running = true
	state.lastError = nil
	supervisor.mu.Unlock()
}

func (supervisor *Supervisor) setStopped(state *programState, err error) {
	supervisor.mu.Lock()
	state.running = false
	state.lastError = err
	supervisor.mu.Unlock()
}

func restartDelay(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	if failures > 5 {
		failures = 5
	}
	return time.Duration(1<<(failures-1)) * time.Second
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func expectedStopError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func unexpectedStopError(err error) error {
	if err == nil {
		return errors.New("program stopped without an error")
	}
	return err
}
