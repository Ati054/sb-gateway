package appliance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

var (
	commandStopTimeout = 8 * time.Second
	commandKillTimeout = 2 * time.Second
)

func CommandProgram(name, executable string, arguments []string, probe func(context.Context) error) (Program, error) {
	if executable == "" {
		return Program{}, errors.New("appliance command path is empty")
	}
	if probe == nil {
		return Program{}, errors.New("appliance command probe is missing")
	}
	args := append([]string(nil), arguments...)
	return Program{
		Name: name,
		Run: func(ctx context.Context) error {
			return runCommand(ctx, executable, args)
		},
		Probe: probe,
	}, nil
}

// TCPProbe performs one bounded connection attempt. Readiness is orchestrated
// by the caller with an overall deadline, so a failed probe never starts a
// hidden retry loop or retains a connection.
func TCPProbe(address string, timeout time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		dialer := net.Dialer{Timeout: timeout}
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return err
		}
		return connection.Close()
	}
}

// WaitProbe retries only while a freshly restarted program is not ready. It
// stops on the first success and owns no ticker outside that bounded window.
func WaitProbe(probe func(context.Context) error, interval time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		for {
			if err := probe(ctx); err == nil {
				return nil
			} else if ctx.Err() != nil {
				return errors.Join(ctx.Err(), err)
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

func runCommand(ctx context.Context, executable string, arguments []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	command := exec.Command(executable, arguments...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	prepareCommand(command)
	if err := command.Start(); err != nil {
		return fmt.Errorf("start %s: %w", executable, err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	select {
	case err := <-finished:
		return err
	case <-ctx.Done():
		_ = terminateCommand(command)
		timer := time.NewTimer(commandStopTimeout)
		defer timer.Stop()
		select {
		case <-finished:
			return ctx.Err()
		case <-timer.C:
			_ = killCommand(command)
			killTimer := time.NewTimer(commandKillTimeout)
			defer killTimer.Stop()
			select {
			case <-finished:
				return ctx.Err()
			case <-killTimer.C:
				return errors.Join(ctx.Err(), errors.New("command did not stop after forced termination"))
			}
		}
	}
}
