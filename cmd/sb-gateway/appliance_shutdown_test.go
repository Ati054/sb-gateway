package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/appliance"
)

type blockedApplianceLogger struct{}

func (blockedApplianceLogger) Write([]byte) (int, error) {
	select {}
}

func TestApplianceShutdownTimeoutExitsWithoutWaitingForLogger(t *testing.T) {
	if os.Getenv("SB_TEST_BLOCKED_SHUTDOWN_LOGGER") == "1" {
		log.SetOutput(blockedApplianceLogger{})
		exitApplianceOnError(fmt.Errorf("stalled worker: %w", appliance.ErrShutdownTimeout))
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApplianceShutdownTimeoutExitsWithoutWaitingForLogger$")
	command.Env = append(os.Environ(), "SB_TEST_BLOCKED_SHUTDOWN_LOGGER=1")
	err := command.Run()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("forced shutdown failed: context=%v, exit=%v", ctx.Err(), err)
	}
}

func TestApplianceSuccessfulShutdownReturns(t *testing.T) {
	exitApplianceOnError(nil)
}
