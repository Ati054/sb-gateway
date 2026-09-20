package agent

import (
	"context"
	"os/exec"
	"time"
)

// Xray's CLI is a short-lived gRPC client but still maps the complete command
// runtime. A single shared slot prevents telemetry and health ticks from
// creating a CPU/RSS burst on one-core RouterOS appliances.
var xrayCommandSlot = make(chan struct{}, 1)

func runXrayCommand(parent context.Context, timeout time.Duration, binary string, arguments ...string) ([]byte, error) {
	select {
	case xrayCommandSlot <- struct{}{}:
		defer func() { <-xrayCommandSlot }()
	case <-parent.Done():
		return nil, parent.Err()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return exec.CommandContext(ctx, binary, arguments...).CombinedOutput()
}
