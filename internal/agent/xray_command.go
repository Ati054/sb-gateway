package agent

import (
	"context"
	"os/exec"
	"time"
)

// Keep live route changes and telemetry serial, while isolated emergency
// probe selectors get a bounded independent pool. The former must never wait
// behind ten background handler preparations during failover.
var xrayCommandSlot = make(chan struct{}, 1)
var xrayProbeCommandSlots = make(chan struct{}, 10)

type backgroundXrayCommandKey struct{}

func backgroundXrayCommandContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundXrayCommandKey{}, true)
}

func runXrayCommand(parent context.Context, timeout time.Duration, binary string, arguments ...string) ([]byte, error) {
	slot := xrayCommandSlot
	if parent.Value(backgroundXrayCommandKey{}) == true {
		slot = xrayProbeCommandSlots
	}
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	case <-parent.Done():
		return nil, parent.Err()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return exec.CommandContext(ctx, binary, arguments...).CombinedOutput()
}
