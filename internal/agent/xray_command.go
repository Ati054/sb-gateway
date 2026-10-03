package agent

import (
	"context"
	"os/exec"
	"time"
)

// API subprocess preparation is CPU-heavy on small ARM64 systems. Limit it
// separately from the HTTPS worker count; release the slot before network I/O.
// The independent live slot must never queue behind background preparations.
var xrayCommandSlot = make(chan struct{}, 1)
var xrayProbeCommandSlots = make(chan struct{}, 2)

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
	command := exec.CommandContext(ctx, binary, arguments...)
	output, err := command.CombinedOutput()
	if command.Process != nil && ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}
