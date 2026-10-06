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

func runXrayCommand(parent context.Context, timeout time.Duration, binary string, arguments ...string) (output []byte, err error) {
	slot := xrayCommandSlot
	lane := "active"
	if parent.Value(backgroundXrayCommandKey{}) == true {
		slot = xrayProbeCommandSlots
		lane = "background"
	}
	trace := beginHealthStage("api", lane, "", "")
	if len(arguments) > 1 && arguments[0] == "api" {
		trace.command(arguments[1])
	}
	defer func() { trace.finish(err == nil) }()
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
		trace.acquiredSlot()
	case <-parent.Done():
		return nil, parent.Err()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, arguments...)
	output, err = command.CombinedOutput()
	if command.Process != nil && ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}
