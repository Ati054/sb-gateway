package agent

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBackgroundCommandSlotsDoNotBlockLiveRouteCommand(t *testing.T) {
	for i := 0; i < cap(xrayProbeCommandSlots); i++ {
		xrayProbeCommandSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(xrayProbeCommandSlots); i++ {
			<-xrayProbeCommandSlots
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := runXrayCommand(ctx, time.Second, "sb-nonexistent-command")
	if errors.Is(err, context.DeadlineExceeded) || err == nil {
		t.Fatalf("live command waited for background slots: %v", err)
	}
	_, err = runXrayCommand(backgroundXrayCommandContext(ctx), time.Second, "sb-nonexistent-command")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full background pool did not bound work: %v", err)
	}
}

func TestBackgroundCommandCanRunWhileLiveCommandSlotIsBusy(t *testing.T) {
	xrayCommandSlot <- struct{}{}
	defer func() { <-xrayCommandSlot }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := runXrayCommand(backgroundXrayCommandContext(ctx), time.Second, "sb-nonexistent-command")
	if errors.Is(err, context.DeadlineExceeded) || err == nil {
		t.Fatalf("background command waited for live slot: %v", err)
	}
}
