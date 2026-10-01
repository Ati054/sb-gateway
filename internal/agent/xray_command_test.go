package agent

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestXrayCommandPreservesDeadline(t *testing.T) {
	_, err := runXrayCommand(context.Background(), 50*time.Millisecond, os.Args[0],
		"-test.run=^TestXrayCommandWaitHelper$", "--", "xray-command-wait")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("subprocess deadline was hidden: %v", err)
	}
}

func TestXrayCommandWaitHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] == "xray-command-wait" {
		time.Sleep(30 * time.Second)
	}
}

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
