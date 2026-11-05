package controlplane

import (
	"context"
	"errors"
	"testing"
)

func TestSubscriptionGateZeroValueCancellationAndExclusion(t *testing.T) {
	var gate subscriptionGate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 20 {
		if err := gate.LockContext(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled free gate acquired: %v", err)
		}
	}
	if !gate.TryLock() || gate.TryLock() {
		t.Fatal("gate did not exclude another owner")
	}
	gate.Unlock()
	if err := gate.LockContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	gate.Unlock()
}
