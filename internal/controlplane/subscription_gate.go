package controlplane

import (
	"context"
	"sync"
)

// subscriptionGate serializes downloads using the shared update selector and
// inventory publication. Its zero value is ready for use. It must not be copied.
type subscriptionGate struct {
	once  sync.Once
	token chan struct{}
}

func (gate *subscriptionGate) initialize() {
	gate.once.Do(func() { gate.token = make(chan struct{}, 1) })
}

func (gate *subscriptionGate) LockContext(ctx context.Context) error {
	gate.initialize()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case gate.token <- struct{}{}:
		// Cancellation and an available token can become ready together.
		if err := ctx.Err(); err != nil {
			gate.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (gate *subscriptionGate) Lock() {
	_ = gate.LockContext(context.Background())
}

func (gate *subscriptionGate) TryLock() bool {
	gate.initialize()
	select {
	case gate.token <- struct{}{}:
		return true
	default:
		return false
	}
}

func (gate *subscriptionGate) Unlock() {
	gate.initialize()
	select {
	case <-gate.token:
	default:
		panic("controlplane: unlock of unlocked subscription gate")
	}
}
