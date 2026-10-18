package watchdog

import "context"

// Diagnostic persistence is best effort and must not hold the live heartbeat.
// Coalesce state changes while one bounded HTTP request is in flight.
func (r *runner) startStateReporter(parent context.Context) func() {
	ctx, cancel := context.WithCancel(parent)
	queue := make(chan statusPayload, 1)
	r.postQueue = queue
	reporter := &runner{opts: r.opts, http: r.http}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case payload := <-queue:
				reporter.postPayload(ctx, payload)
			}
		}
	}()
	return func() { cancel(); <-done }
}

func queueLatestState(queue chan statusPayload, payload statusPayload) {
	select {
	case queue <- payload:
		return
	default:
	}
	select {
	case <-queue:
	default:
	}
	select {
	case queue <- payload:
	default:
	}
}
