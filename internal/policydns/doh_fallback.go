package policydns

import (
	"context"
	"errors"
	"sync"
	"time"
)

type dnsFallbackBudgetKey struct{}
type dnsFallbackBorrow func() (release func(), allowed bool)

var errDoHFallbackWon = errors.New("encrypted DNS fallback completed")

// Keep the primary's full deadline. Only a slow query starts a timer callback
// and an overlapping fallback; the ordinary DoH fast path stays synchronous.
func (u *dohUpstream) exchangeWithFallback(ctx context.Context, query []byte, delay time.Duration) ([]byte, error) {
	primaryCtx, cancelPrimary := context.WithCancelCause(ctx)
	defer cancelPrimary(nil)
	fallbackCtx, cancelFallback := context.WithCancel(ctx)
	defer cancelFallback()
	var mu sync.Mutex
	var primaryDone, started, chosen bool
	var winner []byte
	var fallbackErr error
	fallbackDone := make(chan struct{})
	startFallback := func() {
		mu.Lock()
		if started || chosen || fallbackCtx.Err() != nil {
			mu.Unlock()
			return
		}
		var release func()
		if !primaryDone {
			if borrow, ok := ctx.Value(dnsFallbackBudgetKey{}).(dnsFallbackBorrow); ok {
				var allowed bool
				release, allowed = borrow()
				if !allowed {
					mu.Unlock()
					return
				}
			}
		}
		started = true
		mu.Unlock()
		defer func() {
			if release != nil {
				release()
			}
			close(fallbackDone)
		}()
		answer, err := u.fallback.exchange(fallbackCtx, query)
		if err == nil && !matchingQuestion(query, answer) {
			err = errors.New("encrypted fallback DNS response mismatch")
		}
		mu.Lock()
		fallbackErr = err
		won := err == nil && !chosen && ctx.Err() == nil
		if won {
			chosen, winner = true, answer
		}
		mu.Unlock()
		if won {
			cancelPrimary(errDoHFallbackWon)
		}
	}
	timerDone := make(chan struct{})
	timer := time.AfterFunc(delay, func() { defer close(timerDone); startFallback() })
	defer func() {
		cancelPrimary(nil)
		cancelFallback()
		if timer.Stop() {
			close(timerDone)
		}
		<-timerDone
		mu.Lock()
		wait := started
		mu.Unlock()
		if wait {
			<-fallbackDone
		}
	}()
	answer, primaryErr := u.exchangeDoH(primaryCtx, query)
	mu.Lock()
	primaryDone = true
	if primaryErr == nil && !chosen {
		chosen, winner = true, answer
	}
	mu.Unlock()
	if primaryErr == nil || ctx.Err() != nil {
		cancelFallback()
	}
	if timer.Stop() {
		close(timerDone)
	}
	if primaryErr != nil && ctx.Err() == nil {
		// No overlap needs no additional lease: the primary has ended and
		// its leader's existing work reservation remains held by the caller.
		startFallback()
	}
	<-timerDone
	mu.Lock()
	wait := started
	mu.Unlock()
	if wait {
		<-fallbackDone
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	if chosen {
		return winner, nil
	}
	return nil, errors.Join(primaryErr, fallbackErr)
}
