package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func warmTestTransport(server *httptest.Server) *http.Transport {
	return server.Client().Transport.(*http.Transport).Clone()
}

func TestWarmHTTPSOwnsOneConnectionAndKeepsColdEvidence(t *testing.T) {
	var calls, connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		select {
		case <-time.After(35 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	transport := warmTestTransport(server)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case <-time.After(160 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	measured := measureWarmHTTP(t.Context(), transport, server.URL, http.MethodHead, 0, 2*time.Second, http.StatusNoContent, nil)
	if measured.ColdError != nil || measured.WarmError != nil || measured.Warm.Failed || measured.Warm.DelayMS == nil {
		t.Fatalf("invalid same-TLS measurement: %+v", measured)
	}
	if calls.Load() != 2 || connections.Load() != 1 {
		t.Fatalf("session requests=%d connections=%d", calls.Load(), connections.Load())
	}
	if measured.ColdDelayMS < 190 || *measured.Warm.DelayMS < 30 || measured.ColdDelayMS-*measured.Warm.DelayMS < 100 {
		t.Fatalf("connection setup contaminated warm timing: %+v", measured)
	}
	if measured.Warm.Measurement != qualityMeasurementWarm || measured.Warm.StartedAt.Before(measured.ColdObservedAt) || !measured.Warm.ObservedAt.After(measured.Warm.StartedAt) {
		t.Fatalf("invalid phase boundaries: %+v", measured)
	}
}

func TestWarmQualityUsesTheSameHEADAfterReverseGET(t *testing.T) {
	methods := make(chan string, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods <- r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	measured := measureWarmHTTP(t.Context(), warmTestTransport(server), server.URL, http.MethodGet, 1024, time.Second, http.StatusNoContent, nil)
	if measured.ColdError != nil || measured.WarmError != nil || measured.Warm.DelayMS == nil {
		t.Fatalf("GET then warm HEAD failed: %+v", measured)
	}
	if first, second := <-methods, <-methods; first != http.MethodGet || second != http.MethodHead {
		t.Fatalf("methods changed: %s/%s", first, second)
	}
}

func TestWarmQualityFailureNeverChangesSuccessfulColdResult(t *testing.T) {
	for _, outcome := range []string{"cold-503", "warm-503", "warm-redirect", "cold-close"} {
		t.Run(outcome, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				if outcome == "cold-close" && call == 1 {
					w.Header().Set("Connection", "close")
				}
				if outcome == "cold-503" && call == 1 || outcome == "warm-503" && call == 2 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if outcome == "warm-redirect" && call == 2 {
					w.Header().Set("Location", "/redirected")
					w.WriteHeader(http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			measured := measureWarmHTTP(t.Context(), warmTestTransport(server), server.URL, http.MethodHead, 0, time.Second, http.StatusNoContent, nil)
			if !measured.Warm.Failed || measured.Warm.DelayMS != nil {
				t.Fatalf("failed phase supplied quality: %+v", measured)
			}
			if (measured.ColdError != nil) != (outcome == "cold-503") {
				t.Fatalf("warm failure changed cold result: %+v", measured)
			}
			expectedCalls := int32(2)
			if outcome == "cold-503" || outcome == "cold-close" {
				expectedCalls = 1
			}
			if calls.Load() != expectedCalls {
				t.Fatalf("unexpected retry/redirect: calls=%d expected=%d", calls.Load(), expectedCalls)
			}
		})
	}
}

func TestWarmQualityKeepsOneDeadlineAcrossBothRequests(t *testing.T) {
	var calls atomic.Int32
	warmCanceled := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			select {
			case <-time.After(130 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		<-r.Context().Done()
		close(warmCanceled)
	}))
	defer server.Close()
	started := time.Now()
	measured := measureWarmHTTP(t.Context(), warmTestTransport(server), server.URL, http.MethodHead, 0, 240*time.Millisecond, http.StatusNoContent, nil)
	elapsed := time.Since(started)
	if measured.ColdError != nil || !measured.Warm.Failed || measured.Warm.DelayMS != nil || measured.WarmError == nil || elapsed > 380*time.Millisecond {
		t.Fatalf("deadline was restarted or cold success lost: elapsed=%s %+v", elapsed, measured)
	}
	select {
	case <-warmCanceled:
	case <-time.After(time.Second):
		t.Fatal("second request handler remained active after cancellation")
	}
	if calls.Load() != 2 {
		t.Fatalf("unexpected requests after timeout: %d", calls.Load())
	}
}

func TestWarmBarrierSynchronizesMeasuredPhaseAfterUnequalColdRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	barrier := &qualityStartBarrier{id: 41, ready: make(chan struct{}), cancel: cancel}
	barrier.left.Store(2)
	fastCold := make(chan struct{})
	slowCold := make(chan struct{})
	release := make(chan struct{})
	var fastCalls, slowCalls atomic.Int32
	fast := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fastCalls.Add(1) == 1 {
			close(fastCold)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer fast.Close()
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slowCalls.Add(1) == 1 {
			close(slowCold)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer slow.Close()
	defer cancel()
	results := make(chan warmHTTPObservation, 2)
	for _, server := range []*httptest.Server{fast, slow} {
		go func() {
			results <- measureWarmHTTP(ctx, warmTestTransport(server), server.URL, http.MethodHead, 0, time.Second, http.StatusNoContent, &qualityStartTicket{barrier: barrier})
		}()
	}
	for _, observed := range []<-chan struct{}{fastCold, slowCold} {
		select {
		case <-observed:
		case <-ctx.Done():
			t.Fatal("a cold peer never reached the origin")
		}
	}
	if fastCalls.Load() != 1 || slowCalls.Load() != 1 {
		t.Fatal("a warm request escaped before all cold peers completed")
	}
	close(release)
	first, second := <-results, <-results
	latestCold := first.ColdObservedAt
	if second.ColdObservedAt.After(latestCold) {
		latestCold = second.ColdObservedAt
	}
	for _, measured := range []warmHTTPObservation{first, second} {
		if measured.Warm.Failed || measured.Warm.DelayMS == nil || measured.Warm.Wave != 41 || measured.Warm.StartedAt.Before(latestCold) {
			t.Fatalf("warm phase began against an unprepared peer: %+v", measured)
		}
	}
}

func TestWarmBarrierReleasesPeersAfterColdFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	barrier := &qualityStartBarrier{id: 42, ready: make(chan struct{}), cancel: cancel}
	barrier.left.Store(2)
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer bad.Close()
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer good.Close()
	results := make(chan warmHTTPObservation, 2)
	for _, server := range []*httptest.Server{bad, good} {
		go func() {
			results <- measureWarmHTTP(ctx, warmTestTransport(server), server.URL, http.MethodHead, 0, 500*time.Millisecond, http.StatusNoContent, &qualityStartTicket{barrier: barrier})
		}()
	}
	first, second := <-results, <-results
	if first.ColdError != nil {
		first, second = second, first
	}
	if first.ColdError != nil || !first.Warm.Deferred || first.Warm.Failed || !first.Warm.StartedAt.IsZero() || !errors.Is(first.WarmError, errWarmPeerFailed) || second.ColdError == nil || !second.Warm.Failed || ctx.Err() != nil {
		t.Fatalf("failed cold peer changed reachability or launched an unmatched warm request: %+v %+v", first, second)
	}
}

func TestWarmBarrierDeadlineDoesNotRestartRequestBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	barrier := &qualityStartBarrier{id: 43, ready: make(chan struct{}), cancel: cancel}
	barrier.left.Store(2) // The absent peer never arrives.
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	started := time.Now()
	measured := measureWarmHTTP(ctx, warmTestTransport(server), server.URL, http.MethodHead, 0, 100*time.Millisecond, http.StatusNoContent, &qualityStartTicket{barrier: barrier})
	if measured.ColdError != nil || !measured.Warm.Deferred || measured.Warm.Failed || !measured.Warm.StartedAt.IsZero() || measured.Warm.DelayMS != nil || !errors.Is(measured.WarmError, context.DeadlineExceeded) || calls.Load() != 1 || time.Since(started) > 300*time.Millisecond {
		t.Fatalf("barrier extended the session or lost reachability: %+v calls=%d", measured, calls.Load())
	}
}

func TestWarmBarrierAbortsBeforeColdFailureFallbackFinishes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	barrier := &qualityStartBarrier{id: 45, ready: make(chan struct{}), cancel: cancel}
	barrier.left.Store(2)
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	done := make(chan warmHTTPObservation, 1)
	go func() {
		done <- measureWarmHTTP(ctx, warmTestTransport(server), server.URL, http.MethodHead, 0, 800*time.Millisecond, http.StatusNoContent, &qualityStartTicket{barrier: barrier})
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for barrier.left.Load() != 1 {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("healthy peer never reached warm barrier")
		}
	}
	// The failed peer is still doing its independent availability fallback.
	// Abort the comparison without arriving or canceling that fallback.
	(&qualityStartTicket{barrier: barrier}).abortWarm()
	select {
	case measured := <-done:
		if measured.ColdError != nil || !measured.Warm.Deferred || !errors.Is(measured.WarmError, errWarmPeerFailed) || !measured.Warm.StartedAt.IsZero() || calls.Load() != 1 || ctx.Err() != nil {
			t.Fatalf("aborted comparison changed cold reachability: %+v calls=%d", measured, calls.Load())
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("healthy peer waited for unrelated availability fallback")
	}
}

func TestWarmSessionRefusesRedialAfterSilentIdleClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	barrier := &qualityStartBarrier{id: 44, ready: make(chan struct{}), cancel: cancel}
	barrier.left.Store(2)
	idle := make(chan net.Conn, 2)
	var calls, dials atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ConnState = func(connection net.Conn, state http.ConnState) {
		if state == http.StateIdle {
			idle <- connection
		}
	}
	server.StartTLS()
	defer server.Close()
	defer cancel()
	transport := warmTestTransport(server)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	done := make(chan warmHTTPObservation, 1)
	go func() {
		done <- measureWarmHTTP(ctx, transport, server.URL, http.MethodHead, 0, time.Second, http.StatusNoContent, &qualityStartTicket{barrier: barrier})
	}()
	var connection net.Conn
	select {
	case connection = <-idle:
	case <-ctx.Done():
		t.Fatal("first response never left an idle TLS connection")
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for barrier.left.Load() != 1 {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("first request never reached the warm barrier")
		}
	}
	connection.Close()
	(&qualityStartTicket{barrier: barrier}).arrive()
	measured := <-done
	if measured.ColdError != nil || !measured.Warm.Failed || measured.Warm.DelayMS != nil || measured.WarmError == nil || dials.Load() != 1 || calls.Load() != 1 {
		t.Fatalf("closed first connection was replaced: calls=%d dials=%d %+v", calls.Load(), dials.Load(), measured)
	}
}
