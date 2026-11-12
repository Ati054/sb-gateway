package policydns

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDoHSlowPrimarySurvivesSilentEncryptedFallback(t *testing.T) {
	var fallbackCalls atomic.Int32
	u := &dohUpstream{
		url: "https://resolver.example/dns-query",
		client: &http.Client{Timeout: 5 * time.Second, Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
			query, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			timer := time.NewTimer(3500 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-timer.C:
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/dns-message"}}, Body: io.NopCloser(strings.NewReader(string(dnsAResponse(query, 60))))}, nil
			}
		})},
		fallback: dohTestFallback{exchangeFunc: func(ctx context.Context, _ []byte) ([]byte, error) {
			fallbackCalls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	}
	query := dnsQuery(70, "slow-primary.example")
	started := time.Now()
	answer, err := u.exchange(t.Context(), query)
	if err != nil || !matchingQuestion(query, answer) || fallbackCalls.Load() != 1 {
		t.Fatalf("working primary canceled for fallback: error=%v fallback=%d", err, fallbackCalls.Load())
	}
	if elapsed := time.Since(started); elapsed > 4500*time.Millisecond {
		t.Fatalf("completed answer waited for the losing fallback: %v", elapsed)
	}
}

func TestEncryptedFallbackDoesNotChooseMismatchedAnswer(t *testing.T) {
	// Keep the client alive past the old fallback threshold; an unrelated
	// fallback packet must not cancel its valid pending answer.
	u := &dohUpstream{url: "https://resolver.example/dns-query", client: &http.Client{Timeout: 900 * time.Millisecond, Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
		query, _ := io.ReadAll(r.Body)
		timer := time.NewTimer(750 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-timer.C:
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/dns-message"}}, Body: io.NopCloser(strings.NewReader(string(dnsAResponse(query, 60))))}, nil
		}
	})}, fallback: dohTestFallback{exchangeFunc: func(_ context.Context, query []byte) ([]byte, error) {
		answer := dnsAResponse(query, 60)
		answer[0]++
		return answer, nil
	}}}
	query := dnsQuery(71, "matching-primary.example")
	answer, err := u.exchange(t.Context(), query)
	if err != nil || !matchingQuestion(query, answer) {
		t.Fatalf("mismatched fallback won: %v", err)
	}
}

func delayedFallbackFixture(delay, timeout time.Duration, calls *atomic.Int32) *dohUpstream {
	return &dohUpstream{url: "https://resolver.example/dns-query", client: &http.Client{Timeout: timeout, Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
		query, _ := io.ReadAll(r.Body)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-timer.C:
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/dns-message"}}, Body: io.NopCloser(strings.NewReader(string(dnsAResponse(query, 60))))}, nil
		}
	})}, fallback: dohTestFallback{exchangeFunc: func(_ context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		return dnsAResponse(query, 60), nil
	}}}
}

func TestEncryptedFallbackRespectsGlobalAndProfileAdmission(t *testing.T) {
	for _, profileLimit := range []bool{false, true} {
		t.Run(map[bool]string{false: "global", true: "profile"}[profileLimit], func(t *testing.T) {
			var calls atomic.Int32
			u := delayedFallbackFixture(750*time.Millisecond, 900*time.Millisecond, &calls)
			servers := map[string]upstream{"wan": u}
			if profileLimit {
				servers["other"] = &questionlessUpstream{}
			}
			r := sharedQueryRuntime(t, servers, laneConfig{ID: "lane", Final: "wan"})
			r.timeout = 900 * time.Millisecond
			s, cancel := managedTestService(r)
			s.limit = make(chan struct{}, 2)
			defer cancel()
			if !profileLimit {
				if !s.acquire() {
					t.Fatal("could not reserve fixture work")
				}
				defer s.release()
			}
			query := dnsQuery(72, "budget-primary.example")
			admitted := s.admitQuery("lane", query)
			answer, err := s.resolveAdmitted(admitted, "lane", query)
			if err != nil || !matchingQuestion(query, answer) || answer[3]&15 != 0 || calls.Load() != 0 {
				t.Fatalf("denied extra work canceled primary or bypassed limit: %v calls=%d", err, calls.Load())
			}
			want := 0
			if !profileLimit {
				want = 1
			}
			if len(s.limit) != want || s.queryBytes != 0 || (admitted.route != nil && len(admitted.route.active) != 0) {
				t.Fatal("fallback retained an admission reservation")
			}
		})
	}
}

func TestEncryptedFallbackImmediateErrorReusesLeaderSlot(t *testing.T) {
	var calls atomic.Int32
	u := delayedFallbackFixture(0, time.Second, &calls)
	u.client.Transport = dohTestTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("primary unavailable") })
	r := sharedQueryRuntime(t, map[string]upstream{"wan": u}, laneConfig{ID: "lane", Final: "wan"})
	r.timeout = time.Second
	s, cancel := managedTestService(r)
	defer cancel()
	s.limit = make(chan struct{}, 1)
	query := dnsQuery(73, "sequential-fallback.example")
	answer, err := s.resolveAdmitted(s.admitQuery("lane", query), "lane", query)
	if err != nil || !matchingQuestion(query, answer) || calls.Load() != 1 || len(s.limit) != 0 {
		t.Fatal("sequential fallback required extra capacity or leaked the leader")
	}
}

func TestEncryptedFallbackOverlapBorrowsAndReturnsWork(t *testing.T) {
	var calls atomic.Int32
	u := delayedFallbackFixture(time.Second, 180*time.Millisecond, &calls)
	r := sharedQueryRuntime(t, map[string]upstream{"wan": u}, laneConfig{ID: "lane", Final: "wan"})
	r.timeout = time.Second
	s, cancel := managedTestService(r)
	defer cancel()
	s.limit = make(chan struct{}, 2)
	u.fallback = dohTestFallback{exchangeFunc: func(_ context.Context, query []byte) ([]byte, error) {
		calls.Add(1)
		if len(s.limit) != 2 {
			t.Error("overlapping fallback had no extra work reservation")
		}
		return dnsAResponse(query, 60), nil
	}}
	query := dnsQuery(76, "overlapping-fallback.example")
	answer, err := s.resolveAdmitted(s.admitQuery("lane", query), "lane", query)
	if err != nil || !matchingQuestion(query, answer) || calls.Load() != 1 || len(s.limit) != 0 || s.queryBytes != 0 {
		t.Fatal("winning fallback retained work or returned an invalid reply")
	}
}

func TestFreshEncryptedFallbackRespectsItsWorkerLimit(t *testing.T) {
	var calls atomic.Int32
	u := delayedFallbackFixture(750*time.Millisecond, 900*time.Millisecond, &calls)
	resolver, err := startFreshResolver(t.Context(), FreshResolverConfig{Type: "https", Server: "127.0.0.1", ServerName: "example.com", ServerPort: 443, Path: "/dns-query"}, FreshResolverOptions{Workers: 1, TCPSessions: 1, Timeout: time.Second}, func(serverConfig, time.Duration) (upstream, error) { return u, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	answer := freshQuery(t, resolver, "udp", "fresh-budget.example", 1232)
	// Receiving the UDP answer does not mean the handler defer has run.
	// Shutdown waits for that owner before inspecting returned capacity.
	if err := resolver.Close(); err != nil {
		t.Fatal(err)
	}
	if answer.Rcode != dns.RcodeSuccess || calls.Load() != 0 || len(resolver.limit) != 0 {
		t.Fatal("fresh resolver bypassed its work limit or canceled its primary")
	}
}

func TestEncryptedFallbackKeepsShortParentDeadline(t *testing.T) {
	var calls, leases atomic.Int32
	u := delayedFallbackFixture(time.Second, 5*time.Second, &calls)
	parent, cancel := context.WithTimeout(t.Context(), 90*time.Millisecond)
	defer cancel()
	want, _ := parent.Deadline()
	u.fallback = dohTestFallback{exchangeFunc: func(ctx context.Context, _ []byte) ([]byte, error) {
		calls.Add(1)
		if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(want) {
			t.Error("fallback extended the parent's deadline")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ctx := context.WithValue(parent, dnsFallbackBudgetKey{}, dnsFallbackBorrow(func() (func(), bool) {
		leases.Add(1)
		return func() { leases.Add(-1) }, true
	}))
	started := time.Now()
	_, err := u.exchange(ctx, dnsQuery(78, "short-parent.example"))
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 500*time.Millisecond || calls.Load() != 1 || leases.Load() != 0 {
		t.Fatalf("short deadline was not respected: err=%v calls=%d leases=%d", err, calls.Load(), leases.Load())
	}
}

func TestEncryptedFallbackDoesNotReplaceValidNegativePrimary(t *testing.T) {
	for _, code := range []byte{dns.RcodeNameError, dns.RcodeRefused, dns.RcodeServerFailure} {
		var calls atomic.Int32
		u := delayedFallbackFixture(0, time.Second, &calls)
		u.client.Transport = dohTestTransport(func(r *http.Request) (*http.Response, error) {
			query, _ := io.ReadAll(r.Body)
			answer := dnsAResponse(query, 60)
			answer[3] = answer[3]&0xf0 | code
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/dns-message"}}, Body: io.NopCloser(strings.NewReader(string(answer)))}, nil
		})
		answer, err := u.exchange(t.Context(), dnsQuery(79, "negative-primary.example"))
		if err != nil || len(answer) < 12 || answer[3]&15 != code || calls.Load() != 0 {
			t.Fatal("valid negative primary triggered fallback")
		}
	}
}

func TestFreshEncryptedFallbackCancellationReturnsAllWorkers(t *testing.T) {
	var calls atomic.Int32
	ready := make(chan struct{}, 1)
	u := delayedFallbackFixture(time.Second, 300*time.Millisecond, &calls)
	u.fallback = dohTestFallback{exchangeFunc: func(ctx context.Context, _ []byte) ([]byte, error) {
		calls.Add(1)
		ready <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	resolver, err := startFreshResolver(parent, FreshResolverConfig{Type: "https", Server: "127.0.0.1", ServerName: "example.com", ServerPort: 443, Path: "/dns-query"}, FreshResolverOptions{Workers: 2, TCPSessions: 1, Timeout: time.Second}, func(serverConfig, time.Duration) (upstream, error) { return u, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	conn, err := net.Dial("udp4", resolver.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(dnsQuery(80, "fresh-cancel.example")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("fresh fallback did not start")
	}
	cancel()
	resolver.Close()
	if calls.Load() != 1 || len(resolver.limit) != 0 {
		t.Fatal("fresh shutdown retained fallback workers")
	}
}

func BenchmarkDoHFallbackFastPath(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(b *testing.B) {
			u := delayedFallbackFixture(0, 5*time.Second, new(atomic.Int32))
			u.client.Transport = dohTestTransport(func(r *http.Request) (*http.Response, error) {
				query, _ := io.ReadAll(r.Body)
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/dns-message"}}, Body: io.NopCloser(strings.NewReader(string(dnsAResponse(query, 60))))}, nil
			})
			if !enabled {
				u.fallback = nil
			}
			query := dnsQuery(77, "fast-primary.example")
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := u.exchange(b.Context(), query); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestEncryptedFallbackTimerAndPrimaryCompletionHaveOneWinner(t *testing.T) {
	for _, delay := range []time.Duration{95, 100, 105} {
		var calls, leases atomic.Int32
		u := delayedFallbackFixture(delay*time.Millisecond, 150*time.Millisecond, &calls)
		u.client.Transport = dohTestTransport(func(r *http.Request) (*http.Response, error) {
			timer := time.NewTimer(delay * time.Millisecond)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-timer.C:
				return nil, errors.New("primary unavailable")
			}
		})
		ctx := context.WithValue(t.Context(), dnsFallbackBudgetKey{}, dnsFallbackBorrow(func() (func(), bool) {
			if leases.Add(1) != 1 {
				t.Error("duplicate concurrent fallback lease")
			}
			return func() { leases.Add(-1) }, true
		}))
		query := dnsQuery(74, "timer-boundary.example")
		answer, err := u.exchange(ctx, query)
		if err != nil || !matchingQuestion(query, answer) || calls.Load() != 1 || leases.Load() != 0 {
			t.Fatalf("fallback race: err=%v calls=%d leases=%d", err, calls.Load(), leases.Load())
		}
	}
}

func TestEncryptedFallbackCancellationJoinsTimerAndWorkers(t *testing.T) {
	for _, delay := range []time.Duration{120, 140} {
		var calls, leases atomic.Int32
		u := delayedFallbackFixture(time.Second, 200*time.Millisecond, &calls)
		u.fallback = dohTestFallback{exchangeFunc: func(ctx context.Context, _ []byte) ([]byte, error) {
			calls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		parent, cancel := context.WithCancel(t.Context())
		ctx := context.WithValue(parent, dnsFallbackBudgetKey{}, dnsFallbackBorrow(func() (func(), bool) {
			leases.Add(1)
			return func() { leases.Add(-1) }, true
		}))
		timer := time.AfterFunc(delay*time.Millisecond, cancel)
		_, err := u.exchange(ctx, dnsQuery(75, "cancel-fallback.example"))
		timer.Stop()
		cancel()
		if !errors.Is(err, context.Canceled) || calls.Load() > 1 || leases.Load() != 0 {
			t.Fatalf("cancellation left fallback work: %v calls=%d leases=%d", err, calls.Load(), leases.Load())
		}
	}
}
