package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const admissionSubscriptionBody = "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@provider.example.test:443?security=tls#Provider"

func subscriptionAdmissionFixture(t *testing.T) (*Server, *http.Cookie, string) {
	t.Helper()
	s := newTestServer(t)
	cookie, csrf := bootstrapSession(t, s)
	created := performRequest(t, s, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{
		"id": "provider", "display_name": "Provider", "enabled": true,
		"url": "https://provider.example.test/sub", "max_nodes": 10,
		"download_timeout_seconds": 2, "refresh_minutes": 60,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	return s, cookie, csrf
}

func subscriptionAdmissionRequest(s *Server, ctx context.Context, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil).WithContext(ctx)
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set(csrfHeader, csrf)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	return response
}

func TestSubscriptionRefreshCancelledAdmissionDoesNotFetchAfterRelease(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, cookie, csrf := subscriptionAdmissionFixture(t)
		calls := 0
		s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
			calls++
			return []byte(admissionSubscriptionBody), nil, nil
		}
		s.subscriptionMu.Lock()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- subscriptionAdmissionRequest(s, ctx, cookie, csrf) }()
		synctest.Wait()
		cancel()
		// The response must finish while the gate is still held, not on release.
		response := <-done
		if response.Code != http.StatusConflict || calls != 0 {
			t.Fatalf("cancelled admission: status=%d fetches=%d", response.Code, calls)
		}
		s.subscriptionMu.Unlock()
		synctest.Wait()
		if calls != 0 || !s.subscriptionMu.TryLock() {
			t.Fatal("cancelled admission fetched later or leaked the gate")
		}
		s.subscriptionMu.Unlock()
	})
}

func TestSubscriptionRefreshAdmissionAndFetchShareConfiguredBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, cookie, csrf := subscriptionAdmissionFixture(t)
		var remaining time.Duration
		calls := 0
		s.fetchSubscription = func(ctx context.Context, _ string, _ int) ([]byte, http.Header, error) {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Error("missing download deadline")
			}
			remaining = time.Until(deadline)
			<-ctx.Done()
			return nil, nil, ctx.Err()
		}
		s.subscriptionMu.Lock()
		started := time.Now()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- subscriptionAdmissionRequest(s, context.Background(), cookie, csrf) }()
		synctest.Wait()
		time.Sleep(1500 * time.Millisecond)
		s.subscriptionMu.Unlock()
		response := <-done
		if elapsed := time.Since(started); elapsed != 2*time.Second || remaining != 500*time.Millisecond {
			t.Fatalf("wait reset budget: elapsed=%s fetch_remaining=%s", elapsed, remaining)
		}
		if calls != 1 || response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("timed out fetch: calls=%d status=%d", calls, response.Code)
		}
	})
}

func TestSubscriptionRefreshExpiredAdmissionDoesNotStartFetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, cookie, csrf := subscriptionAdmissionFixture(t)
		calls := 0
		s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
			calls++
			return []byte(admissionSubscriptionBody), nil, nil
		}
		s.subscriptionMu.Lock()
		done := make(chan *httptest.ResponseRecorder, 1)
		started := time.Now()
		go func() { done <- subscriptionAdmissionRequest(s, context.Background(), cookie, csrf) }()
		response := <-done
		if elapsed := time.Since(started); elapsed != 2*time.Second || response.Code != http.StatusConflict || calls != 0 {
			t.Fatalf("expired admission: elapsed=%s status=%d fetches=%d", elapsed, response.Code, calls)
		}
		s.subscriptionMu.Unlock()
	})
}

func TestSubscriptionRefreshRejectsSourceChangedWhileQueued(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, cookie, csrf := subscriptionAdmissionFixture(t)
		calls := 0
		s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
			calls++
			return []byte(admissionSubscriptionBody), nil, nil
		}
		s.subscriptionMu.Lock()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- subscriptionAdmissionRequest(s, context.Background(), cookie, csrf) }()
		synctest.Wait()
		draft, err := s.getDraft()
		if err != nil {
			t.Fatal(err)
		}
		draft["subscriptions"].([]any)[0].(map[string]any)["url_secret_ref"] = "subscriptions/provider/replaced.url"
		if _, err := s.repository.saveDraft(draft); err != nil {
			t.Fatal(err)
		}
		s.subscriptionMu.Unlock()
		response := <-done
		if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"subscription_source_changed"`) || calls != 0 {
			t.Fatalf("changed queued source: status=%d fetches=%d body=%s", response.Code, calls, response.Body.String())
		}
	})
}

func TestSubscriptionRefreshCancellationBeforeCommitPreservesInventory(t *testing.T) {
	s, _, _ := subscriptionAdmissionFixture(t)
	draft, err := s.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	subscription := draft["subscriptions"].([]any)[0].(map[string]any)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		cancel()
		return []byte(admissionSubscriptionBody), nil, nil
	}
	s.subscriptionMu.Lock()
	_, err = s.refreshSubscriptionNow(ctx, subscription)
	s.subscriptionMu.Unlock()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled before commit: %v", err)
	}
	state, readErr := s.repository.auxiliary("subscription-nodes")
	if readErr != nil || len(state) != 0 {
		t.Fatalf("cancelled fetch published inventory: %v %#v", readErr, state)
	}
}

func TestSubscriptionSchedulerChecksDueAfterManualRefreshReleasesGate(t *testing.T) {
	// Keep the real TLS listener outside the virtual-time bubble. The current
	// image and four mounts are still checked through authenticated REST; no
	// compatibility guard is bypassed by this scheduler fixture.
	rest := newCatalogCompatibilityRESTFixture(t, "disk/sb-gateway")
	synctest.Test(t, func(t *testing.T) {
		s, _, _ := subscriptionAdmissionFixture(t)
		draft, err := s.getDraft()
		if err != nil {
			t.Fatal(err)
		}
		bindCatalogCompatibilityRESTFixture(t, s, draft, rest)
		if _, err := s.repository.saveDraft(draft); err != nil {
			t.Fatal(err)
		}
		revision, err := s.repository.stageGeneration(draft)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.repository.setActiveRevision(revision); err != nil {
			t.Fatal(err)
		}
		calls := 0
		s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
			calls++
			return []byte(admissionSubscriptionBody), nil, nil
		}
		s.subscriptionMu.Lock()
		type result struct {
			delay time.Duration
			err   error
		}
		done := make(chan result, 1)
		ctx, cancel := context.WithCancel(context.Background())
		gateHeld, joined := true, false
		defer func() {
			cancel()
			if gateHeld {
				s.subscriptionMu.Unlock()
			}
			if !joined {
				<-done
			}
		}()
		go func() { delay, err := s.refreshOneDueSubscription(ctx); done <- result{delay, err} }()
		synctest.Wait()
		// Complete a manual refresh while the scheduler is queued. Do not start
		// a second HTTP request: this goroutine already owns its admission gate.
		if _, err := s.refreshSubscriptionNow(context.Background(), draft["subscriptions"].([]any)[0].(map[string]any)); err != nil {
			t.Fatal(err)
		}
		s.subscriptionMu.Unlock()
		gateHeld = false
		got := <-done
		joined = true
		if got.err != nil || calls != 1 || got.delay != time.Hour {
			t.Fatalf("stale due download: calls=%d delay=%s err=%v", calls, got.delay, got.err)
		}
		status, err := s.repository.auxiliary("subscription-refresh-status")
		if err != nil || len(status) != 0 {
			t.Fatalf("skipped scheduler published an attempt: %v %#v", err, status)
		}
	})
}

func TestSubscriptionSchedulerCancelledAdmissionDoesNotRecordAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestServer(t)
		s.subscriptionMu.Lock()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := s.refreshOneDueSubscription(ctx); done <- err }()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled scheduler: %v", err)
		}
		s.subscriptionMu.Unlock()
		status, err := s.repository.auxiliary("subscription-refresh-status")
		if err != nil || len(status) != 0 {
			t.Fatalf("cancelled admission recorded failure: %v %#v", err, status)
		}
	})
}

func TestSubscriptionActivationDoesNotHoldMutationWhileDownloadOwnsGate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, runtime, _, _ := subscriptionRuntimeFixture(t)
		s.subscriptionMu.Lock()
		type result struct {
			worked bool
			err    error
		}
		done := make(chan result, 1)
		go func() {
			worked, err := s.activatePendingSubscription(context.Background())
			done <- result{worked, err}
		}()
		synctest.Wait()
		select {
		case got := <-done:
			if got.worked || got.err != nil {
				t.Fatalf("busy gate must defer activation: %+v", got)
			}
		default:
			// Release and join even on the old behavior, so the regression fails
			// without leaving a blocked worker or modifying files after cleanup.
			s.subscriptionMu.Unlock()
			<-done
			t.Fatal("activation waited for download while monopolizing mutation admission")
		}
		if !s.mutationMu.TryLock() {
			t.Fatal("deferred activation retained mutation admission")
		}
		s.mutationMu.Unlock()
		if runtime.prepareCalls != 0 || runtime.activateCalls != 0 {
			t.Fatal("deferred activation changed runtime")
		}
		s.subscriptionMu.Unlock()
		if worked, err := s.activatePendingSubscription(context.Background()); !worked || err != nil {
			t.Fatalf("later activation did not recover: %v %v", worked, err)
		}
	})
}
