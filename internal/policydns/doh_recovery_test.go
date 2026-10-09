package policydns

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type dohTestTransport func(*http.Request) (*http.Response, error)

func (f dohTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type dohTestFallback struct {
	exchangeFunc func(context.Context, []byte) ([]byte, error)
}

func (f dohTestFallback) exchange(ctx context.Context, q []byte) ([]byte, error) {
	return f.exchangeFunc(ctx, q)
}
func (dohTestFallback) close() {}

func TestDoHTimeoutLeavesBudgetForEncryptedFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()
	called := false
	u := &dohUpstream{
		url: "https://resolver.example/dns-query",
		client: &http.Client{Timeout: 900 * time.Millisecond, Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})},
		fallback: dohTestFallback{exchangeFunc: func(ctx context.Context, q []byte) ([]byte, error) {
			called = true
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) < 100*time.Millisecond {
				return nil, errors.New("no fallback budget")
			}
			return dnsAResponse(q, 60), nil
		}},
	}
	q := dnsQuery(7, "example.com")
	r, err := u.exchange(ctx, q)
	if err != nil || !called || !matchingQuestion(q, r) {
		t.Fatalf("fallback called=%v response=%x error=%v", called, r, err)
	}
}

func TestDoHCancellationDoesNotStartFallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	u := &dohUpstream{
		url: "https://resolver.example/dns-query",
		client: &http.Client{Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
			cancel()
			return nil, context.Canceled
		})},
		fallback: dohTestFallback{exchangeFunc: func(context.Context, []byte) ([]byte, error) {
			t.Error("fallback started after generation cancellation")
			return nil, errors.New("unexpected fallback")
		}},
	}
	defer cancel()
	if _, err := u.exchange(ctx, dnsQuery(7, "example.com")); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestDoHRetryIsBoundedAndDoesNotRetryTrustErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"closed", io.EOF, 2},
		{"trust", x509.UnknownAuthorityError{}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			u := &dohUpstream{url: "https://resolver.example/dns-query", client: &http.Client{Transport: dohTestTransport(func(*http.Request) (*http.Response, error) {
				calls++
				return nil, tc.err
			})}}
			if _, err := u.exchange(context.Background(), dnsQuery(1, "example.com")); err == nil {
				t.Fatal("failure accepted")
			}
			if calls != tc.want {
				t.Fatalf("attempts=%d want=%d", calls, tc.want)
			}
		})
	}
}

func TestDoHFallbackDoesNotExtendTotalTimeout(t *testing.T) {
	start := time.Now()
	u := &dohUpstream{url: "https://resolver.example/dns-query", client: &http.Client{Timeout: 300 * time.Millisecond, Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}, fallback: dohTestFallback{exchangeFunc: func(ctx context.Context, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	if _, err := u.exchange(context.Background(), dnsQuery(1, "example.com")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("total timeout extended: %s", elapsed)
	}
}

func TestDoHRetrySharesConfiguredDeadline(t *testing.T) {
	calls := 0
	var deadline time.Time
	u := &dohUpstream{url: "https://resolver.example/dns-query", client: &http.Client{
		Timeout: time.Second, Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			current, ok := r.Context().Deadline()
			if !ok {
				t.Fatal("request has no configured deadline")
			}
			if calls == 1 {
				deadline = current
				time.Sleep(10 * time.Millisecond)
				return nil, io.EOF
			}
			if !current.Equal(deadline) {
				t.Errorf("retry extended deadline: first=%v retry=%v", deadline, current)
			}
			q, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/dns-message"}},
				Body: io.NopCloser(strings.NewReader(string(dnsAResponse(q, 60))))}, nil
		}),
	}}
	q := dnsQuery(1, "example.com")
	r, err := u.exchange(context.Background(), q)
	if err != nil || calls != 2 || !matchingQuestion(q, r) {
		t.Fatalf("attempts=%d error=%v", calls, err)
	}
}

func TestDoHInvalidResponsesUseEncryptedFallback(t *testing.T) {
	q := dnsQuery(7, "example.com")
	for _, tc := range []struct {
		name, contentType string
		body              []byte
		status            int
	}{
		{"status", "application/dns-message", dnsAResponse(q, 60), http.StatusServiceUnavailable},
		{"short", "application/dns-message", []byte{0}, http.StatusOK},
		{"question", "application/dns-message", dnsAResponse(dnsQuery(8, "other.example"), 60), http.StatusOK},
		{"mime", "application/dns-message-invalid", dnsAResponse(q, 60), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			u := &dohUpstream{url: "https://resolver.example/dns-query", client: &http.Client{Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Status: http.StatusText(tc.status), Header: http.Header{"Content-Type": {tc.contentType}}, Body: io.NopCloser(strings.NewReader(string(tc.body)))}, nil
			})}, fallback: dohTestFallback{exchangeFunc: func(_ context.Context, q []byte) ([]byte, error) {
				called = true
				return dnsAResponse(q, 60), nil
			}}}
			r, err := u.exchange(context.Background(), q)
			if err != nil || !called || !matchingQuestion(q, r) {
				t.Fatalf("fallback called=%v response=%x error=%v", called, r, err)
			}
		})
	}
}

func TestDoHRecoversAfterHTTP2FailureAndClosedIdleConnection(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol HTTP/%d", r.ProtoMajor)
		}
		if _, ok := r.Header["Idempotency-Key"]; ok {
			t.Error("internal retry marker leaked to resolver")
		}
		q, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message; charset=binary")
		_, _ = w.Write(dnsAResponse(q, 60))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	host, textPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(textPort)
	if err != nil {
		t.Fatal(err)
	}
	configured, err := newDoHUpstream(serverConfig{Server: host, ServerName: "example.com", ServerPort: port}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u := configured.(*dohUpstream)
	defer u.close()
	if _, err := u.exchange(context.Background(), dnsQuery(1, "example.com")); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("DNS payload reached an untrusted TLS server")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u.transport.TLSClientConfig.RootCAs = roots
	q := dnsQuery(9, "example.com")
	if _, err := u.exchange(context.Background(), q); err == nil {
		t.Fatal("503 accepted")
	}
	for n := 0; n < 4; n++ {
		r, err := u.exchange(context.Background(), q)
		if err != nil || !matchingQuestion(q, r) {
			t.Fatalf("recovery %d: %v", n, err)
		}
		server.CloseClientConnections()
	}
}

func TestDoHDiscardsUnresponsiveHTTP2Connection(t *testing.T) {
	var staleRemote atomic.Value
	staleRemote.Store("")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol HTTP/%d", r.ProtoMajor)
		}
		q, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		if staleRemote.Load() == r.RemoteAddr {
			<-r.Context().Done()
			return
		}
		staleRemote.CompareAndSwap("", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dnsAResponse(q, 60))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	host, textPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(textPort)
	configured, err := newDoHUpstream(serverConfig{Server: host, ServerName: "example.com", ServerPort: port}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u := configured.(*dohUpstream)
	defer u.close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u.transport.TLSClientConfig.RootCAs = roots
	q := dnsQuery(1, "example.com")
	if _, err := u.exchange(context.Background(), q); err != nil {
		t.Fatalf("warmup: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := u.exchange(ctx, q); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unresponsive request: %v", err)
	}
	r, err := u.exchange(context.Background(), q)
	if err != nil || !matchingQuestion(q, r) {
		t.Fatalf("next request reused unresponsive connection: %v", err)
	}
}

func TestDoHRetirementPreservesInflightRequestsAndDrainsPool(t *testing.T) {
	var remote atomic.Value
	remote.Store("")
	started, release, closed := make(chan struct{}, 1), make(chan struct{}), make(chan struct{}, 1)
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		remote.CompareAndSwap("", r.RemoteAddr)
		name, _ := questionName(q)
		switch name {
		case "slow.example":
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		case "stall.example":
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(dnsAResponse(q, 60))
	}))
	server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed && c.RemoteAddr().String() == remote.Load() {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	host, textPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(textPort)
	configured, err := newDoHUpstream(serverConfig{Server: host, ServerName: "example.com", ServerPort: port}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u := configured.(*dohUpstream)
	defer u.close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u.transport.TLSClientConfig.RootCAs = roots
	q := dnsQuery(1, "example.com")
	if _, err := u.exchange(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		slow := dnsQuery(2, "slow.example")
		r, err := u.exchange(context.Background(), slow)
		if err == nil && !matchingQuestion(slow, r) {
			err = errors.New("in-flight response mismatch")
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight request did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := u.exchange(ctx, dnsQuery(3, "stall.example")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stalled request: %v", err)
	}
	if _, err := u.exchange(context.Background(), q); err != nil {
		t.Fatalf("new generation: %v", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("retirement interrupted in-flight request: %v", err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("retired pool retained its old idle connection")
	}
}

func TestDoHRejectsRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			targetCalls.Add(1)
		}
		http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	host, textPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(textPort)
	configured, err := newDoHUpstream(serverConfig{Server: host, ServerName: "example.com", ServerPort: port}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u := configured.(*dohUpstream)
	defer u.close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u.transport.TLSClientConfig.RootCAs = roots
	if _, err := u.exchange(context.Background(), dnsQuery(1, "example.com")); err == nil {
		t.Fatal("redirect accepted")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("redirect followed")
	}
}
