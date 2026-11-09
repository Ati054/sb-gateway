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
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

func TestDoHHTTP2FailureClassification(t *testing.T) {
	for _, fault := range []error{
		http2.StreamError{StreamID: 1, Code: http2.ErrCodeInternal},
		http2.StreamError{StreamID: 3, Code: http2.ErrCodeRefusedStream},
		http2.ConnectionError(http2.ErrCodeProtocol),
		//lint:ignore SA1019 Exercise compatibility with typed failures from existing transports.
		http2.GoAwayError{ErrCode: http2.ErrCodeNo},
		errors.New("http2: server sent GOAWAY and closed the connection; debug=private"),
	} {
		if !dohConnectionClosed(errors.Join(fault, io.EOF)) || !dohConnectionClosed(fault) {
			t.Fatalf("HTTP/2 failure was not retired: %T", fault)
		}
	}
	for _, fault := range []error{x509.UnknownAuthorityError{}, context.Canceled, errors.New("DoH status 503"), http2.StreamError{Code: http2.ErrCodeInadequateSecurity}} {
		if dohConnectionClosed(fault) {
			t.Fatalf("non-retryable failure was retried: %T", fault)
		}
	}
}

func TestDoHHTTP2ResetRetiresTransportAndRecovers(t *testing.T) {
	var calls, accepted atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("fixture was not HTTP/2")
		}
		query, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if calls.Add(1) == 1 {
			panic(http.ErrAbortHandler) // Real RST_STREAM from Go's HTTP/2 server.
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsAResponse(query, 60))
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	created, err := newDoHUpstream(serverConfig{Server: host, ServerName: "example.com", ServerPort: port}, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u := created.(*dohUpstream)
	t.Cleanup(u.close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	u.transport.TLSClientConfig.RootCAs = roots
	previous := u.transport
	query := dnsQuery(51, "http2-reset.example")
	answer, err := u.exchange(t.Context(), query)
	if err != nil || !matchingQuestion(query, answer) || calls.Load() != 2 || accepted.Load() != 2 || u.transport == previous {
		t.Fatalf("HTTP/2 recovery failed: err=%v calls=%d connections=%d retired=%v", err, calls.Load(), accepted.Load(), u.transport != previous)
	}
}

func TestDoHDoesNotReplayNonQueryOrZoneTransfer(t *testing.T) {
	for _, kind := range []uint16{dns.TypeAXFR, dns.TypeIXFR, 0x8004, 0x8005} {
		query := dnsQuery(52, "unsafe.example")
		if kind < 0x8000 {
			query[len(query)-4], query[len(query)-3] = byte(kind>>8), byte(kind)
		} else {
			query[2] = byte(kind&15) << 3
		}
		calls := 0
		u := &dohUpstream{url: "https://resolver.example/dns-query", client: &http.Client{Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if _, exists := r.Header["Idempotency-Key"]; exists {
				t.Error("unsafe request marked replayable")
			}
			return nil, io.EOF
		})}, fallback: dohTestFallback{exchangeFunc: func(context.Context, []byte) ([]byte, error) {
			t.Error("unsafe request replayed through fallback")
			return nil, io.EOF
		}}}
		if _, err := u.exchange(t.Context(), query); err == nil || calls != 1 {
			t.Fatalf("unsafe request replayed: kind=%d calls=%d err=%v", kind, calls, err)
		}
	}
}
