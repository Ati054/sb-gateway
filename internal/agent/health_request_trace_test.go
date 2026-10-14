package agent

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeRequestFailureStages(t *testing.T) {
	for _, stage := range []string{"proxy-connect", "tls-handshake", "response-headers", "response-body"} {
		t.Run(stage, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch stage {
				case "proxy-connect":
					w.WriteHeader(http.StatusServiceUnavailable)
				case "tls-handshake":
					conn, rw, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(time.Second))
					rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
					rw.Flush()
					io.Copy(io.Discard, rw)
				case "response-headers":
					<-r.Context().Done()
				case "response-body":
					w.Header().Set("Content-Length", "1024")
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			target := "http://probe.invalid/"
			if stage == "proxy-connect" || stage == "tls-handshake" {
				target = "https://probe.invalid/"
			}
			_, err := downloadThroughProxyContext(t.Context(), server.URL, target, 150*time.Millisecond, 1024, 200)
			if err == nil || probeErrorStage(err) != stage {
				t.Fatalf("stage=%s want=%s err=%v", probeErrorStage(err), stage, err)
			}
			if stage != "proxy-connect" && classifyProbeError(err) != probeFailureTimeout {
				t.Fatalf("wrapping changed timeout classification: %v", err)
			}
		})
	}
}

func TestProbeRequestStagePreservesCancellationAndRawErrors(t *testing.T) {
	trace := &probeRequestTrace{}
	err := trace.wrap(context.Canceled)
	if !errors.Is(err, context.Canceled) || err.Error() != context.Canceled.Error() {
		t.Fatalf("wrapping lost original error: %v", err)
	}
	if trace.wrap(nil) != nil || probeErrorStage(errors.New("raw error")) != "" {
		t.Fatal("trace invented an error or stage")
	}
}
