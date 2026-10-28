package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQualityProbeDoesNotReuseHTTPConnections(t *testing.T) {
	var connections, requests atomic.Int32
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodHead {
			t.Errorf("unexpected probe method %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	proxy.Start()
	defer proxy.Close()
	for range 2 {
		if _, err := requestThroughProxyContext(t.Context(), proxy.URL, "http://probe.invalid/", http.MethodHead, time.Second, 0, http.StatusNoContent); err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 2 || requests.Load() != 2 {
		t.Fatalf("independent probes reused a connection: connections=%d requests=%d", connections.Load(), requests.Load())
	}
}

func TestRepeatedHTTPSMeasurementExcludesSetupButRetainsOriginDelay(t *testing.T) {
	const setup = 150 * time.Millisecond
	const originDelay = 40 * time.Millisecond
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(originDelay)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	client := origin.Client()
	client.Timeout = 3 * time.Second
	transport := client.Transport.(*http.Transport)
	transport.ForceAttemptHTTP2 = false
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		select {
		case <-time.After(setup):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	defer client.CloseIdleConnections()
	for round := range 2 {
		var reused bool
		request, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
		}), http.MethodHead, origin.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		elapsed := time.Since(started)
		if response.StatusCode != http.StatusNoContent || reused != (round == 1) || elapsed < originDelay {
			t.Fatalf("invalid repeated HTTPS measurement: round=%d reused=%t status=%d elapsed=%s", round, reused, response.StatusCode, elapsed)
		}
		if round == 0 && elapsed < setup+originDelay {
			t.Fatal("initial measurement omitted connection setup")
		}
	}
}

func TestResponseTimingExcludesConnectionSetupAndKeepsServerDelay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, setup := range []time.Duration{0, 200 * time.Millisecond} {
		trace := &probeRequestTrace{}
		transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			select {
			case <-time.After(setup):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}}
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace.hooks()), http.MethodHead, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		client.CloseIdleConnections()
		delay, measured := trace.responseDelayMS()
		if !measured || delay < 30 || delay > 150 || time.Since(start) < setup+30*time.Millisecond {
			t.Fatalf("incorrect timing boundary: setup=%s delay=%d measured=%t total=%s", setup, delay, measured, time.Since(start))
		}
	}
}

func TestResponseTimingIgnoresProxyHeadersBeforeConnectionReady(t *testing.T) {
	trace := &probeRequestTrace{}
	hooks := trace.hooks()
	hooks.GotFirstResponseByte()
	if _, measured := trace.responseDelayMS(); measured {
		t.Fatal("proxy setup headers entered origin response timing")
	}
	hooks.GotConn(httptrace.GotConnInfo{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(hooks.GotFirstResponseByte)
	}
	workers.Wait()
	delay, measured := trace.responseDelayMS()
	if !measured || delay < 1 {
		t.Fatal("valid response timing missing")
	}
	first := trace.responseNS.Load()
	hooks.GotFirstResponseByte()
	if trace.responseNS.Load() != first {
		t.Fatal("later response byte replaced the first byte")
	}
}

func TestObservedProxyRequestKeepsStatusAndTimeoutChecks(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusServiceUnavailable} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		trace := &probeRequestTrace{}
		_, err := requestThroughProxyObservedContext(t.Context(), server.URL, "http://probe.invalid/", http.MethodHead, time.Second, 0, http.StatusNoContent, trace)
		server.Close()
		if (err == nil) != (status == http.StatusNoContent) {
			t.Fatalf("timing changed HTTP validation: status=%d error=%v", status, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	trace := &probeRequestTrace{}
	_, err := requestThroughProxyObservedContext(t.Context(), server.URL, "http://probe.invalid/", http.MethodHead, 60*time.Millisecond, 0, http.StatusNoContent, trace)
	if err == nil || classifyProbeError(err) != probeFailureTimeout {
		t.Fatalf("timing changed timeout classification: %v", err)
	}
	if _, measured := trace.responseDelayMS(); measured {
		t.Fatal("timed-out request supplied a response delay")
	}
}

func TestFullRequestLatencySelectionKeepsConfiguredMarginAndConfirmations(t *testing.T) {
	for _, difference := range []int{199, 200, 201} {
		p := effectivePolicySettings{active: 60, improvement: 200}
		item := newPolicyHealthState()
		for round := range 2 {
			at := time.Unix(1000+int64(round)*60, 0)
			active, reserve := successfulEvidence(100+difference), successfulEvidence(100)
			activeResponse, reserveResponse := 10, 2000
			active.ResponseDelayMS, reserve.ResponseDelayMS = &activeResponse, &reserveResponse
			comparison := compareOptimization(at, "active", "reserve", map[string]probeEvidence{
				"active": active, "reserve": reserve,
			}, true, true, p)
			if comparison.ImprovementMS != 200 || comparison.Measurement != latencyMeasurement {
				t.Fatal("switch evidence does not identify the metric and applied threshold")
			}
			selected, _ := gatePlannedOptimization(at, "active", "reserve", "meaningfully-faster", comparison, item, p)
			want := "active"
			if difference > 200 && round == 1 {
				want = "reserve"
			}
			if selected != want {
				t.Fatalf("margin=%d round=%d selected=%s want=%s", difference, round, selected, want)
			}
		}
	}
}

func BenchmarkResponseTimingHooks(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		trace := &probeRequestTrace{}
		hooks := trace.hooks()
		hooks.GotConn(httptrace.GotConnInfo{})
		hooks.GotFirstResponseByte()
		trace.responseDelayMS()
	}
}
