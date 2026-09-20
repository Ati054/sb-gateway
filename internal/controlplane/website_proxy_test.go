package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func websiteConfig(t *testing.T, server *Server, rawURL string) {
	websiteConfigWithBandwidth(t, server, rawURL, nil)
}

func websiteConfigWithBandwidth(t *testing.T, server *Server, rawURL string, bandwidth *float64) {
	t.Helper()
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := testTransportByKind(t, config, "hysteria2")
	transport["enabled"] = true
	masquerade := map[string]any{"type": "website", "url": rawURL}
	if bandwidth != nil {
		masquerade["bandwidth_mbps"] = *bandwidth
	}
	transport["xray_hysteria"] = map[string]any{"quic_params": map[string]any{}, "masquerade": masquerade}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
}

func apiCoverConfig(t *testing.T, server *Server) {
	t.Helper()
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := testTransportByKind(t, config, "hysteria2")
	transport["enabled"] = true
	transport["xray_hysteria"] = map[string]any{"quic_params": map[string]any{}, "masquerade": map[string]any{"type": "api"}}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
}

func TestManagedAPICoverIsNeutralAndMethodSafe(t *testing.T) {
	server := newTestServer(t)
	apiCoverConfig(t, server)
	proxy := newWebsiteProxy(server.repository)

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		response := httptest.NewRecorder()
		proxy.serveHTTP(response, httptest.NewRequest(method, "http://127.0.0.1/private", nil))
		if response.Code != http.StatusNotFound || response.Header().Get("Content-Type") != "application/json" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s API cover response = %d %#v", method, response.Code, response.Header())
		}
		if method == http.MethodHead && response.Body.Len() != 0 {
			t.Fatalf("HEAD API cover leaked a body: %q", response.Body.String())
		}
		if method != http.MethodHead && (!strings.Contains(response.Body.String(), `"error":"not_found"`) || !strings.Contains(response.Body.String(), `"request_id":"`)) {
			t.Fatalf("%s API cover body = %q", method, response.Body.String())
		}
	}
	options := httptest.NewRecorder()
	proxy.serveHTTP(options, httptest.NewRequest(http.MethodOptions, "http://127.0.0.1/", nil))
	if options.Code != http.StatusNoContent || options.Body.Len() != 0 {
		t.Fatalf("OPTIONS API cover = %d %q", options.Code, options.Body.String())
	}
	rejectedRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", strings.NewReader("private"))
	rejectedRequest.Header.Set("Hysteria-Auth", "not-a-valid-key")
	rejected := httptest.NewRecorder()
	proxy.serveHTTP(rejected, rejectedRequest)
	if rejected.Code != http.StatusNotFound || rejected.Header().Get("Content-Type") != "application/json" || !strings.Contains(rejected.Body.String(), `"error":"not_found"`) {
		t.Fatalf("rejected API cover request = %d %#v %q", rejected.Code, rejected.Header(), rejected.Body.String())
	}
}

func TestWebsiteProxyUsesFixedAppliedTargetAndSanitizesHeaders(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		upstreamCalls.Add(1)
		if (request.URL.Path != "/cover/styles.css" && request.URL.Path != "/cover/") || request.URL.RawQuery != "" || request.Host != "example.com" {
			t.Errorf("target changed by client input: path=%q host=%q", request.URL.Path, request.Host)
		}
		for _, name := range []string{"Cookie", "Authorization", "Proxy-Authorization", "Hysteria-Auth"} {
			if request.Header.Get(name) != "" {
				t.Errorf("unsafe header forwarded: %s", name)
			}
		}
		if request.Header.Get("User-Agent") != "Mozilla/5.0" {
			t.Errorf("unexpected user agent %q", request.Header.Get("User-Agent"))
		}
		response.Header().Set("Content-Type", "text/css")
		response.Header().Set("Set-Cookie", "session=secret")
		response.Header().Set("WWW-Authenticate", "secret")
		response.Header().Set("Location", "https://elsewhere.invalid/")
		response.Header().Set("Alt-Svc", "h3=\":443\"")
		_, _ = response.Write([]byte("body{}"))
	}))
	defer upstream.Close()

	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/cover")
	proxy := newWebsiteProxy(server.repository)
	proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	proxy.tlsConfig = &tls.Config{RootCAs: pool}
	var firstDialFailed atomic.Bool
	proxy.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "8.8.8.8:443" {
			firstDialFailed.Store(true)
			return nil, errors.New("first verified address unavailable")
		}
		if address != "1.1.1.1:443" {
			t.Fatalf("unverified dial %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}

	request := httptest.NewRequest(http.MethodGet, "http://attacker.invalid/styles.css?private=input", nil)
	request.Host = "attacker.invalid"
	request.Header.Set("Cookie", "browser-secret")
	request.Header.Set("Authorization", "Bearer browser-secret")
	response := httptest.NewRecorder()
	proxy.serveHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "body{}" || upstreamCalls.Load() != 1 || !firstDialFailed.Load() {
		t.Fatalf("website response=%d %q calls=%d", response.Code, response.Body.String(), upstreamCalls.Load())
	}
	if response.Header().Get("Content-Length") != "6" {
		t.Fatalf("small response did not retain bounded content length: %q", response.Header().Get("Content-Length"))
	}
	for _, name := range []string{"Set-Cookie", "WWW-Authenticate", "Location", "Alt-Svc"} {
		if response.Header().Get(name) != "" {
			t.Fatalf("unsafe response header leaked: %s", name)
		}
	}
	rootResponse := httptest.NewRecorder()
	proxy.serveHTTP(rootResponse, httptest.NewRequest(http.MethodGet, "http://attacker.invalid/", nil))
	if rootResponse.Code != http.StatusOK || upstreamCalls.Load() != 2 {
		t.Fatalf("trailing root path was not preserved: response=%d calls=%d", rootResponse.Code, upstreamCalls.Load())
	}
}

func TestWebsiteProxyRejectsNonGETAndHysteriaAuthBeforeFetch(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	proxy := newWebsiteProxy(server.repository)
	var lookups atomic.Int32
	proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, nil
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "http://127.0.0.1/", strings.NewReader("blocked")),
		httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil),
	} {
		if request.Method == http.MethodGet {
			request.Header.Set("Hysteria-Auth", "blocked")
		}
		response := httptest.NewRecorder()
		proxy.serveHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d", request.Method, response.Code)
		}
	}
	if lookups.Load() != 0 {
		t.Fatalf("blocked requests reached resolver: %d", lookups.Load())
	}
}

func TestWebsiteProxyFailsClosedForUnsafeResolvedAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "240.0.0.1", "::1", "fc00::1", "64:ff9b::808:808", "2002::1", "4000::1", "::ffff:8.8.8.8"} {
		if safeWebsiteAddress(netip.MustParseAddr(address)) {
			t.Fatalf("unsafe address accepted: %s", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if !safeWebsiteAddress(netip.MustParseAddr(address)) {
			t.Fatalf("public address rejected: %s", address)
		}
	}
}

func TestWebsiteProxyRejectsMixedDNSAndWrongTLS(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	proxy := newWebsiteProxy(server.repository)
	var dials atomic.Int32
	proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	proxy.dialContext = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, nil
	}
	response := httptest.NewRecorder()
	proxy.serveHTTP(response, httptest.NewRequest(http.MethodGet, "http://local/", nil))
	if response.Code != http.StatusBadGateway || dials.Load() != 0 {
		t.Fatalf("mixed DNS was not rejected before dialing: %d dials=%d", response.Code, dials.Load())
	}

	wrongTLS := httptest.NewTLSServer(http.NotFoundHandler())
	defer wrongTLS.Close()
	proxy = newWebsiteProxy(server.repository)
	proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	proxy.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, wrongTLS.Listener.Addr().String())
	}
	response = httptest.NewRecorder()
	proxy.serveHTTP(response, httptest.NewRequest(http.MethodGet, "http://local/", nil))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("untrusted TLS was accepted: %d", response.Code)
	}
}

func TestWebsiteProxyDropsCacheOnActiveDisableAndHandlesPressure(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	proxy := newWebsiteProxy(server.repository)
	if _, available := proxy.currentTarget(); !available {
		t.Fatal("initial active target unavailable")
	}
	initialRevision, err := server.repository.activeRevision()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(server.repository.root, "active.json")); err != nil {
		t.Fatal(err)
	}
	if _, available := proxy.currentTarget(); available {
		t.Fatal("missing active pointer retained a cached target")
	}
	if err := server.repository.setActiveRevision(initialRevision); err != nil {
		t.Fatal(err)
	}
	active, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := testTransportByKind(t, active, "hysteria2")
	transport["enabled"] = false
	revision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	if _, available := proxy.currentTarget(); available {
		t.Fatal("disabled active target retained from cache")
	}
	for range websiteProxyMaxConcurrent {
		proxy.active <- struct{}{}
	}
	proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		t.Fatal("pressure request resolved DNS")
		return nil, nil
	}
	response := httptest.NewRecorder()
	proxy.serveHTTP(response, httptest.NewRequest(http.MethodGet, "http://local/", nil))
	for range websiteProxyMaxConcurrent {
		<-proxy.active
	}
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("full helper did not reject request: %d", response.Code)
	}
}

func TestWebsiteProxyBoundsResponseAndDoesNotFollowRedirect(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus int
	}{
		{
			name: "body limit",
			handler: func(response http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(response, strings.Repeat("x", websiteProxyMaxBody+1))
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "header limit",
			handler: func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("X-Too-Large", strings.Repeat("x", websiteProxyMaxHeaders+1))
				_, _ = response.Write([]byte("unreachable"))
			},
			wantStatus: http.StatusBadGateway,
		},
		{
			name: "redirect is not followed",
			handler: func(response http.ResponseWriter, _ *http.Request) {
				response.Header().Set("Location", "https://redirected.invalid/")
				response.WriteHeader(http.StatusFound)
			},
			wantStatus: http.StatusFound,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(scenario.handler)
			defer upstream.Close()
			server := newTestServer(t)
			fastBandwidth := 100.0
			websiteConfigWithBandwidth(t, server, "https://example.com/", &fastBandwidth)
			proxy := newWebsiteProxy(server.repository)
			proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			pool := x509.NewCertPool()
			pool.AddCert(upstream.Certificate())
			proxy.tlsConfig = &tls.Config{RootCAs: pool}
			proxy.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "8.8.8.8:443" {
					t.Fatalf("unverified dial %q", address)
				}
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			}
			response := httptest.NewRecorder()
			proxy.serveHTTP(response, httptest.NewRequest(http.MethodGet, "http://local/", nil))
			if response.Code != scenario.wantStatus {
				t.Fatalf("response=%d want=%d", response.Code, scenario.wantStatus)
			}
			if response.Header().Get("Location") != "" {
				t.Fatal("redirect location leaked to client")
			}
		})
	}
}

func TestWebsiteProxyTokenBucketBurstAndRefill(t *testing.T) {
	proxy := newWebsiteProxy(nil)
	now := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	proxy.now = func() time.Time { return now }
	for range websiteProxyBurst {
		if !proxy.allowRequest() {
			t.Fatal("initial burst was restricted before its limit")
		}
	}
	if proxy.allowRequest() {
		t.Fatal("request beyond burst limit was accepted")
	}
	now = now.Add(250 * time.Millisecond)
	if !proxy.allowRequest() || proxy.allowRequest() {
		t.Fatal("one rate token was not refilled deterministically")
	}
	now = now.Add(10 * time.Second)
	for range websiteProxyBurst {
		if !proxy.allowRequest() {
			t.Fatal("refilled burst was restricted before its limit")
		}
	}
	if proxy.allowRequest() {
		t.Fatal("refilled bucket exceeded its burst limit")
	}
}

func TestWebsitePayloadLimitIsSharedAcrossConcurrentRequests(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, strings.Repeat("x", websitePayloadChunk))
	}))
	defer upstream.Close()
	server := newTestServer(t)
	slowBandwidth := 0.1
	websiteConfigWithBandwidth(t, server, "https://example.com/", &slowBandwidth)
	proxy := newWebsiteProxy(server.repository)
	proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	proxy.tlsConfig = &tls.Config{RootCAs: pool}
	proxy.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}

	started := time.Now()
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			response := httptest.NewRecorder()
			proxy.serveHTTP(response, httptest.NewRequest(http.MethodGet, "http://local/", nil))
			responses <- response
		}()
	}
	for range 2 {
		response := <-responses
		if response.Code != http.StatusOK || response.Body.Len() != websitePayloadChunk {
			t.Fatalf("limited response=%d bytes=%d", response.Code, response.Body.Len())
		}
	}
	if elapsed := time.Since(started); elapsed < 500*time.Millisecond {
		t.Fatalf("concurrent requests did not share one payload budget: %s", elapsed)
	}
}

func TestWebsitePayloadLimiterBurstRefillAndCancellation(t *testing.T) {
	limiter := newWebsitePayloadLimiter(time.Now)
	limiter.mu.Lock()
	limiter.rateBytesPerSecond = 100
	limiter.tokens = 8
	limiter.last = time.Now()
	limiter.mu.Unlock()
	withTokens, cancelWithTokens := context.WithCancel(context.Background())
	cancelWithTokens()
	if err := limiter.take(withTokens, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled payload with tokens returned %v", err)
	}
	limiter.mu.Lock()
	remaining := limiter.tokens
	limiter.mu.Unlock()
	if remaining != 8 {
		t.Fatalf("cancelled payload request spent a token: %v", remaining)
	}
	if err := limiter.take(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	refillContext, cancelRefill := context.WithTimeout(context.Background(), time.Second)
	defer cancelRefill()
	if err := limiter.take(refillContext, 8); err != nil {
		t.Fatalf("payload bucket did not refill: %v", err)
	}
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if err := limiter.take(cancelledContext, websitePayloadChunk); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled payload wait returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled payload wait lasted %s", elapsed)
	}
}

func TestWebsitePayloadRateUsesOnlyActiveConfig(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	proxy := newWebsiteProxy(server.repository)
	if target, available := proxy.currentTarget(); !available || target.bandwidthMbps != websiteBandwidthDefault {
		t.Fatalf("legacy website bandwidth=%#v available=%v", target, available)
	}
	fixedNow := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	proxy.payload.mu.Lock()
	proxy.payload.now = func() time.Time { return fixedNow }
	proxy.payload.tokens = 1
	proxy.payload.last = fixedNow
	proxy.payload.mu.Unlock()
	active, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	draft := cloneJSONObject(active)
	draftHysteria, _ := testTransportByKind(t, draft, "hysteria2")
	nestedObject(draftHysteria, "xray_hysteria", "masquerade")["bandwidth_mbps"] = 3.5
	if _, err := server.repository.saveDraft(draft); err != nil {
		t.Fatal(err)
	}
	if target, available := proxy.currentTarget(); !available || target.bandwidthMbps != websiteBandwidthDefault {
		t.Fatalf("draft bandwidth affected helper: %#v available=%v", target, available)
	}
	updated := cloneJSONObject(active)
	updatedHysteria, _ := testTransportByKind(t, updated, "hysteria2")
	nestedObject(updatedHysteria, "xray_hysteria", "masquerade")["bandwidth_mbps"] = 2.5
	revision, err := server.repository.stageGeneration(updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	if target, available := proxy.currentTarget(); !available || target.bandwidthMbps != 2.5 {
		t.Fatalf("active bandwidth was not applied: %#v available=%v", target, available)
	}
	proxy.payload.mu.Lock()
	rate, tokens := proxy.payload.rateBytesPerSecond, proxy.payload.tokens
	proxy.payload.mu.Unlock()
	if rate != websiteBandwidthBytesPerSecond(2.5) || tokens >= websitePayloadBurst {
		t.Fatalf("active rate=%v tokens=%v reset shared payload bucket", rate, tokens)
	}
}

func TestWebsitePayloadRateUpdateDoesNotPublishStaleRevision(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	proxy := newWebsiteProxy(server.repository)
	loadGeneration := proxy.loadGeneration
	started, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	proxy.loadGeneration = func(revision string) (map[string]any, error) {
		first.Do(func() {
			close(started)
			<-release
		})
		return loadGeneration(revision)
	}
	type targetResult struct {
		target    websiteTarget
		available bool
	}
	result := make(chan targetResult, 1)
	go func() {
		target, available := proxy.currentTarget()
		result <- targetResult{target: target, available: available}
	}()
	<-started
	updated, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	updatedHysteria, _ := testTransportByKind(t, updated, "hysteria2")
	nestedObject(updatedHysteria, "xray_hysteria", "masquerade")["bandwidth_mbps"] = 4.0
	revision, err := server.repository.stageGeneration(updated)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	close(release)
	updatedTarget := <-result
	if !updatedTarget.available || updatedTarget.target.bandwidthMbps != 4 {
		t.Fatalf("stale target published after revision update: %#v available=%v", updatedTarget.target, updatedTarget.available)
	}
	proxy.payload.mu.Lock()
	rate := proxy.payload.rateBytesPerSecond
	proxy.payload.mu.Unlock()
	if rate != websiteBandwidthBytesPerSecond(4) {
		t.Fatalf("stale payload rate after revision update: %v", rate)
	}
}

func TestWebsiteTargetFailsClosedWhenActivePointerDisappearsDuringLoad(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	proxy := newWebsiteProxy(server.repository)
	loadGeneration := proxy.loadGeneration
	started, release := make(chan struct{}), make(chan struct{})
	proxy.loadGeneration = func(revision string) (map[string]any, error) {
		close(started)
		<-release
		return loadGeneration(revision)
	}
	result := make(chan bool, 1)
	go func() {
		_, available := proxy.currentTarget()
		result <- available
	}()
	<-started
	if err := os.Remove(filepath.Join(server.repository.root, "active.json")); err != nil {
		t.Fatal(err)
	}
	close(release)
	if available := <-result; available {
		t.Fatal("target survived a missing active pointer during cache update")
	}
}

type websiteAbortWriter struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
	short  bool
	writes int
}

func (writer *websiteAbortWriter) Write(body []byte) (int, error) {
	writer.writes++
	if writer.short {
		return len(body) - 1, nil
	}
	if writer.writes == 1 {
		writer.cancel()
	}
	return writer.ResponseRecorder.Write(body)
}

func TestWebsiteProxyAbortsIncompleteOutput(t *testing.T) {
	for _, scenario := range []struct {
		name  string
		short bool
	}{
		{name: "cancelled after first chunk"},
		{name: "short write", short: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(response, strings.Repeat("x", websitePayloadChunk*2))
			}))
			defer upstream.Close()
			server := newTestServer(t)
			fastBandwidth := 100.0
			websiteConfigWithBandwidth(t, server, "https://example.com/", &fastBandwidth)
			proxy := newWebsiteProxy(server.repository)
			proxy.lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}
			pool := x509.NewCertPool()
			pool.AddCert(upstream.Certificate())
			proxy.tlsConfig = &tls.Config{RootCAs: pool}
			proxy.dialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			}
			ctx, cancel := context.WithCancel(context.Background())
			writer := &websiteAbortWriter{ResponseRecorder: httptest.NewRecorder(), cancel: cancel, short: scenario.short}
			defer cancel()
			defer func() {
				if recovered := recover(); recovered != http.ErrAbortHandler {
					t.Fatalf("incomplete response did not abort handler: %#v", recovered)
				}
			}()
			proxy.serveHTTP(writer, httptest.NewRequest(http.MethodGet, "http://local/", nil).WithContext(ctx))
		})
	}
}

func TestWebsiteProxyListenerStartAndShutdown(t *testing.T) {
	server := newTestServer(t)
	_, websiteServer, listener, err := startWebsiteProxy(server.repository)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- websiteServer.Serve(listener) }()
	shutdownContext, cancel := context.WithCancel(context.Background())
	cancel()
	if err := websiteServer.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if err := websiteServer.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("website listener did not exit cleanly: %v", err)
	}
}

func TestWebsiteProxyHonorsRequestCancellation(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	proxy := newWebsiteProxy(server.repository)
	var cancelled atomic.Bool
	proxy.lookupNetIP = func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		cancelled.Store(true)
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, "http://local/", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	proxy.serveHTTP(response, request)
	if response.Code != http.StatusBadGateway || !cancelled.Load() {
		t.Fatalf("cancelled request was not stopped: response=%d cancelled=%v", response.Code, cancelled.Load())
	}
}

func TestWebsiteProxyUsesOnlyActiveGenerationAndManagementMuxDoesNotServeIt(t *testing.T) {
	server := newTestServer(t)
	websiteConfig(t, server, "https://example.com/")
	draft, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	draftHysteria, _ := testTransportByKind(t, draft, "hysteria2")
	draftHysteria["xray_hysteria"] = map[string]any{"quic_params": map[string]any{}, "masquerade": map[string]any{"type": "website", "url": "https://draft.invalid/"}}
	if _, err = server.repository.saveDraft(draft); err != nil {
		t.Fatal(err)
	}
	proxy := newWebsiteProxy(server.repository)
	target, available := proxy.currentTarget()
	if !available || target.host != "example.com" {
		t.Fatalf("draft target leaked into helper: %#v %v", target, available)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("management mux unexpectedly served website helper: %d", response.Code)
	}
}

func TestWebsiteURLValidationAndSingleHysteriaBoundary(t *testing.T) {
	for _, raw := range []string{"https://example.com/", "https://example.com/base"} {
		if !validWebsiteMasqueradeURL(raw) {
			t.Fatalf("valid website URL rejected: %q", raw)
		}
	}
	for _, raw := range []string{"", "http://example.com/", "https://127.0.0.1/", "https://example.com:444/", "https://user@example.com/", "https://example.com/?x=1", "https://example.com/#fragment"} {
		if validWebsiteMasqueradeURL(raw) {
			t.Fatalf("unsafe website URL accepted: %q", raw)
		}
	}
	for _, scenario := range []struct {
		value any
		valid bool
		want  float64
	}{
		{value: nil, valid: true, want: websiteBandwidthDefault},
		{value: 2.5, valid: true, want: 2.5},
		{value: 0.1, valid: true, want: 0.1},
		{value: 100.0, valid: true, want: 100},
		{value: 0.0}, {value: 100.1}, {value: "1"}, {value: math.NaN()}, {value: math.Inf(1)},
	} {
		actual, valid := websiteBandwidthMbps(scenario.value)
		if valid != scenario.valid || (valid && actual != scenario.want) {
			t.Fatalf("bandwidth %#v = %v,%v", scenario.value, actual, valid)
		}
	}
	server := newTestServer(t)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	hysteria, hysteriaIndex := testTransportByKind(t, config, "hysteria2")
	hysteria["enabled"] = true
	hysteria["xray_hysteria"] = map[string]any{"quic_params": map[string]any{}, "masquerade": map[string]any{"type": "website", "url": "https://example.com/"}}
	duplicate := cloneJSONObject(hysteria)
	duplicate["id"] = "hysteria-duplicate"
	duplicate["listen_port"] = 4443
	config["transports"] = append(config["transports"].([]any), duplicate)
	if result := validateCurrentConfig(config); !hasValidationPath(result.Errors, fmt.Sprintf("transports[%d].xray_hysteria.masquerade.type", hysteriaIndex)) {
		t.Fatalf("website with ambiguous Hysteria renderer accepted: %#v", result.Errors)
	}
	config["transports"] = config["transports"].([]any)[:len(config["transports"].([]any))-1]
	hysteria["xray_hysteria"] = map[string]any{"quic_params": map[string]any{}, "masquerade": map[string]any{"type": "website", "url": "https://example.com/", "bandwidth_mbps": 0}}
	if result := validateCurrentConfig(config); !hasValidationPath(result.Errors, fmt.Sprintf("transports[%d].xray_hysteria.masquerade.bandwidth_mbps", hysteriaIndex)) {
		t.Fatalf("invalid website bandwidth accepted: %#v", result.Errors)
	}
}
