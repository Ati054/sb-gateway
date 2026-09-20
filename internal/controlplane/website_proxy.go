package controlplane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

const (
	websiteProxyAddress       = "127.0.0.1:18081"
	websiteProxyRate          = 4
	websiteProxyBurst         = 8
	websiteProxyMaxConcurrent = 4
	websiteProxyTimeout       = 15 * time.Second
	websiteProxyMaxBody       = 2 << 20
	websiteProxyMaxHeaders    = 32 << 10
	websitePayloadChunk       = 4 << 10
	websitePayloadBurst       = 8 << 10
	websiteBandwidthDefault   = 1.0
	websiteBandwidthMinimum   = 0.1
	websiteBandwidthMaximum   = 100.0
)

type websiteTarget struct {
	url           *url.URL
	host          string
	bandwidthMbps float64
	mode          string
}

type websitePayloadLimiter struct {
	mu                 sync.Mutex
	rateBytesPerSecond float64
	tokens             float64
	last               time.Time
	now                func() time.Time
}

func newWebsitePayloadLimiter(now func() time.Time) *websitePayloadLimiter {
	return &websitePayloadLimiter{
		rateBytesPerSecond: websiteBandwidthBytesPerSecond(websiteBandwidthDefault),
		tokens:             websitePayloadBurst,
		now:                now,
	}
}

func websiteBandwidthBytesPerSecond(mbps float64) float64 {
	return mbps * 1_000_000 / 8
}

func (limiter *websitePayloadLimiter) refillLocked(now time.Time) {
	if limiter.last.IsZero() {
		limiter.last = now
		return
	}
	if elapsed := now.Sub(limiter.last); elapsed > 0 {
		limiter.tokens = min(float64(websitePayloadBurst), limiter.tokens+elapsed.Seconds()*limiter.rateBytesPerSecond)
		limiter.last = now
	}
}

func (limiter *websitePayloadLimiter) configure(mbps float64) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.refillLocked(limiter.now())
	limiter.rateBytesPerSecond = websiteBandwidthBytesPerSecond(mbps)
	limiter.tokens = min(limiter.tokens, float64(websitePayloadBurst))
}

func (limiter *websitePayloadLimiter) take(ctx context.Context, count int) error {
	if count <= 0 {
		return nil
	}
	wanted := float64(count)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		limiter.mu.Lock()
		if err := ctx.Err(); err != nil {
			limiter.mu.Unlock()
			return err
		}
		limiter.refillLocked(limiter.now())
		if limiter.tokens >= wanted {
			limiter.tokens -= wanted
			limiter.mu.Unlock()
			return nil
		}
		wait := time.Duration((wanted - limiter.tokens) / limiter.rateBytesPerSecond * float64(time.Second))
		limiter.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (limiter *websitePayloadLimiter) refund(count int) {
	if count <= 0 {
		return
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.refillLocked(limiter.now())
	limiter.tokens = min(float64(websitePayloadBurst), limiter.tokens+float64(count))
}

type websiteProxy struct {
	repository *stateRepository

	lookupNetIP    func(context.Context, string, string) ([]netip.Addr, error)
	dialContext    func(context.Context, string, string) (net.Conn, error)
	loadGeneration func(string) (map[string]any, error)
	tlsConfig      *tls.Config
	now            func() time.Time

	mu        sync.Mutex
	revision  string
	target    websiteTarget
	available bool
	tokens    float64
	last      time.Time
	active    chan struct{}
	payload   *websitePayloadLimiter
}

func newWebsiteProxy(repository *stateRepository) *websiteProxy {
	proxy := &websiteProxy{
		repository:     repository,
		lookupNetIP:    net.DefaultResolver.LookupNetIP,
		dialContext:    (&net.Dialer{Timeout: websiteProxyTimeout}).DialContext,
		loadGeneration: repository.loadGeneration,
		now:            time.Now,
		tokens:         websiteProxyBurst,
		active:         make(chan struct{}, websiteProxyMaxConcurrent),
	}
	proxy.payload = newWebsitePayloadLimiter(proxy.now)
	return proxy
}

func startWebsiteProxy(repository *stateRepository) (*websiteProxy, *http.Server, net.Listener, error) {
	listener, err := net.Listen("tcp4", websiteProxyAddress)
	if err != nil {
		return nil, nil, nil, err
	}
	proxy := newWebsiteProxy(repository)
	server := &http.Server{
		Handler:           http.HandlerFunc(proxy.serveHTTP),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       websiteProxyTimeout,
		WriteTimeout:      websiteProxyTimeout,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    websiteProxyMaxHeaders,
	}
	return proxy, server, netutil.LimitListener(listener, 32), nil
}

func validWebsiteMasqueradeURL(raw string) bool {
	_, ok := parseWebsiteTarget(raw)
	return ok
}

func parseWebsiteTarget(raw string) (websiteTarget, bool) {
	if strings.TrimSpace(raw) != raw || len(raw) == 0 || len(raw) > 2048 || strings.ContainsAny(raw, "?#") {
		return websiteTarget{}, false
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return websiteTarget{}, false
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return websiteTarget{}, false
	}
	host := strings.ToLower(parsed.Hostname())
	if net.ParseIP(host) != nil || !validReverseExportHostname(host) || strings.EqualFold(host, "localhost") {
		return websiteTarget{}, false
	}
	parsed.Host = host
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	return websiteTarget{url: parsed, host: host, bandwidthMbps: websiteBandwidthDefault, mode: "website"}, true
}

func websiteBandwidthMbps(value any) (float64, bool) {
	if value == nil {
		return websiteBandwidthDefault, true
	}
	var number float64
	switch typed := value.(type) {
	case float64:
		number = typed
	case float32:
		number = float64(typed)
	case int:
		number = float64(typed)
	case int64:
		number = float64(typed)
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		number = parsed
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number < websiteBandwidthMinimum || number > websiteBandwidthMaximum {
		return 0, false
	}
	return number, true
}

func websiteTargetForConfig(config map[string]any) (websiteTarget, bool) {
	var hysteria map[string]any
	count := 0
	transports, _ := config["transports"].([]any)
	for _, raw := range transports {
		transport, _ := raw.(map[string]any)
		if text(transport["kind"]) != "hysteria2" || transport["enabled"] == false {
			continue
		}
		count++
		hysteria = transport
	}
	if count != 1 {
		return websiteTarget{}, false
	}
	masquerade := nestedObject(hysteria, "xray_hysteria", "masquerade")
	if text(masquerade["type"]) == "api" {
		return websiteTarget{mode: "api"}, true
	}
	if text(masquerade["type"]) != "website" {
		return websiteTarget{}, false
	}
	target, valid := parseWebsiteTarget(text(masquerade["url"]))
	if !valid {
		return websiteTarget{}, false
	}
	bandwidth, valid := websiteBandwidthMbps(masquerade["bandwidth_mbps"])
	if !valid {
		return websiteTarget{}, false
	}
	target.bandwidthMbps = bandwidth
	return target, true
}

func (proxy *websiteProxy) currentTarget() (websiteTarget, bool) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	for attempt := 0; attempt < 3; attempt++ {
		revision, err := proxy.repository.activeRevision()
		if err != nil || revision == "" {
			return websiteTarget{}, false
		}
		if proxy.revision == revision {
			return proxy.target, proxy.available
		}
		config, err := proxy.loadGeneration(revision)
		if err != nil {
			return websiteTarget{}, false
		}
		publishedRevision, err := proxy.repository.activeRevision()
		if err != nil || publishedRevision == "" {
			return websiteTarget{}, false
		}
		if publishedRevision != revision {
			continue
		}
		target, available := websiteTargetForConfig(config)
		proxy.revision, proxy.target, proxy.available = revision, target, available
		if available && target.mode == "website" {
			proxy.payload.configure(target.bandwidthMbps)
		}
		return target, available
	}
	return websiteTarget{}, false
}

func (proxy *websiteProxy) allowRequest() bool {
	now := proxy.now()
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.last.IsZero() {
		proxy.last = now
	} else if elapsed := now.Sub(proxy.last); elapsed > 0 {
		proxy.tokens = min(float64(websiteProxyBurst), proxy.tokens+elapsed.Seconds()*websiteProxyRate)
		proxy.last = now
	}
	if proxy.tokens < 1 {
		return false
	}
	proxy.tokens--
	return true
}

func (proxy *websiteProxy) serveHTTP(response http.ResponseWriter, request *http.Request) {
	rejected := request.ContentLength > 0 || len(request.TransferEncoding) != 0 || request.Header.Get("Hysteria-Auth") != "" || request.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade")
	if rejected {
		if target, available := proxy.currentTarget(); available && target.mode == "api" {
			serveManagedAPICover(response, request, http.StatusNotFound, "not_found")
		} else {
			http.Error(response, "Not found", http.StatusNotFound)
		}
		return
	}
	if !proxy.allowRequest() {
		if target, available := proxy.currentTarget(); available && target.mode == "api" {
			serveManagedAPICover(response, request, http.StatusTooManyRequests, "rate_limited")
		} else {
			http.Error(response, "Not found", http.StatusTooManyRequests)
		}
		return
	}
	select {
	case proxy.active <- struct{}{}:
		defer func() { <-proxy.active }()
	default:
		if target, available := proxy.currentTarget(); available && target.mode == "api" {
			serveManagedAPICover(response, request, http.StatusTooManyRequests, "rate_limited")
		} else {
			http.Error(response, "Not found", http.StatusTooManyRequests)
		}
		return
	}
	target, available := proxy.currentTarget()
	if !available {
		http.Error(response, "Not found", http.StatusNotFound)
		return
	}
	if target.mode == "api" {
		serveManagedAPICover(response, request, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(response, "Not found", http.StatusNotFound)
		return
	}
	if err := proxy.fetch(response, request, target); err != nil {
		if errors.Is(err, errWebsiteResponseAborted) {
			panic(http.ErrAbortHandler)
		}
		http.Error(response, "Not found", http.StatusBadGateway)
	}
}

func serveManagedAPICover(response http.ResponseWriter, request *http.Request, status int, code string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method == http.MethodOptions {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	identifier := make([]byte, 12)
	if _, err := rand.Read(identifier); err != nil {
		identifier = []byte(strconv.FormatInt(time.Now().UnixNano(), 16))
	}
	body, _ := json.Marshal(map[string]string{"error": code, "request_id": hex.EncodeToString(identifier)})
	response.WriteHeader(status)
	if request.Method != http.MethodHead {
		_, _ = response.Write(append(body, '\n'))
	}
}

var errWebsiteResponseAborted = errors.New("website response aborted")

func (proxy *websiteProxy) fetch(response http.ResponseWriter, incoming *http.Request, target websiteTarget) error {
	fetchContext, cancel := context.WithTimeout(incoming.Context(), websiteProxyTimeout)
	defer cancel()
	addresses, err := proxy.lookupNetIP(fetchContext, "ip", target.host)
	if err != nil || len(addresses) == 0 {
		return errors.New("website DNS lookup failed")
	}
	allowed := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if !safeWebsiteAddress(address) {
			return errors.New("website DNS lookup returned an unsafe address")
		}
		allowed = append(allowed, address)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.host}
	if proxy.tlsConfig != nil {
		tlsConfig = proxy.tlsConfig.Clone()
		tlsConfig.ServerName = target.host
		tlsConfig.InsecureSkipVerify = false
	}
	transport := &http.Transport{
		Proxy:                  nil,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: websiteProxyMaxHeaders,
		TLSClientConfig:        tlsConfig,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil || port != "443" || !strings.EqualFold(host, target.host) {
				return nil, errors.New("website proxy refused an unexpected dial")
			}
			var lastErr error
			for _, ip := range allowed {
				attempt, attemptCancel := context.WithTimeout(ctx, 3*time.Second)
				connection, dialErr := proxy.dialContext(attempt, network, net.JoinHostPort(ip.String(), port))
				attemptCancel()
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			if lastErr == nil {
				lastErr = errors.New("website proxy has no verified address")
			}
			return nil, lastErr
		},
	}
	defer transport.CloseIdleConnections()
	upstreamURL := *target.url
	requestedPath := pathpkg.Clean("/" + strings.TrimPrefix(incoming.URL.Path, "/"))
	basePath := pathpkg.Clean("/" + strings.TrimPrefix(target.url.Path, "/"))
	upstreamURL.Path = pathpkg.Join(basePath, requestedPath)
	if strings.HasSuffix(incoming.URL.Path, "/") && !strings.HasSuffix(upstreamURL.Path, "/") {
		upstreamURL.Path += "/"
	}
	upstreamURL.RawPath = ""
	upstreamURL.RawQuery = ""
	request, err := http.NewRequestWithContext(fetchContext, incoming.Method, upstreamURL.String(), nil)
	if err != nil {
		return errors.New("website request construction failed")
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml")
	request.Header.Set("Accept-Language", "ru,en;q=0.8")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	upstream, err := client.Do(request)
	if err != nil {
		return errors.New("website request failed")
	}
	defer upstream.Body.Close()
	body, err := proxy.readBody(fetchContext, upstream.Body)
	if err != nil {
		return err
	}
	for _, name := range []string{"Content-Type", "Cache-Control", "Content-Language", "Last-Modified"} {
		if value := upstream.Header.Get(name); value != "" {
			response.Header().Set(name, value)
		}
	}
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Content-Length", strconv.Itoa(len(body)))
	response.WriteHeader(upstream.StatusCode)
	if incoming.Method != http.MethodHead {
		for len(body) > 0 {
			chunkSize := min(len(body), websitePayloadChunk)
			if err := proxy.payload.take(fetchContext, chunkSize); err != nil {
				return errWebsiteResponseAborted
			}
			written, err := response.Write(body[:chunkSize])
			if err != nil || written != chunkSize {
				return errWebsiteResponseAborted
			}
			body = body[chunkSize:]
		}
	}
	return nil
}

func (proxy *websiteProxy) readBody(ctx context.Context, body io.Reader) ([]byte, error) {
	var result bytes.Buffer
	chunk := make([]byte, websitePayloadChunk)
	for {
		if err := proxy.payload.take(ctx, len(chunk)); err != nil {
			return nil, err
		}
		count, err := body.Read(chunk)
		proxy.payload.refund(len(chunk) - count)
		if count > 0 {
			if result.Len()+count > websiteProxyMaxBody {
				return nil, errors.New("website response body exceeds limit")
			}
			_, _ = result.Write(chunk[:count])
		}
		if err == io.EOF {
			return result.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func safeWebsiteAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Is4In6() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, prefix := range websiteBlockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var websiteBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}
