package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestControlPlaneWriteTimeoutCoversBoundedOperations(t *testing.T) {
	for name, timeout := range map[string]time.Duration{
		"apply":                applyResponseTimeout,
		"lifecycle image":      lifecycleImageUpdateResponseTimeout,
		"subscription refresh": subscriptionRefreshResponseTimeout,
	} {
		if controlPlaneWriteTimeout <= timeout {
			t.Fatalf("control-plane write timeout %s does not cover %s response timeout %s", controlPlaneWriteTimeout, name, timeout)
		}
	}
}

func TestControlPlaneReadTimeoutCoversStreamingUploads(t *testing.T) {
	if controlPlaneReadTimeout < 10*time.Minute {
		t.Fatalf("control-plane read timeout %s is too short for a streamed appliance archive", controlPlaneReadTimeout)
	}
}

func TestBootstrapSessionAndLogout(t *testing.T) {
	server := newTestServer(t)
	now := time.Unix(1_700_000_000, 0)
	server.now = func() time.Time { return now }

	session := performRequest(t, server, http.MethodGet, apiPrefix+"/auth/session", nil, nil)
	if session.Code != http.StatusOK || !decodeResponse(t, session)["bootstrap_required"].(bool) {
		t.Fatalf("unexpected initial session: %d %s", session.Code, session.Body.String())
	}

	bootstrap := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/bootstrap", map[string]any{
		"username": "admin", "password": "panel-password-123", "password_confirmation": "panel-password-123",
	}, map[string]string{"Authorization": "Bearer management-test-token"})
	if bootstrap.Code != http.StatusOK {
		t.Fatalf("bootstrap failed: %d %s", bootstrap.Code, bootstrap.Body.String())
	}
	bootstrapBody := decodeResponse(t, bootstrap)
	csrf := bootstrapBody["csrf_token"].(string)
	cookies := bootstrap.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || cookies[0].Value == "" {
		t.Fatalf("session cookie missing: %#v", cookies)
	}
	for _, reference := range []string{recoveryMasterKeyRef, recoveryKeyWrapRef, recoveryBackupPwdRef} {
		if !server.secrets.exists(reference) {
			t.Fatalf("bootstrap did not provision %s", reference)
		}
	}

	authenticated := performRequest(t, server, http.MethodGet, apiPrefix+"/auth/session", nil, nil, cookies[0])
	if !decodeResponse(t, authenticated)["authenticated"].(bool) {
		t.Fatal("issued session was not accepted")
	}

	withoutCSRF := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/logout", map[string]any{}, nil, cookies[0])
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("logout accepted without CSRF: %d", withoutCSRF.Code)
	}
	logout := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/logout", map[string]any{}, map[string]string{csrfHeader: csrf}, cookies[0])
	if logout.Code != http.StatusOK || decodeResponse(t, logout)["authenticated"].(bool) {
		t.Fatalf("logout failed: %d %s", logout.Code, logout.Body.String())
	}
}

func TestLoginRateLimitAndSecurityHeaders(t *testing.T) {
	server := newTestServer(t)
	hash, err := makePasswordHash("panel-password-123", []byte("0123456789abcdef"))
	if err != nil || server.secrets.write("admin-password-hash", hash, false) != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		response := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
			"username": "admin", "password": "wrong-password",
		}, nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected failed login response: %d", response.Code)
		}
	}
	blocked := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "panel-password-123",
	}, nil)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("login guard failed: %d", blocked.Code)
	}
	if blocked.Header().Get("Cache-Control") != "no-store" || blocked.Header().Get("X-Frame-Options") != "DENY" || blocked.Header().Get("X-Request-ID") == "" {
		t.Fatalf("security headers missing: %#v", blocked.Header())
	}
}

func TestNativeLoginFormRedirectsAndIssuesSession(t *testing.T) {
	server := newTestServer(t)
	hash, err := makePasswordHash("panel-password-123", []byte("0123456789abcdef"))
	if err != nil || server.secrets.write("admin-password-hash", hash, false) != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"username": {"admin"},
		"password": {"panel-password-123"},
	}
	request := httptest.NewRequest(http.MethodPost, apiPrefix+"/auth/login-form", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "192.0.2.10:12345"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("native login returned %d: %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); location != "/#/overview" {
		t.Fatalf("unexpected native login redirect: %q", location)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || cookies[0].Value == "" {
		t.Fatalf("session cookie missing: %#v", cookies)
	}
	authenticated := performRequest(t, server, http.MethodGet, apiPrefix+"/auth/session", nil, nil, cookies[0])
	if !decodeResponse(t, authenticated)["authenticated"].(bool) {
		t.Fatal("native login session was not accepted")
	}
}

func TestNativeLoginFormReturnsSafeFailureRedirect(t *testing.T) {
	server := newTestServer(t)
	hash, err := makePasswordHash("panel-password-123", []byte("0123456789abcdef"))
	if err != nil || server.secrets.write("admin-password-hash", hash, false) != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"username": {"admin"},
		"password": {"wrong-password"},
	}
	request := httptest.NewRequest(http.MethodPost, apiPrefix+"/auth/login-form", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "192.0.2.11:12345"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("native login failure returned %d: %s", response.Code, response.Body.String())
	}
	if location := response.Header().Get("Location"); location != "/?login_error=invalid_credentials" {
		t.Fatalf("unexpected failure redirect: %q", location)
	}
	if cookies := response.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("failed login issued cookies: %#v", cookies)
	}
	if strings.Contains(response.Header().Get("Location"), "wrong-password") {
		t.Fatal("failure redirect exposed password")
	}
}

func TestRequestBodyLimitAndSingleDocument(t *testing.T) {
	server := newTestServer(t)
	tooLargeBody := `{"username":"` + strings.Repeat("x", maxRequestBytes) + `"}`
	tooLarge := httptest.NewRequest(http.MethodPost, apiPrefix+"/auth/login", strings.NewReader(tooLargeBody))
	tooLarge.ContentLength = -1
	tooLarge.RemoteAddr = "192.0.2.10:12345"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, tooLarge)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body accepted: %d", response.Code)
	}

	request := httptest.NewRequest(http.MethodPost, apiPrefix+"/auth/login", bytes.NewBufferString(`{} {}`))
	request.RemoteAddr = "192.0.2.10:12345"
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("multiple JSON documents accepted: %d", response.Code)
	}
}

func TestReadOnlyStateEndpointsUseCompatibleDocuments(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)

	draft := performRequest(t, server, http.MethodGet, apiPrefix+"/drafts/current", nil, nil, cookie)
	if draft.Code != http.StatusOK {
		t.Fatalf("draft failed: %d %s", draft.Code, draft.Body.String())
	}
	draftBody := decodeResponse(t, draft)
	if draftBody["revision"] != "e63eb47127f2ad90e7af399f2459c487f32bc97c11a109239d891faf911e2446" {
		t.Fatalf("default config revision drifted: %v", draftBody["revision"])
	}
	config := draftBody["config"].(map[string]any)
	if config["schema_version"].(float64) != 1 {
		t.Fatalf("default config missing: %#v", config)
	}
	directGRPC := map[string]any{}
	directGRPCTLSPin := map[string]any{}
	for _, raw := range config["transports"].([]any) {
		transport := raw.(map[string]any)
		if transport["kind"] == "reality-grpc" {
			directGRPC = transport
		}
		if transport["kind"] == "grpc-tls" {
			directGRPCTLSPin = transport
		}
	}
	if directGRPC["grpc_idle_timeout"] != float64(60) ||
		directGRPC["grpc_health_check_timeout"] != float64(20) ||
		directGRPC["grpc_permit_without_stream"] != true {
		t.Fatalf("direct gRPC stability defaults missing: %#v", directGRPC)
	}
	if directGRPCTLSPin["id"] != "grpc-tls-pin" || directGRPCTLSPin["listen_port"] != float64(2445) || directGRPCTLSPin["enabled"] != false || directGRPCTLSPin["grpc_idle_timeout"] != float64(60) {
		t.Fatalf("direct gRPC TLS Pin defaults missing: %#v", directGRPCTLSPin)
	}

	if err := server.repository.saveAuxiliary("client-telemetry", map[string]any{
		"snapshot": map[string]any{"generated_at": "2026-09-03T00:00:00Z", "clients": []any{}},
	}); err != nil {
		t.Fatal(err)
	}
	telemetry := performRequest(t, server, http.MethodGet, apiPrefix+"/client-telemetry", nil, nil, cookie)
	if telemetry.Code != http.StatusOK || decodeResponse(t, telemetry)["generated_at"] != "2026-09-03T00:00:00Z" {
		t.Fatalf("telemetry failed: %d %s", telemetry.Code, telemetry.Body.String())
	}

	status := performRequest(t, server, http.MethodGet, apiPrefix+"/status", nil, nil, cookie)
	if status.Code != http.StatusOK || decodeResponse(t, status)["state"] != "unconfigured" {
		t.Fatalf("status failed: %d %s", status.Code, status.Body.String())
	}
}

func TestReadinessAndWatchdogManagementContract(t *testing.T) {
	server := newTestServer(t)
	headers := map[string]string{"Authorization": "Bearer management-test-token"}
	ready := performRequest(t, server, http.MethodGet, "/api/health/ready", nil, headers)
	if ready.Code != http.StatusOK || !decodeResponse(t, ready)["ready"].(bool) {
		t.Fatalf("unconfigured readiness failed: %d %s", ready.Code, ready.Body.String())
	}
	watchdog := performRequest(t, server, http.MethodPost, apiPrefix+"/runtime/watchdog", map[string]any{
		"state": "healthy", "container_healthy": true, "restarts": 2,
		"failure_count": 0, "max_restarts_per_hour": 6, "last_action": "probe-ok",
	}, headers)
	if watchdog.Code != http.StatusOK {
		t.Fatalf("watchdog update failed: %d %s", watchdog.Code, watchdog.Body.String())
	}
	body := decodeResponse(t, watchdog)
	if body["ok"] != true || body["watchdog"].(map[string]any)["budget_remaining"].(float64) != 4 {
		t.Fatalf("unexpected watchdog payload: %#v", body)
	}
	invalid := performRequest(t, server, http.MethodPost, apiPrefix+"/runtime/watchdog", map[string]any{
		"state": "healthy", "restarts": "many",
	}, headers)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid watchdog counters accepted: %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestDraftRedactsSensitiveValues(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	if _, err := server.repository.saveDraft(map[string]any{
		"schema_version":   1,
		"subscription_url": "https://example.test/private-token?secret=yes",
		"routeros":         map[string]any{"password_secret_ref": "routeros/password"},
	}); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/drafts/current", nil, nil, cookie)
	body := decodeResponse(t, response)
	config := body["config"].(map[string]any)
	if config["subscription_url"] != redacted {
		t.Fatalf("subscription URL was exposed: %#v", config)
	}
	if config["routeros"].(map[string]any)["password_secret_ref"] != "routeros/password" {
		t.Fatal("safe secret reference was redacted")
	}
}

func TestBootstrapOverviewLifecycleAndCollectionReads(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["storage"] = map[string]any{"root": "usb1/sb-gateway"}
	config["subscriptions"] = []any{map[string]any{
		"id": "primary", "name": "Primary", "url": "https://example.test/private-token",
	}}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.appendAudit(map[string]any{
		"action": "draft.save", "outcome": "ok", "timestamp": "2026-09-03T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	bootstrap := performRequest(t, server, http.MethodGet, apiPrefix+"/bootstrap-state", nil, nil, cookie)
	if bootstrap.Code != http.StatusOK {
		t.Fatalf("bootstrap state failed: %d %s", bootstrap.Code, bootstrap.Body.String())
	}
	bootstrapBody := decodeResponse(t, bootstrap)
	overview := bootstrapBody["overview"].(map[string]any)
	if overview["pending_change_count"].(float64) != 1 || len(overview["rule_order"].([]any)) != 12 {
		t.Fatalf("overview contract drifted: %#v", overview)
	}
	if overview["counts"].(map[string]any)["subscriptions"].(float64) != 1 {
		t.Fatalf("collection count missing: %#v", overview["counts"])
	}

	list := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions", nil, nil, cookie)
	if list.Code != http.StatusOK {
		t.Fatalf("collection list failed: %d %s", list.Code, list.Body.String())
	}
	items := decodeResponse(t, list)["items"].([]any)
	if items[0].(map[string]any)["url"] != "https://example.test/<redacted>" {
		t.Fatalf("collection secret leaked: %#v", items)
	}
	item := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/primary", nil, nil, cookie)
	if item.Code != http.StatusOK || decodeResponse(t, item)["item"].(map[string]any)["name"] != "Primary" {
		t.Fatalf("collection item failed: %d %s", item.Code, item.Body.String())
	}
	missing := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/missing", nil, nil, cookie)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing collection item returned %d", missing.Code)
	}
	unknown := performRequest(t, server, http.MethodGet, apiPrefix+"/unknown", nil, nil, cookie)
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown collection returned %d", unknown.Code)
	}

	lifecycle := performRequest(t, server, http.MethodGet, apiPrefix+"/lifecycle", nil, nil, cookie)
	lifecycleBody := decodeResponse(t, lifecycle)
	if lifecycleBody["storage_root"] != "usb1/sb-gateway" || lifecycleBody["registry_requires_digest"] != true {
		t.Fatalf("lifecycle contract drifted: %#v", lifecycleBody)
	}
}

func bootstrapSession(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/bootstrap", map[string]any{
		"username": "admin", "password": "panel-password-123", "password_confirmation": "panel-password-123",
	}, map[string]string{"Authorization": "Bearer management-test-token"})
	if response.Code != http.StatusOK {
		t.Fatalf("bootstrap failed: %d %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	return cookies[0], decodeResponse(t, response)["csrf_token"].(string)
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		for attempt := 0; attempt < 4; attempt++ {
			if err := os.RemoveAll(root); err == nil || runtime.GOOS != "windows" {
				return
			}
			time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
		}
	})
	opts := Options{
		Host: "127.0.0.1", Port: 8080,
		StateDir: root + "/state", SecretsDir: root + "/secrets", DataDir: root + "/data",
		AdminUser: "admin", SecureCookie: false,
	}
	server, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.secrets.write("management-api-token", "management-test-token", false); err != nil {
		t.Fatal(err)
	}
	return server
}

func performRequest(t *testing.T, handler http.Handler, method, path string, body map[string]any, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, &payload)
	request.RemoteAddr = "192.0.2.10:12345"
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	value := map[string]any{}
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode response: %v: %s", err, response.Body.String())
	}
	return value
}
