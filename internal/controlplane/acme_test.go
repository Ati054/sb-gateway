package controlplane

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func acmeTestSettings() acmejob.Settings {
	return acmejob.Settings{Enabled: true, Provider: "gcore", Email: "admin@example.com", Domains: []string{"api.example.com"}, TermsAccepted: true}
}
func acmeTestPair(t *testing.T, now time.Time, names []string) (acmejob.Result, *x509.CertPool) {
	return acmeTestPairValidity(t, now, names, now.Add(-time.Hour), now.Add(90*24*time.Hour))
}

func acmeTestPairValidity(t *testing.T, now time.Time, names []string, notBefore, notAfter time.Time) (acmejob.Result, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACME test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), DNSNames: names, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	roots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(root)
	roots.AddCert(parsed)
	return acmejob.Result{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}, roots
}
func queueTestACME(t *testing.T, s *Server) {
	t.Helper()
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
}

func queueTestACMEForSession(t *testing.T, s *Server, cookie *http.Cookie, csrf string) {
	t.Helper()
	response := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings(), "credentials": map[string]string{"token": "test-dns-secret"}, "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != 202 {
		t.Fatalf("configure: %d %s", response.Code, response.Body.String())
	}
	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	if status.Code != 200 || strings.Contains(status.Body.String(), "test-dns-secret") || strings.Contains(status.Body.String(), "credentials_ref") {
		t.Fatalf("unsafe status: %s", status.Body.String())
	}
}

func loginTestSession(t *testing.T, s *Server) (*http.Cookie, string) {
	t.Helper()
	login := performRequest(t, s, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "panel-password-123",
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login: %d %s", login.Code, login.Body.String())
	}
	return login.Result().Cookies()[0], decodeResponse(t, login)["csrf_token"].(string)
}

func assertACMEError(t *testing.T, responseCode int, responseBody string, response map[string]any, wantStatus int, wantCode string) {
	t.Helper()
	if responseCode != wantStatus {
		t.Fatalf("response: %d %s", responseCode, responseBody)
	}
	problem, _ := response["error"].(map[string]any)
	if problem["code"] != wantCode {
		t.Fatalf("error code: %#v", response)
	}
}

func storedACMERecord(t *testing.T, s *Server) acmeRecord {
	t.Helper()
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	return decodeACMERecord(state["cdn-default"])
}
func TestACMEIssueAndRenewWithoutRouterOSApply(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	queueTestACME(t, s)
	calls := 0
	s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
		calls++
		if req.Credentials["token"] != "test-dns-secret" || !strings.Contains(req.AccountKey, "PRIVATE KEY") {
			t.Fatal("missing worker input")
		}
		result, roots := acmeTestPair(t, now, req.Settings.Domains)
		s.acmeRoots = roots
		return result, nil
	}
	s.applyRouterOS = func(context.Context, map[string]any, string, string, func(context.Context) error, func(context.Context, routeros.BackupRef) error) (routerOSApplyOutput, error) {
		t.Fatal("ACME must not touch RouterOS")
		return routerOSApplyOutput{}, nil
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	draft, _ := s.getDraft()
	p := acmeProfile(draft, "cdn-default")
	ref := subscriptionText(p["certificate_secret_ref"])
	if ref == "" || p["private_key_secret_ref"] != ref {
		t.Fatal("certificate pair is not atomic")
	}
	bundle, err := s.secrets.read(ref, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tlsCertificateMetadata(bundle, bundle); err != nil {
		t.Fatal(err)
	}
	activeRevision, err := s.repository.stageGeneration(draft)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.repository.setActiveRevision(activeRevision); err != nil {
		t.Fatal(err)
	}
	p["display_name"] = "Pending user edit"
	draftRevision, err := s.repository.saveDraft(draft)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.processOneACME(context.Background()); err != nil || calls != 1 {
		t.Fatal("early reissue", err, calls)
	}
	now = now.Add(62 * 24 * time.Hour)
	if err := s.processOneACME(context.Background()); err != nil || calls != 2 {
		t.Fatal("renewal", err, calls)
	}
	renewed, _ := s.secrets.read(ref, true)
	if renewed == bundle {
		t.Fatal("renewal did not replace bundle")
	}
	draft, _ = s.getDraft()
	afterRevision, _ := revisionFor(draft)
	if afterRevision != draftRevision {
		t.Fatal("renewal changed pending user draft")
	}
}
func TestACMEFailureKeepsCertificateAndBackoff(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	queueTestACME(t, s)
	result, roots := acmeTestPair(t, now, []string{"api.example.com"})
	s.acmeRoots = roots
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) { return result, nil }
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	ref := "tls-profiles/cdn-default/acme-bundle.pem"
	before, _ := s.secrets.read(ref, true)
	now = now.Add(62 * 24 * time.Hour)
	calls := 0
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		calls++
		return acmejob.Result{}, errors.New("upstream leaked secret-token")
	}
	if s.processOneACME(context.Background()) == nil {
		t.Fatal("failure ignored")
	}
	_ = s.processOneACME(context.Background())
	if calls != 1 {
		t.Fatal("backoff ignored")
	}
	failed := storedACMERecord(t, s)
	now = failed.NextAttempt
	if s.processOneACME(context.Background()) == nil || calls != 2 {
		t.Fatalf("verified renewal failure did not retry automatically: %d", calls)
	}
	after, _ := s.secrets.read(ref, true)
	if before != after {
		t.Fatal("failure replaced valid certificate")
	}
	state, _ := s.repository.auxiliary("acme")
	rec := decodeACMERecord(state["cdn-default"])
	if rec.State != "failed" || strings.Contains(rec.Message, "secret-token") {
		t.Fatal("unsafe failure state")
	}
}

func TestACMEFailureStatusUsesAllowlistedStage(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		return acmejob.Result{}, errors.Join(acmejob.ErrPropagation, errors.New("provider returned secret-token"))
	}
	if err := s.processOneACME(context.Background()); !errors.Is(err, acmejob.ErrPropagation) {
		t.Fatalf("worker failure: %v", err)
	}
	record := storedACMERecord(t, s)
	want := acmejob.ErrPropagation.Error() + " Выпуск не выполнен. Повторите вручную."
	if record.Message != want || strings.Contains(record.Message, "secret-token") {
		t.Fatalf("unsafe propagation status: %q", record.Message)
	}
	for _, stage := range []error{acmejob.ErrDNSProvider, acmejob.ErrRegistration, acmejob.ErrCAValidation, acmejob.ErrLocalInstall, acmejob.ErrWorkerInput, acmejob.ErrWorker} {
		message := acmeFailureMessage(errors.Join(stage, errors.New("another secret-token")))
		if message != stage.Error() || strings.Contains(message, "secret-token") {
			t.Fatalf("unsafe stage status: %q", message)
		}
	}
}

func TestACMEStatusRunningUsesSharedControllerTimeout(t *testing.T) {
	s := newTestServer(t)
	cookie, _ := bootstrapSession(t, s)
	settingsCases := map[string]acmejob.Settings{
		"REG.RU":                   {Enabled: true, Provider: "regru", Domains: []string{"api.example.com"}},
		"Cloudflare":               {Enabled: true, Provider: "cloudflare", Domains: []string{"api.example.com"}},
		"Yandex Cloud":             {Enabled: true, Provider: "yandexcloud", Domains: []string{"api.example.com"}},
		"Gcore":                    {Enabled: true, Provider: "gcore", Domains: []string{"api.example.com"}},
		"ACME-DNS automatic":       {Enabled: true, Provider: "acmedns", Domains: []string{"api.example.com"}},
		"ACME-DNS manual with SAN": {Enabled: true, Provider: "acmedns", PropagationTimeoutMinutes: 120, Domains: []string{"api.example.com", "www.example.com"}},
	}
	for name, settings := range settingsCases {
		t.Run(name, func(t *testing.T) {
			state, err := s.repository.auxiliary("acme")
			if err != nil {
				t.Fatal(err)
			}
			state["cdn-default"] = acmeRecord{Settings: settings, State: "running", LastAttempt: time.Now().UTC()}
			if err := s.repository.saveAuxiliary("acme", state); err != nil {
				t.Fatal(err)
			}
			response := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
			if response.Code != http.StatusOK {
				t.Fatalf("status: %d %s", response.Code, response.Body.String())
			}
			body := decodeResponse(t, response)
			want := int64(acmejob.ControllerTimeout(settings) / time.Second)
			if got, ok := body["operation_timeout_seconds"].(float64); !ok || int64(got) != want {
				t.Fatalf("operation timeout: got %#v want %d", body["operation_timeout_seconds"], want)
			}
		})
	}
	for _, stateName := range []string{"queued", "failed", "issued", "disabled"} {
		t.Run("does not expose timeout for "+stateName, func(t *testing.T) {
			state, err := s.repository.auxiliary("acme")
			if err != nil {
				t.Fatal(err)
			}
			state["cdn-default"] = acmeRecord{Settings: settingsCases["REG.RU"], State: stateName, LastAttempt: time.Now().UTC()}
			if err := s.repository.saveAuxiliary("acme", state); err != nil {
				t.Fatal(err)
			}
			response := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
			if _, exists := decodeResponse(t, response)["operation_timeout_seconds"]; exists {
				t.Fatalf("non-running status exposes operation timeout: %s", response.Body.String())
			}
		})
	}
}

func TestACMERateLimitPersistsSafeDeadlineAndBlocksManualRetry(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	diagnostic := acmejob.Diagnostic{Version: 1, ExitCode: acmejob.WorkerExitValidation, Stage: "before_dns_check", Category: "ca_rate_limited", HTTPStatus: 429, RetryAfterSeconds: int64(time.Hour / time.Second)}
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		return acmejob.Result{}, acmejob.WrapDiagnostic(acmejob.ErrCAValidation, diagnostic)
	}
	if err := s.processOneACME(context.Background()); !errors.Is(err, acmejob.ErrCAValidation) {
		t.Fatalf("rate limit was lost: %v", err)
	}
	failed := storedACMERecord(t, s)
	deadline := now.Add(time.Hour)
	if failed.Diagnostic == nil || *failed.Diagnostic != diagnostic || !failed.CARetryNotBefore.Equal(deadline) || !failed.NextAttempt.IsZero() || strings.Contains(failed.Message, "15 минут") || !strings.Contains(failed.Message, "Выпуск не выполнен") || failed.Intent != acmeIntentInitial {
		t.Fatalf("rate limit record: %#v", failed)
	}
	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	statusBody := decodeResponse(t, status)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"diagnostic"`) || strings.Contains(status.Body.String(), "test-dns-secret") || strings.Contains(status.Body.String(), "credentials_ref") || statusBody["manual_retry_only"] != true || statusBody["ca_retry_not_before"] == nil {
		t.Fatalf("unsafe diagnostic status: %d %s", status.Code, status.Body.String())
	}
	if statusBody["message"] != "CA: лимит выпуска сертификатов. "+manualACMEFailureSuffix {
		t.Fatalf("rate-limit status lost safe cause: %#v", statusBody)
	}
	if _, exists := statusBody["next_attempt"]; exists {
		t.Fatalf("initial CA hold advertised an automatic deadline: %#v", statusBody)
	}
	now = now.Add(manualACMERetryCooldown + time.Second)
	blocked := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings(), "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, blocked.Code, blocked.Body.String(), decodeResponse(t, blocked), http.StatusTooManyRequests, "acme_ca_backoff")
	after := storedACMERecord(t, s)
	if !after.NextAttempt.IsZero() || !after.CARetryNotBefore.Equal(deadline) || after.Revision != failed.Revision {
		t.Fatalf("manual retry changed CA hold: before=%#v after=%#v", failed, after)
	}
	restarted, err := NewServer(s.opts)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return now }
	login := performRequest(t, restarted, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "panel-password-123",
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login after restart: %d %s", login.Code, login.Body.String())
	}
	cookie, csrf = login.Result().Cookies()[0], decodeResponse(t, login)["csrf_token"].(string)
	blocked = performRequest(t, restarted, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings(), "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, blocked.Code, blocked.Body.String(), decodeResponse(t, blocked), http.StatusTooManyRequests, "acme_ca_backoff")
	persisted := storedACMERecord(t, restarted)
	if !persisted.CARetryNotBefore.Equal(deadline) || !persisted.NextAttempt.IsZero() {
		t.Fatalf("restart bypassed CA hold: %#v", persisted)
	}
}

func TestACMERetryAfterFailsClosedWhenUnrepresentable(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	const maxDurationSeconds = int64((1<<63 - 1) / int64(time.Second))
	for name, diagnostic := range map[string]acmejob.Diagnostic{
		"explicit unsupported":    {Version: 1, ExitCode: acmejob.WorkerExitValidation, Stage: "before_dns_check", Category: "ca_rate_limited", RetryAfterUnsupported: true},
		"unrepresentable seconds": {Version: 1, ExitCode: acmejob.WorkerExitValidation, Stage: "before_dns_check", Category: "ca_rate_limited", RetryAfterSeconds: maxDurationSeconds + 1},
	} {
		t.Run(name, func(t *testing.T) {
			record := acmeRecord{Settings: acmejob.Settings{Enabled: true}, State: "failed", LastOutcome: "failed", NextAttempt: now.Add(automaticACMERetryDelay)}
			if !persistCARetryHold(&record, now, diagnostic) || !record.CARetryAfterUnsupported || !record.caRetryBlocked(now) || acmeDue(record, now) {
				t.Fatalf("unrepresentable Retry-After was not fail-closed: %#v", record)
			}
		})
	}
}

func TestACMEUnsupportedCARetryOmitsOrdinaryDeadline(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	diagnostic := acmejob.Diagnostic{Version: 1, ExitCode: acmejob.WorkerExitValidation, Stage: "before_dns_check", Category: "ca_rate_limited", HTTPStatus: 429, RetryAfterUnsupported: true}
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		return acmejob.Result{}, acmejob.WrapDiagnostic(acmejob.ErrCAValidation, diagnostic)
	}
	if err := s.processOneACME(context.Background()); !errors.Is(err, acmejob.ErrCAValidation) {
		t.Fatalf("unsupported Retry-After was lost: %v", err)
	}
	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	if status.Code != http.StatusOK {
		t.Fatalf("status: %d %s", status.Code, status.Body.String())
	}
	response := decodeResponse(t, status)
	if response["ca_retry_after_unsupported"] != true {
		t.Fatalf("unsupported Retry-After missing from status: %#v", response)
	}
	if _, exists := response["next_attempt"]; exists {
		t.Fatalf("status advertised ordinary retry deadline: %#v", response)
	}
	if response["message"] != "CA передал неподдерживаемый срок ожидания. Выпуск временно заблокирован." {
		t.Fatalf("unsupported Retry-After status implied a manual recovery: %#v", response)
	}
	now = now.Add(manualACMERetryCooldown + time.Second)
	blocked := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings(), "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, blocked.Code, blocked.Body.String(), decodeResponse(t, blocked), http.StatusTooManyRequests, "acme_ca_backoff")
}

func TestACMERateLimitSurvivesInFlightSaveDisableEnable(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	diagnostic := acmejob.Diagnostic{Version: 1, ExitCode: acmejob.WorkerExitValidation, Stage: "after_dns_check", Category: "ca_rate_limited", HTTPStatus: 429, RetryAfterSeconds: int64(2 * time.Hour / time.Second)}
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		saved := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings()}, map[string]string{csrfHeader: csrf}, cookie)
		if saved.Code != http.StatusAccepted {
			t.Fatalf("in-flight save: %d %s", saved.Code, saved.Body.String())
		}
		disabled := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"disable": true}, map[string]string{csrfHeader: csrf}, cookie)
		if disabled.Code != http.StatusOK {
			t.Fatalf("in-flight disable: %d %s", disabled.Code, disabled.Body.String())
		}
		return acmejob.Result{}, acmejob.WrapDiagnostic(acmejob.ErrCAValidation, diagnostic)
	}
	if err := s.processOneACME(context.Background()); !errors.Is(err, acmejob.ErrCAValidation) {
		t.Fatalf("rate limit was discarded: %v", err)
	}
	deadline := now.Add(2 * time.Hour)
	afterFlight := storedACMERecord(t, s)
	if afterFlight.State != "disabled" || !afterFlight.CARetryNotBefore.Equal(deadline) || !afterFlight.NextAttempt.Equal(deadline) || afterFlight.Diagnostic == nil || *afterFlight.Diagnostic != diagnostic {
		t.Fatalf("obsolete job did not retain only CA hold: %#v", afterFlight)
	}
	enabled := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings()}, map[string]string{csrfHeader: csrf}, cookie)
	if enabled.Code != http.StatusAccepted {
		t.Fatalf("enable: %d %s", enabled.Code, enabled.Body.String())
	}
	now = now.Add(manualACMERetryCooldown + time.Second)
	blocked := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings(), "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, blocked.Code, blocked.Body.String(), decodeResponse(t, blocked), http.StatusTooManyRequests, "acme_ca_backoff")
	after := storedACMERecord(t, s)
	if !after.CARetryNotBefore.Equal(deadline) || !after.NextAttempt.Equal(deadline) || after.State != "configured" {
		t.Fatalf("disable/enable bypassed CA hold: %#v", after)
	}
}

func TestACMEManualRetryAfterFailureUsesShortCooldown(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	attempts := 0
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		attempts++
		return acmejob.Result{}, errors.New("test DNS API failure")
	}
	if err := s.processOneACME(context.Background()); err == nil {
		t.Fatal("initial failure ignored")
	}
	failed := storedACMERecord(t, s)
	if failed.State != "failed" || failed.LastOutcome != "failed" || failed.Intent != acmeIntentInitial || !failed.NextAttempt.IsZero() || !strings.Contains(failed.Message, "Выпуск не выполнен") {
		t.Fatalf("failed state: %#v", failed)
	}
	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	statusBody := decodeResponse(t, status)
	if statusBody["manual_retry_only"] != true {
		t.Fatalf("initial failure status is not manual-only: %#v", statusBody)
	}
	if _, exists := statusBody["next_attempt"]; exists {
		t.Fatalf("initial failure advertised automatic retry: %#v", statusBody)
	}
	secretBefore, err := s.secrets.read(failed.CredentialsRef, true)
	if err != nil {
		t.Fatal(err)
	}

	early := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "credentials": map[string]string{"token": "must-not-replace"}, "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, early.Code, early.Body.String(), decodeResponse(t, early), http.StatusTooManyRequests, "acme_retry_cooldown")
	afterEarly := storedACMERecord(t, s)
	secretAfter, err := s.secrets.read(failed.CredentialsRef, true)
	if err != nil {
		t.Fatal(err)
	}
	if afterEarly.State != failed.State || afterEarly.Revision != failed.Revision || afterEarly.LastOutcome != failed.LastOutcome || !afterEarly.LastAttempt.Equal(failed.LastAttempt) || !afterEarly.NextAttempt.Equal(failed.NextAttempt) || secretAfter != secretBefore {
		t.Fatalf("early retry changed persisted state: before=%#v after=%#v", failed, afterEarly)
	}

	now = now.Add(manualACMERetryCooldown)
	accepted := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("manual retry: %d %s", accepted.Code, accepted.Body.String())
	}
	queued := storedACMERecord(t, s)
	if queued.State != "queued" || !queued.NextAttempt.Equal(now) || !queued.LastAttempt.Equal(failed.LastAttempt) || queued.LastOutcome != "failed" || !acmeDue(queued, now) {
		t.Fatalf("manual retry not due: %#v", queued)
	}
	if err := s.processOneACME(context.Background()); err == nil || attempts != 2 {
		t.Fatalf("manual retry did not reach worker: %v (%d attempts)", err, attempts)
	}
}

func TestACMEIssueRejectsQueuedOrRunningWithoutMutation(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)

	for _, stateName := range []string{"queued", "running"} {
		t.Run(stateName, func(t *testing.T) {
			state, err := s.repository.auxiliary("acme")
			if err != nil {
				t.Fatal(err)
			}
			record := decodeACMERecord(state["cdn-default"])
			record.State = stateName
			record.LastOutcome = stateName
			record.Revision = "in-flight-" + stateName
			record.LastAttempt = now
			record.NextAttempt = now.Add(automaticACMERetryDelay)
			state["cdn-default"] = record
			if err := s.repository.saveAuxiliary("acme", state); err != nil {
				t.Fatal(err)
			}
			secretBefore, err := s.secrets.read(record.CredentialsRef, true)
			if err != nil {
				t.Fatal(err)
			}

			response := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
				"settings": acmeTestSettings(), "credentials": map[string]string{"token": "must-not-replace"}, "issue": true,
			}, map[string]string{csrfHeader: csrf}, cookie)
			assertACMEError(t, response.Code, response.Body.String(), decodeResponse(t, response), http.StatusConflict, "acme_busy")
			after := storedACMERecord(t, s)
			secretAfter, err := s.secrets.read(record.CredentialsRef, true)
			if err != nil {
				t.Fatal(err)
			}
			if after.State != record.State || after.Revision != record.Revision || after.CredentialsRef != record.CredentialsRef || !after.LastAttempt.Equal(record.LastAttempt) || !after.NextAttempt.Equal(record.NextAttempt) || secretAfter != secretBefore {
				t.Fatalf("busy issue changed in-flight state: before=%#v after=%#v", record, after)
			}
		})
	}
}

func TestACMEInitialFailureNeverRetriesAutomatically(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	queueTestACME(t, s)
	attempts := 0
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		attempts++
		return acmejob.Result{}, errors.New("test DNS API failure")
	}
	if err := s.processOneACME(context.Background()); err == nil {
		t.Fatal("initial failure ignored")
	}
	failed := storedACMERecord(t, s)
	if !failed.NextAttempt.IsZero() || failed.Intent != acmeIntentInitial || !failed.manualRetryOnly() {
		t.Fatalf("initial failure is not manual-only: %#v", failed)
	}
	now = now.Add(365 * 24 * time.Hour)
	if err := s.processOneACME(context.Background()); err != nil || attempts != 1 {
		t.Fatalf("initial failure retried automatically: %v (%d attempts)", err, attempts)
	}
}

func TestACMELegacyInitialStatusSuppressesAutomaticRetryMessage(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	record := decodeACMERecord(state["cdn-default"])
	record.State, record.LastOutcome, record.Intent = "failed", "failed", ""
	record.LastAttempt = now
	record.NextAttempt = now.Add(automaticACMERetryDelay)
	record.Message = "Выпуск не выполнен. Повтор через 15 минут."
	state["cdn-default"] = record
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}

	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	body := decodeResponse(t, status)
	if body["manual_retry_only"] != true {
		t.Fatalf("legacy initial status is not manual-only: %#v", body)
	}
	if _, exists := body["next_attempt"]; exists {
		t.Fatalf("legacy initial status advertised retry: %#v", body)
	}
	if body["message"] != manualACMEFailureSuffix {
		t.Fatalf("legacy initial status kept old retry promise: %#v", body)
	}
}

func TestACMELongInitialFailureRequiresManualRetry(t *testing.T) {
	s := newTestServer(t)
	started := time.Now().UTC()
	now := started
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	attempts := 0
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		attempts++
		now = now.Add(4*time.Hour + 15*time.Minute)
		return acmejob.Result{}, errors.New("test long propagation failure")
	}
	if err := s.processOneACME(context.Background()); err == nil {
		t.Fatal("long failure ignored")
	}
	failed := storedACMERecord(t, s)
	if !failed.LastAttempt.Equal(started) || !failed.NextAttempt.IsZero() || failed.Intent != acmeIntentInitial {
		t.Fatalf("initial failure was not made manual-only: %#v", failed)
	}
	if err := s.processOneACME(context.Background()); err != nil || attempts != 1 {
		t.Fatalf("initial failure retried automatically: %v (%d)", err, attempts)
	}
	manual := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if manual.Code != http.StatusAccepted {
		t.Fatalf("manual retry after long failure: %d %s", manual.Code, manual.Body.String())
	}
	queued := storedACMERecord(t, s)
	if queued.State != "queued" || !queued.NextAttempt.Equal(now) {
		t.Fatalf("manual retry was not queued: %#v", queued)
	}
}

func TestACMEOrphanedInitialDoesNotReissueAndKeepsCAHold(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for name, hold := range map[string]struct {
		deadline    time.Time
		unsupported bool
	}{
		"positive hold":    {deadline: now.Add(time.Hour)},
		"unsupported hold": {unsupported: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t)
			s.now = func() time.Time { return now }
			cookie, csrf := bootstrapSession(t, s)
			queueTestACMEForSession(t, s, cookie, csrf)
			state, err := s.repository.auxiliary("acme")
			if err != nil {
				t.Fatal(err)
			}
			record := decodeACMERecord(state["cdn-default"])
			record.State, record.LastOutcome, record.Intent = "running", "running", acmeIntentInitial
			record.LastAttempt = now.Add(-time.Minute)
			record.CARetryNotBefore = hold.deadline
			record.CARetryAfterUnsupported = hold.unsupported
			record.Diagnostic = &acmejob.Diagnostic{Version: 1, ExitCode: acmejob.WorkerExitValidation, Stage: "before_dns_check", Category: "ca_rate_limited", HTTPStatus: 429}
			state["cdn-default"] = record
			if err := s.repository.saveAuxiliary("acme", state); err != nil {
				t.Fatal(err)
			}
			calls := 0
			s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
				calls++
				return acmejob.Result{}, nil
			}
			if err := s.processOneACME(context.Background()); err != nil || calls != 0 {
				t.Fatalf("orphaned initial issued again: %v (%d)", err, calls)
			}
			after := storedACMERecord(t, s)
			if !after.manualRetryOnly() || after.Diagnostic == nil || !after.NextAttempt.IsZero() || after.CARetryAfterUnsupported != hold.unsupported || !after.CARetryNotBefore.Equal(hold.deadline) {
				t.Fatalf("orphan recovery lost safe hold: %#v", after)
			}
			status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
			body := decodeResponse(t, status)
			if body["manual_retry_only"] != true {
				t.Fatalf("manual-only status missing: %#v", body)
			}
			if _, exists := body["next_attempt"]; exists {
				t.Fatalf("orphan status advertised automatic retry: %#v", body)
			}
			blocked := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings(), "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
			assertACMEError(t, blocked.Code, blocked.Body.String(), decodeResponse(t, blocked), http.StatusTooManyRequests, "acme_ca_backoff")
		})
	}
}

func TestACMEOrphanedRenewalKeepsLongerCAHold(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
		result, roots := acmeTestPair(t, now, req.Settings.Domains)
		s.acmeRoots = roots
		return result, nil
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	record := decodeACMERecord(state["cdn-default"])
	deadline := now.Add(2 * time.Hour)
	record.State, record.LastOutcome, record.Intent = "running", "running", ""
	record.CARetryNotBefore = deadline
	record.NextAttempt = deadline
	state["cdn-default"] = record
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := storedACMERecord(t, s)
	if after.manualRetryOnly() || after.Intent != acmeIntentRenewal || !after.NextAttempt.Equal(deadline) || !after.CARetryNotBefore.Equal(deadline) || !strings.Contains(after.Message, "указанного времени") || strings.Contains(after.Message, "15 минут") {
		t.Fatalf("orphaned renewal shortened CA hold: %#v", after)
	}
	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	body := decodeResponse(t, status)
	if body["manual_retry_only"] == true || body["next_attempt"] == nil || body["ca_retry_not_before"] == nil {
		t.Fatalf("renewal status did not expose automatic deadline: %#v", body)
	}
}

func TestACMELegacyManagedRenewalMigratesOnlyAfterPairVerification(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	calls := 0
	s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
		calls++
		result, roots := acmeTestPair(t, now, req.Settings.Domains)
		s.acmeRoots = roots
		return result, nil
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	legacy := decodeACMERecord(state["cdn-default"])
	legacy.State, legacy.LastOutcome, legacy.Intent = "failed", "failed", ""
	legacy.NextAttempt = now
	state["cdn-default"] = legacy
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}
	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	statusBody := decodeResponse(t, status)
	if statusBody["manual_retry_only"] == true || statusBody["next_attempt"] == nil {
		t.Fatalf("verified legacy renewal status is misleading: %#v", statusBody)
	}
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		calls++
		return acmejob.Result{}, errors.New("renewal failure")
	}
	if err := s.processOneACME(context.Background()); err == nil || calls != 2 {
		t.Fatalf("verified legacy renewal did not migrate: %v (%d)", err, calls)
	}
	after := storedACMERecord(t, s)
	if after.Intent != acmeIntentRenewal || !after.NextAttempt.Equal(now.Add(automaticACMERetryDelay)) || after.manualRetryOnly() {
		t.Fatalf("legacy renewal migration is unsafe: %#v", after)
	}
}

func TestACMEMissingPairBlocksButExpiredPairKeepsRenewal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	t.Run("missing pair", func(t *testing.T) {
		s := newTestServer(t)
		s.now = func() time.Time { return now }
		queueTestACME(t, s)
		s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
			result, roots := acmeTestPair(t, now, req.Settings.Domains)
			s.acmeRoots = roots
			return result, nil
		}
		if err := s.processOneACME(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := s.secrets.remove("tls-profiles/cdn-default/acme-bundle.pem"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(62 * 24 * time.Hour)
		s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
			t.Fatal("missing pair reached ACME worker")
			return acmejob.Result{}, nil
		}
		if err := s.processOneACME(context.Background()); err != nil {
			t.Fatal(err)
		}
		after := storedACMERecord(t, s)
		if !after.manualRetryOnly() || after.Intent != acmeIntentInitial || !after.NextAttempt.IsZero() {
			t.Fatalf("missing pair enabled automatic renewal: %#v", after)
		}
	})
	t.Run("expired pair", func(t *testing.T) {
		s := newTestServer(t)
		s.now = func() time.Time { return now }
		queueTestACME(t, s)
		result, _ := acmeTestPairValidity(t, now, []string{"api.example.com"}, now.Add(-90*24*time.Hour), now.Add(-time.Hour))
		metadata, err := tlsCertificateMetadata(result.Certificate, result.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		ref := "tls-profiles/cdn-default/acme-bundle.pem"
		if err := s.secrets.write(ref, result.Certificate+result.PrivateKey, false); err != nil {
			t.Fatal(err)
		}
		draft, _ := s.getDraft()
		profile := acmeProfile(draft, "cdn-default")
		profile["certificate_secret_ref"], profile["private_key_secret_ref"] = ref, ref
		if _, err := s.repository.saveDraft(draft); err != nil {
			t.Fatal(err)
		}
		state, _ := s.repository.auxiliary("acme")
		record := decodeACMERecord(state["cdn-default"])
		record.State, record.LastOutcome, record.Intent, record.Metadata, record.NextAttempt = "failed", "failed", acmeIntentRenewal, metadata, now
		state["cdn-default"] = record
		if err := s.repository.saveAuxiliary("acme", state); err != nil {
			t.Fatal(err)
		}
		calls := 0
		s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
			calls++
			return acmejob.Result{}, errors.New("renewal attempted")
		}
		if err := s.processOneACME(context.Background()); err == nil || calls != 1 {
			t.Fatalf("expired verified pair did not renew: %v (%d)", err, calls)
		}
	})
}

func TestACMEControllerUsesSharedDeadlineAndParentCancellation(t *testing.T) {
	s := newTestServer(t)
	queueTestACME(t, s)
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	want := acmejob.ControllerTimeout(acmeTestSettings())
	s.issueACME = func(ctx context.Context, _ acmejob.Request) (acmejob.Result, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("controller deadline missing")
		}
		remaining := time.Until(deadline)
		if remaining < want-time.Second || remaining > want {
			t.Fatalf("controller deadline: got %v want %v", remaining, want)
		}
		stop()
		<-ctx.Done()
		return acmejob.Result{}, ctx.Err()
	}
	if err := s.processOneACME(parent); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation was not passed to worker: %v", err)
	}
}

func TestACMEValidCertificateRequiresRenewalBeforeManualIssue(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
		result, roots := acmeTestPair(t, now, req.Settings.Domains)
		s.acmeRoots = roots
		return result, nil
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	issued := storedACMERecord(t, s)
	if issued.State != "issued" || issued.LastOutcome != "issued" || !issued.NextAttempt.Equal(now.Add(successfulACMECooldown)) {
		t.Fatalf("issued state: %#v", issued)
	}
	status := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	statusBody := decodeResponse(t, status)
	if statusBody["manual_issue_needed"] != false || statusBody["renewal_not_before"] == nil {
		t.Fatalf("issued status does not prove manual issue is unnecessary: %#v", statusBody)
	}
	changedSettings := acmeTestSettings()
	changedSettings.Provider = "cloudflare"
	saved := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": changedSettings, "credentials": map[string]string{"token": "changed-dns-secret"},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if saved.Code != http.StatusAccepted {
		t.Fatalf("save after success: %d %s", saved.Code, saved.Body.String())
	}
	if body := decodeResponse(t, saved); body["manual_issue_needed"] != false || body["renewal_not_before"] == nil {
		t.Fatalf("save did not refresh manual issue eligibility: %#v", body)
	}
	disabled := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"disable": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable after success: %d %s", disabled.Code, disabled.Body.String())
	}
	enabled := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": changedSettings,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if enabled.Code != http.StatusAccepted {
		t.Fatalf("enable after success: %d %s", enabled.Code, enabled.Body.String())
	}
	beforeManual := storedACMERecord(t, s)
	secretBefore, err := s.secrets.read(beforeManual.CredentialsRef, true)
	if err != nil {
		t.Fatal(err)
	}
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		t.Fatal("manual issue reached worker before renewal window")
		return acmejob.Result{}, nil
	}
	response := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": changedSettings, "credentials": map[string]string{"token": "must-not-replace"}, "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, response.Code, response.Body.String(), decodeResponse(t, response), http.StatusConflict, "acme_not_due")
	after := storedACMERecord(t, s)
	secretAfter, err := s.secrets.read(beforeManual.CredentialsRef, true)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != beforeManual.State || after.Revision != beforeManual.Revision || after.Settings.Provider != "cloudflare" || !after.LastAttempt.Equal(beforeManual.LastAttempt) || !after.NextAttempt.Equal(beforeManual.NextAttempt) || secretAfter != secretBefore {
		t.Fatalf("manual issue changed a certificate that is not due: before=%#v after=%#v", beforeManual, after)
	}
}

func TestACMEManualIssueAllowsChangedDomainsAndPairRecovery(t *testing.T) {
	started := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name    string
		advance time.Duration
		mutate  func(t *testing.T, s *Server, settings *acmejob.Settings)
	}{
		{name: "changed domains", advance: successfulACMECooldown + time.Second, mutate: func(_ *testing.T, _ *Server, settings *acmejob.Settings) {
			settings.Domains = []string{"api.example.com", "new.example.com"}
		}},
		{name: "missing pair", advance: successfulACMECooldown + time.Second, mutate: func(t *testing.T, s *Server, _ *acmejob.Settings) {
			if err := s.secrets.remove("tls-profiles/cdn-default/acme-bundle.pem"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "corrupt pair", advance: successfulACMECooldown + time.Second, mutate: func(t *testing.T, s *Server, _ *acmejob.Settings) {
			if err := s.secrets.write("tls-profiles/cdn-default/acme-bundle.pem", "not-a-pem-pair", true); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "renewal window", advance: 61 * 24 * time.Hour, mutate: func(_ *testing.T, _ *Server, _ *acmejob.Settings) {}},
		{name: "expired pair", advance: 91 * 24 * time.Hour, mutate: func(_ *testing.T, _ *Server, _ *acmejob.Settings) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t)
			now := started
			s.now = func() time.Time { return now }
			cookie, csrf := bootstrapSession(t, s)
			queueTestACMEForSession(t, s, cookie, csrf)
			s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
				result, roots := acmeTestPair(t, started, req.Settings.Domains)
				s.acmeRoots = roots
				return result, nil
			}
			if err := s.processOneACME(context.Background()); err != nil {
				t.Fatal(err)
			}
			settings := acmeTestSettings()
			test.mutate(t, s, &settings)
			now = now.Add(test.advance)
			// Time-traveling into the renewal window also expires the original
			// test session; it must not be mistaken for an ACME rejection.
			cookie, csrf = loginTestSession(t, s)
			response := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": settings, "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
			if response.Code != http.StatusAccepted {
				t.Fatalf("manual recovery was not queued: %d %s", response.Code, response.Body.String())
			}
			if body := decodeResponse(t, response); body["manual_issue_needed"] != true {
				t.Fatalf("manual recovery response hid required issuance: %#v", body)
			}
			record := storedACMERecord(t, s)
			if record.State != "queued" {
				t.Fatalf("manual recovery state: %#v", record)
			}
		})
	}
}

func TestACMEManualIssueNeededRequiresCurrentCertificateOrRenewalWindow(t *testing.T) {
	now := time.Date(2026, time.September, 9, 12, 0, 0, 0, time.UTC)
	metadata := func(notBefore, notAfter time.Time) map[string]any {
		return map[string]any{"not_before": notBefore.Format(time.RFC3339), "not_after": notAfter.Format(time.RFC3339)}
	}
	for name, test := range map[string]struct {
		metadata map[string]any
		needed   bool
	}{
		"current before window": {metadata: metadata(now.Add(-10*24*time.Hour), now.Add(80*24*time.Hour)), needed: false},
		"renewal window":        {metadata: metadata(now.Add(-80*24*time.Hour), now.Add(10*24*time.Hour)), needed: true},
		"expired":               {metadata: metadata(now.Add(-100*24*time.Hour), now.Add(-time.Second)), needed: true},
		"not yet valid":         {metadata: metadata(now.Add(time.Second), now.Add(90*24*time.Hour)), needed: true},
		"invalid lifetime":      {metadata: metadata(now.Add(time.Hour), now.Add(-time.Hour)), needed: true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := acmeManualIssueNeeded(test.metadata, now); got != test.needed {
				t.Fatalf("manual issue needed = %v, want %v", got, test.needed)
			}
		})
	}
}

func TestACMEFailedRetryEligibilitySurvivesSaveAndRestart(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		return acmejob.Result{}, errors.New("test DNS API failure")
	}
	if err := s.processOneACME(context.Background()); err == nil {
		t.Fatal("initial failure ignored")
	}
	failed := storedACMERecord(t, s)

	saved := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(),
	}, map[string]string{csrfHeader: csrf}, cookie)
	if saved.Code != http.StatusAccepted {
		t.Fatalf("save: %d %s", saved.Code, saved.Body.String())
	}
	afterSave := storedACMERecord(t, s)
	if afterSave.State != "configured" || afterSave.LastOutcome != "failed" || !afterSave.LastAttempt.Equal(failed.LastAttempt) || !afterSave.NextAttempt.Equal(failed.NextAttempt) {
		t.Fatalf("save masked failed outcome: before=%#v after=%#v", failed, afterSave)
	}

	reopened, err := NewServer(s.opts)
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return now }
	login := performRequest(t, reopened, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "panel-password-123",
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login after restart: %d %s", login.Code, login.Body.String())
	}
	cookie, csrf = login.Result().Cookies()[0], decodeResponse(t, login)["csrf_token"].(string)
	early := performRequest(t, reopened, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, early.Code, early.Body.String(), decodeResponse(t, early), http.StatusTooManyRequests, "acme_retry_cooldown")
	if afterRestart := storedACMERecord(t, reopened); afterRestart.State != afterSave.State || afterRestart.LastOutcome != "failed" || afterRestart.Revision != afterSave.Revision || !afterRestart.NextAttempt.Equal(afterSave.NextAttempt) {
		t.Fatalf("early retry after restart changed state: before=%#v after=%#v", afterSave, afterRestart)
	}

	now = now.Add(manualACMERetryCooldown)
	accepted := performRequest(t, reopened, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("manual retry after restart: %d %s", accepted.Code, accepted.Body.String())
	}
}

func TestACMEFailedRetryGuardsSurviveDisableAndEnable(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		return acmejob.Result{}, errors.New("test DNS API failure")
	}
	if err := s.processOneACME(context.Background()); err == nil {
		t.Fatal("initial failure ignored")
	}
	failed := storedACMERecord(t, s)
	disabled := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"disable": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", disabled.Code, disabled.Body.String())
	}
	enabled := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(),
	}, map[string]string{csrfHeader: csrf}, cookie)
	if enabled.Code != http.StatusAccepted {
		t.Fatalf("enable: %d %s", enabled.Code, enabled.Body.String())
	}
	afterEnable := storedACMERecord(t, s)
	if afterEnable.State != "configured" || afterEnable.LastOutcome != "failed" || !afterEnable.LastAttempt.Equal(failed.LastAttempt) || !afterEnable.NextAttempt.Equal(failed.NextAttempt) {
		t.Fatalf("disable/enable lost retry guards: before=%#v after=%#v", failed, afterEnable)
	}
	early := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	assertACMEError(t, early.Code, early.Body.String(), decodeResponse(t, early), http.StatusTooManyRequests, "acme_retry_cooldown")
	if acmeDue(afterEnable, now.Add(365*24*time.Hour)) || !afterEnable.NextAttempt.IsZero() || !afterEnable.manualRetryOnly() {
		t.Fatalf("disable/enable re-enabled an initial automatic retry: %#v", afterEnable)
	}
}

func TestACMELegacyFailedRecordAllowsOneManualRetry(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	legacy := decodeACMERecord(state["cdn-default"])
	legacy.State = "failed"
	legacy.LastOutcome = ""
	legacy.LastAttempt = time.Time{}
	legacy.NextAttempt = now.Add(automaticACMERetryDelay)
	state["cdn-default"] = legacy
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}

	response := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusAccepted {
		t.Fatalf("legacy manual retry: %d %s", response.Code, response.Body.String())
	}
	queued := storedACMERecord(t, s)
	if queued.State != "queued" || queued.LastOutcome != "failed" || !queued.NextAttempt.Equal(now) {
		t.Fatalf("legacy retry was not migrated: %#v", queued)
	}
}

func TestACMEInFlightAttemptKeepsAutomaticBackoffAfterSave(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	failed := decodeACMERecord(state["cdn-default"])
	failed.State = "failed"
	failed.LastOutcome = "failed"
	failed.LastAttempt = now.Add(-manualACMERetryCooldown)
	failed.NextAttempt = now.Add(automaticACMERetryDelay)
	state["cdn-default"] = failed
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}
	manual := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
		"settings": acmeTestSettings(), "issue": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if manual.Code != http.StatusAccepted {
		t.Fatalf("manual retry: %d %s", manual.Code, manual.Body.String())
	}
	started := now

	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		running := storedACMERecord(t, s)
		if running.State != "running" || running.LastOutcome != "running" || !running.LastAttempt.Equal(started) || !running.NextAttempt.Equal(started.Add(automaticACMERetryDelay)) {
			t.Fatalf("worker did not replace previous failure outcome: %#v", running)
		}
		now = now.Add(manualACMERetryCooldown + time.Second)
		saved := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
			"settings": acmeTestSettings(),
		}, map[string]string{csrfHeader: csrf}, cookie)
		if saved.Code != http.StatusAccepted {
			t.Fatalf("save during worker: %d %s", saved.Code, saved.Body.String())
		}
		beforeRetry := storedACMERecord(t, s)
		retry := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{
			"settings": acmeTestSettings(), "issue": true,
		}, map[string]string{csrfHeader: csrf}, cookie)
		assertACMEError(t, retry.Code, retry.Body.String(), decodeResponse(t, retry), http.StatusTooManyRequests, "acme_backoff")
		afterRetry := storedACMERecord(t, s)
		if afterRetry.Revision != beforeRetry.Revision || afterRetry.State != "configured" || afterRetry.LastOutcome != "running" || !afterRetry.NextAttempt.Equal(beforeRetry.NextAttempt) {
			t.Fatalf("manual retry changed in-flight replacement: before=%#v after=%#v", beforeRetry, afterRetry)
		}
		return acmejob.Result{}, errors.New("discarded due to configuration change")
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatalf("changed configuration should discard worker result: %v", err)
	}
}
func TestACMERejectsWrongNamesAndTrust(t *testing.T) {
	now := time.Now()
	result, roots := acmeTestPair(t, now, []string{"other.example.com"})
	if _, err := validateACMEPair(result, []string{"api.example.com"}, now, roots); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	if _, err := validateACMEPair(result, []string{"other.example.com"}, now, x509.NewCertPool()); err == nil {
		t.Fatal("untrusted cert accepted")
	}
}

func TestACMEManagedPairRequiresLiteralWildcardSAN(t *testing.T) {
	now := time.Now().UTC()
	wrong, _ := acmeTestPair(t, now, []string{"acme-check.example.com"})
	if acmePairCoversDomains(wrong.Certificate, wrong.PrivateKey, []string{"*.example.com"}) {
		t.Fatal("ordinary hostname was accepted as wildcard coverage")
	}
	wildcard, _ := acmeTestPair(t, now, []string{"*.example.com"})
	if !acmePairCoversDomains(wildcard.Certificate, wildcard.PrivateKey, []string{"*.example.com"}) {
		t.Fatal("literal wildcard SAN was not accepted")
	}
}

func TestRunACMEWorkerReturnsSafeContextFailures(t *testing.T) {
	original := acmeWorkerCommand
	marker := os.Args[0] + ".acme-worker-started"
	_ = os.Remove(marker)
	t.Cleanup(func() { _ = os.Remove(marker) })
	acmeWorkerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACMEWorkerProcessHelper$")
	}
	defer func() { acmeWorkerCommand = original }()
	start := func(ctx context.Context) <-chan error {
		done := make(chan error, 1)
		go func() {
			_, err := runACMEWorker(ctx, acmejob.Request{})
			done <- err
		}()
		deadline := time.Now().Add(time.Second)
		for {
			if _, err := os.Stat(marker); err == nil {
				return done
			}
			if time.Now().After(deadline) {
				t.Fatal("ACME helper did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Run("deadline after child start", func(t *testing.T) {
		_ = os.Remove(marker)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := <-start(ctx); !errors.Is(err, acmejob.ErrWorkerTimeout) {
			t.Fatalf("unsafe deadline result: %v", err)
		}
	})
	t.Run("cancel after child start", func(t *testing.T) {
		_ = os.Remove(marker)
		ctx, cancel := context.WithCancel(context.Background())
		done := start(ctx)
		cancel()
		if err := <-done; !errors.Is(err, acmejob.ErrWorkerCancel) {
			t.Fatalf("unsafe cancel result: %v", err)
		}
	})
}

func TestRunACMEWorkerPreservesContextFailureBeforeStart(t *testing.T) {
	original := acmeWorkerCommand
	acmeWorkerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACMEWorkerExitHelper$")
	}
	defer func() { acmeWorkerCommand = original }()

	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		if _, err := runACMEWorker(ctx, acmejob.Request{}); !errors.Is(err, acmejob.ErrWorkerTimeout) {
			t.Fatalf("deadline before start = %v", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := runACMEWorker(ctx, acmejob.Request{}); !errors.Is(err, acmejob.ErrWorkerCancel) {
			t.Fatalf("cancel before start = %v", err)
		}
	})
}

func TestRunACMEWorkerFallsBackForOldWorker(t *testing.T) {
	original := acmeWorkerCommand
	acmeWorkerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACMEWorkerExitHelper$")
	}
	defer func() { acmeWorkerCommand = original }()
	_, err := runACMEWorker(context.Background(), acmejob.Request{})
	if !errors.Is(err, acmejob.ErrCAValidation) {
		t.Fatalf("old worker exit did not retain fixed stage: %v", err)
	}
	if _, ok := acmejob.DiagnosticFromError(err); ok {
		t.Fatal("old worker without stdout received a diagnostic")
	}
}

// The real child process used by TestRunACMEWorkerReturnsSafeContextFailures.
// It has no network or secret input and runs only when the exact child flag is
// present; ordinary test runs return immediately.
func TestACMEWorkerProcessHelper(t *testing.T) {
	for _, argument := range os.Args[1:] {
		if argument == "-test.run=^TestACMEWorkerProcessHelper$" {
			if err := os.WriteFile(os.Args[0]+".acme-worker-started", []byte("started"), 0o600); err != nil {
				t.Fatal(err)
			}
			time.Sleep(10 * time.Second)
			return
		}
	}
}

// The old worker emitted no stdout on a nonzero exit. Keep that IPC fallback
// compatible without accepting an invented diagnostic.
func TestACMEWorkerExitHelper(t *testing.T) {
	for _, argument := range os.Args[1:] {
		if argument == "-test.run=^TestACMEWorkerExitHelper$" {
			os.Exit(acmejob.WorkerExitValidation)
		}
	}
}

func TestACMEDisableDuringIssueDiscardsResult(t *testing.T) {
	s := newTestServer(t)
	queueTestACME(t, s)
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		s.configMu.Lock()
		defer s.configMu.Unlock()
		state, _ := s.repository.auxiliary("acme")
		rec := decodeACMERecord(state["cdn-default"])
		rec.Settings.Enabled = false
		rec.Revision = "changed"
		state["cdn-default"] = rec
		_ = s.repository.saveAuxiliary("acme", state)
		result, roots := acmeTestPair(t, time.Now(), []string{"api.example.com"})
		s.acmeRoots = roots
		return result, nil
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.secrets.exists("tls-profiles/cdn-default/acme-bundle.pem") {
		t.Fatal("disabled job installed")
	}
}
func TestACMENginxFailureRestoresBundle(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	pair, roots := acmeTestPair(t, now, []string{"api.example.com"})
	s.acmeRoots = roots
	ref := "tls-profiles/cdn-default/acme-bundle.pem"
	old := pair.Certificate + pair.PrivateKey
	if err := s.secrets.write(ref, old, false); err != nil {
		t.Fatal(err)
	}
	config, _ := s.getDraft()
	p := acmeProfile(config, "cdn-default")
	p["certificate_secret_ref"], p["private_key_secret_ref"] = ref, ref
	_, _ = s.repository.saveDraft(config)
	path, _ := s.secrets.path(ref)
	nginx := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(nginx, []byte(path), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.runtime = &nativeRuntime{options: RuntimeOptions{NginxConfig: nginx}, controller: &recordingRuntimeController{}, nginxCommand: func(context.Context, ...string) error {
		calls++
		if calls == 1 {
			return errors.New("invalid nginx")
		}
		return nil
	}}
	newer, newRoots := acmeTestPair(t, now.Add(time.Minute), []string{"api.example.com"})
	s.acmeRoots = newRoots
	if s.installACMECertificate(context.Background(), "cdn-default", []string{"api.example.com"}, ref, newer, &acmeRecord{}) == nil {
		t.Fatal("reload failure ignored")
	}
	restored, _ := s.secrets.read(ref, true)
	if restored != strings.TrimSpace(old) || calls < 3 {
		t.Fatal("old pair/reload not restored")
	}
}
func TestACMEDueUsesLifetimeAndRequiresFirstClick(t *testing.T) {
	now := time.Now()
	rec := acmeRecord{Settings: acmeTestSettings(), State: "configured"}
	if acmeDue(rec, now) {
		t.Fatal("configuration alone issued certificate")
	}
	rec.Metadata = map[string]any{"not_before": now.Add(-5 * 24 * time.Hour).Format(time.RFC3339), "not_after": now.Add(2 * 24 * time.Hour).Format(time.RFC3339)}
	if !acmeDue(rec, now) {
		t.Fatal("short lifetime missed")
	}
	rec.Settings.Enabled = false
	if acmeDue(rec, now) {
		t.Fatal("disabled renewed")
	}
}

func TestACMEConfigurationRequiresSessionAndCSRF(t *testing.T) {
	s := newTestServer(t)
	url := apiPrefix + "/tls-profiles/cdn-default/acme"
	if r := performRequest(t, s, http.MethodGet, url, nil, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status: %d", r.Code)
	}
	cookie, csrf := bootstrapSession(t, s)
	body := map[string]any{"settings": acmeTestSettings(), "credentials": map[string]string{"token": "test-only"}}
	if r := performRequest(t, s, http.MethodPost, url, body, nil, cookie); r.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF: %d", r.Code)
	}
	if r := performRequest(t, s, http.MethodPost, url, body, map[string]string{csrfHeader: csrf}, cookie); r.Code != 202 {
		t.Fatalf("save: %d %s", r.Code, r.Body.String())
	}
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		t.Fatal("save must not issue a certificate")
		return acmejob.Result{}, nil
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTLSProfileEditRetainsAsyncIssuedPair(t *testing.T) {
	s := newTestServer(t)
	cookie, csrf := bootstrapSession(t, s)
	draft, _ := s.getDraft()
	p := acmeProfile(draft, "cdn-default")
	ref := "tls-profiles/cdn-default/acme-bundle.pem"
	p["certificate_secret_ref"], p["private_key_secret_ref"] = ref, ref
	p["certificate_metadata"] = map[string]any{"not_after": "2026-12-01T00:00:00Z"}
	_, _ = s.repository.saveDraft(draft)
	item := cloneJSONObject(p)
	delete(item, "certificate_secret_ref")
	delete(item, "private_key_secret_ref")
	delete(item, "certificate_metadata")
	item["display_name"] = "Renamed"
	r := performRequest(t, s, http.MethodPut, apiPrefix+"/tls-profiles/cdn-default", item, map[string]string{csrfHeader: csrf}, cookie)
	if r.Code != http.StatusOK {
		t.Fatalf("update: %d %s", r.Code, r.Body.String())
	}
	draft, _ = s.getDraft()
	p = acmeProfile(draft, "cdn-default")
	metadata, _ := p["certificate_metadata"].(map[string]any)
	if p["certificate_secret_ref"] != ref || p["private_key_secret_ref"] != ref || metadata["not_after"] != "2026-12-01T00:00:00Z" {
		t.Fatal("stale form dropped issued pair")
	}
}

func TestACMEUsesActiveDirectResolverAndDraftFallback(t *testing.T) {
	t.Run("active configuration wins over pending draft", func(t *testing.T) {
		s := newTestServer(t)
		now := time.Now().UTC()
		s.now = func() time.Time { return now }
		queueTestACME(t, s)
		draft, err := s.getDraft()
		if err != nil {
			t.Fatal(err)
		}
		active := cloneJSONObject(draft)
		revision, err := s.repository.stageGeneration(active)
		if err != nil || s.repository.setActiveRevision(revision) != nil {
			t.Fatalf("activate config: %v", err)
		}
		draftDNS := objectAt(draft, "dns")
		draftDNS["direct_resolver"] = map[string]any{"provider": "quad9", "protocol": "dot"}
		if _, err := s.repository.saveDraft(draft); err != nil {
			t.Fatal(err)
		}
		s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
			if req.RecursiveResolver.Type != "https" || req.RecursiveResolver.Server != "77.88.8.8" || req.RecursiveResolver.ServerName != "common.dot.dns.yandex.net" || req.RecursiveResolver.ServerPort != 443 {
				t.Fatalf("pending draft DNS leaked into active ACME job: %#v", req.RecursiveResolver)
			}
			result, roots := acmeTestPair(t, now, req.Settings.Domains)
			s.acmeRoots = roots
			return result, nil
		}
		if err := s.processOneACME(context.Background()); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("draft is used before the first active configuration", func(t *testing.T) {
		s := newTestServer(t)
		now := time.Now().UTC()
		s.now = func() time.Time { return now }
		queueTestACME(t, s)
		draft, err := s.getDraft()
		if err != nil {
			t.Fatal(err)
		}
		objectAt(draft, "dns")["direct_resolver"] = map[string]any{"provider": "quad9", "protocol": "dot"}
		if _, err := s.repository.saveDraft(draft); err != nil {
			t.Fatal(err)
		}
		s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
			if req.RecursiveResolver.Type != "tls" || req.RecursiveResolver.Server != "9.9.9.9" || req.RecursiveResolver.ServerName != "dns.quad9.net" || req.RecursiveResolver.ServerPort != 853 || req.RecursiveResolver.DoTFallback {
				t.Fatalf("draft resolver was not normalized: %#v", req.RecursiveResolver)
			}
			result, roots := acmeTestPair(t, now, req.Settings.Domains)
			s.acmeRoots = roots
			return result, nil
		}
		if err := s.processOneACME(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestACMEInvalidActiveResolverFailsJobWithBackoff(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	queueTestACME(t, s)
	draft, err := s.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	active := cloneJSONObject(draft)
	objectAt(active, "dns")["direct_resolver"] = map[string]any{"provider": "unsupported", "protocol": "doh"}
	revision, err := s.repository.stageGeneration(active)
	if err != nil || s.repository.setActiveRevision(revision) != nil {
		t.Fatalf("activate invalid test config: %v", err)
	}
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		t.Fatal("invalid active resolver reached worker")
		return acmejob.Result{}, nil
	}
	if err := s.processOneACME(context.Background()); err == nil {
		t.Fatal("invalid active resolver was ignored")
	}
	record := storedACMERecord(t, s)
	if record.State != "failed" || record.LastOutcome != "failed" || record.Message != "Не удалось подготовить доверенный DNS-резолвер ACME. Выпуск не выполнен. Повторите вручную." || !record.LastAttempt.Equal(now) || !record.NextAttempt.IsZero() || !record.manualRetryOnly() {
		t.Fatalf("resolver failure was not persisted safely: %#v", record)
	}
}
