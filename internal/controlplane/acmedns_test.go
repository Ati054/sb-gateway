package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func acmeDNSFixture() (acmejob.Settings, map[string]string) {
	s := acmeTestSettings()
	s.Provider = "acmedns"
	s.ACMEDNSServer = "https://auth.example.net"
	s.PropagationTimeoutMinutes = 90
	return s, map[string]string{"accounts": `{"api.example.com":{"username":"test-user","password":"test-dns-secret","subdomain":"record1","fulldomain":"record1.auth.example.net"}}`}
}

func TestACMEDNSCheckAuthIsolationAndSavedKeys(t *testing.T) {
	s := newTestServer(t)
	settings, credentials := acmeDNSFixture()
	body := map[string]any{"settings": settings, "credentials": credentials}
	url := apiPrefix + "/tls-profiles/acme-dns/check"
	if r := performRequest(t, s, "POST", url, body, nil); r.Code != http.StatusUnauthorized {
		t.Fatal("check needs session", r.Code)
	}
	cookie, csrf := bootstrapSession(t, s)
	headers := map[string]string{csrfHeader: csrf}
	if r := performRequest(t, s, "POST", url, body, nil, cookie); r.Code != http.StatusForbidden {
		t.Fatal("check needs CSRF", r.Code)
	}
	before, _ := s.getDraft()
	stateBefore, _ := s.repository.auxiliary("acme")
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		t.Fatal("check issued certificate")
		return acmejob.Result{}, nil
	}
	calls := 0
	s.acmeDNSLookup = func(_ context.Context, name string) (string, error) {
		calls++
		if name != "_acme-challenge.api.example.com." {
			t.Fatal("unexpected query", name)
		}
		return "record1.auth.example.net.", nil
	}
	if r := performRequest(t, s, "POST", url, body, headers, cookie); r.Code != 200 || !strings.Contains(r.Body.String(), "record1.auth.example.net") || strings.Contains(r.Body.String(), "test-dns-secret") {
		t.Fatal("check failed or leaked", r.Code)
	}
	after, _ := s.getDraft()
	stateAfter, _ := s.repository.auxiliary("acme")
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(stateBefore, stateAfter) || s.secrets.exists("acme/cdn-default/dns.json") {
		t.Fatal("read-only check mutated storage")
	}
	configure := apiPrefix + "/tls-profiles/cdn-default/acme"
	if r := performRequest(t, s, "POST", configure, body, headers, cookie); r.Code != 202 {
		t.Fatal("save", r.Code, r.Body.String())
	}
	status := performRequest(t, s, "GET", configure, nil, nil, cookie)
	if status.Code != 200 || !strings.Contains(status.Body.String(), "_acme-challenge.api.example.com") || strings.Contains(status.Body.String(), "test-dns-secret") || strings.Contains(status.Body.String(), "test-user") || strings.Contains(status.Body.String(), "credentials_ref") {
		t.Fatal("unsafe status")
	}
	delete(body, "credentials")
	body["profile_id"] = "cdn-default"
	if r := performRequest(t, s, "POST", url, body, headers, cookie); r.Code != 200 {
		t.Fatal("saved keys check", r.Code)
	}
	settings.ACMEDNSServer = "https://changed.example.net"
	body["settings"] = settings
	for _, endpoint := range []string{url, configure} {
		if r := performRequest(t, s, "POST", endpoint, body, headers, cookie); r.Code != 422 {
			t.Fatal("reused keys on changed server", r.Code)
		}
	}
	if calls != 2 {
		t.Fatal("invalid configuration reached DNS", calls)
	}
	settings, _ = acmeDNSFixture()
	body["settings"] = settings
	s.acmeDNSLookup = func(context.Context, string) (string, error) { return "", errors.New("upstream test-dns-secret") }
	if r := performRequest(t, s, "POST", url, body, headers, cookie); r.Code != 422 || strings.Contains(r.Body.String(), "test-dns-secret") {
		t.Fatal("unsafe DNS failure", r.Code)
	}
	settings.Domains = append(settings.Domains, "msk.example.com")
	body["settings"] = settings
	if r := performRequest(t, s, "POST", configure, body, headers, cookie); r.Code != 422 {
		t.Fatal("saved account did not cover SAN")
	}
}

func TestACMEDNSCheckOnlyValidatesProviderFields(t *testing.T) {
	s := newTestServer(t)
	settings, credentials := acmeDNSFixture()
	settings.Email = ""
	settings.TermsAccepted = false
	cookie, csrf := bootstrapSession(t, s)
	url := apiPrefix + "/tls-profiles/acme-dns/check"
	lookupCalls := 0
	s.acmeDNSLookup = func(_ context.Context, name string) (string, error) {
		lookupCalls++
		if name != "_acme-challenge.api.example.com." {
			t.Fatalf("unexpected query %q", name)
		}
		return "record1.auth.example.net.", nil
	}
	body := map[string]any{"settings": settings, "credentials": credentials}
	if response := performRequest(t, s, http.MethodPost, url, body, map[string]string{csrfHeader: csrf}, cookie); response.Code != http.StatusOK {
		t.Fatalf("CNAME check incorrectly required issuance consent: %d %s", response.Code, response.Body.String())
	}
	settings.PropagationTimeoutMinutes = 1441
	body["settings"] = settings
	if response := performRequest(t, s, http.MethodPost, url, body, map[string]string{csrfHeader: csrf}, cookie); response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("CNAME check accepted malformed timeout: %d %s", response.Code, response.Body.String())
	}
	if lookupCalls != 1 {
		t.Fatalf("invalid timeout reached DNS: %d calls", lookupCalls)
	}
}

func TestACMEDNSRenewalFailureAndEncryptedTransfer(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	settings, credentials := acmeDNSFixture()
	cookie, csrf := bootstrapSession(t, s)
	r := performRequest(t, s, "POST", apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": settings, "credentials": credentials, "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
	if r.Code != 202 {
		t.Fatal("configure", r.Code, r.Body.String())
	}
	calls := 0
	s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
		calls++
		if !reflect.DeepEqual(req.Settings, settings) || !reflect.DeepEqual(req.Credentials, credentials) {
			t.Fatal("lost ACME-DNS inputs")
		}
		pair, roots := acmeTestPair(t, now, req.Settings.Domains)
		s.acmeRoots = roots
		return pair, nil
	}
	s.applyRouterOS = func(context.Context, map[string]any, string, string, func(context.Context) error, func(context.Context, routeros.BackupRef) error) (routerOSApplyOutput, error) {
		t.Fatal("ACME changed RouterOS")
		return routerOSApplyOutput{}, nil
	}
	if err := s.processOneACME(context.Background()); err != nil {
		t.Fatal(err)
	}
	ref := "tls-profiles/cdn-default/acme-bundle.pem"
	first, _ := s.secrets.read(ref, true)
	now = now.Add(62 * 24 * time.Hour)
	if err := s.processOneACME(context.Background()); err != nil || calls != 2 {
		t.Fatal("automatic renewal", err, calls)
	}
	second, _ := s.secrets.read(ref, true)
	if first == second {
		t.Fatal("certificate not renewed")
	}
	login := performRequest(t, s, "POST", apiPrefix+"/auth/login", map[string]any{"username": "admin", "password": "panel-password-123"}, nil)
	if login.Code != 200 {
		t.Fatal("renewed session", login.Code)
	}
	cookie, csrf = login.Result().Cookies()[0], decodeResponse(t, login)["csrf_token"].(string)
	archive := transferTestExport(t, s, cookie, csrf)
	target := newTestServer(t)
	tc, token := bootstrapSession(t, target)
	r = performRequest(t, target, "POST", apiPrefix+"/tls-profiles/import", map[string]any{"password": transferTestPassword, "archive": archive}, map[string]string{csrfHeader: token}, tc)
	if r.Code != 200 {
		t.Fatal("transfer", r.Code, r.Body.String())
	}
	var result struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &result)
	state, _ := target.repository.auxiliary("acme")
	record := decodeACMERecord(state[result.ID])
	if record.Settings.Enabled || record.State != "disabled" || record.Settings.ACMEDNSServer != settings.ACMEDNSServer || record.Settings.Provider != "acmedns" || record.Settings.PropagationTimeoutMinutes != settings.PropagationTimeoutMinutes {
		t.Fatal("transfer configuration changed or activated")
	}
	secret, err := target.secrets.read(record.CredentialsRef, true)
	if err != nil {
		t.Fatal(err)
	}
	var imported map[string]string
	_ = json.Unmarshal([]byte(secret), &imported)
	if !reflect.DeepEqual(imported, credentials) {
		t.Fatal("transfer dropped registration")
	}
	// Re-enable explicitly on the target; subsequent scheduled jobs retain all inputs.
	record.Settings.Enabled = true
	record.State = "queued"
	state[result.ID] = record
	if err := target.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}
	target.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
		if !reflect.DeepEqual(req.Credentials, credentials) || req.Settings.ACMEDNSServer != settings.ACMEDNSServer || req.Settings.PropagationTimeoutMinutes != settings.PropagationTimeoutMinutes || !strings.Contains(req.AccountKey, "PRIVATE KEY") {
			t.Fatal("target lost renewal inputs")
		}
		pair, roots := acmeTestPair(t, time.Now(), req.Settings.Domains)
		target.acmeRoots = roots
		return pair, nil
	}
	if err := target.processOneACME(context.Background()); err != nil {
		t.Fatal("target renewal", err)
	}
	now = now.Add(62 * 24 * time.Hour)
	failures := 0
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		failures++
		return acmejob.Result{}, acmejob.ErrDelegation
	}
	if err := s.processOneACME(context.Background()); !errors.Is(err, acmejob.ErrDelegation) {
		t.Fatal("delegation failure lost", err)
	}
	_ = s.processOneACME(context.Background())
	retained, _ := s.secrets.read(ref, true)
	state, _ = s.repository.auxiliary("acme")
	record = decodeACMERecord(state["cdn-default"])
	if failures != 1 || retained != second || !strings.HasPrefix(record.Message, acmejob.ErrDelegation.Error()) || !record.NextAttempt.After(now) {
		t.Fatal("CNAME failure did not preserve certificate/backoff")
	}
}

func TestACMEDNSPropagationTimeoutInputValidation(t *testing.T) {
	settings, credentials := acmeDNSFixture()
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]any
	if err := json.Unmarshal(encoded, &base); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		value any
		code  int
	}{
		"automatic": {value: 0, code: http.StatusAccepted},
		"minimum":   {value: 1, code: http.StatusAccepted},
		"maximum":   {value: 1440, code: http.StatusAccepted},
		"negative":  {value: -1, code: http.StatusUnprocessableEntity},
		"too large": {value: 1441, code: http.StatusUnprocessableEntity},
		"fraction":  {value: 1.5, code: http.StatusUnprocessableEntity},
		"text":      {value: "90", code: http.StatusUnprocessableEntity},
	} {
		t.Run(name, func(t *testing.T) {
			s := newTestServer(t)
			cookie, csrf := bootstrapSession(t, s)
			candidate := map[string]any{}
			for key, value := range base {
				candidate[key] = value
			}
			candidate["propagation_timeout_minutes"] = test.value
			body := map[string]any{"settings": candidate, "credentials": credentials}
			response := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", body, map[string]string{csrfHeader: csrf}, cookie)
			if response.Code != test.code {
				t.Fatalf("configure: %d %s", response.Code, response.Body.String())
			}
			if test.code == http.StatusAccepted {
				record := storedACMERecord(t, s)
				if record.Settings.PropagationTimeoutMinutes != test.value.(int) {
					t.Fatalf("timeout not persisted: %#v", record.Settings)
				}
			}
		})
	}

	s := newTestServer(t)
	cookie, csrf := bootstrapSession(t, s)
	direct := acmeTestSettings()
	direct.PropagationTimeoutMinutes = 90
	response := performRequest(t, s, http.MethodPost, apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": direct, "credentials": map[string]string{"token": "test-dns-secret"}}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("direct provider accepted ACME-DNS timeout: %d %s", response.Code, response.Body.String())
	}
}
