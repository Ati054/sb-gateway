package controlplane

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

const transferTestPassword = "synthetic-test-passphrase"

func TestTLSProfileIDAcceptsEveryTokenSuffix(t *testing.T) {
	for _, token := range []string{"abcdefghijklmn-_", "ABCDEFGHIJKLMNOP", "0123456789abcdef"} {
		id := tlsTransferProfileID(token)
		if !entityIDPattern.MatchString(id) {
			t.Fatalf("invalid generated profile ID %q", id)
		}
	}
}

func TestTLSProfileEnvelope(t *testing.T) {
	plain := []byte(`{"certificate":"private-test-material"}`)
	a, err := sealTLSProfile(plain, transferTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := sealTLSProfile(plain, transferTestPassword)
	if bytes.Equal(a, b) || bytes.Contains(a, plain) {
		t.Fatal("not randomized or plaintext")
	}
	opened, err := openTLSProfile(a, transferTestPassword)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatal("round trip", err)
	}
	if _, err := openTLSProfile(a, "wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	for _, offset := range []int{0, len(tlsTransferMagic), len(a) - 1} {
		bad := append([]byte(nil), a...)
		bad[offset] ^= 1
		if _, err := openTLSProfile(bad, transferTestPassword); err == nil {
			t.Fatal("tampered archive accepted")
		}
	}
	for _, bad := range [][]byte{nil, a[:10], append(a, 0), make([]byte, tlsTransferLimit+100)} {
		if _, err := openTLSProfile(bad, transferTestPassword); err == nil {
			t.Fatal("malformed archive accepted")
		}
	}
}

func transferTestExport(t *testing.T, s *Server, cookie *http.Cookie, csrf string) string {
	t.Helper()
	r := performRequest(t, s, "POST", apiPrefix+"/tls-profiles/cdn-default/export", map[string]any{"password": transferTestPassword}, map[string]string{csrfHeader: csrf}, cookie)
	if r.Code != 200 {
		t.Fatalf("export %d %s", r.Code, r.Body.String())
	}
	if strings.Contains(r.Body.String(), "PRIVATE KEY") || strings.Contains(r.Body.String(), "test-dns-secret") {
		t.Fatal("secret returned in plaintext")
	}
	var body struct {
		Archive string `json:"archive"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Archive
}
func transferTestSource(t *testing.T, acme bool) (*Server, *http.Cookie, string) {
	t.Helper()
	s := newTestServer(t)
	cookie, csrf := bootstrapSession(t, s)
	if acme {
		r := performRequest(t, s, "POST", apiPrefix+"/tls-profiles/cdn-default/acme", map[string]any{"settings": acmeTestSettings(), "credentials": map[string]string{"token": "test-dns-secret"}, "issue": true}, map[string]string{csrfHeader: csrf}, cookie)
		if r.Code != 202 {
			t.Fatal(r.Code, r.Body.String())
		}
		s.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
			p, roots := acmeTestPair(t, time.Now(), req.Settings.Domains)
			s.acmeRoots = roots
			return p, nil
		}
		if err := s.processOneACME(context.Background()); err != nil {
			t.Fatal(err)
		}
	} else {
		p, _ := acmeTestPair(t, time.Now(), []string{"api.example.com"})
		draft, _ := s.getDraft()
		profile := acmeProfile(draft, "cdn-default")
		profile["certificate_secret_ref"] = "tls-profiles/cdn-default/certificate.pem"
		profile["private_key_secret_ref"] = "tls-profiles/cdn-default/private-key.pem"
		if err := s.secrets.write(subscriptionText(profile["certificate_secret_ref"]), p.Certificate, true); err != nil {
			t.Fatal(err)
		}
		if err := s.secrets.write(subscriptionText(profile["private_key_secret_ref"]), p.PrivateKey, true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.repository.saveDraft(draft); err != nil {
			t.Fatal(err)
		}
	}
	return s, cookie, csrf
}

func TestTLSProfileTransferIsolatedAndRenewable(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(map[bool]string{false: "manual", true: "acme"}[managed], func(t *testing.T) {
			s, cookie, csrf := transferTestSource(t, managed)
			archive := transferTestExport(t, s, cookie, csrf)
			target := newTestServer(t)
			tc, token := bootstrapSession(t, target)
			before, _ := target.getDraft()
			activeBefore, _ := target.repository.loadActive()
			r := performRequest(t, target, "POST", apiPrefix+"/tls-profiles/import", map[string]any{"password": transferTestPassword, "archive": archive}, map[string]string{csrfHeader: token}, tc)
			if r.Code != 200 {
				t.Fatalf("import %d %s", r.Code, r.Body.String())
			}
			var result struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(r.Body.Bytes(), &result)
			after, _ := target.getDraft()
			p := acmeProfile(after, result.ID)
			if p == nil || p["enabled"] != false || result.ID == "cdn-default" {
				t.Fatal("must create a disabled isolated profile")
			}
			oldProfiles := before["tls_profiles"].([]any)
			newProfiles := after["tls_profiles"].([]any)
			if !reflect.DeepEqual(oldProfiles, newProfiles[:len(oldProfiles)]) {
				t.Fatal("existing profiles changed")
			}
			for _, key := range []string{"policies", "transports", "ingress", "networks", "remote_users"} {
				if !reflect.DeepEqual(before[key], after[key]) {
					t.Fatalf("unrelated %s changed", key)
				}
			}
			activeAfter, _ := target.repository.loadActive()
			if !reflect.DeepEqual(activeBefore, activeAfter) {
				t.Fatal("active config changed")
			}
			cert, _ := target.secrets.read(subscriptionText(p["certificate_secret_ref"]), true)
			key, _ := target.secrets.read(subscriptionText(p["private_key_secret_ref"]), true)
			if _, err := tlsCertificateMetadata(cert, key); err != nil {
				t.Fatal(err)
			}
			state, _ := target.repository.auxiliary("acme")
			if managed {
				rec := decodeACMERecord(state[result.ID])
				if rec.Settings.Enabled || rec.State != "disabled" || acmeDue(rec, time.Now().Add(365*24*time.Hour)) {
					t.Fatal("import started renewal")
				}
				secret, _ := target.secrets.read(rec.CredentialsRef, true)
				account, _ := target.secrets.read("acme/"+result.ID+"/account.pem", true)
				if !strings.Contains(secret, "test-dns-secret") || !strings.Contains(account, "PRIVATE KEY") {
					t.Fatal("ACME credentials/account missing")
				}
				// Reopen persistent state, then enable the imported managed pair. A
				// legacy record has no intent yet: its verified pair and metadata must
				// make an overdue renewal eligible without a manual queue operation.
				reopened, err := NewServer(target.opts)
				if err != nil {
					t.Fatal(err)
				}
				renewalNow := time.Now().UTC().Add(62 * 24 * time.Hour)
				reopened.now = func() time.Time { return renewalNow }
				p["enabled"] = true
				if _, err := reopened.repository.saveDraft(after); err != nil {
					t.Fatal(err)
				}
				rec.Settings.Enabled = true
				rec.State = "configured"
				state[result.ID] = rec
				if err := reopened.repository.saveAuxiliary("acme", state); err != nil {
					t.Fatal(err)
				}
				calls := 0
				reopened.issueACME = func(_ context.Context, req acmejob.Request) (acmejob.Result, error) {
					calls++
					if req.AccountKey != account || req.Credentials["token"] != "test-dns-secret" {
						t.Fatal("lost renewal inputs")
					}
					pair, roots := acmeTestPair(t, renewalNow, req.Settings.Domains)
					reopened.acmeRoots = roots
					return pair, nil
				}
				if err := reopened.processOneACME(context.Background()); err != nil || calls != 1 {
					t.Fatal("renewal failed", err, calls)
				}
			} else if _, exists := state[result.ID]; exists {
				t.Fatal("manual profile gained ACME")
			}
		})
	}
}

func TestTLSProfileTransferPreservesLocalCA(t *testing.T) {
	source := newTestServer(t)
	cookie, csrf := bootstrapSession(t, source)
	created := performRequest(t, source, http.MethodPost, apiPrefix+"/tls-profiles", map[string]any{
		"item": map[string]any{
			"id": "private-pin", "display_name": "Private pin", "enabled": true,
			"certificate_source": "local-ca", "local_ca_server_name": "cover.example.test",
			"generate_local_ca": true,
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("local CA create failed: %d %s", created.Code, created.Body.String())
	}
	exported := performRequest(t, source, http.MethodPost, apiPrefix+"/tls-profiles/private-pin/export", map[string]any{
		"password": transferTestPassword,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if exported.Code != http.StatusOK {
		t.Fatalf("local CA export failed: %d %s", exported.Code, exported.Body.String())
	}
	archive := decodeResponse(t, exported)["archive"]

	target := newTestServer(t)
	targetCookie, targetCSRF := bootstrapSession(t, target)
	imported := performRequest(t, target, http.MethodPost, apiPrefix+"/tls-profiles/import", map[string]any{
		"password": transferTestPassword, "archive": archive,
	}, map[string]string{csrfHeader: targetCSRF}, targetCookie)
	if imported.Code != http.StatusOK {
		t.Fatalf("local CA import failed: %d %s", imported.Code, imported.Body.String())
	}
	result := decodeResponse(t, imported)
	id := result["id"].(string)
	draft, err := target.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	profile := acmeProfile(draft, id)
	if profile == nil || profile["certificate_source"] != "local-ca" || profile["local_ca_server_name"] != "cover.example.test" {
		t.Fatalf("imported local CA profile = %#v", profile)
	}
	bundle := localCABundle{}
	bundle.certificate, _ = target.secrets.read(subscriptionText(profile["certificate_secret_ref"]), true)
	bundle.privateKey, _ = target.secrets.read(subscriptionText(profile["private_key_secret_ref"]), true)
	bundle.rootCertificate, _ = target.secrets.read(subscriptionText(profile["local_ca_certificate_secret_ref"]), true)
	bundle.rootPrivateKey, _ = target.secrets.read(subscriptionText(profile["local_ca_private_key_secret_ref"]), true)
	if err := validateLocalCABundle(bundle, "cover.example.test", target.now()); err != nil {
		t.Fatal(err)
	}
}

func TestTLSProfileTransferRejectsUnsafeInputs(t *testing.T) {
	s, cookie, csrf := transferTestSource(t, true)
	archive := transferTestExport(t, s, cookie, csrf)
	before, _ := s.getDraft()
	stateBefore, _ := s.repository.auxiliary("acme")
	for _, endpoint := range []string{"/tls-profiles/import", "/tls-profiles/cdn-default/export"} {
		body := map[string]any{"password": transferTestPassword, "archive": archive}
		for _, auth := range []bool{false, true} {
			var cookies []*http.Cookie
			if auth {
				cookies = append(cookies, cookie)
			}
			r := performRequest(t, s, "POST", apiPrefix+endpoint, body, nil, cookies...)
			if r.Code != 401 && r.Code != 403 {
				t.Fatalf("missing auth/CSRF accepted: %d", r.Code)
			}
		}
	}
	for _, body := range []map[string]any{
		{"password": "short", "archive": archive},
		{"password": "wrong-but-long-password", "archive": archive},
		{"password": transferTestPassword, "archive": "bad"},
	} {
		r := performRequest(t, s, "POST", apiPrefix+"/tls-profiles/import", body, map[string]string{csrfHeader: csrf}, cookie)
		if r.Code != 422 {
			t.Fatal(r.Code, r.Body.String())
		}
	}
	blob, _ := base64.StdEncoding.DecodeString(archive)
	plain, _ := openTLSProfile(blob, transferTestPassword)
	var payload map[string]any
	_ = json.Unmarshal(plain, &payload)
	for _, mutate := range []func(map[string]any){
		func(p map[string]any) { p["certificate_secret_ref"] = "../session.key" },
		func(p map[string]any) { p["version"] = 2 },
		func(p map[string]any) { p["private_key"] = "invalid" },
		func(p map[string]any) {
			p["acme"].(map[string]any)["settings"].(map[string]any)["domains"] = []string{"wrong.example.com"}
		},
	} {
		var p map[string]any
		_ = json.Unmarshal(plain, &p)
		mutate(p)
		encoded, _ := json.Marshal(p)
		sealed, _ := sealTLSProfile(encoded, transferTestPassword)
		r := performRequest(t, s, "POST", apiPrefix+"/tls-profiles/import", map[string]any{"password": transferTestPassword, "archive": base64.StdEncoding.EncodeToString(sealed)}, map[string]string{csrfHeader: csrf}, cookie)
		if r.Code != 422 {
			t.Fatal("unsafe payload accepted", r.Code, r.Body.String())
		}
	}
	after, _ := s.getDraft()
	stateAfter, _ := s.repository.auxiliary("acme")
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(stateBefore, stateAfter) {
		t.Fatal("failed import changed state")
	}
}

func TestTLSProfileImportRejectsUnavailableState(t *testing.T) {
	s, cookie, csrf := transferTestSource(t, true)
	archive := transferTestExport(t, s, cookie, csrf)
	target := newTestServer(t)
	tc, token := bootstrapSession(t, target)
	// A damaged destination state is rejected before any secret is written.
	before, _ := target.getDraft()
	blocked := filepath.Join(target.opts.StateDir, "acme.json")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	r := performRequest(t, target, "POST", apiPrefix+"/tls-profiles/import", map[string]any{"password": transferTestPassword, "archive": archive}, map[string]string{csrfHeader: token}, tc)
	if r.Code != 500 {
		t.Fatal("expected storage failure", r.Code)
	}
	after, _ := target.getDraft()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed persistence changed draft")
	}
	var leaked bool
	_ = filepath.WalkDir(target.opts.SecretsDir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(filepath.ToSlash(path), "tls-import-") {
			leaked = true
		}
		return err
	})
	if leaked {
		t.Fatal("failed import leaked secrets")
	}
}
