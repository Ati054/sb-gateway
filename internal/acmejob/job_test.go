package acmejob

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func TestYandexRenewableCredentials(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"id": "synthetickey", "service_account_id": "syntheticaccount", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	values := map[string]string{"folder_id": "syntheticfolder", "service_account_key": string(raw)}
	if err := ValidateCredentials("yandexcloud", values); err != nil {
		t.Fatal(err)
	}
	if err := Validate(Settings{Provider: "yandexcloud", Email: "test@example.com", Domains: []string{"api.example.com"}, TermsAccepted: true}); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"IAM-short-lived-token", `{}`, `{"id":"key","service_account_id":"account","private_key":"broken"}`} {
		values["service_account_key"] = invalid
		if ValidateCredentials("yandexcloud", values) == nil {
			t.Fatal("invalid or nonrenewable key accepted")
		}
	}
	if ValidateCredentials("unknown", map[string]string{"token": "anything"}) == nil {
		t.Fatal("unknown provider accepted")
	}
}

func TestValidation(t *testing.T) {
	base := Settings{Enabled: true, Provider: "gcore", Email: "admin@example.com", Domains: []string{"api.example.com", "*.msk.example.com"}, TermsAccepted: true}
	if err := Validate(base); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"127.0.0.1", "https://example.com", "example.com;bad", "*.com", "EXAMPLE.COM", "example.com\n"} {
		copy := base
		copy.Domains = []string{domain}
		if Validate(copy) == nil {
			t.Fatalf("accepted %q", domain)
		}
	}
	for _, provider := range []string{"gcore", "regru", "cloudflare"} {
		values := map[string]string{"token": "token"}
		if provider == "regru" {
			values = map[string]string{"username": "user", "password": "password"}
		}
		if err := ValidateCredentials(provider, values); err != nil {
			t.Fatal(err)
		}
		values["unexpected"] = "secret"
		if ValidateCredentials(provider, values) == nil {
			t.Fatal("unknown credential accepted")
		}
	}
	base.TermsAccepted = false
	if Validate(base) == nil {
		t.Fatal("terms not required")
	}
}

func TestACMEDNSPropagationTimeoutValidation(t *testing.T) {
	base := Settings{Enabled: true, Provider: "acmedns", ACMEDNSServer: "https://auth.example.net", Email: "admin@example.com", Domains: []string{"api.example.com"}, TermsAccepted: true}
	for _, minutes := range []int{0, 1, 1440} {
		settings := base
		settings.PropagationTimeoutMinutes = minutes
		if err := Validate(settings); err != nil {
			t.Fatalf("ACME-DNS %d minutes rejected: %v", minutes, err)
		}
	}
	for _, minutes := range []int{-1, 1441} {
		settings := base
		settings.PropagationTimeoutMinutes = minutes
		if Validate(settings) == nil {
			t.Fatalf("ACME-DNS %d minutes accepted", minutes)
		}
	}
	for _, provider := range []string{"regru", "gcore", "cloudflare", "yandexcloud"} {
		settings := base
		settings.Provider = provider
		settings.ACMEDNSServer = ""
		settings.PropagationTimeoutMinutes = 90
		if Validate(settings) == nil {
			t.Fatalf("%s accepted ACME-DNS timeout", provider)
		}
	}
}

func TestRecursiveResolverValidationFailsClosed(t *testing.T) {
	validDoH := RecursiveResolver{Type: "https", Server: "77.88.8.8", ServerName: "common.dot.dns.yandex.net", ServerPort: 443, Path: "/dns-query", DoTFallback: true}
	validDoT := RecursiveResolver{Type: "tls", Server: "9.9.9.9", ServerName: "dns.quad9.net", ServerPort: 853}
	for name, resolver := range map[string]RecursiveResolver{
		"DoH": validDoH,
		"DoT": validDoT,
	} {
		if err := resolver.Validate(); err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
	}
	for name, resolver := range map[string]RecursiveResolver{
		"missing":        {},
		"plain DNS":      {Type: "udp", Server: "77.88.8.8", ServerName: "common.dot.dns.yandex.net", ServerPort: 53},
		"untrusted path": {Type: "https", Server: "77.88.8.8", ServerName: "common.dot.dns.yandex.net", ServerPort: 443, Path: "/other"},
		"DoT fallback":   {Type: "tls", Server: "9.9.9.9", ServerName: "dns.quad9.net", ServerPort: 853, DoTFallback: true},
	} {
		if err := resolver.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestDiagnosticEnvelopeIsStrictAndBackwardCompatible(t *testing.T) {
	diagnostic := Diagnostic{Version: diagnosticVersion, ExitCode: WorkerExitValidation, Stage: "after_dns_check", Category: "ca_rate_limited", HTTPStatus: 429, RetryAfterSeconds: 3600}
	body, err := EncodeDiagnostic(diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, ok := DecodeDiagnostic(body, WorkerExitValidation); !ok || decoded != diagnostic {
		t.Fatalf("valid diagnostic rejected: %#v %t", decoded, ok)
	}
	for _, malicious := range [][]byte{
		[]byte(`{"diagnostic":{"version":1,"exit_code":5,"stage":"after_dns_check","category":"ca_rate_limited","detail":"secret-token"}}`),
		[]byte(`{"diagnostic":{"version":1,"exit_code":6,"stage":"before_dns_check","category":"ca_rate_limited"}}`),
		[]byte(`{"diagnostic":{"version":1,"exit_code":4,"stage":"after_dns_check","category":"ca_rate_limited"}}`),
		[]byte(`{"diagnostic":{"version":1,"exit_code":5,"stage":"after_dns_check","category":"not-allowlisted"}}`),
		[]byte(`not JSON`),
		nil, // The old worker produced no stdout on failure.
	} {
		if _, ok := DecodeDiagnostic(malicious, WorkerExitValidation); ok {
			t.Fatalf("unsafe diagnostic accepted: %q", malicious)
		}
	}
}
