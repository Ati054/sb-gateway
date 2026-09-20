package acmejob

import (
	"encoding/json"
	"strings"
	"testing"
)

func dnsSettings() Settings {
	return Settings{Enabled: true, Provider: "acmedns", ACMEDNSServer: "https://auth.example.net/api/", Email: "admin@example.com", TermsAccepted: true, Domains: []string{"api.example.com", "*.api.example.com"}}
}

func dnsCredentials(accounts map[string]ACMEDNSAccount) map[string]string {
	data, _ := json.Marshal(accounts)
	return map[string]string{"accounts": string(data)}
}

func TestACMEDNSURL(t *testing.T) {
	for _, address := range []string{"https://auth.example.net", "https://auth.example.net/", "https://auth.example.net:8443/api/"} {
		if err := ValidateACMEDNSURL(address); err != nil {
			t.Fatalf("valid URL: %s: %v", address, err)
		}
	}
	for _, address := range []string{"", "http://auth.example.net", "https://u:secret@auth.example.net", "https://auth.example.net?", "https://auth.example.net?q=key", "https://auth.example.net/#key", "https://auth.example.net#", "https://auth.example.net:", "https://127.0.0.1", "https://[::1]", "https://localhost", "https://auth.example.net/a/../b", "https://auth.example.net//api", "https://auth.example.net/%2e", "https://auth.example.net:65536", "https://auth.example.net:0", "https://auth.example.net\\evil"} {
		if err := ValidateACMEDNSURL(address); err == nil {
			t.Fatalf("unsafe URL accepted: %s", address)
		}
	}
}

func TestACMEDNSAccountAndDomainContract(t *testing.T) {
	s := dnsSettings()
	a := ACMEDNSAccount{Username: "synthetic-user", Password: "synthetic-secret", Subdomain: "record1", FullDomain: "record1.auth.example.net"}
	credentials := dnsCredentials(map[string]ACMEDNSAccount{"api.example.com": a})
	if err := ValidateConfiguration(s, credentials); err != nil {
		t.Fatal(err)
	}
	records, err := ACMEDNSDelegations(s, credentials)
	if err != nil || len(records) != 1 || records[0].Name != "_acme-challenge.api.example.com" || records[0].Target != a.FullDomain {
		t.Fatal("wildcard delegation", records, err)
	}
	s.Domains = append(s.Domains, "msk.example.com")
	if ValidateConfiguration(s, credentials) == nil {
		t.Fatal("missing SAN account accepted")
	}
	if _, err := ACMEDNSAccounts(dnsCredentials(map[string]ACMEDNSAccount{"api.example.com": a, "msk.example.com": a})); err == nil {
		t.Fatal("shared rotating TXT slots accepted")
	}
	b := a
	b.Subdomain = "record2"
	b.FullDomain = "record2.auth.example.net"
	credentials = dnsCredentials(map[string]ACMEDNSAccount{"api.example.com": a, "msk.example.com": b})
	if err := ValidateConfiguration(s, credentials); err != nil {
		t.Fatal(err)
	}
	s.Domains = []string{"api.example.com"}
	if ValidateConfiguration(s, credentials) == nil {
		t.Fatal("extra account accepted")
	}
	s.Provider = "gcore"
	if Validate(s) == nil {
		t.Fatal("foreign provider URL accepted")
	}
	for _, mutate := range []func(*ACMEDNSAccount){
		func(a *ACMEDNSAccount) { a.Password = "" }, func(a *ACMEDNSAccount) { a.Password = "secret\r\nInjected: yes" },
		func(a *ACMEDNSAccount) { a.Password = " secret " }, func(a *ACMEDNSAccount) { a.Username = "bad user" },
		func(a *ACMEDNSAccount) { a.Subdomain = "../bad" }, func(a *ACMEDNSAccount) { a.FullDomain = "other.auth.example.net" },
	} {
		bad := a
		mutate(&bad)
		if _, err := ACMEDNSAccounts(dnsCredentials(map[string]ACMEDNSAccount{"api.example.com": bad})); err == nil {
			t.Fatal("invalid account accepted")
		}
	}
	for _, value := range []string{"null", "{}", "[]", "secret-invalid-json", credentials["accounts"] + "{}", strings.Replace(credentials["accounts"], `"username":`, `"extra":"secret","username":`, 1), strings.Repeat("x", 20481)} {
		_, err := ACMEDNSAccounts(map[string]string{"accounts": value})
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid or leaking validation", err)
		}
	}
}
