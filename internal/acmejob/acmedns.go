package acmejob

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var ErrDelegation = errors.New("ACME-DNS: проверьте CNAME для всех доменов сертификата.")

type ACMEDNSAccount struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"`
}
type Delegation struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Target string `json:"target"`
}

func ValidateACMEDNSURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || len(value) > 2048 || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Hostname() == "" || len(u.Hostname()) > 253 || strings.HasSuffix(u.Host, ":") || !hostname.MatchString(u.Hostname()) || net.ParseIP(u.Hostname()) != nil || strings.ContainsAny(value, "\\%?#\r\n\x00") {
		return errors.New("Укажите HTTPS-адрес ACME-DNS без пароля, параметров и IP-адреса.")
	}
	if u.Path != "" && path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" {
		return errors.New("Некорректный путь сервиса ACME-DNS.")
	}
	if u.Port() != "" {
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return errors.New("Некорректный порт ACME-DNS.")
		}
	}
	return nil
}

var acmeAccountID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var acmeSubdomain = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func ACMEDNSAccounts(values map[string]string) (map[string]ACMEDNSAccount, error) {
	invalid := errors.New("Загрузите JSON учётных записей ACME-DNS для доменов сертификата.")
	if len(values) != 1 || len(values["accounts"]) > 20<<10 {
		return nil, invalid
	}
	var accounts map[string]ACMEDNSAccount
	decoder := json.NewDecoder(strings.NewReader(values["accounts"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&accounts) != nil || len(accounts) < 1 || len(accounts) > 10 {
		return nil, invalid
	}
	// Reject trailing JSON as well as unknown registration fields.
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, invalid
	}
	seen := map[string]bool{}
	for domain, account := range accounts {
		if len(domain) > 253 || !hostname.MatchString(domain) || net.ParseIP(domain) != nil || !acmeAccountID.MatchString(account.Username) || len(account.Password) < 1 || len(account.Password) > 512 || strings.TrimSpace(account.Password) != account.Password || strings.ContainsAny(account.Password, "\r\n\x00") || !acmeSubdomain.MatchString(account.Subdomain) || len(account.FullDomain) > 253 || !hostname.MatchString(account.FullDomain) || !strings.HasPrefix(account.FullDomain, account.Subdomain+".") || seen[account.FullDomain] {
			return nil, invalid
		}
		seen[account.FullDomain] = true
	}
	return accounts, nil
}

// A base domain and its wildcard share the server's two rotating TXT slots.
// Different base domains must never share an account/target in one order.
func ACMEDNSDelegations(settings Settings, values map[string]string) ([]Delegation, error) {
	accounts, err := ACMEDNSAccounts(values)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var result []Delegation
	for _, name := range settings.Domains {
		domain := strings.TrimPrefix(name, "*.")
		if seen[domain] {
			continue
		}
		seen[domain] = true
		account, ok := accounts[domain]
		if !ok {
			return nil, errors.New("Для каждого домена нужна учётная запись ACME-DNS; wildcard использует запись основного имени.")
		}
		result = append(result, Delegation{Domain: domain, Name: "_acme-challenge." + domain, Target: account.FullDomain})
	}
	if len(seen) != len(accounts) {
		return nil, errors.New("JSON ACME-DNS должен содержать только домены этого сертификата.")
	}
	return result, nil
}

func ValidateConfiguration(settings Settings, values map[string]string) error {
	if err := Validate(settings); err != nil {
		return err
	}
	if err := ValidateCredentials(settings.Provider, values); err != nil {
		return err
	}
	if settings.Provider == "acmedns" {
		_, err := ACMEDNSDelegations(settings, values)
		return err
	}
	return nil
}
