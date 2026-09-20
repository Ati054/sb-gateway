// Package acmejob is the small IPC contract shared by the panel and its
// short-lived ACME worker. Provider SDKs are linked only into the worker.
package acmejob

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/mail"
	"regexp"
	"strings"
)

type Settings struct {
	Enabled                   bool     `json:"enabled"`
	Provider                  string   `json:"provider"`
	Email                     string   `json:"email"`
	Domains                   []string `json:"domains"`
	TermsAccepted             bool     `json:"terms_accepted"`
	ACMEDNSServer             string   `json:"acme_dns_server,omitempty"`
	PropagationTimeoutMinutes int      `json:"propagation_timeout_minutes,omitempty"`
}

// RecursiveResolver is a normalized public resolver selected from the active
// direct DNS profile. It is not user supplied to the ACME worker: the control
// plane derives it from validated configuration before starting a job.
//
// The worker forwards ordinary loopback DNS requests to this encrypted
// upstream, so lego can retain both of its recursive and authoritative DNS-01
// propagation checks without inheriting a stale RouterOS cache.
type RecursiveResolver struct {
	Type        string `json:"type"`
	Server      string `json:"server"`
	ServerName  string `json:"server_name"`
	ServerPort  int    `json:"server_port"`
	Path        string `json:"path,omitempty"`
	DoTFallback bool   `json:"dot_fallback,omitempty"`
}

type Request struct {
	Settings          Settings          `json:"settings"`
	Credentials       map[string]string `json:"credentials"`
	AccountKey        string            `json:"account_key"`
	RecursiveResolver RecursiveResolver `json:"recursive_resolver"`
}
type Result struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (resolver RecursiveResolver) Validate() error {
	if net.ParseIP(resolver.Server) == nil || !hostname.MatchString(resolver.ServerName) {
		return errors.New("Некорректный доверенный DNS-резолвер ACME.")
	}
	if resolver.ServerPort < 1 || resolver.ServerPort > 65535 {
		return errors.New("Некорректный доверенный DNS-резолвер ACME.")
	}
	switch resolver.Type {
	case "https":
		if resolver.Path != "/dns-query" {
			return errors.New("Некорректный доверенный DNS-резолвер ACME.")
		}
	case "tls":
		if resolver.Path != "" || resolver.DoTFallback {
			return errors.New("Некорректный доверенный DNS-резолвер ACME.")
		}
	default:
		return errors.New("Некорректный доверенный DNS-резолвер ACME.")
	}
	return nil
}

func Validate(s Settings) error {
	if s.Provider != "gcore" && s.Provider != "regru" && s.Provider != "cloudflare" && s.Provider != "yandexcloud" && s.Provider != "acmedns" {
		return errors.New("Выберите поддерживаемого DNS-провайдера.")
	}
	if s.Provider == "acmedns" {
		if err := ValidateACMEDNSSettings(s); err != nil {
			return err
		}
	} else if s.ACMEDNSServer != "" || s.PropagationTimeoutMinutes != 0 {
		return errors.New("Настройки ACME-DNS применимы только к провайдеру ACME-DNS.")
	}
	address, err := mail.ParseAddress(s.Email)
	if err != nil || address.Address != s.Email || len(s.Email) > 254 {
		return errors.New("Укажите корректный email ACME-аккаунта.")
	}
	if !s.TermsAccepted {
		return errors.New("Подтвердите условия Let's Encrypt.")
	}
	if len(s.Domains) < 1 || len(s.Domains) > 10 {
		return errors.New("Укажите от 1 до 10 доменных имён.")
	}
	seen := map[string]bool{}
	for _, name := range s.Domains {
		host := strings.TrimPrefix(name, "*.")
		if len(name) > 253 || !hostname.MatchString(host) || net.ParseIP(host) != nil || name != strings.ToLower(name) || seen[name] {
			return errors.New("Домены должны быть уникальными DNS-именами; используйте punycode для IDN.")
		}
		seen[name] = true
	}
	return nil
}

// ValidateACMEDNSSettings validates the provider-only fields which are also
// safe to use in the read-only CNAME preflight. Issuance-only fields such as
// email, domains, and terms are intentionally validated by Validate instead.
func ValidateACMEDNSSettings(s Settings) error {
	if s.Provider != "acmedns" {
		return errors.New("Настройки ACME-DNS применимы только к провайдеру ACME-DNS.")
	}
	if err := ValidateACMEDNSURL(s.ACMEDNSServer); err != nil {
		return err
	}
	if s.PropagationTimeoutMinutes < 0 || s.PropagationTimeoutMinutes > 1440 {
		return errors.New("Укажите ожидание DNS ACME-DNS от 1 до 1440 минут.")
	}
	return nil
}

func ValidateCredentials(provider string, values map[string]string) error {
	fields := []string{"token"}
	switch provider {
	case "acmedns":
		_, err := ACMEDNSAccounts(values)
		return err
	case "regru":
		fields = []string{"username", "password"}
	case "yandexcloud":
		fields = []string{"folder_id", "service_account_key"}
	case "gcore", "cloudflare":
	default:
		return errors.New("Выберите поддерживаемого DNS-провайдера.")
	}
	if len(values) != len(fields) {
		return errors.New("Укажите доступ к API выбранного DNS-провайдера.")
	}
	for _, field := range fields {
		value := values[field]
		if provider == "yandexcloud" && field == "service_account_key" {
			if !validYandexKey(value) {
				return errors.New("Загрузите JSON авторизованного ключа сервисного аккаунта Yandex Cloud.")
			}
			continue
		}
		if strings.TrimSpace(value) == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return errors.New("Некорректные учётные данные DNS API.")
		}
	}
	return nil
}

// A renewable service-account key, not a short-lived IAM access token.
func validYandexKey(value string) bool {
	if len(value) > 16<<10 {
		return false
	}
	var key struct {
		ID               string `json:"id"`
		ServiceAccountID string `json:"service_account_id"`
		PrivateKey       string `json:"private_key"`
	}
	if json.Unmarshal([]byte(value), &key) != nil || !regexp.MustCompile(`^[a-z0-9]{1,64}$`).MatchString(key.ID) || !regexp.MustCompile(`^[a-z0-9]{1,64}$`).MatchString(key.ServiceAccountID) {
		return false
	}
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return false
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	return err == nil && ok && rsaKey.N.BitLen() >= 2048 && rsaKey.Validate() == nil
}
