// Package acmedns implements the small ACME-DNS update API, without a
// registration side effect, a persistent daemon, or provider SDKs in the panel.
package acmedns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

type Provider struct {
	settings acmejob.Settings
	accounts map[string]acmejob.ACMEDNSAccount
	client   *http.Client
	lookup   func(context.Context, string) (string, error)
}

func New(settings acmejob.Settings, credentials map[string]string) (*Provider, error) {
	if settings.Provider != "acmedns" {
		return nil, errors.New("invalid ACME-DNS provider")
	}
	if err := acmejob.ValidateConfiguration(settings, credentials); err != nil {
		return nil, err
	}
	accounts, _ := acmejob.ACMEDNSAccounts(credentials)
	return &Provider{settings: settings, accounts: accounts, client: newClient(), lookup: net.DefaultResolver.LookupCNAME}, nil
}

func CheckDelegations(ctx context.Context, records []acmejob.Delegation, lookup func(context.Context, string) (string, error)) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, record := range records {
		name, err := lookup(ctx, record.Name+".")
		if err != nil || !strings.EqualFold(strings.TrimSuffix(name, "."), record.Target) {
			return acmejob.ErrDelegation
		}
	}
	return nil
}

func (p *Provider) Check(ctx context.Context) error {
	records := make([]acmejob.Delegation, 0, len(p.accounts))
	for domain, account := range p.accounts {
		records = append(records, acmejob.Delegation{Name: "_acme-challenge." + domain, Target: account.FullDomain})
	}
	return CheckDelegations(ctx, records, p.lookup)
}

// SetLookup installs the resolver used by the read-only delegation preflight.
// The ACME worker supplies its fresh loopback resolver so this check cannot be
// satisfied or blocked by an unrelated local recursive-cache entry.
func (p *Provider) SetLookup(lookup func(context.Context, string) (string, error)) {
	if lookup != nil {
		p.lookup = lookup
	}
}

func (p *Provider) Present(ctx context.Context, domain, _ string, keyAuth string) error {
	domain = strings.TrimPrefix(domain, "*.")
	account, ok := p.accounts[domain]
	if !ok {
		return acmejob.ErrDelegation
	}
	if err := CheckDelegations(ctx, []acmejob.Delegation{{Name: "_acme-challenge." + domain, Target: account.FullDomain}}, p.lookup); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(keyAuth))
	value := base64.RawURLEncoding.EncodeToString(digest[:])
	body, _ := json.Marshal(map[string]string{"subdomain": account.Subdomain, "txt": value})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(p.settings.ACMEDNSServer, "/")+"/update", bytes.NewReader(body))
	if err != nil {
		return errors.New("ACME-DNS request failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Api-User", account.Username)
	request.Header.Set("X-Api-Key", account.Password)
	response, err := p.client.Do(request)
	if err != nil {
		return errors.New("ACME-DNS service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("ACME-DNS update rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<10)+1))
	var result struct {
		TXT string `json:"txt"`
	}
	if err != nil || len(data) > 4<<10 || json.Unmarshal(data, &result) != nil || result.TXT != value {
		return errors.New("ACME-DNS update not confirmed")
	}
	return nil
}

// ACME-DNS has no delete endpoint. Do not replace its two rotating values:
// the second slot may still be needed by the concurrent wildcard challenge.
func (p *Provider) CleanUp(context.Context, string, string, string) error { return nil }
func (p *Provider) Timeout() (time.Duration, time.Duration) {
	return acmejob.PropagationTimeout(p.settings), acmejob.PropagationPollingInterval
}

var blockedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
}

func publicIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blockedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	return ip.Is4() || netip.MustParsePrefix("2000::/3").Contains(ip)
}

func publicDial(ctx context.Context, network, address string, lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid ACME-DNS destination")
	}
	ips, err := lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("ACME-DNS DNS lookup failed")
	}
	// Validate the whole answer, then dial the checked numeric IP (no rebinding).
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, errors.New("ACME-DNS requires a public address")
		}
	}
	for _, ip := range ips {
		connection, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
	}
	return nil, errors.New("ACME-DNS connection failed")
}

func newClient() *http.Client {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	return &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10,
			TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return publicDial(ctx, network, address, net.DefaultResolver.LookupNetIP, dialer.DialContext)
			},
		},
	}
}
