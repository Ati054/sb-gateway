package acmedns

import (
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
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testProvider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(acmejob.Settings{Provider: "acmedns", ACMEDNSServer: "https://auth.example.net/api/", Email: "admin@example.com", TermsAccepted: true, Domains: []string{"api.example.com", "*.api.example.com"}}, map[string]string{"accounts": `{"api.example.com":{"username":"test-user","password":"test-secret","subdomain":"record1","fulldomain":"record1.auth.example.net"}}`})
	if err != nil {
		t.Fatal(err)
	}
	p.SetLookup(func(ctx context.Context, name string) (string, error) {
		if name != "_acme-challenge.api.example.com." {
			t.Fatalf("wrong CNAME query: %s", name)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("unbounded DNS check")
		}
		return "Record1.Auth.Example.Net.", nil
	})
	return p
}

func TestPresentProtocolAndWildcard(t *testing.T) {
	p := testProvider(t)
	keyAuth := "test-token.test-account-thumbprint"
	digest := sha256.Sum256([]byte(keyAuth))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	calls := 0
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != "https://auth.example.net/api/update" || r.Header.Get("X-Api-Key") != "test-secret" || r.Header.Get("X-Api-User") != "test-user" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("wrong update request")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["subdomain"] != "record1" || body["txt"] != want || len(body["txt"]) != 43 {
			t.Fatal("wrong DNS-01 payload")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"txt":"` + want + `"}`)), Header: make(http.Header)}, nil
	})
	if err := p.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"api.example.com", "*.api.example.com"} {
		if err := p.Present(context.Background(), name, "unused-token", keyAuth); err != nil {
			t.Fatal(err)
		}
		if err := p.CleanUp(context.Background(), name, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("cleanup altered rotating slots")
	}
	if timeout, interval := p.Timeout(); timeout != 4*time.Hour+15*time.Minute || interval != 10*time.Second {
		t.Fatal("unexpected propagation budget")
	}
	p.settings.PropagationTimeoutMinutes = 90
	if timeout, interval := p.Timeout(); timeout != 90*time.Minute || interval != 10*time.Second {
		t.Fatal("manual propagation budget not forwarded")
	}
	p.lookup = func(context.Context, string) (string, error) { return "wrong.example.net", nil }
	if !errors.Is(p.Present(context.Background(), "api.example.com", "", keyAuth), acmejob.ErrDelegation) || calls != 2 {
		t.Fatal("wrong CNAME reached API")
	}
	if !errors.Is(p.Present(context.Background(), "other.example.com", "", keyAuth), acmejob.ErrDelegation) {
		t.Fatal("foreign domain accepted")
	}
}

func TestUpdateFailureAndRedirectDoNotLeakOrFollow(t *testing.T) {
	for _, scenario := range []string{"http-error", "wrong-txt", "invalid-json", "large", "redirect", "network"} {
		t.Run(scenario, func(t *testing.T) {
			p := testProvider(t)
			calls := 0
			p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					t.Fatal("followed redirect with credentials")
				}
				status, body := 200, `{"txt":"test-secret"}`
				headers := make(http.Header)
				switch scenario {
				case "http-error":
					status = 403
				case "invalid-json":
					body = "test-secret"
				case "large":
					body = strings.Repeat("test-secret", 500)
				case "redirect":
					status = 307
					headers.Set("Location", "https://other.example.net/update")
				case "network":
					return nil, errors.New("test-secret")
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: headers, Request: r}, nil
			})
			err := p.Present(context.Background(), "api.example.com", "", "key-auth")
			if err == nil || strings.Contains(err.Error(), "test-secret") || calls != 1 {
				t.Fatal("unsafe failure", err, calls)
			}
		})
	}
}

func TestPublicDialPinsValidatedAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.1.1", "0.0.0.0", "192.0.2.1", "198.18.0.1", "224.0.0.1", "240.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:8.8.8.8", "64:ff9b::a00:1", "2002:7f00:1::", "2001:db8::1", "ff02::1"} {
		t.Run(address, func(t *testing.T) {
			_, err := publicDial(context.Background(), "tcp", "auth.example.net:443", func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr(address)}, nil
			}, func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("unsafe answer dialed")
				return nil, nil
			})
			if err == nil {
				t.Fatal("unsafe answer accepted")
			}
		})
	}
	for _, address := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		lookups, dials := 0, 0
		_, err := publicDial(context.Background(), "tcp", "auth.example.net:8443", func(_ context.Context, network, host string) ([]netip.Addr, error) {
			lookups++
			if network != "ip" || host != "auth.example.net" {
				t.Fatal("wrong resolution")
			}
			return []netip.Addr{netip.MustParseAddr(address)}, nil
		}, func(_ context.Context, network, target string) (net.Conn, error) {
			dials++
			if network != "tcp" || target != net.JoinHostPort(address, "8443") {
				t.Fatal("second DNS lookup possible")
			}
			return nil, nil
		})
		if err != nil || lookups != 1 || dials != 1 {
			t.Fatal("public address rejected", err)
		}
	}
	client := newClient()
	transport := client.Transport.(*http.Transport)
	if client.Timeout != 30*time.Second || transport.Proxy != nil || transport.TLSClientConfig != nil || transport.DialContext == nil || !transport.DisableKeepAlives {
		t.Fatal("unsafe HTTP transport")
	}
}

func TestDelegationCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := CheckDelegations(ctx, []acmejob.Delegation{{Name: "_acme-challenge.api.example.com", Target: "record1.auth.example.net"}}, func(ctx context.Context, _ string) (string, error) { <-ctx.Done(); return "", ctx.Err() })
	if !errors.Is(err, acmejob.ErrDelegation) {
		t.Fatal("cancellation lost")
	}
}
