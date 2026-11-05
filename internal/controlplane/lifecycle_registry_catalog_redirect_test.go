package controlplane

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

type registryCatalogFixtureTransport func(*http.Request) (*http.Response, error)

func (transport registryCatalogFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestRegistryCatalogBlobRedirectVerifiesBytesWithoutCredentials(t *testing.T) {
	for _, scenario := range []string{"valid", "two-hop", "corrupt", "oversized", "too-many"} {
		t.Run(scenario, func(t *testing.T) {
			one := "1"
			config := registryCatalogFixtureConfig(t, &one)
			fixture := newRegistryCatalogFixture(t, config, false)
			fixture.mu.Lock()
			fixture.auth = true
			object := fixture.objects[fixture.configPath]
			object.redirect = "https://cdn.example.test/blob?signature=synthetic"
			fixture.objects[fixture.configPath] = object
			fixture.mu.Unlock()
			var requests atomic.Int64
			cdn := &http.Client{Transport: registryCatalogFixtureTransport(func(request *http.Request) (*http.Response, error) {
				count := requests.Add(1)
				if request.URL.Scheme != "https" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.Header.Get("Referer") != "" {
					t.Error("registry credentials crossed CDN boundary")
				}
				if scenario == "too-many" || scenario == "two-hop" && count == 1 {
					return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"https://next.example.test/blob"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
				}
				body := config
				if scenario == "corrupt" {
					body = append(append([]byte(nil), body...), byte(' '))
				}
				if scenario == "oversized" {
					body = make([]byte, registryCatalogMetadataLimit+1)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			actual, err := inspectRegistryImageCatalogSchemaWithClients(context.Background(), fixture.reference, fixture.version, fixture.server.Client(), cdn)
			if scenario == "valid" || scenario == "two-hop" {
				if err != nil || actual != 1 {
					t.Fatalf("verified CDN blob schema=%d err=%v", actual, err)
				}
			} else if err == nil {
				t.Fatal("unverified CDN blob accepted")
			}
			want := int64(1)
			if scenario == "too-many" || scenario == "two-hop" {
				want = 2
			}
			if requests.Load() != want {
				t.Fatalf("CDN requests=%d want=%d", requests.Load(), want)
			}
		})
	}
}

func TestRegistryCatalogBlobRedirectRejectsUnsafeURLsBeforeRequest(t *testing.T) {
	for _, target := range []string{"http://cdn.example.test/blob", "https://127.0.0.1/blob", "https://10.0.0.1/blob", "https://169.254.169.254/blob", "https://[::1]/blob", "https://[::ffff:192.168.1.1]/blob", "https://user@cdn.example.test/blob", "https://cdn.example.test/blob#fragment"} {
		t.Run(target, func(t *testing.T) {
			one := "1"
			fixture := newRegistryCatalogFixture(t, registryCatalogFixtureConfig(t, &one), false)
			fixture.mu.Lock()
			object := fixture.objects[fixture.configPath]
			object.redirect = target
			fixture.objects[fixture.configPath] = object
			fixture.mu.Unlock()
			var requests atomic.Int64
			cdn := &http.Client{Transport: registryCatalogFixtureTransport(func(*http.Request) (*http.Response, error) { requests.Add(1); return nil, errRegistryCatalogCapability })}
			if _, err := inspectRegistryImageCatalogSchemaWithClients(context.Background(), fixture.reference, fixture.version, fixture.server.Client(), cdn); err == nil || requests.Load() != 0 {
				t.Fatal("unsafe blob target reached transport")
			}
		})
	}
}

func TestRegistryCatalogBlobDialPinsResolvedPublicIP(t *testing.T) {
	lookups, dials := 0, 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		dials++
		if network != "tcp" || address != "8.8.8.8:443" {
			t.Fatal("hostname was re-resolved at dial time")
		}
		return left, nil
	}
	connection, err := registryCatalogPublicDialer(lookup, dial)(context.Background(), "tcp", "cdn.example.test:443")
	if err != nil || connection != left || lookups != 1 || dials != 1 {
		t.Fatalf("DNS pinning lookups=%d dials=%d err=%v", lookups, dials, err)
	}
}

func TestRegistryCatalogBlobDialRejectsPrivateOrMixedDNS(t *testing.T) {
	for _, addresses := range [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("169.254.169.254")}, {netip.MustParseAddr("fd00::1")},
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.168.1.1")},
	} {
		lookup := func(context.Context, string, string) ([]netip.Addr, error) { return addresses, nil }
		dial := func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("non-public DNS answer was dialed")
			return nil, errRegistryCatalogCapability
		}
		if _, err := registryCatalogPublicDialer(lookup, dial)(context.Background(), "tcp", "cdn.example.test:443"); err == nil {
			t.Fatal("non-public CDN accepted")
		}
	}
}

func TestRegistryCatalogBlobTransportDropsOriginClientAuthentication(t *testing.T) {
	original := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "registry.example.test", Certificates: []tls.Certificate{{}}}}
	client, err := newRegistryCatalogBlobClient(&http.Client{Transport: original})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.DialTLSContext != nil || transport.DialTLS != nil || transport.TLSClientConfig.ServerName != "" || transport.TLSClientConfig.InsecureSkipVerify || len(transport.TLSClientConfig.Certificates) != 0 {
		t.Fatal("origin authentication or TLS override survived CDN boundary")
	}
	if original.TLSClientConfig.ServerName != "registry.example.test" || len(original.TLSClientConfig.Certificates) != 1 {
		t.Fatal("original client was mutated")
	}
}
