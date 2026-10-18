package policydns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestDoHResumesTLSAfterTransportRetirementWithoutSharingProfiles(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, http2 := range []bool{false, true} {
			t.Run(tls.VersionName(version)+"/h2="+strconv.FormatBool(http2), func(t *testing.T) {
				resumed := make(chan bool, 3)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if (r.ProtoMajor == 2) != http2 {
						t.Errorf("unexpected HTTP protocol: %s", r.Proto)
					}
					query, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					resumed <- r.TLS.DidResume
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(dnsAResponse(query, 60))
				}))
				server.EnableHTTP2 = http2
				server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
				server.StartTLS()
				defer server.Close()
				host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				port, err := strconv.Atoi(portText)
				if err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				makeClient := func() *dohUpstream {
					t.Helper()
					configured, err := newDoHUpstream(serverConfig{
						ServerName: "example.com", TunnelHost: host, TunnelPort: port,
					}, 2*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					client := configured.(*dohUpstream)
					client.transport.TLSClientConfig.RootCAs = roots
					t.Cleanup(client.close)
					return client
				}
				client := makeClient()
				query := dnsQuery(1, "example.org")
				if _, err := client.exchange(context.Background(), query); err != nil {
					t.Fatal(err)
				}
				old := client.transport
				cache := old.TLSClientConfig.ClientSessionCache
				client.finishDoH(old, context.DeadlineExceeded)
				if client.transport == old || client.transport.TLSClientConfig.ClientSessionCache != cache {
					t.Fatal("transport retirement did not preserve its own TLS session cache")
				}
				if _, err := client.exchange(context.Background(), query); err != nil {
					t.Fatal(err)
				}
				other := makeClient()
				if other.transport.TLSClientConfig.ClientSessionCache == cache {
					t.Fatal("separate resolver profiles share a TLS session cache")
				}
				if _, err := other.exchange(context.Background(), query); err != nil {
					t.Fatal(err)
				}
				for i, want := range []bool{false, true, false} {
					select {
					case got := <-resumed:
						if got != want {
							t.Fatalf("connection %d resumed=%t, want %t", i, got, want)
						}
					case <-time.After(time.Second):
						t.Fatal("missing server-side TLS observation")
					}
				}
			})
		}
	}
}
