package routeros

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSchedulerGuardRequiredForRouterOS724(t *testing.T) {
	for _, test := range []struct {
		version string
		want    bool
	}{
		{"7.21.5 (stable)", false},
		{"7.24 (stable)", true},
		{"7.24.2 (stable)", true},
		{"7.25beta1 (testing)", false},
	} {
		t.Run(test.version, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/rest/system/resource" {
					t.Fatalf("path = %q", request.URL.Path)
				}
				response.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(response, `{"version":%q}`, test.version)
			}))
			defer server.Close()
			client := versionTestClient(t, server)
			got, err := client.SchedulerGuardRequired(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("guard = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSchedulerGuardRequiresOneValidVersion(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	client := versionTestClient(t, server)
	if _, err := client.SchedulerGuardRequired(context.Background()); err == nil {
		t.Fatal("missing RouterOS version was accepted")
	}
}

func versionTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{
		BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
