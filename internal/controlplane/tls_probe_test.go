package controlplane

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestTLSProbeEndpointValidatesAndReturnsNativeResult(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	server.probeTLS = func(_ context.Context, request tlsProbeRequest) (map[string]any, *tlsProbeError) {
		if request.Hostname != "target.example" || request.Port != 443 || request.ServerName != "sni.example" {
			t.Fatalf("unexpected probe request: %#v", request)
		}
		return map[string]any{"hostname": request.Hostname, "all_addresses_ok": true}, nil
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/network/tls-probe", map[string]any{
		"hostname": "target.example.", "port": 443, "server_name": "sni.example.",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK || decodeResponse(t, response)["hostname"] != "target.example" {
		t.Fatalf("probe failed: %d %s", response.Code, response.Body.String())
	}
	invalid := performRequest(t, server, http.MethodPost, apiPrefix+"/network/tls-probe", map[string]any{
		"hostname": "https://target.example/path", "port": 70000,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid target accepted: %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestTLSProbeRejectsConfiguredRouterAddressBeforeHandshake(t *testing.T) {
	request := tlsProbeRequest{Hostname: "127.0.0.1", Port: 443, ServerName: "example.test", RouterAddresses: []string{"127.0.0.1/32"}}
	_, err := probeTLSEndpoint(context.Background(), request)
	if err == nil || err.Code != "tls_probe_target_loop" {
		t.Fatalf("router loop accepted: %#v", err)
	}
}

func TestTLSProbeCompletesVerifiedHandshake(t *testing.T) {
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer endpoint.Close()
	host, portText, err := net.SplitHostPort(endpoint.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(endpoint.Certificate())
	result, probeErr := probeTLSEndpoint(context.Background(), tlsProbeRequest{
		Hostname: host, Port: port, ServerName: "example.com", RootCAs: roots,
	})
	if probeErr != nil {
		t.Fatalf("verified handshake failed: %#v", probeErr)
	}
	if result["all_addresses_ok"] != true || result["tls_version"] == "mixed" {
		t.Fatalf("unexpected TLS result: %#v", result)
	}
}

func TestTLSProbeReportsHandshakeFailureWithoutStateChange(t *testing.T) {
	request := tlsProbeRequest{Hostname: "127.0.0.1", Port: 1, ServerName: "example.test"}
	_, err := probeTLSEndpoint(context.Background(), request)
	if err == nil || err.Code != "tls_probe_handshake_failed" {
		t.Fatalf("unexpected handshake error: %#v", err)
	}
}
