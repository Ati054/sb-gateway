//go:build xray_multicall

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestDefaultChrome155CompletesVerifiedTLSHandshake(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "chrome155-ok") }))
	defer server.Close()
	fingerprint := xtls.GetFingerprint("chrome")
	if fingerprint == nil || fingerprint.Version != "155" {
		t.Fatalf("unexpected default fingerprint: %+v", fingerprint)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	trusted := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	secured := xtls.UClient(raw, &tls.Config{RootCAs: trusted, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}, fingerprint).(*xtls.UConn)
	if err = secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if len(secured.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("TLS handshake bypassed certificate verification")
	}
	if _, err = io.WriteString(secured, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secured), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || string(body) != "chrome155-ok" {
		t.Fatalf("TLS application exchange failed: status=%d body=%q error=%v", response.StatusCode, body, err)
	}
}
