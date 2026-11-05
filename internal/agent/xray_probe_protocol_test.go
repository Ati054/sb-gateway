package agent

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fresh process is required: the ordinary TLS trust store is cached globally.
// Setting Transport.TLSClientConfig in the fixture would itself disable the
// default H2 negotiation and conceal the production protocol mismatch.
func TestProbeHTTPSProtocolHelper(t *testing.T) {
	if os.Getenv("SB_TEST_PROBE_PROTOCOL_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	proxyURL, target := os.Getenv("SB_TEST_PROTOCOL_PROXY"), os.Getenv("SB_TEST_PROTOCOL_ORIGIN")
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), ForceAttemptHTTP2: true}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Head(target + "/h2-control")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	transport.CloseIdleConnections()
	if response.ProtoMajor != 2 {
		t.Fatal("fixture must negotiate H2 with the ordinary trusted TLS stack")
	}
	for _, path := range []string{"cold-one", "cold-two"} {
		if _, err := requestThroughProxyContext(t.Context(), proxyURL, target+"/"+path, http.MethodHead, 2*time.Second, 0, http.StatusNoContent); err != nil {
			t.Fatal(err)
		}
	}
	runtime := newXraySelectorRuntime(Options{ProbeURL: proxyURL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	originalTargets := healthTargets
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	defer func() { healthTargets = originalTargets }()
	for _, path := range []string{"fresh-one", "fresh-two"} {
		healthTargets[0].url = target + "/" + path
		evidence := runtime.ProbeWithQualityRequest("direct-wan", qualityProbeRequest{Measurement: qualityMeasurementFreshPaired})
		if !evidence.OK || !validPlanningQuality(evidence.Planning, qualityMeasurementFreshPaired) || evidence.Warm != nil {
			t.Fatalf("fresh paired HTTPS failed: %+v", evidence)
		}
	}
	measured := requestWarmThroughProxy(t.Context(), proxyURL, target+"/warm", http.MethodHead, 0, 2*time.Second, http.StatusNoContent, nil)
	if measured.ColdError != nil || measured.WarmError != nil || !validWarmQuality(&measured.Warm) {
		t.Fatalf("same-connection measurement failed: %+v", measured)
	}
	bad, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	bad.Host = net.JoinHostPort("wrong.invalid", bad.Port())
	if _, err := requestThroughProxyContext(t.Context(), proxyURL, bad.String(), http.MethodHead, 2*time.Second, 0, http.StatusNoContent); err == nil || probeErrorStage(err) != "tls-handshake" {
		t.Fatalf("cold request must verify the origin hostname: %v", err)
	}
	failed := requestWarmThroughProxy(t.Context(), proxyURL, bad.String(), http.MethodHead, 0, 2*time.Second, http.StatusNoContent, nil)
	if failed.ColdError == nil || probeErrorStage(failed.ColdError) != "tls-handshake" || validWarmQuality(&failed.Warm) {
		t.Fatalf("warm session must verify the origin hostname: %+v", failed)
	}
}

func TestColdAndWarmHTTPSUseOneProtocolWithoutChangingTrust(t *testing.T) {
	type observation struct {
		path, connection string
		major            int
	}
	var mu sync.Mutex
	var observed []observation
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		observed = append(observed, observation{r.URL.Path, r.RemoteAddr, r.ProtoMajor})
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(r.Context(), "tcp", origin.Listener.Addr().String())
		if err != nil {
			http.Error(w, "origin unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		connection, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		if _, err := fmt.Fprint(buffered, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(upstream, buffered)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(connection, upstream)
		_ = connection.Close()
		<-done
	}))
	defer proxy.Close()
	root := t.TempDir()
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestProbeHTTPSProtocolHelper$", "-test.v")
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if key != "SSL_CERT_FILE" && key != "SSL_CERT_DIR" && key != "GODEBUG" && !strings.HasPrefix(key, "SB_TEST_PROTOCOL_") && key != "SB_TEST_PROBE_PROTOCOL_HELPER" {
			child.Env = append(child.Env, value)
		}
	}
	child.Env = append(child.Env, "SB_TEST_PROBE_PROTOCOL_HELPER=1", "SB_TEST_PROTOCOL_PROXY="+proxy.URL,
		"SB_TEST_PROTOCOL_ORIGIN="+origin.URL, "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+root, "GODEBUG=http2client=1")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("protocol helper failed: %v\n%s", err, output)
	}
	mu.Lock()
	defer mu.Unlock()
	byPath := map[string][]observation{}
	for _, row := range observed {
		byPath[row.path] = append(byPath[row.path], row)
		want := 1
		if row.path == "/h2-control" {
			want = 2
		}
		if row.major != want {
			t.Errorf("%s negotiated HTTP/%d, want HTTP/%d", row.path, row.major, want)
		}
	}
	if len(observed) != 7 || len(byPath["/cold-one"]) != 1 || len(byPath["/cold-two"]) != 1 ||
		len(byPath["/fresh-one"]) != 1 || len(byPath["/fresh-two"]) != 1 || len(byPath["/warm"]) != 2 {
		t.Fatalf("unexpected request count: %+v", observed)
	}
	if byPath["/cold-one"][0].connection == byPath["/cold-two"][0].connection {
		t.Fatal("independent cold checks reused a connection")
	}
	if byPath["/fresh-one"][0].connection == byPath["/fresh-two"][0].connection {
		t.Fatal("independent fresh paired checks reused a connection")
	}
	if byPath["/warm"][0].connection != byPath["/warm"][1].connection {
		t.Fatal("warm comparison opened another connection")
	}
}
