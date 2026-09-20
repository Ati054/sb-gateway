package runtimeconfig

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// Run in an isolated Linux container (ports 443/9443/11001/16443-16448).
// Exercises actual Nginx modules, not a simulator of its configuration.
func TestSharedIngressLiveNginx(t *testing.T) {
	if os.Getenv("SB_SHARED_LIVE_NGINX") != "1" {
		t.Skip("isolated Linux Nginx integration disabled")
	}
	root := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "shared ingress test"}, DNSNames: []string{"cf.example.test", "g.example.test", "reality.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "cert"), certPEM)
	write(filepath.Join(root, "key"), keyPEM)
	write(filepath.Join(root, "cloudflare", "addresses.conf"), []byte("127.0.0.2/32 1;\n"))
	write(filepath.Join(root, "gcore", "addresses.conf"), []byte("127.0.0.3/32 1;\n"))
	write(filepath.Join(root, "decoy.inc"), []byte("location / { return 404; }\n"))
	write(filepath.Join(root, "api-decoy.inc"), []byte("location / { default_type application/json; return 404 '{\"error\":\"not_found\"}'; }\n"))
	config := sharedIngressFixture()
	template, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderNginxCandidate(config, func(ref string) (string, error) {
		if ref == "path" {
			return "/private", nil
		}
		return "management-token", nil
	}, func(ref string) (string, error) { return filepath.Join(root, ref), nil }, NginxRenderOptions{Template: string(template), OriginCIDRRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	rendered = strings.ReplaceAll(rendered, "user www-data;", "")
	rendered = strings.ReplaceAll(rendered, "pid /run/nginx.pid;", "pid "+filepath.Join(root, "nginx.pid")+";")
	rendered = strings.ReplaceAll(rendered, "/logs/nginx/", root+"/")
	rendered = strings.ReplaceAll(rendered, "/opt/sb-gateway/templates/nginx-decoy.inc", filepath.Join(root, "decoy.inc"))
	rendered = strings.ReplaceAll(rendered, "/opt/sb-gateway/templates/nginx-api-decoy.inc", filepath.Join(root, "api-decoy.inc"))
	rendered = strings.ReplaceAll(rendered, "/run/sb-gateway/nginx-client-body", filepath.Join(root, "body"))
	cfg := filepath.Join(root, "nginx.conf")
	write(cfg, []byte(rendered))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "nginx", "-t", "-c", cfg, "-p", "/").CombinedOutput(); err != nil {
		t.Fatalf("nginx -t: %v %s", err, out)
	}
	backend, err := net.Listen("tcp", "127.0.0.1:11001")
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "sb-echo" {
			c, b, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			fmt.Fprint(b, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: sb-echo\r\nConnection: Upgrade\r\n\r\n")
			b.Flush()
			io.Copy(c, c)
			return
		}
		w.Write([]byte("CDN backend"))
	})}
	go web.Serve(backend)
	defer web.Close()
	reality, err := net.Listen("tcp", "127.0.0.1:16444")
	if err != nil {
		t.Fatal(err)
	}
	defer reality.Close()
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	proxyLine := make(chan string, 1)
	go func() {
		connection, err := reality.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(10 * time.Second))
		reader := bufio.NewReader(connection)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		proxyLine <- line
		secure := tls.Server(&bufferedIngressConn{Conn: connection, reader: reader}, &tls.Config{Certificates: []tls.Certificate{pair}})
		if secure.Handshake() != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(secure))
		if err == nil {
			request.Body.Close()
			fmt.Fprint(secure, "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nReality")
		}
	}()
	command := exec.Command("nginx", "-c", cfg, "-p", "/", "-g", "daemon off;")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "127.0.0.1:443", 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nginx did not listen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	request := func(source, sni, host string) (int, string, error) {
		d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
		raw, err := d.Dial("tcp", "127.0.0.1:443")
		if err != nil {
			return 0, "", err
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		c := tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: roots})
		if err := c.Handshake(); err != nil {
			return 0, "", err
		}
		fmt.Fprintf(c, "GET /private HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return response.StatusCode, string(body), err
	}
	for _, tc := range []struct {
		source, sni, host string
		code              int
	}{
		{"127.0.0.2", "cf.example.test", "cf.example.test", 200},
		{"127.0.0.2", "g.example.test", "g.example.test", 403},
		{"127.0.0.3", "g.example.test", "g.example.test", 200},
		{"127.0.0.3", "cf.example.test", "cf.example.test", 403},
		{"127.0.0.2", "cf.example.test", "g.example.test", 421},
	} {
		code, _, err := request(tc.source, tc.sni, tc.host)
		if err != nil || code != tc.code {
			t.Fatalf("%+v: code %d err %v", tc, code, err)
		}
	}
	code, body, err := request("127.0.0.4", "reality.example.test", "reality.example.test")
	if err != nil || code != 200 || body != "Reality" {
		t.Fatalf("Reality passthrough: %d %s %v", code, body, err)
	}
	select {
	case line := <-proxyLine:
		if !strings.HasPrefix(line, "PROXY TCP4 127.0.0.4 ") {
			t.Fatal("source IP lost", line)
		}
	case <-ctx.Done():
		t.Fatal("missing PROXY header")
	}
	h2Transport := &http2.Transport{
		TLSClientConfig: &tls.Config{ServerName: "reality.example.test", RootCAs: roots},
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			return tls.DialWithDialer(dialer, network, "127.0.0.1:16448", cfg)
		},
	}
	h2Client := &http.Client{Transport: h2Transport, Timeout: 3 * time.Second}
	h2Response, err := h2Client.Get("https://reality.example.test/")
	if err != nil {
		t.Fatal("Reality API cover HTTP/2 request:", err)
	}
	h2Body, readErr := io.ReadAll(h2Response.Body)
	h2Response.Body.Close()
	if readErr != nil || h2Response.ProtoMajor != 2 || h2Response.StatusCode != http.StatusNotFound || !strings.Contains(string(h2Body), `"error":"not_found"`) {
		t.Fatalf("Reality API cover HTTP/2 response: proto=%s code=%d body=%s err=%v", h2Response.Proto, h2Response.StatusCode, h2Body, readErr)
	}
	if _, _, err := request("127.0.0.2", "unknown.example.test", "cf.example.test"); err == nil {
		t.Fatal("unknown SNI accepted")
	}
	// A withdrawn address is rejected for new requests after a graceful reload.
	dialer := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	raw, err := dialer.Dial("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	long := tls.Client(raw, &tls.Config{ServerName: "cf.example.test", RootCAs: roots})
	long.SetDeadline(time.Now().Add(5 * time.Second))
	if err := long.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(long, "GET /private HTTP/1.1\r\nHost: cf.example.test\r\nConnection: Upgrade\r\nUpgrade: sb-echo\r\n\r\n")
	longReader := bufio.NewReader(long)
	upgraded, err := http.ReadResponse(longReader, nil)
	if err != nil || upgraded.StatusCode != 101 {
		t.Fatal("upgrade failed", err)
	}
	echo := func() {
		t.Helper()
		fmt.Fprint(long, "still-alive")
		reply := make([]byte, len("still-alive"))
		if _, err := io.ReadFull(longReader, reply); err != nil || string(reply) != "still-alive" {
			t.Fatal("established connection interrupted", err)
		}
	}
	echo()
	write(filepath.Join(root, "cloudflare", "addresses.conf"), []byte("127.0.0.5/32 1;\n"))
	if out, err := exec.CommandContext(ctx, "nginx", "-s", "reload", "-c", cfg).CombinedOutput(); err != nil {
		t.Fatalf("reload: %v %s", err, out)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		code, _, err := request("127.0.0.2", "cf.example.test", "cf.example.test")
		if err == nil && code == 403 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("withdrawn CIDR remained allowed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	echo()
}

type bufferedIngressConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedIngressConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
