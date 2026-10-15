package runtimeconfig

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/diagnosticlog"
)

// Use an isolated Linux container with nginx-mod-stream and nofile >= 16384.
// Every held Upgrade connection traverses stream -> Nginx TLS/HTTP -> backend.
func TestNginxCapacityAndLogReopenLive(t *testing.T) {
	if os.Getenv("SB_SHARED_LIVE_NGINX") != "1" {
		t.Skip("isolated Nginx integration disabled")
	}
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	pair := certificateServer.TLS.Certificates[0]
	certificate := certificateServer.Certificate()
	certificateServer.Close()
	private, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = fmt.Fprint(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: sb-echo\r\nConnection: Upgrade\r\n\r\n")
		if buffer.Flush() == nil {
			_, _ = io.Copy(connection, connection)
		}
	}))
	defer backend.Close()
	for _, legacy := range []bool{true, false} {
		name := "fixed"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			// Reopen runs in the unprivileged worker, unlike initial master opens.
			// Let it traverse the owned fixture tree just like /logs/nginx.
			for _, directory := range []string{filepath.Dir(root), root} {
				if err := os.Chmod(directory, 0755); err != nil {
					t.Fatal(err)
				}
			}
			certPath, keyPath := filepath.Join(root, "cert"), filepath.Join(root, "key")
			for path, data := range map[string][]byte{certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			address := func() string {
				t.Helper()
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				return listener.Addr().String()
			}
			outer, inner := address(), address()
			errorLog, publicLog := filepath.Join(root, "error.log"), filepath.Join(root, "public-error.log")
			pidPath := filepath.Join(root, "nginx.pid")
			config := fmt.Sprintf(`load_module /usr/lib/nginx/modules/ngx_stream_module.so;
worker_processes 1;
pid %s;
error_log %s notice;
events { worker_connections 1024; }
stream { server { listen %s; ssl_preread on; proxy_protocol on; proxy_pass %s; } }
http { access_log off; server { listen %s ssl proxy_protocol;
ssl_certificate %s; ssl_certificate_key %s; error_log %s error;
location /echo { proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection upgrade; proxy_pass %s; }
location /missing { root /sb-capacity-test-missing; }
} }`, pidPath, errorLog, outer, inner, inner, certPath, keyPath, publicLog, backend.URL)
			if !legacy {
				var err error
				config, err = UpgradeNginxCapacity(config)
				if err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(root, "nginx.conf")
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("nginx", "-c", path, "-p", "/", "-g", "daemon off;")
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { command.Process.Signal(syscall.SIGTERM); command.Wait() }()
			deadline := time.Now().Add(3 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", outer, 100*time.Millisecond)
				if err == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Nginx did not listen")
				}
				time.Sleep(20 * time.Millisecond)
			}
			type held struct {
				connection net.Conn
				reader     *bufio.Reader
			}
			var connections []held
			defer func() {
				for _, item := range connections {
					item.connection.Close()
				}
			}()
			var openErr error
			for len(connections) < 512 {
				connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", outer, &tls.Config{RootCAs: roots, ServerName: certificate.DNSNames[0], MinVersion: tls.VersionTLS12})
				if err != nil {
					openErr = err
					break
				}
				_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
				_, err = fmt.Fprint(connection, "GET /echo HTTP/1.1\r\nHost: example.test\r\nUpgrade: sb-echo\r\nConnection: Upgrade\r\n\r\n")
				reader := bufio.NewReader(connection)
				if err == nil {
					var response *http.Response
					response, err = http.ReadResponse(reader, nil)
					if err == nil && response.StatusCode != 101 {
						err = fmt.Errorf("upgrade status %d", response.StatusCode)
					}
				}
				if err != nil {
					connection.Close()
					openErr = err
					break
				}
				connections = append(connections, held{connection, reader})
			}
			if legacy {
				master, _ := os.ReadFile(errorLog)
				public, _ := os.ReadFile(publicLog)
				if openErr == nil || len(connections) > 256 || !strings.Contains(string(master)+string(public), "worker_connections are not enough") {
					t.Fatalf("legacy failure not reproduced: connections=%d error=%v", len(connections), openErr)
				}
				t.Logf("legacy saturated at %d Upgrade connections", len(connections))
				return
			}
			if openErr != nil {
				t.Fatalf("capacity: %d/512 connections: %v", len(connections), openErr)
			}
			echoAll := func() {
				t.Helper()
				for index, item := range connections {
					_ = item.connection.SetDeadline(time.Now().Add(3 * time.Second))
					_, err := fmt.Fprint(item.connection, "alive")
					reply := make([]byte, 5)
					if err == nil {
						_, err = io.ReadFull(item.reader, reply)
					}
					if err != nil || string(reply) != "alive" {
						t.Fatalf("connection %d interrupted: %v", index, err)
					}
				}
			}
			echoAll()
			before, _ := os.ReadFile(pidPath)
			for _, logPath := range []string{errorLog, publicLog} {
				f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(strings.Repeat("rotation fixture\n", 1024))
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			rotator := diagnosticlog.ExternalRotator{ReopenPaths: []string{errorLog, publicLog}, Maximum: 1024, Reopen: func(ctx context.Context) error {
				output, err := exec.CommandContext(ctx, "nginx", "-s", "reopen", "-c", path, "-p", "/").CombinedOutput()
				if err != nil {
					return fmt.Errorf("reopen: %w %s", err, output)
				}
				return nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := rotator.Check(ctx); err != nil {
				t.Fatal(err)
			}
			deadline = time.Now().Add(3 * time.Second)
			for {
				_, a := os.Stat(errorLog)
				_, b := os.Stat(publicLog)
				if a == nil && b == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Nginx did not reopen logs")
				}
				time.Sleep(20 * time.Millisecond)
			}
			client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: certificate.DNSNames[0], MinVersion: tls.VersionTLS12}}}
			defer client.CloseIdleConnections()
			for {
				response, err := client.Get("https://" + outer + "/missing/not-found")
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				current, _ := os.ReadFile(publicLog)
				if strings.Contains(string(current), "not-found") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("new error record did not reach reopened file")
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, logPath := range []string{errorLog, publicLog} {
				info, err := os.Stat(logPath + ".1")
				if err != nil || info.Size() > 1024 {
					t.Fatalf("archive not bounded: %v", err)
				}
			}
			after, _ := os.ReadFile(pidPath)
			if string(before) != string(after) {
				t.Fatal("Nginx restarted during reopen")
			}
			echoAll()
			t.Log("512 concurrent shared-chain Upgrade connections survived log rotation")
		})
	}
}
