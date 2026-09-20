package controlplane

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Opt-in: a disposable Linux container with nginx; never the user's router.
func TestACMELiveNginxBundleReload(t *testing.T) {
	if os.Getenv("SB_ACME_LIVE_NGINX") != "1" {
		t.Skip("isolated Nginx integration disabled")
	}
	s := newTestServer(t)
	now := time.Now()
	old, _ := acmeTestPair(t, now, []string{"api.example.com"})
	ref := "tls-profiles/cdn-default/acme-bundle.pem"
	if err := s.secrets.write(ref, old.Certificate+old.PrivateKey, false); err != nil {
		t.Fatal(err)
	}
	draft, _ := s.getDraft()
	p := acmeProfile(draft, "cdn-default")
	p["certificate_secret_ref"], p["private_key_secret_ref"] = ref, ref
	_, _ = s.repository.saveDraft(draft)
	path, _ := s.secrets.path(ref)
	root := t.TempDir()
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.Addr().String()
	_ = socket.Close()
	config := filepath.Join(root, "nginx.conf")
	content := fmt.Sprintf("pid %s/nginx.pid; error_log %s/error.log; events {} http { access_log off; server { listen %s ssl; ssl_certificate %s; ssl_certificate_key %s; location / { return 200 'ok'; } } }", root, root, address, path, path)
	if err := os.WriteFile(config, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("nginx", "-c", config, "-p", "/").CombinedOutput(); err != nil {
		t.Fatalf("nginx start: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nginx", "-s", "quit", "-c", config, "-p", "/").Run() })
	s.runtime = &nativeRuntime{options: RuntimeOptions{NginxBinary: "nginx", NginxConfig: config}, controller: &recordingRuntimeController{}}
	newPair, roots := acmeTestPair(t, now.Add(time.Second), []string{"api.example.com"})
	s.acmeRoots = roots
	if err := s.installACMECertificate(context.Background(), "cdn-default", []string{"api.example.com"}, ref, newPair, &acmeRecord{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{ServerName: "api.example.com", RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("new certificate not served: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
