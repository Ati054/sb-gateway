package agent

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Opt-in, loopback-only: real REALITY sockets must close after probe expiry,
// while an authenticated ordinary Vision connection remains usable.
func TestXrayRealityProbeLifetimePreservesClient(t *testing.T) {
	binary := os.Getenv("SB_TEST_XRAY")
	if binary == "" {
		t.Skip("set SB_TEST_XRAY to test the pinned core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	freePort := func() int {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	probePorts := []int{freePort(), freePort(), freePort()}
	clientPort, realityPort := freePort(), freePort()
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	cover.EnableHTTP2 = true
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	cover.StartTLS()
	defer cover.Close()
	echo, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	silent, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	var active, accepted atomic.Int32
	var peersMu sync.Mutex
	var peers []net.Conn
	defer func() {
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, peer := range peers {
			peer.Close()
		}
	}()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			peersMu.Lock()
			peers = append(peers, conn)
			peersMu.Unlock()
			active.Add(1)
			accepted.Add(1)
			go func() { defer active.Add(-1); defer conn.Close(); io.Copy(io.Discard, conn) }()
		}
	}()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(key.Bytes())
	config := fmt.Sprintf(`{
		"log":{"loglevel":"error"},
		"inbounds":[
			{"tag":"outbound-health-probe","listen":"127.0.0.1","port":%d,"protocol":"http"},
			{"tag":"outbound-health-background","listen":"127.0.0.1","port":%d,"protocol":"http"},
			{"tag":"outbound-health-background-2","listen":"127.0.0.1","port":%d,"protocol":"http"},
			{"tag":"ordinary-client","listen":"127.0.0.1","port":%d,"protocol":"http"},
			{"tag":"reality-server","listen":"127.0.0.1","port":%d,"protocol":"vless",
			 "settings":{"decryption":"none","clients":[{"id":"11111111-1111-1111-1111-111111111111","flow":"xtls-rprx-vision"}]},
			 "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"target":"%s","serverNames":["example.com"],"privateKey":"%s","shortIds":[""]}}}
		],
		"outbounds":[
			{"tag":"silent","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none","flow":"xtls-rprx-vision"}]}]},
			 "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","fingerprint":"chrome","publicKey":"%s","shortId":""}}},
			{"tag":"live","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":%d,"users":[{"id":"11111111-1111-1111-1111-111111111111","encryption":"none","flow":"xtls-rprx-vision"}]}]},
			 "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","fingerprint":"chrome","publicKey":"%s","shortId":""}}},
			{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}
		],
		"routing":{"rules":[
			{"type":"field","inboundTag":["outbound-health-probe","outbound-health-background","outbound-health-background-2"],"outboundTag":"silent"},
			{"type":"field","inboundTag":["ordinary-client"],"outboundTag":"live"},
			{"type":"field","inboundTag":["reality-server"],"outboundTag":"direct"}
		]}
	}`, probePorts[0], probePorts[1], probePorts[2], clientPort, realityPort,
		cover.Listener.Addr(), priv, silent.Addr().(*net.TCPAddr).Port, pub, realityPort, pub)
	dir := t.TempDir()
	coverCA := filepath.Join(dir, "cover-ca.pem")
	if err := os.WriteFile(coverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cover.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "core.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "core.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	args := []string{"run", "-c", path}
	var child *exec.Cmd
	if runner := os.Getenv("SB_TEST_XRAY_RUNNER"); runner != "" {
		child = exec.CommandContext(ctx, runner, append([]string{binary}, args...)...)
	} else {
		child = exec.CommandContext(ctx, binary, args...)
	}
	child.Stdout, child.Stderr = logFile, logFile
	child.Env = append(os.Environ(), "SSL_CERT_FILE="+coverCA)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { child.Process.Kill(); child.Wait() }()
	clientAddress := fmt.Sprintf("127.0.0.1:%d", clientPort)
	deadline := time.Now().Add(8 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", clientAddress, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			body, _ := os.ReadFile(logFile.Name())
			t.Fatalf("core startup timeout: %s", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	live, err := net.DialTimeout("tcp", clientAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	live.SetDeadline(time.Now().Add(12 * time.Second))
	fmt.Fprintf(live, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())
	reader := bufio.NewReader(live)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
		if strings.HasPrefix(line, "HTTP/") && line != "HTTP/1.1 200 Connection established\r\n" {
			t.Fatalf("CONNECT failed: %s", line)
		}
	}
	exchange := func() {
		t.Helper()
		live.SetDeadline(time.Now().Add(12 * time.Second))
		payload := strings.Repeat("live", 16)
		if _, err := live.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(payload))
		if _, err := io.ReadFull(reader, response); err != nil {
			body, _ := os.ReadFile(logFile.Name())
			t.Fatalf("ordinary REALITY stream failed: %v; %s", err, body)
		}
		if string(response) != payload {
			t.Fatalf("invalid echo: %q", response)
		}
	}
	exchange()
	for round := 0; round < 2; round++ {
		before := accepted.Load()
		var workers sync.WaitGroup
		for _, port := range probePorts {
			for worker := 0; worker < 3; worker++ {
				workers.Add(1)
				go func(port int) {
					defer workers.Done()
					_, err := downloadThroughProxyContext(ctx, fmt.Sprintf("http://127.0.0.1:%d", port), "https://example.org/", time.Second, 1024, 200)
					if err == nil {
						t.Error("silent REALITY peer passed HTTPS availability")
					}
				}(port)
			}
		}
		workers.Wait()
		if accepted.Load()-before < 9 {
			t.Fatalf("expected nine real handshakes, saw %d", accepted.Load()-before)
		}
		deadline = time.Now().Add(10 * time.Second)
		for active.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if active.Load() != 0 {
			t.Fatalf("%d upstream sockets survived probe expiry", active.Load())
		}
		exchange()
		t.Logf("round %d: stalled sockets released; ordinary REALITY connection preserved", round+1)
	}
}
