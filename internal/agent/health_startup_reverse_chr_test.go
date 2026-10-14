package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The external client runs on the lab host. This exercises the native ARM64
// core and real Reverse reconnects without changing existing route sheets.
func TestStartupReverseWaitPinnedCoreReconnect(t *testing.T) {
	binary, exchange, address := os.Getenv("SB_TEST_XRAY"), os.Getenv("SB_TEST_REVERSE_EXCHANGE"), os.Getenv("SB_TEST_REVERSE_ADDRESS")
	if binary == "" || exchange == "" || net.ParseIP(address) == nil {
		t.Skip("set SB_TEST_XRAY, SB_TEST_REVERSE_EXCHANGE and SB_TEST_REVERSE_ADDRESS for the CHR live reconnect fixture")
	}
	if _, err := os.Stat(exchange); !os.IsNotExist(err) {
		t.Fatal("exchange file must not exist")
	}
	t.Cleanup(func() { _ = os.Remove(exchange) })
	port := func() int {
		l, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	apiPort, reversePort, probePort := port(), port(), port()
	config, opts := startupReverseFixture(t, "priority", []string{"reverse-vless-home", "de"}, "reverse-vless-home")
	apiAddress := fmt.Sprintf("127.0.0.1:%d", apiPort)
	uuid := "11111111-1111-4111-8111-111111111111"
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverStream := map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"dest": "www.microsoft.com:443", "serverNames": []string{"www.microsoft.com"}, "privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{"abcd"}}}
	clientStream := map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"serverName": "www.microsoft.com", "fingerprint": "chrome", "password": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": "abcd"}}
	if os.Getenv("SB_TEST_REVERSE_FAULTS") == "1" {
		// Keep the controlled timeout fixture independent of public camouflage
		// endpoints. It still negotiates real TLS 1.3 through REALITY.
		disguise := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		disguise.EnableHTTP2 = true
		disguise.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		disguise.StartTLS()
		defer disguise.Close()
		serverStream["realitySettings"].(map[string]any)["dest"] = disguise.Listener.Addr().String()
		serverStream["realitySettings"].(map[string]any)["serverNames"] = []string{"example.com"}
		clientStream["realitySettings"].(map[string]any)["serverName"] = "example.com"
	}
	flow := "xtls-rprx-vision"
	clientStream["sockopt"] = map[string]any{"tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 10, "tcpUserTimeout": 60000}
	switch transport := os.Getenv("SB_TEST_REVERSE_TRANSPORT"); transport {
	case "", "tcp":
	case "xhttp":
		flow = ""
		for _, stream := range []map[string]any{serverStream, clientStream} {
			stream["network"] = "xhttp"
			stream["xhttpSettings"] = map[string]any{"path": "/reverse-fixture", "mode": "auto"}
		}
	default:
		t.Fatalf("unsupported fixture transport %q", transport)
	}
	compareBuffers := os.Getenv("SB_TEST_REVERSE_BUFFER_COMPARE") == "1"
	buffers := []int{-1, -1}
	if compareBuffers {
		if os.Getenv("SB_TEST_REVERSE_BULK") != "1" || os.Getenv("SB_TEST_REVERSE_BURST") == "1" {
			t.Fatal("buffer comparison requires bulk mode without burst mode")
		}
		buffers = []int{4, 128, 128, 4}
	}
	core := map[string]any{
		"log":    map[string]any{"loglevel": "warning"},
		"api":    map[string]any{"tag": "api", "services": []string{"RoutingService", "StatsService", "HandlerService"}},
		"stats":  map[string]any{},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserOnline": true}}},
		"inbounds": []any{
			map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}},
			map[string]any{"tag": "outbound-health-fixture", "listen": "127.0.0.1", "port": probePort, "protocol": "http", "settings": map[string]any{}},
			map[string]any{"tag": "reverse-in", "listen": "0.0.0.0", "port": reversePort, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": uuid, "email": "reverse-vless-home", "reverse": map[string]any{"tag": "reverse-vless-home"}}}}},
		},
		"outbounds": []any{map[string]any{"tag": "de", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}},
		"routing": map[string]any{
			"balancers": []any{
				map[string]any{"tag": "europe", "selector": []string{"reverse-vless-home", "sb-urltest-fixture-"}, "strategy": map[string]any{"type": "random"}},
				map[string]any{"tag": "outbound-health-probe", "selector": []string{"reverse-vless-home", "de"}, "strategy": map[string]any{"type": "random"}},
			},
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"},
				map[string]any{"type": "field", "inboundTag": []string{"outbound-health-fixture"}, "balancerTag": "outbound-health-probe"},
			},
		},
	}
	if compareBuffers {
		core["policy"].(map[string]any)["levels"].(map[string]any)["0"].(map[string]any)["bufferSize"] = buffers[0]
	}
	for _, inbound := range core["inbounds"].([]any) {
		value := inbound.(map[string]any)
		if value["tag"] == "reverse-in" {
			value["streamSettings"] = serverStream
			value["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)["flow"] = flow
		}
	}
	writeFixture(t, config, core)
	var pool healthPool
	if err := readJSON(opts.HealthPoolFile, &pool); err != nil {
		t.Fatal(err)
	}
	pool.Policies = map[string][]string{"europe": {"reverse-vless-home", "de"}}
	pool.PolicyPrefixes = map[string]string{"europe": "sb-urltest-fixture-"}
	pool.BaseOutboundTags = []string{"block", "de", "reverse-vless-home"}
	writeFixture(t, opts.HealthPoolFile, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	var process *exec.Cmd
	logFile, err := os.Create(filepath.Join(opts.StateRoot, "core.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	start := func() {
		process = exec.CommandContext(ctx, binary, "run", "-config", config)
		process.Stdout, process.Stderr = logFile, logFile
		if err := process.Start(); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
			conn, err := net.DialTimeout("tcp", apiAddress, 50*time.Millisecond)
			if err == nil {
				conn.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("fixture API not ready")
	}
	defer func() {
		if process != nil {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	}()
	start()
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	_ = origin.Listener.Close()
	origin.Listener, err = net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	origin.Start()
	defer origin.Close()
	target := fmt.Sprintf("http://%s:%d/", address, origin.Listener.Addr().(*net.TCPAddr).Port)
	if configured := os.Getenv("SB_TEST_REVERSE_TARGET"); configured != "" {
		target = configured
	}
	parsed, err := url.Parse(target)
	if err != nil || net.ParseIP(parsed.Hostname()) == nil || parsed.Port() == "" {
		t.Fatal("fixture target must have an explicit IP and port")
	}
	client := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"outbounds": []any{
			map[string]any{"tag": "tunnel", "protocol": "vless", "settings": map[string]any{"address": address, "port": reversePort, "id": uuid, "encryption": "none", "reverse": map[string]any{"tag": "reverse-client"}}},
			map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "ip": parsed.Hostname(), "port": parsed.Port()}}}},
		},
		"routing": map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"reverse-client"}, "outboundTag": "direct"}}},
	}
	client["outbounds"].([]any)[0].(map[string]any)["streamSettings"] = clientStream
	client["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["flow"] = flow
	writeFixture(t, exchange, client)
	targets := slices.Clone(healthTargets)
	defer func() { healthTargets = targets }()
	for i := range healthTargets {
		healthTargets[i].url = target
		healthTargets[i].status = http.StatusNoContent
	}
	opts.XrayBinary, opts.XrayAPIServer, opts.ProbeURL = binary, apiAddress, fmt.Sprintf("http://127.0.0.1:%d", probePort)
	burst := os.Getenv("SB_TEST_REVERSE_BURST") == "1"
	for attempt, bufferKiB := range buffers {
		if bufferKiB < 0 {
			t.Logf("live attempt=%d core_buffer=architecture-default", attempt+1)
		} else {
			t.Logf("live attempt=%d core_buffer_kib=%d", attempt+1, bufferKiB)
		}
		started := time.Now()
		if err := RestoreXraySelectors(ctx, config, opts); err != nil {
			t.Fatal(err)
		}
		control, err := newXrayControlClient(apiAddress)
		if err != nil {
			t.Fatal(err)
		}
		selected, err := control.selected(ctx, "europe")
		restoreElapsed := time.Since(started)
		if err != nil || selected != "reverse-vless-home" {
			body, _ := os.ReadFile(logFile.Name())
			t.Logf("isolated core diagnostics: %s", body)
			runtime := newXraySelectorRuntime(opts)
			runtime.control, runtime.pool, runtime.probeContext = control, pool, ctx
			t.Logf("final live path evidence: %+v", runtime.ProbeAvailability("reverse-vless-home"))
			_, directErr := downloadThroughProxyContext(ctx, opts.ProbeURL, healthTargets[0].url, time.Second, 1024, http.StatusNoContent)
			t.Logf("proxy diagnostic: %v", directErr)
			control.close()
			t.Fatalf("real Reverse was not restored: selected=%q err=%v", selected, err)
		}
		runtime := newXraySelectorRuntime(opts)
		runtime.control, runtime.pool, runtime.probeContext = control, pool, ctx
		samples := 12
		if burst {
			samples = 320
		}
		if compareBuffers {
			samples = 1
		}
		if os.Getenv("SB_TEST_REVERSE_FAULTS") == "1" && attempt == 0 && !compareBuffers {
			testLiveReverseHTTPSFaults(t, ctx, runtime, selected, target, process.Process.Pid)
		}
		if os.Getenv("SB_TEST_REVERSE_BULK") == "1" && (attempt == 0 || compareBuffers) {
			testLiveReverseBulk(t, ctx, runtime, selected, target, process.Process.Pid)
		}
		for sample := 0; sample < samples; sample++ {
			if evidence := runtime.ProbeAvailability(selected); !evidence.OK {
				control.close()
				t.Fatalf("live Reverse failed sample %d: %+v", sample, evidence)
			}
			if burst {
				if evidence := runtime.Probe(selected); !evidence.OK || evidence.QualityUnmeasured {
					control.close()
					t.Fatalf("live Reverse quality failed sample %d: %+v", sample, evidence)
				}
			}
			pause := time.Second
			if compareBuffers {
				pause = 0
			}
			if burst {
				pause = 0
				if (sample+1)%64 == 0 {
					pause = 3 * time.Second // Let mux drain/replacement timers run.
				}
			}
			if !wait(ctx, pause) {
				t.Fatal(ctx.Err())
			}
		}
		control.close()
		t.Logf("live restore %d confirmed after %s; %d path proofs passed (burst=%t)", attempt+1, restoreElapsed, samples, burst)
		if attempt+1 < len(buffers) {
			_ = process.Process.Kill()
			_ = process.Wait()
			process = nil
			level := core["policy"].(map[string]any)["levels"].(map[string]any)["0"].(map[string]any)
			if buffers[attempt+1] < 0 {
				delete(level, "bufferSize")
			} else {
				level["bufferSize"] = buffers[attempt+1]
			}
			writeFixture(t, config, core)
			start()
		}
	}
}
