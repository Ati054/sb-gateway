package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Opt-in, loopback-only integration test against the actual pinned core.
// SB_TEST_XRAY_RUNNER may name qemu-aarch64-static when testing an ARM64 core.
func TestXrayLiveSwitchPreservesEstablishedTCP(t *testing.T) {
	binary := os.Getenv("SB_TEST_XRAY")
	if binary == "" {
		t.Skip("set SB_TEST_XRAY to run the real-core integration test")
	}
	command := func(ctx context.Context, args ...string) *exec.Cmd {
		if runner := os.Getenv("SB_TEST_XRAY_RUNNER"); runner != "" {
			return exec.CommandContext(ctx, runner, append([]string{binary}, args...)...)
		}
		return exec.CommandContext(ctx, binary, args...)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
				scanner := bufio.NewScanner(conn)
				source := conn.RemoteAddr().(*net.TCPAddr).IP.String()
				for scanner.Scan() {
					_, _ = fmt.Fprintf(conn, "%s %s\n", source, scanner.Text())
				}
			}()
		}
	}()
	freePort := func() int {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	proxyPort, apiPort, fastPort, backgroundPort := freePort(), freePort(), freePort(), freePort()
	apiAddress := fmt.Sprintf("127.0.0.1:%d", apiPort)
	root := t.TempDir()
	config := filepath.Join(root, "xray.json")
	if err := os.WriteFile(config, []byte(fmt.Sprintf(`{
  "log":{"loglevel":"warning"},
  "api":{"tag":"api","services":["RoutingService","HandlerService"]},
  "inbounds":[
    {"tag":"client","listen":"127.0.0.1","port":%d,"protocol":"http","settings":{}},
    {"tag":"api-in","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}},
    {"tag":"fast","listen":"127.0.0.1","port":%d,"protocol":"http","settings":{}},
    {"tag":"background","listen":"127.0.0.1","port":%d,"protocol":"http","settings":{}}
  ],
  "outbounds":[
    {"tag":"de","protocol":"freedom","sendThrough":"127.0.0.2"},
    {"tag":"nl","protocol":"freedom","sendThrough":"127.0.0.3"}
  ],
  "routing":{"balancers":[
    {"tag":"europe","selector":["de","nl","sb-urltest-europe-"],"strategy":{"type":"random"}},
    {"tag":"outbound-health-probe","selector":["de","nl"],"strategy":{"type":"random"}},
    {"tag":"outbound-health-background","selector":["de","nl"],"strategy":{"type":"random"}}
  ],"rules":[
    {"type":"field","inboundTag":["api-in"],"outboundTag":"api"},
    {"type":"field","inboundTag":["fast"],"balancerTag":"outbound-health-probe"},
    {"type":"field","inboundTag":["background"],"balancerTag":"outbound-health-background"},
    {"type":"field","inboundTag":["client"],"balancerTag":"europe"}
  ]}
}`, proxyPort, apiPort, fastPort, backgroundPort)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	process := command(ctx, "run", "-config", config)
	logFile, err := os.Create(filepath.Join(root, "xray.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	process.Stdout, process.Stderr = logFile, logFile
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = process.Process.Kill()
		_ = process.Wait()
		if t.Failed() {
			body, _ := os.ReadFile(logFile.Name())
			t.Log(string(body))
		}
	}()
	waitAPI := func() {
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
			conn, err := net.DialTimeout("tcp", apiAddress, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("Xray API did not start")
	}
	waitAPI()
	runtime := newXraySelectorRuntime(Options{XrayBinary: binary, XrayAPIServer: apiAddress})
	runtime.command = func(_ context.Context, timeout time.Duration, _ string, args ...string) ([]byte, error) {
		callCtx, stop := context.WithTimeout(ctx, timeout)
		defer stop()
		return command(callCtx, args...).CombinedOutput()
	}
	if err := runtime.Select("europe", "de"); err != nil {
		t.Fatal(err)
	}
	openAt := func(port int) (net.Conn, *bufio.Reader) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", listener.Addr(), listener.Addr())
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil || !strings.Contains(line, "200") {
			t.Fatalf("CONNECT: %q, %v", line, err)
		}
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if line == "\r\n" {
				break
			}
		}
		return conn, reader
	}
	open := func() (net.Conn, *bufio.Reader) { return openAt(proxyPort) }
	check := func(conn net.Conn, reader *bufio.Reader, source string) {
		if _, err := fmt.Fprintln(conn, "still-connected"); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != source+" still-connected\n" {
			t.Fatalf("session path %q, want %s: %v", line, source, err)
		}
	}
	old, oldReader := open()
	check(old, oldReader, "127.0.0.2")
	for _, target := range []string{"nl", "de", "nl"} {
		if err := runtime.Select("europe", target); err != nil {
			t.Fatal(err)
		}
		check(old, oldReader, "127.0.0.2")
		fresh, reader := open()
		source := "127.0.0.3"
		if target == "de" {
			source = "127.0.0.2"
		}
		check(fresh, reader, source)
		fresh.Close()
	}
	t.Log("three API switches: established TCP stays on original egress; new TCP follows selected egress")
	for selector, member := range map[string]string{"outbound-health-probe": "de", "outbound-health-background": "nl"} {
		if err := runtime.Select(selector, member); err != nil {
			t.Fatal(err)
		}
	}
	backgroundConn, backgroundReader := openAt(backgroundPort)
	check(backgroundConn, backgroundReader, "127.0.0.3")
	if err := runtime.Select("outbound-health-probe", "nl"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Select("outbound-health-background", "de"); err != nil {
		t.Fatal(err)
	}
	fastConn, fastReader := openAt(fastPort)
	check(fastConn, fastReader, "127.0.0.3")
	freshBackground, freshBackgroundReader := openAt(backgroundPort)
	check(freshBackground, freshBackgroundReader, "127.0.0.2")
	check(backgroundConn, backgroundReader, "127.0.0.3")
	check(old, oldReader, "127.0.0.2")
	fastConn.Close()
	freshBackground.Close()
	backgroundConn.Close()
	t.Log("fast/background selectors use independent egress; existing background and client sockets remain intact")

	// Provider refreshes keep the logical node ID while credentials or endpoint
	// fields change. Add the replacement handler, switch the live selector, and
	// remove the retired handler without terminating a stream that still owns it.
	pidBeforeHotRefresh := process.Process.Pid
	runtime.pool = healthPool{
		Policies:       map[string][]string{"europe": {"provider"}},
		PolicyPrefixes: map[string]string{"europe": "sb-urltest-europe-"},
		Outbounds: map[string]json.RawMessage{
			"provider": json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`),
		},
	}
	if err := runtime.Select("europe", "provider"); err != nil {
		t.Fatal(err)
	}
	dynamic, dynamicReader := open()
	check(dynamic, dynamicReader, "127.0.0.4")
	for _, source := range []string{"127.0.0.5", "127.0.0.6"} {
		runtime.pool.Outbounds["provider"] = json.RawMessage(`{"protocol":"freedom","sendThrough":"` + source + `"}`)
		if err := runtime.Select("europe", "provider"); err != nil {
			t.Fatal(err)
		}
		fresh, freshReader := open()
		check(fresh, freshReader, source)
		fresh.Close()
		check(dynamic, dynamicReader, "127.0.0.4")
	}
	if process.Process.Pid != pidBeforeHotRefresh {
		t.Fatalf("Xray PID changed during hot refresh: %d -> %d", pidBeforeHotRefresh, process.Process.Pid)
	}
	dynamic.Close()
	t.Log("two provider generations switched through HandlerService; the first handler was removed while its established TCP stream survived")

	// A full core restart cannot preserve sockets, but must restore the saved
	// leaf before new traffic is admitted, without waiting for a fresh scan.
	old.Close()
	opts := Options{StateRoot: root, HealthPoolFile: filepath.Join(root, "pool.json")}
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = "best"
	pool.HealthPolicies["europe"] = contract
	if err := writeJSONAtomic(opts.HealthPoolFile, pool); err != nil {
		t.Fatal(err)
	}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed, item.Mode = "nl", "nl", true, "best"
	item.CandidateSignature = "de\nnl"
	item.AvailabilityOK = map[string]bool{"nl": true}
	rememberWorkingSelection(contract, item)
	// Shutdown-time API errors must not affect the first post-restart TCP path.
	item.RuntimeSelected, item.RuntimeConfirmed = "", false
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	_ = process.Process.Kill()
	_ = process.Wait()
	process = command(ctx, "run", "-config", config)
	process.Stdout, process.Stderr = logFile, logFile
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	waitAPI()
	runtime.selectorMembers = make(map[string]string)
	if err := restoreXraySelectors(config, opts, runtime); err != nil {
		t.Fatal(err)
	}
	restarted, reader := open()
	check(restarted, reader, "127.0.0.3")
	restarted.Close()
	t.Log("core process restart with unconfirmed API status: first admitted TCP restores saved nl")
}
