package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Opt-in against the image's pinned core; all processes and API calls are local
// to this test, never the running gateway's routing service.
func TestXrayRoutingReloadKeepsSelectorResponsive(t *testing.T) {
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
	apiPort := listener.Addr().(*net.TCPAddr).Port
	apiAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeConfig := func(name string, value any) string {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	balancers := []any{map[string]any{
		"tag": "reload-test", "selector": []string{"de", "nl"},
		"strategy": map[string]any{"type": "random"},
	}}
	apiRule := func(tag string) map[string]any {
		return map[string]any{
			"type": "field", "ruleTag": tag, "inboundTag": []string{"api-in"}, "outboundTag": "api",
		}
	}
	config := writeConfig("xray.json", map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"api": map[string]any{"tag": "api", "services": []string{"RoutingService"}},
		"inbounds": []any{map[string]any{
			"tag": "api-in", "listen": "127.0.0.1", "port": apiPort,
			"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"},
		}},
		"outbounds": []any{
			map[string]any{"tag": "de", "protocol": "freedom"},
			map[string]any{"tag": "nl", "protocol": "freedom"},
		},
		"routing": map[string]any{"balancers": balancers, "rules": []any{apiRule("old-api")}},
	})

	// The first localIP rule logs from server-side BuildCondition, before the
	// remaining CIDR matchers are compiled. Separate matchers keep the work large
	// without approaching gRPC's message limit or relying on external GeoIP data.
	const ruleCount, cidrsPerRule = 128, 256
	rules := []any{apiRule("new-api"), map[string]any{
		"type": "field", "ruleTag": "compile-start", "localIP": []string{"127.0.0.1/32"},
		"network": "udp", "outboundTag": "de",
	}}
	for rule := 0; rule < ruleCount; rule++ {
		cidrs := make([]string, cidrsPerRule)
		for i := range cidrs {
			address := 2 * (rule*cidrsPerRule + i)
			cidrs[i] = fmt.Sprintf("10.%d.%d.%d/32", (address>>16)&255, (address>>8)&255, address&255)
		}
		rules = append(rules, map[string]any{
			"type": "field", "ruleTag": fmt.Sprintf("compiled-%03d", rule),
			"ip": cidrs, "outboundTag": "de",
		})
	}
	reloadConfig := writeConfig("reload.json", map[string]any{
		"routing": map[string]any{"balancers": balancers, "rules": rules},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	log := &xrayRoutingCompileLog{started: make(chan struct{})}
	process := command(ctx, "run", "-config", config)
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = process.Process.Kill()
		_ = process.Wait()
		if t.Failed() {
			t.Log(log.String())
		}
	}()
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", apiAddress, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated Xray API did not start")
	}
	var slowestCall time.Duration
	var selectorCalls int
	call := func(_ context.Context, timeout time.Duration, _ string, args ...string) ([]byte, error) {
		callCtx, stop := context.WithTimeout(ctx, timeout)
		defer stop()
		started := time.Now()
		output, err := command(callCtx, args...).CombinedOutput()
		elapsed := time.Since(started)
		if len(args) > 1 && (args[1] == "bo" || args[1] == "bi") {
			selectorCalls++
			if elapsed > slowestCall {
				slowestCall = elapsed
			}
		}
		if err != nil {
			return output, fmt.Errorf("%s after %s: %w: %s", args[1], elapsed, err, output)
		}
		if elapsed > 5*time.Second {
			return output, fmt.Errorf("%s took %s, exceeding the existing 5s API budget", args[1], elapsed)
		}
		return output, nil
	}
	runtime := newXraySelectorRuntime(Options{XrayBinary: binary, XrayAPIServer: apiAddress})
	runtime.command = call
	if err := runtime.Select("reload-test", "de"); err != nil {
		t.Fatal(err)
	}
	listRules := func() map[string]bool {
		t.Helper()
		output, err := call(ctx, 5*time.Second, binary, "api", "lsrules", "--server="+apiAddress)
		if err != nil {
			t.Fatal(err)
		}
		var response struct {
			Rules []struct {
				RuleTag string `json:"ruleTag"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(output, &response); err != nil {
			t.Fatalf("decode isolated routing inventory: %v: %s", err, output)
		}
		tags := make(map[string]bool, len(response.Rules))
		for _, rule := range response.Rules {
			tags[rule.RuleTag] = true
		}
		return tags
	}
	if tags := listRules(); !tags["old-api"] || tags["new-api"] {
		t.Fatalf("unexpected initial routing inventory: %v", tags)
	}

	reloadCtx, stopReload := context.WithCancel(ctx)
	reloadDone := make(chan struct{})
	var reloadOutput []byte
	var reloadErr error
	reloadStarted := time.Now()
	go func() {
		defer close(reloadDone)
		reloadOutput, reloadErr = command(reloadCtx, "api", "adrules", "--server="+apiAddress, "--timeout=80", reloadConfig).CombinedOutput()
	}()
	defer func() {
		stopReload()
		<-reloadDone
	}()
	select {
	case <-log.started:
	case <-reloadDone:
		t.Fatalf("reload ended without server-side compilation evidence: %v: %s", reloadErr, reloadOutput)
	case <-ctx.Done():
		t.Fatal("timed out waiting for server-side routing compilation")
	}
	compilationSeen := time.Now()
	for i, member := range []string{"nl", "de", "nl"} {
		// Select performs the real bo command followed by bi read-back. Keeping
		// the old inventory afterwards proves both finished before publication.
		if err := runtime.Select("reload-test", member); err != nil {
			t.Fatalf("selector change %d during compilation: %v", i+1, err)
		}
		if tags := listRules(); !tags["old-api"] || tags["new-api"] {
			t.Fatalf("real compilation overlap not established for selector change %d; increase test workload", i+1)
		}
	}
	overlap := time.Since(compilationSeen)
	select {
	case <-reloadDone:
		if reloadErr != nil {
			t.Fatalf("routing reload: %v: %s", reloadErr, reloadOutput)
		}
	case <-ctx.Done():
		t.Fatal("routing reload did not finish within the bounded test deadline")
	}
	if tags := listRules(); tags["old-api"] || !tags["new-api"] || len(tags) != len(rules) {
		t.Fatalf("replacement routing inventory is incomplete: %d tags, want %d", len(tags), len(rules))
	}
	if current, err := runtime.Current("reload-test"); err != nil || current != "nl" {
		t.Fatalf("reload lost latest concurrent override: current=%q, err=%v", current, err)
	}
	t.Logf("%d CIDRs compiled; three Set/Get pairs completed during proven overlap=%s; %d selector CLI calls, slowest=%s (<5s); reload=%s; latest override retained",
		ruleCount*cidrsPerRule, overlap, selectorCalls, slowestCall, time.Since(reloadStarted))
}

type xrayRoutingCompileLog struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	started chan struct{}
	seen    bool
}

func (log *xrayRoutingCompileLog) Write(body []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	n, err := log.buffer.Write(body)
	if !log.seen && strings.Contains(log.buffer.String(), "localIP is always equal to listen interface IP") {
		log.seen = true
		close(log.started)
	}
	return n, err
}

func (log *xrayRoutingCompileLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.buffer.String()
}
