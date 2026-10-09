//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

func TestMulticallArtifactRulesets(t *testing.T) {
	binary := os.Getenv("SB_TEST_MULTICALL_BINARY")
	if binary == "" {
		t.Skip("set SB_TEST_MULTICALL_BINARY to a native shared executable")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("SB_RULESET_DIR", root)
	t.Setenv("SB_GATEWAY_CONTROL_PLANE_LOG", filepath.Join(t.TempDir(), "gateway.log"))
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		output, err := exec.CommandContext(ctx, binary, "rulesets", "--prepare").CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("prepare attempt %d: %v: %s", attempt+1, err, output)
		}
	}
	if _, err := rulesets.ValidateLocal(root); err != nil {
		t.Fatalf("artifact seed validation: %v", err)
	}
	packs, err := rulesets.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	for _, pack := range packs {
		body, err := os.ReadFile(filepath.Join(root, pack.ID+".json"))
		if err != nil || !json.Valid(body) {
			t.Fatalf("missing or invalid artifact seed %q: %v", pack.ID, err)
		}
	}
}

// Check the built artifact instead of a synthetic test entry point.
func TestMulticallArtifactCLI(t *testing.T) {
	binary := os.Getenv("SB_TEST_MULTICALL_BINARY")
	if binary == "" {
		t.Skip("set SB_TEST_MULTICALL_BINARY to a native shared executable")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	xray := filepath.Join(dir, "xray")
	if err := os.Symlink(binary, xray); err != nil {
		t.Fatal(err)
	}
	command := func(path string, wantSuccess bool, contains string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = append(os.Environ(), "SB_GATEWAY_CONTROL_PLANE_LOG="+filepath.Join(dir, "gateway.log"))
		out, err := cmd.CombinedOutput()
		if (err == nil) != wantSuccess || !strings.Contains(string(out), contains) {
			t.Fatalf("%s %v: err=%v output=%s", filepath.Base(path), args, err, out)
		}
	}
	command(binary, true, "sb-gateway ", "version")
	command(xray, true, "Xray ", "version")
	command(xray, true, "Xray ", "-version")
	command(binary, false, "Usage of api:", "api", "-help")
	command(xray, true, "API", "help", "api")
	command(xray, true, "Run Xray", "help", "run")
	config := filepath.Join(dir, "config.json")
	if err := os.WriteFile(config, []byte(`{"outbounds":[{"protocol":"freedom","tag":"direct"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	command(xray, true, "Configuration OK.", "run", "-test", "-config", config)
	command(xray, true, "Configuration OK.", "run", "-test", "-confdir", dir)
	t.Run("upstream environment", func(t *testing.T) {
		t.Setenv("XRAY_LOCATION_CONFDIR", dir)
		command(xray, true, "Configuration OK.", "run", "-test")
	})
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"outbounds":[{"protocol":"not-a-protocol"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	command(xray, false, "failed", "run", "-test", "-config", bad)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	body, err := json.Marshal(map[string]any{
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "http"}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, body, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, xray, "run", "-config", config)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("core did not become ready")
		}
		time.Sleep(50 * time.Millisecond)
	}
	executable, err := os.Stat(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := os.Stat(binary)
	if err != nil || !os.SameFile(executable, shared) || cmd.Process.Pid == os.Getpid() {
		t.Fatalf("core must have its own PID backed by the shared executable: %v", err)
	}
	command(binary, true, "sb-gateway ", "version")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("upstream graceful shutdown: %v", err)
	}
}
