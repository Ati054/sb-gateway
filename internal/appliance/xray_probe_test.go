package appliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResetXrayStartupProofRemovesOnlyPreviousReadyMarkers(t *testing.T) {
	root := t.TempDir()
	options := Options{XrayReadyFile: filepath.Join(root, "custom-ready"), XrayValidatedFile: filepath.Join(root, "custom-proof")}
	retained := []string{filepath.Join(root, "xray.json"), filepath.Join(root, "xray-prevalidated.sha256")}
	for _, path := range append(retained, options.XrayReadyFile, options.XrayValidatedFile) {
		if err := os.WriteFile(path, []byte("previous startup"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := resetXrayStartupProof(options); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{options.XrayReadyFile, options.XrayValidatedFile} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("previous readiness proof remains: %s: %v", path, err)
			}
		}
	}
	for _, path := range retained {
		if body, err := os.ReadFile(path); err != nil || string(body) != "previous startup" {
			t.Fatalf("unrelated runtime input changed: %s: %v", path, err)
		}
	}
	if err := resetXrayStartupProof(Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestRunClearsPreviousProofBeforeAnyStartupWork(t *testing.T) {
	root := t.TempDir()
	options := Options{XrayReadyFile: filepath.Join(root, "ready"), XrayValidatedFile: filepath.Join(root, "proof"), NginxConfig: root}
	for _, path := range []string{options.XrayReadyFile, options.XrayValidatedFile} {
		if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A directory cannot be read as a Nginx config. No program may start.
	if err := Run(context.Background(), options); err == nil {
		t.Fatal("invalid Nginx config was accepted")
	}
	for _, path := range []string{options.XrayReadyFile, options.XrayValidatedFile} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("startup work preceded proof cleanup: %s: %v", path, err)
		}
	}
}

func TestResetXrayStartupProofRejectsUnremovableMarker(t *testing.T) {
	root := t.TempDir()
	blocked := filepath.Join(root, "ready")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := resetXrayStartupProof(Options{XrayReadyFile: blocked}); err == nil {
		t.Fatal("startup continued with an uncleared marker")
	}
	if body, err := os.ReadFile(filepath.Join(blocked, "keep")); err != nil || string(body) != "unrelated" {
		t.Fatalf("marker cleanup recursively removed data: %v", err)
	}
}

func TestXrayProbeRequiresCompletedStartupNotJustOpenAPI(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	root := t.TempDir()
	options := Options{XrayReady: listener.Addr().String(), XrayReadyFile: filepath.Join(root, "ready"),
		XrayValidatedFile: filepath.Join(root, "proof"), XrayConfig: filepath.Join(root, "xray.json")}
	proc := filepath.Join(root, "proc")
	process := filepath.Join(proc, "123")
	if err := os.MkdirAll(process, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(options.XrayConfig, "{}")
	probe := xrayStartupProbe(options, proc)
	if err := probe(context.Background()); err == nil {
		t.Fatal("open API admitted unfinished startup")
	}
	write(options.XrayReadyFile, "123")
	if err := probe(context.Background()); err == nil {
		t.Fatal("PID-only marker admitted unconfirmed core")
	}
	sum := sha256.Sum256([]byte("{}"))
	write(options.XrayValidatedFile, "123 456 "+hex.EncodeToString(sum[:]))
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "456"
	write(filepath.Join(process, "stat"), "123 (xray) "+strings.Join(fields, " "))
	write(filepath.Join(process, "cmdline"), "/usr/local/bin/xray\x00run\x00-config\x00"+options.XrayConfig+"\x00")
	if err := probe(context.Background()); err != nil {
		t.Fatalf("complete live startup rejected: %v", err)
	}
	write(options.XrayConfig, "{ }")
	if err := probe(context.Background()); err == nil {
		t.Fatal("stale config proof admitted traffic")
	}
}
