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
