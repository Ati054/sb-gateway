package watchdog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

func watchdogProcessFixture(t testing.TB, count int) (Options, string, string) {
	t.Helper()
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	for n := 1; n <= count; n++ {
		dir := filepath.Join(proc, fmt.Sprint(n))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte("unrelated\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	core := filepath.Join(proc, "9999")
	if err := os.MkdirAll(core, 0700); err != nil {
		t.Fatal(err)
	}
	opts := Options{XrayReadyFile: filepath.Join(root, "ready"), XrayConfig: "/config/xray.json"}
	fields := strings.Fields("S " + strings.Repeat("0 ", 18) + "1234")
	files := map[string]string{
		opts.XrayReadyFile:             "9999\n",
		filepath.Join(core, "comm"):    "xray\n",
		filepath.Join(core, "stat"):    "9999 (xray) " + strings.Join(fields, " "),
		filepath.Join(core, "cmdline"): "/usr/local/bin/xray\x00run\x00-config\x00/config/xray.json\x00",
	}
	for path, body := range files {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return opts, proc, core
}

func TestWatchdogProcessUsesExactReadyPIDAndStartupFallback(t *testing.T) {
	opts, proc, core := watchdogProcessFixture(t, 16)
	if err := os.Remove(filepath.Join(core, "comm")); err != nil {
		t.Fatal(err)
	}
	if generation, running := xrayProcessState(opts, proc); generation != "9999 1234" || !running {
		t.Fatalf("ready process needed comm scan: %q %t", generation, running)
	}
	if err := os.WriteFile(filepath.Join(core, "comm"), []byte("xray\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(opts.XrayReadyFile); err != nil {
		t.Fatal(err)
	}
	if generation, running := xrayProcessState(opts, proc); generation != "" || !running {
		t.Fatalf("startup discovery changed: %q %t", generation, running)
	}
	if err := os.Remove(filepath.Join(core, "comm")); err != nil {
		t.Fatal(err)
	}
	if generation, running := xrayProcessState(opts, proc); generation != "" || running {
		t.Fatalf("missing core accepted: %q %t", generation, running)
	}
}

func TestWatchdogProcessDoesNotAcceptStaleOrCLIReadyMarker(t *testing.T) {
	for _, command := range []string{
		"/usr/local/bin/xray\x00api\x00lso\x00",
		"/usr/local/bin/xray\x00run\x00-test\x00-config\x00/config/xray.json\x00",
		"/usr/local/bin/xray\x00run\x00-config\x00/config/other.json\x00",
	} {
		opts, proc, core := watchdogProcessFixture(t, 2)
		if err := os.WriteFile(filepath.Join(core, "cmdline"), []byte(command), 0600); err != nil {
			t.Fatal(err)
		}
		if generation, _ := xrayProcessState(opts, proc); generation != "" {
			t.Fatalf("non-core process trusted: %q", command)
		}
	}
}

func BenchmarkWatchdogReadyProcess(b *testing.B) {
	for _, count := range []int{16, 128} {
		for _, direct := range []bool{false, true} {
			b.Run(fmt.Sprintf("processes=%d/direct=%t", count, direct), func(b *testing.B) {
				opts, proc, _ := watchdogProcessFixture(b, count)
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					if direct {
						_, _ = xrayProcessState(opts, proc)
					} else {
						_ = processRunningAt(proc, "xray")
						_ = runtimeproof.XrayGeneration(opts.XrayReadyFile, opts.XrayConfig, proc)
					}
				}
			})
		}
	}
}
