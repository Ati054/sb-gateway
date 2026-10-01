package runtimeproof

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunningXrayValidationRequiresExactLiveGeneration(t *testing.T) {
	for _, test := range []struct {
		name    string
		proof   string
		ready   string
		state   string
		start   string
		command string
		missing string
		want    bool
	}{
		{name: "current core", want: true},
		{name: "other config hash", proof: "123 456 " + strings.Repeat("b", 64)},
		{name: "PID reused", start: "457"},
		{name: "another ready PID", ready: "124"},
		{name: "zombie", state: "Z"},
		{name: "dead core", state: "X"},
		{name: "validation subprocess is not core", command: "xray\x00run\x00-test\x00-config\x00/config/xray.json\x00"},
		{name: "different running config", command: "xray\x00run\x00-config\x00/config/other.json\x00"},
		{name: "different executable", command: "other\x00run\x00-config\x00/config/xray.json\x00"},
		{name: "missing proof", missing: "proof"},
		{name: "missing ready marker", missing: "ready"},
		{name: "process exited", missing: "stat"},
		{name: "missing command", missing: "cmdline"},
		{name: "truncated proof", proof: "123 456"},
		{name: "invalid PID", proof: "../123 456 " + strings.Repeat("a", 64)},
		{name: "invalid start ticks", proof: "123 bad " + strings.Repeat("a", 64)},
		{name: "extra proof fields", proof: "123 456 " + strings.Repeat("a", 64) + " extra"},
		{name: "oversized proof", proof: strings.Repeat("a", 257)},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			proc := filepath.Join(root, "proc")
			process := filepath.Join(proc, "123")
			if err := os.MkdirAll(process, 0o700); err != nil {
				t.Fatal(err)
			}
			signature := strings.Repeat("a", 64)
			proof := test.proof
			if proof == "" {
				proof = "123 456 " + signature
			}
			ready := test.ready
			if ready == "" {
				ready = "123"
			}
			state := test.state
			if state == "" {
				state = "S"
			}
			start := test.start
			if start == "" {
				start = "456"
			}
			fields := make([]string, 20)
			for index := range fields {
				fields[index] = "0"
			}
			fields[0], fields[19] = state, start
			command := test.command
			if command == "" {
				command = "/usr/local/bin/xray\x00run\x00-config\x00/config/xray.json\x00"
			}
			files := map[string]string{
				"proof": filepath.Join(root, "proof"), "ready": filepath.Join(root, "ready"),
				"stat": filepath.Join(process, "stat"), "cmdline": filepath.Join(process, "cmdline"),
			}
			bodies := map[string]string{
				"proof": proof + "\n", "ready": ready + "\n",
				"stat": "123 (xray) " + strings.Join(fields, " "), "cmdline": command,
			}
			for name, path := range files {
				if name != test.missing {
					if err := os.WriteFile(path, []byte(bodies[name]), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := XrayValidated(files["proof"], files["ready"], "/config/xray.json", proc, signature); got != test.want {
				t.Fatalf("running validation proof=%t, want %t", got, test.want)
			}
		})
	}
}
