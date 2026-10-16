//go:build sb_cpu_lab

package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLabMemoryRequestIsNarrowAndBounded(t *testing.T) {
	for _, body := range []string{"", "../escape:110", "a:111", "a:110:restore", "a:0", "a: 110"} {
		if _, _, ok := parseLabMemoryRequest(body); ok {
			t.Fatalf("accepted %q", body)
		}
	}
	for _, target := range []string{"110", "restore"} {
		id, limit, ok := parseLabMemoryRequest(" owned-test:" + target + "\n")
		if !ok || id != "owned-test" || (target == "110" && limit != 110<<20) || (target == "restore" && limit != 0) {
			t.Fatal("valid request rejected")
		}
	}
	name := filepath.Join(t.TempDir(), "request")
	if err := os.WriteFile(name, []byte(strings.Repeat("a", 129)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLabMemoryRequest(name); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestLabMemoryLimitRequiresFiniteHeadroomAndChangesOnlyController(t *testing.T) {
	for _, tc := range []struct {
		name, high, max, current string
		valid                    bool
	}{
		{"256", "268435456", "335544320", "146800640", true},
		{"288", "301989888", "335544320", "146800640", true},
		{"insufficient", "268435456", "335544320", "230686720", false},
		{"small", "234881024", "268435456", "146800640", false},
		{"unbounded", "max", "335544320", "146800640", false},
		{"inverted", "402653184", "335544320", "146800640", false},
		{"invalid", "268435456", "335544320", "-1", false},
		{"oversized", strings.Repeat("1", 65), "335544320", "146800640", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for name, value := range map[string]string{"memory.high": tc.high, "memory.max": tc.max, "memory.current": tc.current} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			previous, err := applyLabGatewayMemoryLimit(root, func(limit int64) int64 {
				calls++
				if limit != 110<<20 {
					t.Fatalf("unexpected limit %s", strconv.FormatInt(limit, 10))
				}
				return 85 << 20
			})
			if tc.valid {
				if err != nil || calls != 1 || previous != 85<<20 {
					t.Fatalf("valid diagnostic failed: %v", err)
				}
			} else if err == nil || calls != 0 {
				t.Fatal("unsafe diagnostic changed runtime")
			}
		})
	}
}

func TestLabCPUProfileIDCannotSelectAPath(t *testing.T) {
	for _, id := range []string{"", "../outside", "x/y", "x\\y", "one two", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if validLabCPUProfileID(id) {
			t.Fatalf("unsafe profile request accepted: %q", id)
		}
	}
	if !validLabCPUProfileID("owned-test-1") {
		t.Fatal("valid diagnostic token rejected")
	}
}

func TestLabCPUProfileCreatesExclusiveReadableArtifact(t *testing.T) {
	name := filepath.Join(t.TempDir(), "cpu.pprof")
	if err := writeLabCPUProfile(name, 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil || len(body) == 0 {
		t.Fatalf("invalid CPU profile: %v", err)
	}
	if err := writeLabCPUProfile(name, time.Millisecond); err == nil {
		t.Fatal("existing profile overwritten")
	}
}
