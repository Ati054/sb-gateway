package memorybudget

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestDerivedBudgetsFitContainer(t *testing.T) {
	p := Derive(Limits{High: 1 << 59, Max: 1 << 59})
	if p.Gateway <= 0 || p.Xray <= 0 || p.Gateway+p.Xray+2*p.Worker+p.Reserve != p.Ceiling {
		t.Fatal("large finite cgroup overflow")
	}
	for maximum := int64(16); maximum <= 8192; maximum += 16 {
		for _, high := range []int64{maximum / 2, maximum, maximum * 2, 0} {
			p := Derive(Limits{High: high * MiB, Max: maximum * MiB})
			if p.Gateway <= 0 || p.Xray <= 0 || p.Worker <= 0 || p.Gateway+p.Xray+2*p.Worker+p.Reserve != p.Ceiling || p.Ceiling > maximum*MiB*7/8 {
				t.Fatalf("inconsistent plan %d/%d: %+v", high, maximum, p)
			}
			if high > 0 && p.Ceiling > high*MiB {
				t.Fatal("budget exceeds high")
			}
		}
	}
	for _, limits := range []Limits{{}, {224 * MiB, 256 * MiB}, {320 * MiB, 384 * MiB}, {128 * MiB, 128 * MiB}} {
		p := Derive(limits)
		if p.Worker > 32*MiB || p.Reserve > 40*MiB || p.Xray <= p.Gateway {
			t.Fatalf("bad allocation: %+v", p)
		}
	}
}

func TestReadV2IncludesParentsAndUnlimited(t *testing.T) {
	root := t.TempDir()
	write := func(dir, name, value string) {
		t.Helper()
		dir = filepath.Join(root, dir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("", "memory.high", "max\n")
	write("", "memory.max", fmt.Sprint(384*MiB))
	write("group", "memory.high", fmt.Sprint(224*MiB))
	write("group/child", "memory.high", "broken\n")
	write("group/child", "memory.max", "max\n")
	got := ReadV2(root, "/group/child")
	if got != (Limits{224 * MiB, 384 * MiB}) {
		t.Fatalf("limits: %+v", got)
	}
	write("group/child", "memory.max", fmt.Sprint(128*MiB))
	if got := ReadV2(root, "/group/child"); got.Max != 128*MiB {
		t.Fatalf("tight child ignored: %+v", got)
	}
	write("", "memory.max", "9223372036854771712\n")
	if got := ReadV2(root, "/"); got != (Limits{}) {
		t.Fatalf("unlimited treated as finite: %+v", got)
	}
}

func TestExplicitLimitsCanOnlyLowerBudget(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int64
	}{{"", 64 * MiB}, {"off", 64 * MiB}, {"192MiB", 64 * MiB}, {"32MiB", 32 * MiB}, {"1024KiB", MiB}, {"524288", MiB / 2}, {"0", 64 * MiB}, {"-1", 64 * MiB}, {"2GB", 64 * MiB}, {"9223372036854775807GiB", 64 * MiB}} {
		if got := Cap(64*MiB, tc.input); got != tc.want {
			t.Fatalf("cap(%q)=%d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestConfigureUsesActualRuntimeLimitAndOptIn(t *testing.T) {
	old := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(old)
	t.Setenv("SB_MEMORY_BUDGET", "")
	if Configure(Gateway, "1MiB") != 0 || debug.SetMemoryLimit(-1) != old {
		t.Fatal("developer process changed without opt-in")
	}
	t.Setenv("SB_MEMORY_BUDGET", "1")
	if got := Configure(Xray, "4MiB"); got != 4*MiB || debug.SetMemoryLimit(-1) != 4*MiB {
		t.Fatal("runtime soft limit was not set")
	}
}

func TestKnownLimitsFallback(t *testing.T) {
	state := t.TempDir()
	if got := readHint(state); got != (Limits{}) {
		t.Fatalf("missing hint: %+v", got)
	}
	for _, tc := range []struct {
		body string
		want Limits
	}{
		{`{"high_bytes":117440512,"max_bytes":134217728}`, Limits{112 * MiB, 128 * MiB}},
		{`{"high_bytes":0,"max_bytes":134217728}`, Limits{}},
		{`{"high_bytes":268435456,"max_bytes":134217728}`, Limits{}},
		{`{"high_bytes":224,"max_bytes":9223372036854775807}`, Limits{}},
		{`{"high_bytes":`, Limits{}},
	} {
		if err := os.WriteFile(filepath.Join(state, HintName+".json"), []byte(tc.body), 0600); err != nil {
			t.Fatal(err)
		}
		if got := readHint(state); got != tc.want {
			t.Fatalf("%s: %+v", tc.body, got)
		}
	}
}
