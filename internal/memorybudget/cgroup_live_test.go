package memorybudget

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"testing"
)

// Run inside an isolated container with --memory and no memory.high override.
func TestLiveCgroupBudget(t *testing.T) {
	maximum, err := strconv.ParseInt(os.Getenv("SB_TEST_MEMORY_MAX_MIB"), 10, 64)
	if err != nil {
		t.Skip("isolated memory-cgroup integration disabled")
	}
	plan := Current()
	expected := Derive(Limits{Max: maximum * MiB})
	if plan != expected {
		t.Fatalf("actual cgroup plan %+v, expected %+v", plan, expected)
	}
	t.Setenv("SB_MEMORY_BUDGET", "1")
	old := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(old)
	for _, role := range []Role{Gateway, Xray, Worker} {
		if got := Configure(role, "192MiB"); got != plan.For(role) || debug.SetMemoryLimit(-1) != got {
			t.Fatalf("role %d did not set actual runtime budget: %d", role, got)
		}
	}
	fmt.Printf("cgroup max=%d MiB gateway=%d xray=%d helper=%d reserve=%d ceiling=%d\n", maximum, plan.Gateway, plan.Xray, plan.Worker, plan.Reserve, plan.Ceiling)
}
