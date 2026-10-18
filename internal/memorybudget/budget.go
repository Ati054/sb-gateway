// Package memorybudget coordinates soft Go budgets within the appliance cgroup.
package memorybudget

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

const MiB int64 = 1 << 20
const HintName = "memory-budget-limits"

type Limits struct {
	High int64 `json:"high_bytes"`
	Max  int64 `json:"max_bytes"`
}

type Plan struct {
	Ceiling, Gateway, Xray, Worker, Reserve int64
}

type Role int

const (
	Gateway Role = iota
	Xray
	Worker
)

// Derive leaves headroom below memory.max even when memory.high is unlimited.
// Reserve two independent helper budgets: ACME must not prevent an Apply.
func Derive(limits Limits) Plan {
	ceiling := limits.High
	if limits.Max > 0 {
		hardBudget := limits.Max - limits.Max/8
		if ceiling <= 0 || hardBudget < ceiling {
			ceiling = hardBudget
		}
	}
	if ceiling <= 0 {
		ceiling = 224 * MiB
	}
	reserve := min(40*MiB, ceiling/4)
	worker := min(32*MiB, ceiling/8)
	regular := ceiling - reserve - 2*worker
	xray := regular/100*65 + regular%100*65/100
	return Plan{Ceiling: ceiling, Gateway: regular - xray, Xray: xray, Worker: worker, Reserve: reserve}
}

func (p Plan) For(role Role) int64 {
	switch role {
	case Gateway:
		return p.Gateway
	case Xray:
		return p.Xray
	default:
		return p.Worker
	}
}

// ReadV2 includes tighter parent limits when the process sees a non-namespaced
// cgroup mount. Namespace-rooted RouterOS mounts expose limits at root itself.
func ReadV2(root, relative string) Limits {
	var result Limits
	relative = path.Clean("/" + relative)
	for {
		dir := filepath.Join(root, strings.TrimPrefix(relative, "/"))
		result.High = tighter(result.High, finiteLimit(filepath.Join(dir, "memory.high")))
		result.Max = tighter(result.Max, finiteLimit(filepath.Join(dir, "memory.max")))
		if relative == "/" || relative == "." {
			return result
		}
		relative = path.Dir(relative)
	}
}

func tighter(a, b int64) int64 {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	return min(a, b)
}

func finiteLimit(path string) int64 {
	body, err := readBounded(path, 64)
	if err != nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil || value <= 0 || value >= 1<<60 {
		return 0
	}
	return value
}

func readBounded(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxBytes))
}

func currentCgroupRelative() string {
	relative := "/"
	if body, err := readBounded("/proc/self/cgroup", 4096); err == nil {
		for _, line := range strings.Split(string(body), "\n") {
			if path, ok := strings.CutPrefix(line, "0::"); ok {
				relative = path
				break
			}
		}
	}
	return relative
}

func detectedLimits() Limits {
	return ReadV2("/sys/fs/cgroup", currentCgroupRelative())
}

func Current() Plan {
	limits := detectedLimits()
	if limits.High <= 0 && limits.Max <= 0 {
		state := os.Getenv("SB_GATEWAY_STATE_DIR")
		if state == "" {
			state = "/state/control-plane"
		}
		limits = readHint(state)
	}
	return Derive(limits)
}

func readHint(state string) Limits {
	if body, err := readBounded(filepath.Join(state, HintName+".json"), 4096); err == nil {
		var known Limits
		if json.Unmarshal(body, &known) == nil && known.High >= 16*MiB && known.High <= known.Max && known.Max <= 8192*MiB {
			return known
		}
	}
	return Limits{}
}

// Configure is opt-in for the packaged appliance, not host-side developer tools.
// Existing explicit limits can lower, but cannot raise, the derived role budget.
func Configure(role Role, requested string) int64 {
	if os.Getenv("SB_MEMORY_BUDGET") != "1" {
		return 0
	}
	plan := Current()
	limit := Cap(plan.For(role), requested)
	if role == Gateway {
		limit = configureACMELoan(plan, requested)
	}
	debug.SetMemoryLimit(limit)
	if role == Gateway {
		startACMEPressureMonitor()
	}
	return limit
}

func Cap(budget int64, requested string) int64 {
	requested = strings.TrimSpace(requested)
	if requested == "" || requested == "off" {
		return budget
	}
	for _, suffix := range []struct {
		text  string
		scale int64
	}{{"KiB", 1 << 10}, {"MiB", MiB}, {"GiB", 1 << 30}, {"TiB", 1 << 40}, {"B", 1}} {
		if value, ok := strings.CutSuffix(requested, suffix.text); ok {
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n > 0 && n <= budget/suffix.scale {
				return n * suffix.scale
			}
			return budget
		}
	}
	if n, err := strconv.ParseInt(requested, 10, 64); err == nil && n > 0 {
		return min(n, budget)
	}
	return budget
}
