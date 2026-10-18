package memorybudget

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Only the controller may lend its idle ACME slot. Validation keeps its own
// independent slot, so certificate propagation never blocks an Apply.
type acmeLoan struct {
	mu            sync.Mutex
	slot          chan struct{}
	base, idle    int64
	worker, limit int64
	current       int64
	setLimit      func(int64) int64
	usage         func() (int64, bool)
	reclaim       func()
	pressure      func() (loanPressure, bool)
	stopPressure  func()
}

var controllerLoan struct {
	sync.Mutex
	loan *acmeLoan
}

func configureACMELoan(plan Plan, requested string) int64 {
	base := Cap(plan.Gateway, requested)
	controllerLoan.Lock()
	defer controllerLoan.Unlock()
	if previous := controllerLoan.loan; previous != nil && previous.stopPressure != nil {
		previous.stopPressure()
	}
	controllerLoan.loan = nil
	if os.Getenv("SB_MEMORY_BUDGET_ACME_LOAN") != "1" {
		return base
	}
	_, readable := currentUsage()
	if !canLendACME(plan, detectedLimits(), readable) {
		return base
	}
	idle := Cap(plan.Gateway+plan.Worker, requested)
	if idle <= base {
		return base
	}
	loan := &acmeLoan{
		slot: make(chan struct{}, 1), base: base, idle: idle,
		worker: plan.Worker, limit: plan.Ceiling, current: idle,
		setLimit: debug.SetMemoryLimit, usage: currentUsage, reclaim: debug.FreeOSMemory,
	}
	if os.Getenv("SB_MEMORY_PRESSURE_BUDGET") == "1" {
		loan.pressure = controllerPressure
		if _, ok := loan.pressure(); !ok {
			return base
		}
	}
	controllerLoan.loan = loan
	return idle
}

func canLendACME(plan Plan, limits Limits, readable bool) bool {
	return readable && (limits.High > 0 || limits.Max > 0) && Derive(limits).Ceiling == plan.Ceiling
}

// AcquireACME recalls the loan before starting a worker. The returned release
// must run after the worker and its progress pipe have exited, on every path.
// This is a no-op unless the packaged controller explicitly enabled lending.
func AcquireACME(ctx context.Context) (func(), error) {
	controllerLoan.Lock()
	loan := controllerLoan.loan
	controllerLoan.Unlock()
	if loan == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	return loan.acquire(ctx)
}

func (loan *acmeLoan) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case loan.slot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			loan.mu.Lock()
			defer loan.mu.Unlock()
			<-loan.slot
			loan.applyLimit(loan.idleLimit())
		})
	}
	loan.mu.Lock()
	loan.applyLimit(loan.base)
	loan.mu.Unlock()
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	// Soft Go limits alone cannot prove that a new process physically fits.
	// Keep an additional margin; reclaim only on this rare admission path.
	ready := func() (bool, bool) {
		used, ok := loan.usage()
		return ok && used <= loan.limit-loan.worker-min(16*MiB, loan.worker/2), ok
	}
	fits, known := ready()
	if !known {
		release()
		return nil, errors.New("ACME worker memory usage counter is unavailable")
	}
	if !fits {
		loan.reclaim()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			fits, known := ready()
			if !known {
				release()
				return nil, errors.New("ACME worker memory usage counter is unavailable")
			}
			if fits {
				break
			}
			select {
			case <-ctx.Done():
				release()
				return nil, ctx.Err()
			case <-deadline.C:
				release()
				return nil, errors.New("insufficient verified memory headroom for ACME worker")
			case <-ticker.C:
			}
		}
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func currentUsage() (int64, bool) {
	return cgroupRootUsage("/sys/fs/cgroup", os.Getpid())
}

func cgroupRootUsage(root string, pid int) (int64, bool) {
	if !ownsCgroupRoot(root, strconv.Itoa(pid), 0) {
		return 0, false
	}
	body, err := readBounded(filepath.Join(root, "memory.current"), 64)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	return value, err == nil && value >= 0
}

func ownsCgroupRoot(root, own string, depth int) bool {
	if depth >= 8 {
		return false
	}
	processes, err := readBounded(filepath.Join(root, "cgroup.procs"), 64<<10)
	if err != nil {
		return false
	}
	found := false
	fields := strings.Fields(string(processes))
	for _, process := range fields {
		value, err := strconv.Atoi(process)
		if err != nil || value <= 0 {
			return false
		}
		found = found || process == own
	}
	if len(fields) > 0 {
		return found
	}
	// RouterOS puts tasks in /init below an empty, limited container root.
	// Accept only a single branch; siblings could share the parent's budget.
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	child := ""
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return false
		}
		if entry.IsDir() {
			if child != "" {
				return false
			}
			child = filepath.Join(root, entry.Name())
		}
	}
	return child != "" && ownsCgroupRoot(child, own, depth+1)
}
