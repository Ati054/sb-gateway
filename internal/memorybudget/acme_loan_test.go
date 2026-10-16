package memorybudget

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func testLoan() (*acmeLoan, *atomic.Int64, *atomic.Int64, *atomic.Int64) {
	var limit, usage, reclaims atomic.Int64
	plan := Derive(Limits{256 * MiB, 320 * MiB})
	limit.Store(plan.Gateway + plan.Worker)
	usage.Store(120 * MiB)
	loan := &acmeLoan{
		slot: make(chan struct{}, 1), base: plan.Gateway, idle: plan.Gateway + plan.Worker,
		worker: plan.Worker, limit: plan.Ceiling,
		setLimit: func(v int64) int64 { return limit.Swap(v) },
		usage:    func() (int64, bool) { return usage.Load(), true },
		reclaim:  func() { reclaims.Add(1) },
	}
	return loan, &limit, &usage, &reclaims
}

func TestIdleACMELoanPreservesValidationReservation(t *testing.T) {
	for _, limits := range []Limits{{224 * MiB, 256 * MiB}, {256 * MiB, 320 * MiB}, {320 * MiB, 384 * MiB}} {
		p := Derive(limits)
		idle := p.Gateway + p.Worker
		if idle+p.Xray+p.Worker+p.Reserve != p.Ceiling || p.Gateway+p.Xray+2*p.Worker+p.Reserve != p.Ceiling {
			t.Fatal("idle or active budget lost its independent validation slot")
		}
	}
}

func TestACMELoanConfigurationHonorsOptInAndExplicitLowerCap(t *testing.T) {
	controllerLoan.Lock()
	previous := controllerLoan.loan
	controllerLoan.Unlock()
	defer func() {
		controllerLoan.Lock()
		controllerLoan.loan = previous
		controllerLoan.Unlock()
	}()
	p := Derive(Limits{256 * MiB, 320 * MiB})
	t.Setenv("SB_MEMORY_BUDGET_ACME_LOAN", "0")
	if got := configureACMELoan(p, "off"); got != p.Gateway || controllerLoan.loan != nil {
		t.Fatal("loan enabled without opt-in")
	}
	t.Setenv("SB_MEMORY_BUDGET_ACME_LOAN", "1")
	if got := configureACMELoan(p, "32MiB"); got != 32*MiB || controllerLoan.loan != nil {
		t.Fatal("loan bypassed explicit lower controller cap")
	}
	actual := Current()
	got := configureACMELoan(actual, "off")
	_, readable := currentUsage()
	if canLendACME(actual, detectedLimits(), readable) {
		if got != actual.Gateway+actual.Worker || controllerLoan.loan == nil {
			t.Fatal("readable cgroup did not enable the idle loan")
		}
	} else if got != actual.Gateway || controllerLoan.loan != nil {
		t.Fatal("loan enabled without a readable usage counter")
	}
}

func TestACMELoanRequiresMatchingFiniteCgroup(t *testing.T) {
	limits := Limits{256 * MiB, 320 * MiB}
	p := Derive(limits)
	if !canLendACME(p, limits, true) {
		t.Fatal("known matching limits rejected")
	}
	for _, known := range []Limits{{}, {224 * MiB, 256 * MiB}, {320 * MiB, 384 * MiB}} {
		if canLendACME(p, known, true) {
			t.Fatal("unknown or changed cgroup limits enabled lending")
		}
	}
	if canLendACME(p, limits, false) {
		t.Fatal("missing usage counter enabled lending")
	}
}

func TestACMELoanUsageRejectsSharedParentAndInvalidCounters(t *testing.T) {
	root := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("cgroup.procs", "1\n20\n")
	write("memory.current", "44040192\n")
	if used, ok := cgroupRootUsage(root, 20); !ok || used != 42*MiB {
		t.Fatal("own namespace-rooted usage not recognized")
	}
	if _, ok := cgroupRootUsage(root, 2); ok {
		t.Fatal("shared ancestor usage treated as an owned root")
	}
	for _, value := range []string{"max", "-1", "", "invalid"} {
		write("memory.current", value)
		if _, ok := cgroupRootUsage(root, 20); ok {
			t.Fatalf("invalid usage accepted: %q", value)
		}
	}
	if _, ok := cgroupRootUsage(t.TempDir(), 20); ok {
		t.Fatal("missing cgroup accepted")
	}
}

func TestACMELoanUsageAcceptsOnlyDedicatedEmptyParent(t *testing.T) {
	for _, scenario := range []struct {
		name, processes  string
		sibling, symlink bool
		allowed          bool
	}{
		{name: "routeros-init", processes: "1\n20\n", allowed: true},
		{name: "different-process", processes: "2\n"},
		{name: "invisible-process", processes: "0\n20\n"},
		{name: "invalid-process", processes: "bad\n20\n"},
		{name: "shared-parent", processes: "20\n", sibling: true},
		{name: "linked-child", processes: "20\n", symlink: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root := t.TempDir()
			child := filepath.Join(root, "init")
			if err := os.Mkdir(child, 0700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"cgroup.procs": "", "memory.current": "44040192\n",
				"init/cgroup.procs": scenario.processes, "init/memory.current": "1\n",
			} {
				if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario.sibling {
				if err := os.Mkdir(filepath.Join(root, "other"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if scenario.symlink {
				if err := os.Symlink(child, filepath.Join(root, "linked")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			used, ok := cgroupRootUsage(root, 20)
			if ok != scenario.allowed || ok && used != 42*MiB {
				t.Fatalf("usage=%d allowed=%v; want %v and parent counter", used, ok, scenario.allowed)
			}
		})
	}
}

func TestACMELoanUsageRejectsUnboundedEmptyAncestry(t *testing.T) {
	root := t.TempDir()
	current := root
	for i := 0; i < 9; i++ {
		if err := os.WriteFile(filepath.Join(current, "cgroup.procs"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		current = filepath.Join(current, "child")
		if err := os.Mkdir(current, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(current, "cgroup.procs"), []byte("20\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if ownsCgroupRoot(root, "20", 0) {
		t.Fatal("unbounded ancestor traversal accepted")
	}
}

func TestACMELoanRecallAndIdempotentRelease(t *testing.T) {
	loan, limit, _, reclaims := testLoan()
	release, err := loan.acquire(context.Background())
	if err != nil || limit.Load() != loan.base || reclaims.Load() != 0 {
		t.Fatalf("recall: limit=%d reclaims=%d err=%v", limit.Load(), reclaims.Load(), err)
	}
	release()
	release()
	if limit.Load() != loan.idle || len(loan.slot) != 0 {
		t.Fatal("idle budget or slot not restored")
	}
}

func TestACMELoanWaitIsCancellableAndDoesNotReleaseAnotherWorker(t *testing.T) {
	loan, limit, _, _ := testLoan()
	release, err := loan.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loan.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting worker: %v", err)
	}
	if limit.Load() != loan.base || len(loan.slot) != 1 {
		t.Fatal("cancelled waiter released the running worker's reservation")
	}
}

func TestCancelledACMELoanDoesNotChangeRuntimeLimit(t *testing.T) {
	loan, limit, _, reclaims := testLoan()
	var changes atomic.Int64
	loan.setLimit = func(value int64) int64 { changes.Add(1); return limit.Swap(value) }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := loan.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled admission: %v", err)
	}
	if changes.Load() != 0 || reclaims.Load() != 0 || len(loan.slot) != 0 {
		t.Fatal("cancelled work altered GC pressure")
	}
}

func TestACMELoanReclaimsOnlyOnPressure(t *testing.T) {
	loan, limit, usage, reclaims := testLoan()
	usage.Store(loan.limit)
	loan.reclaim = func() { reclaims.Add(1); usage.Store(120 * MiB) }
	release, err := loan.acquire(context.Background())
	if err != nil || limit.Load() != loan.base || reclaims.Load() != 1 {
		t.Fatalf("pressure admission: %v", err)
	}
	release()
	if limit.Load() != loan.idle {
		t.Fatal("loan not restored after pressured worker")
	}
}

func TestACMELoanRejectsUnknownHeadroomWithoutForcedGC(t *testing.T) {
	loan, limit, _, reclaims := testLoan()
	loan.usage = func() (int64, bool) { return 0, false }
	if _, err := loan.acquire(context.Background()); err == nil {
		t.Fatal("unknown physical headroom admitted")
	}
	if limit.Load() != loan.idle || len(loan.slot) != 0 || reclaims.Load() != 0 {
		t.Fatal("unknown usage leaked the reservation or forced a collection")
	}
}

func TestACMELoanRestoresBudgetWhenPressureWaitIsCancelled(t *testing.T) {
	loan, limit, usage, _ := testLoan()
	usage.Store(loan.limit)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := loan.acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled pressure wait: %v", err)
	}
	if limit.Load() != loan.idle || len(loan.slot) != 0 {
		t.Fatal("failed admission leaked the reservation")
	}
}

func TestACMELoanRejectsPressureWithoutStartingWorker(t *testing.T) {
	loan, limit, usage, reclaims := testLoan()
	usage.Store(loan.limit)
	if _, err := loan.acquire(context.Background()); err == nil {
		t.Fatal("unsafe physical headroom admitted")
	}
	if limit.Load() != loan.idle || len(loan.slot) != 0 || reclaims.Load() != 1 {
		t.Fatal("failed admission leaked budget or repeatedly forced collection")
	}
}

func TestACMELoanRecallsBeforeAdmittingConcurrentWorker(t *testing.T) {
	loan, limit, _, _ := testLoan()
	release, err := loan.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		release, err := loan.acquire(context.Background())
		if err == nil {
			if limit.Load() != loan.base {
				err = errors.New("second worker admitted before recall")
			}
			release()
		}
		done <- err
	}()
	<-started
	select {
	case <-done:
		t.Fatal("concurrent ACME worker bypassed the single helper slot")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if limit.Load() != loan.idle || len(loan.slot) != 0 {
		t.Fatal("budget not restored after both workers")
	}
}
