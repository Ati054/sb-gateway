package memorybudget

import (
	"path/filepath"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"
)

type loanPressure struct {
	used, managed, live, nonHeap int64
	cleanFile                    int64
}

// Keep hot mapped code and a small clean file working set out of the loan.
// Socket memory remains charged in full; a Go soft limit does not account it.
func pressureFileCache(body []byte) (int64, bool) {
	values := map[string]int64{}
	for _, line := range strings.Split(string(body), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		switch key {
		case "file", "file_mapped", "file_dirty", "file_writeback":
			n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil || n < 0 || n >= 1<<60 {
				return 0, false
			}
			if _, duplicate := values[key]; duplicate {
				return 0, false
			}
			values[key] = n
		}
	}
	if len(values) != 4 {
		return 0, false
	}
	protected := values["file_mapped"] + values["file_dirty"] + values["file_writeback"] + 4*MiB
	return max(0, values["file"]-protected), true
}

func controllerPressure() (loanPressure, bool) {
	used, ok := currentUsage()
	if !ok {
		return loanPressure{}, false
	}
	body, err := readBounded(filepath.Join("/sys/fs/cgroup", "memory.stat"), 32<<10)
	if err != nil {
		return loanPressure{}, false
	}
	cleanFile, ok := pressureFileCache(body)
	if !ok {
		return loanPressure{}, false
	}
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/gc/heap/live:bytes"},
	}
	metrics.Read(samples)
	values := make([]int64, len(samples))
	for i, sample := range samples {
		if sample.Value.Kind() != metrics.KindUint64 || sample.Value.Uint64() >= 1<<60 {
			return loanPressure{}, false
		}
		values[i] = int64(sample.Value.Uint64())
	}
	managed := max(0, values[0]-values[1])
	nonHeap := max(0, managed-values[2]-values[3]-values[4])
	return loanPressure{used: used, managed: managed, live: values[5], nonHeap: nonHeap, cleanFile: cleanFile}, true
}

func (loan *acmeLoan) idleLimit() int64 {
	if len(loan.slot) != 0 {
		return loan.base
	}
	if loan.pressure == nil {
		return loan.idle
	}
	pressure, ok := loan.pressure()
	if !ok {
		return loan.base
	}
	other := max(0, pressure.used-pressure.managed-pressure.cleanFile)
	available := loan.limit - min(24*MiB, loan.limit/8) - other
	// A temporary live heap cannot be reclaimed by lowering GOMEMLIMIT.
	// Leave it growth room instead of turning pressure into continuous GC.
	floor := min(loan.idle, max(loan.base, pressure.live+pressure.nonHeap+8*MiB))
	return max(floor, min(loan.idle, available))
}

// Call with loan.mu held. ACME admission and release use the same lock as the
// monitor, so monitoring cannot restore a loan while its helper is running.
func (loan *acmeLoan) applyLimit(limit int64) {
	loan.setLimit(limit)
	loan.current = limit
}

func (loan *acmeLoan) adjustPressure() {
	loan.mu.Lock()
	defer loan.mu.Unlock()
	target := loan.idleLimit()
	if loan.current == 0 {
		loan.current = loan.idle
	}
	if target > loan.current {
		target = min(target, loan.current+4*MiB)
	}
	difference := max(target, loan.current) - min(target, loan.current)
	if target != loan.current && (target == loan.base || target == loan.idle || difference >= MiB) {
		loan.applyLimit(target)
	}
}

func startACMEPressureMonitor() {
	controllerLoan.Lock()
	defer controllerLoan.Unlock()
	loan := controllerLoan.loan
	if loan == nil || loan.pressure == nil || loan.stopPressure != nil {
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	var once sync.Once
	loan.stopPressure = func() { once.Do(func() { close(stop); <-done }) }
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				loan.adjustPressure()
			}
		}
	}()
}
