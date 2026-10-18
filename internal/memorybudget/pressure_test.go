package memorybudget

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPressureFileCacheProtectsMappedAndDirtyMemory(t *testing.T) {
	for _, test := range []struct {
		body string
		want int64
		ok   bool
	}{
		{"file 67108864\nfile_mapped 16777216\nfile_dirty 2097152\nfile_writeback 1048576\n", 41 * MiB, true},
		{"file 1048576\nfile_mapped 2097152\nfile_dirty 0\nfile_writeback 0\n", 0, true},
		{"anon 3000\nfile 8388608\nfile_mapped 0\nfile_dirty 0\nfile_writeback 0\n", 4 * MiB, true},
		{"file 10\n", 0, false},
		{"file -1\nfile_mapped 0\nfile_dirty 0\nfile_writeback 0\n", 0, false},
		{"file max\nfile_mapped 0\nfile_dirty 0\nfile_writeback 0\n", 0, false},
		{"file 1\nfile 2\nfile_mapped 0\nfile_dirty 0\nfile_writeback 0\n", 0, false},
	} {
		got, ok := pressureFileCache([]byte(test.body))
		if got != test.want || ok != test.ok {
			t.Fatalf("pressureFileCache(%q)=%d,%t want %d,%t", test.body, got, ok, test.want, test.ok)
		}
	}
}

func TestPressureLoanTracksNonGoUsage(t *testing.T) {
	p := Derive(Limits{224 * MiB, 256 * MiB})
	for _, test := range []struct {
		name     string
		pressure loanPressure
		known    bool
		want     int64
	}{
		{"spare", loanPressure{used: 160 * MiB, managed: 60 * MiB, live: 20 * MiB, nonHeap: 8 * MiB, cleanFile: 32 * MiB}, true, p.Gateway + p.Worker},
		{"other memory grows", loanPressure{used: 210 * MiB, managed: 65 * MiB, live: 18 * MiB, nonHeap: 8 * MiB}, true, 55 * MiB},
		{"loan recalled", loanPressure{used: 220 * MiB, managed: 60 * MiB, live: 20 * MiB, nonHeap: 8 * MiB}, true, p.Gateway},
		{"clean cache", loanPressure{used: 210 * MiB, managed: 65 * MiB, live: 18 * MiB, nonHeap: 8 * MiB, cleanFile: 40 * MiB}, true, p.Gateway + p.Worker},
		{"live heap floor", loanPressure{used: 224 * MiB, managed: 70 * MiB, live: 54 * MiB, nonHeap: 12 * MiB}, true, p.Gateway + p.Worker},
		{"unknown", loanPressure{}, false, p.Gateway},
	} {
		t.Run(test.name, func(t *testing.T) {
			loan := &acmeLoan{slot: make(chan struct{}, 1), base: p.Gateway, idle: p.Gateway + p.Worker, limit: p.Ceiling,
				pressure: func() (loanPressure, bool) { return test.pressure, test.known }}
			if got := loan.idleLimit(); got != test.want {
				t.Fatalf("idleLimit=%d want %d", got, test.want)
			}
		})
	}
}

func TestPressureLoanCannotOverrideActiveACME(t *testing.T) {
	loan, limit, _, reclaims := testLoan()
	var pressured atomic.Bool
	loan.current = loan.idle
	loan.pressure = func() (loanPressure, bool) {
		used := int64(100 * MiB)
		if pressured.Load() {
			used = loan.limit
		}
		return loanPressure{used: used, managed: 48 * MiB, live: 20 * MiB, nonHeap: 8 * MiB}, true
	}
	release, err := loan.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			for range 100 {
				loan.adjustPressure()
				if limit.Load() != loan.base {
					t.Error("monitor lent memory to an active helper slot")
				}
			}
		})
	}
	wait.Wait()
	pressured.Store(true)
	release()
	release()
	if limit.Load() != loan.base || len(loan.slot) != 0 {
		t.Fatal("release restored an unsafe loan or retained its slot")
	}
	pressured.Store(false)
	loan.adjustPressure()
	if limit.Load() != min(loan.idle, loan.base+4*MiB) {
		t.Fatal("recovery skipped its growth bound")
	}
	for range 16 {
		loan.adjustPressure()
	}
	if limit.Load() != loan.idle || reclaims.Load() != 0 {
		t.Fatal("loan did not return or monitoring forced GC")
	}
}

func TestPressureUnknownRecallsLoanWithoutForcingGC(t *testing.T) {
	loan, limit, _, reclaims := testLoan()
	loan.current = loan.idle
	loan.pressure = func() (loanPressure, bool) { return loanPressure{}, false }
	loan.adjustPressure()
	if limit.Load() != loan.base || reclaims.Load() != 0 {
		t.Fatal("unknown stats retained the loan or forced collection")
	}
}

func TestPressureLoanIgnoresSmallCounterJitter(t *testing.T) {
	loan, limit, _, _ := testLoan()
	used := int64(208 * MiB)
	loan.current = 84 * MiB
	limit.Store(loan.current)
	loan.pressure = func() (loanPressure, bool) {
		return loanPressure{used: used, managed: 60 * MiB, live: 20 * MiB, nonHeap: 8 * MiB}, true
	}
	used += 64 << 10
	loan.adjustPressure()
	if limit.Load() != 84*MiB {
		t.Fatal("small accounting jitter changed the GC limit")
	}
	used = 210 * MiB
	loan.adjustPressure()
	if limit.Load() != 82*MiB {
		t.Fatal("meaningful memory pressure was ignored")
	}
}

func FuzzPressureLoanBounds(f *testing.F) {
	f.Add(uint32(200), uint32(60), uint32(20), uint32(8), uint32(10))
	f.Fuzz(func(t *testing.T, used, managed, live, nonHeap, cache uint32) {
		p := Derive(Limits{224 * MiB, 256 * MiB})
		sample := loanPressure{int64(used%1024) * MiB, int64(managed%256) * MiB, int64(live%128) * MiB, int64(nonHeap%64) * MiB, int64(cache%512) * MiB}
		loan := &acmeLoan{slot: make(chan struct{}, 1), base: p.Gateway, idle: p.Gateway + p.Worker, limit: p.Ceiling,
			pressure: func() (loanPressure, bool) { return sample, true }}
		before := loan.idleLimit()
		sample.used += MiB
		after := loan.idleLimit()
		if before < loan.base || before > loan.idle || after > before || after < loan.base {
			t.Fatal("pressure increased the loan or escaped its bounds")
		}
	})
}
