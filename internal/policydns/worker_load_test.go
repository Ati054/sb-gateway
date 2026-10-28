package policydns

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Run the admission and resolution paths with the same retained packet buffers
// as UDP serving. Synthetic upstream delay excludes Internet and NIC variance;
// this does not model TLS memory or establish whole-router CPU performance.
func runDNSAdmissionBurst(tb testing.TB, workers, count int) (int, int) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	backend := &burstUpstream{}
	s := burstService(ctx, backend, workers, 4*time.Second)
	type queued struct {
		admission queryAdmission
		query     []byte
	}
	batch := make([]queued, 0, count)
	for i := range count {
		query := dnsQuery(uint16(i+1), fmt.Sprintf("burst-%d.example.test", i))
		batch = append(batch, queued{s.admitQuery("lane", query), query})
	}
	var success, failed atomic.Int32
	var wait sync.WaitGroup
	for _, q := range batch {
		wait.Add(1)
		go func() {
			defer wait.Done()
			answer, err := s.resolveAdmitted(q.admission, "lane", q.query)
			if err != nil || len(answer) < 12 || binary.BigEndian.Uint16(answer[:2]) != binary.BigEndian.Uint16(q.query[:2]) {
				failed.Add(1)
				return
			}
			if binary.BigEndian.Uint16(answer[2:4])&15 == 0 {
				success.Add(1)
			} else {
				failed.Add(1)
			}
		}()
	}
	wait.Wait()
	if backend.peak.Load() > int32(workers) || len(s.limit) != 0 || len(s.pending) != 0 || s.queryBytes != 0 || s.sharedQueries != 0 || len(s.runtime.flights.flights) != 0 {
		tb.Fatalf("admission leaked or exceeded concurrency: peak=%d active=%d pending=%d", backend.peak.Load(), len(s.limit), len(s.pending))
	}
	return int(success.Load()), int(failed.Load())
}

func TestDNSBurstCapacityAt16And32Workers(t *testing.T) {
	for _, workers := range []int{16, 32} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			success, failed := runDNSAdmissionBurst(t, workers, 96)
			want := min(96, workers*5)
			if success != want || failed != 96-want {
				t.Fatalf("served=%d failed=%d want served=%d", success, failed, want)
			}
		})
	}
}

type heldDNSUpstream struct {
	started chan struct{}
	release <-chan struct{}
}

func (h *heldDNSUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	h.started <- struct{}{}
	select {
	case <-h.release:
		return dnsAResponse(query, 60), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*heldDNSUpstream) close() {}

func TestDNSSlowResolverPreservesAnotherProfilesSlot(t *testing.T) {
	for _, test := range []struct{ workers, slow int }{{16, 8}, {32, 16}, {64, 32}} {
		t.Run(fmt.Sprintf("workers-%d-slow-%d", test.workers, test.slow), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			slow := &heldDNSUpstream{started: make(chan struct{}, test.slow), release: release}
			fast := &burstUpstream{}
			s := burstService(ctx, slow, test.workers, 4*time.Second)
			s.runtime.lanes["fast"] = &lane{id: "fast", final: "fast"}
			s.runtime.servers["fast"] = fast
			done := make(chan error, test.slow+1)
			for i := range test.slow {
				q := dnsQuery(uint16(i+1), fmt.Sprintf("slow-%d.example.test", i))
				a := s.admitQuery("lane", q)
				go func() { _, e := s.resolveAdmitted(a, "lane", q); done <- e }()
			}
			for range test.slow {
				select {
				case <-slow.started:
				case <-ctx.Done():
					t.Fatal("slow requests did not enter resolver")
				}
			}
			q := dnsQuery(1000, "fast.example.test")
			a := s.admitQuery("fast", q)
			if a.queued {
				t.Fatalf("unexpected isolation/concurrency: queued=%t", a.queued)
			}
			go func() {
				answer, e := s.resolveAdmitted(a, "fast", q)
				if e == nil && (len(answer) < 12 || binary.BigEndian.Uint16(answer[2:4])&15 != 0) {
					e = fmt.Errorf("fast resolver failed")
				}
				done <- e
			}()
			if !a.queued {
				select {
				case e := <-done:
					if e != nil {
						t.Fatal(e)
					}
				case <-ctx.Done():
					t.Fatal("healthy resolver could not use remaining worker")
				}
			}
			unblock()
			remaining := test.slow + 1
			if !a.queued {
				remaining--
			}
			for range remaining {
				select {
				case e := <-done:
					if e != nil {
						t.Fatal(e)
					}
				case <-ctx.Done():
					t.Fatal("requests failed to drain")
				}
			}
			if len(s.limit) != 0 || len(s.pending) != 0 {
				t.Fatal("admission did not drain")
			}
		})
	}
}

func BenchmarkDNSAdmissionBurst(b *testing.B) {
	for _, workers := range []int{16, 32, 64} {
		b.Run(fmt.Sprint(workers), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				success, failed := runDNSAdmissionBurst(b, workers, 64)
				if success != 64 || failed != 0 {
					b.Fatalf("served=%d failed=%d", success, failed)
				}
			}
			b.ReportMetric(64, "queries/burst")
		})
	}
}
