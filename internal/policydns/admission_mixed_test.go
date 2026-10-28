package policydns

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Slow VLESS saturates its allowance and fills its unique queue while copies
// wait on those same exchanges. WAN must retain the same parallelism as alone.
func TestMixedDNSFastWANSlowVLESSDuplicatesAndUnique(t *testing.T) {
	for _, workers := range []int{16, 32, 64} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			slow := &heldDNSUpstream{started: make(chan struct{}, workers*3), release: release}
			fast := &burstUpstream{}
			s := burstService(ctx, slow, workers, 3*time.Second)
			s.runtime.servers["fast-wan"] = fast
			s.runtime.lanes["fast-wan"] = &lane{id: "fast-wan", final: "fast-wan"}
			var slowWait sync.WaitGroup
			for i := range workers/2 + workers*2 {
				q := dnsQuery(uint16(i+1), fmt.Sprintf("slow-%d.example.test", i))
				a := s.admitQuery("lane", q)
				if a.immediate {
					t.Fatal("slow workload was refused before its own quota")
				}
				slowWait.Add(1)
				go func() { defer slowWait.Done(); _, _ = s.resolveAdmitted(a, "lane", q) }()
			}
			for range workers / 2 {
				select {
				case <-slow.started:
				case <-ctx.Done():
					t.Fatal("slow profile failed to saturate")
				}
			}
			for i := range workers * 2 {
				q := dnsQuery(uint16(1000+i), "slow-0.example.test")
				a := s.admitQuery("lane", q)
				if !a.shared || a.immediate {
					t.Fatal("copy failed to join saturated VLESS")
				}
				slowWait.Add(1)
				go func() { defer slowWait.Done(); _, _ = s.resolveAdmitted(a, "lane", q) }()
			}
			if !s.admitQuery("lane", dnsQuery(9000, "excess-slow.example.test")).immediate {
				t.Fatal("slow profile exceeded unique queue quota")
			}
			start := time.Now()
			fastResults := make(chan error, workers/2)
			for i := range workers / 2 {
				q := dnsQuery(uint16(2000+i), fmt.Sprintf("fast-%d.example.test", i))
				a := s.admitQuery("fast-wan", q)
				if a.immediate || a.queued {
					t.Fatal("slow profile consumed WAN admission")
				}
				go func() {
					answer, err := s.resolveAdmitted(a, "fast-wan", q)
					if err == nil && (len(answer) < 12 || binary.BigEndian.Uint16(answer[2:4])&15 != 0) {
						err = fmt.Errorf("invalid WAN answer")
					}
					fastResults <- err
				}()
			}
			for range workers / 2 {
				select {
				case err := <-fastResults:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("WAN stalled behind VLESS")
				}
			}
			elapsed := time.Since(start)
			if fast.peak.Load() != int32(workers/2) {
				t.Fatalf("WAN lost concurrency: %d", fast.peak.Load())
			}
			// A generous deadline detects waiting for the held VLESS exchange;
			// exact elapsed timings belong in benchmarks, not timing assertions.
			if elapsed > time.Second {
				t.Fatalf("WAN delayed %v by VLESS", elapsed)
			}
			t.Logf("WAN batch=%d completed in %v with VLESS held", workers/2, elapsed)
			releaseOnce.Do(func() { close(release) })
			slowWait.Wait()
			if s.queryBytes != 0 || s.sharedQueries != 0 || len(s.pending) != 0 || len(s.limit) != 0 || len(s.runtime.flights.flights) != 0 {
				t.Fatal("mixed admission did not drain")
			}
		})
	}
}
