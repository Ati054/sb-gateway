package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUnderlayPositiveEvidenceCancelsAndJoinsSlowSiblings(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	slowStarted := make(chan struct{}, 2)
	slowCanceled := make(chan struct{}, 2)
	allowFinish := make(chan struct{})
	release := sync.OnceFunc(func() { close(allowFinish) })
	defer release()
	var completed atomic.Int32
	var wanCalls, dnsCalls atomic.Int32
	done := make(chan underlayEvidence, 1)
	go func() {
		done <- collectUnderlayStatus(ctx, []string{"working", "slow-1", "slow-2"}, func(ctx context.Context, address string) bool {
			wanCalls.Add(1)
			if address == "working" {
				<-slowStarted
				<-slowStarted
				return true
			}
			slowStarted <- struct{}{}
			<-ctx.Done()
			slowCanceled <- struct{}{}
			<-allowFinish
			completed.Add(1)
			return false
		}, func(context.Context) bool {
			dnsCalls.Add(1)
			return true
		})
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-slowCanceled:
		case <-ctx.Done():
			t.Fatal("healthy WAN and DNS waited for unrelated WAN timeouts")
		}
	}
	select {
	case <-done:
		t.Fatal("underlay returned before canceled workers finished")
	default:
	}
	release()
	select {
	case status := <-done:
		if status != (underlayEvidence{Known: true, WANOK: true, DNSOK: true}) || completed.Load() != 2 || wanCalls.Load() != 3 || dnsCalls.Load() != 1 || ctx.Err() != nil {
			t.Fatalf("wrong early-success result or worker lifecycle: status=%+v completed=%d WAN=%d DNS=%d parent=%v", status, completed.Load(), wanCalls.Load(), dnsCalls.Load(), ctx.Err())
		}
	case <-ctx.Done():
		t.Fatal("canceled underlay workers were not joined promptly")
	}
}

func TestUnderlayFailureRequiresBothPositiveFacts(t *testing.T) {
	for _, test := range []struct {
		name string
		wan  bool
		dns  bool
	}{
		{name: "DNS failed", wan: true},
		{name: "all WAN failed", dns: true},
		{name: "WAN and DNS failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wanCalls, dnsCalls atomic.Int32
			status := collectUnderlayStatus(context.Background(), []string{"first", "second", "third"}, func(context.Context, string) bool {
				wanCalls.Add(1)
				return test.wan
			}, func(context.Context) bool {
				dnsCalls.Add(1)
				return test.dns
			})
			if status != (underlayEvidence{Known: true, WANOK: test.wan, DNSOK: test.dns}) || wanCalls.Load() != 3 || dnsCalls.Load() != 1 {
				t.Fatalf("failure was hidden or probe count changed: %+v WAN=%d DNS=%d", status, wanCalls.Load(), dnsCalls.Load())
			}
		})
	}
}

func TestUnderlayCancellationJoinsEveryWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, canceled := make(chan struct{}, 4), make(chan struct{}, 4)
	allowFinish := make(chan struct{})
	release := sync.OnceFunc(func() { close(allowFinish) })
	defer release()
	var completed atomic.Int32
	probe := func(ctx context.Context) bool {
		entered <- struct{}{}
		<-ctx.Done()
		canceled <- struct{}{}
		<-allowFinish
		completed.Add(1)
		return false
	}
	done := make(chan underlayEvidence, 1)
	go func() {
		done <- collectUnderlayStatus(ctx, []string{"first", "second", "third"}, func(ctx context.Context, _ string) bool { return probe(ctx) }, probe)
	}()
	deadline := time.After(time.Second)
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-deadline:
			t.Fatal("underlay worker did not start")
		}
	}
	cancel()
	for i := 0; i < 4; i++ {
		select {
		case <-canceled:
		case <-deadline:
			t.Fatal("underlay worker did not receive cancellation")
		}
	}
	select {
	case <-done:
		t.Fatal("parent cancellation returned before worker cleanup")
	default:
	}
	release()
	select {
	case status := <-done:
		if status != (underlayEvidence{Known: true}) || completed.Load() != 4 {
			t.Fatalf("canceled probe fabricated evidence or leaked workers: %+v completed=%d", status, completed.Load())
		}
	case <-deadline:
		t.Fatal("underlay cancellation did not finish")
	}
}
