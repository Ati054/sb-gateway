package dnsroute

import (
	"fmt"
	"sync"
	"testing"
)

func TestConfirmedRouteEpochsAreScopedAndDoNotResurrect(t *testing.T) {
	r := New()
	p := r.NewPublisher()
	core := Core{PID: 10, StartTicks: 20}
	p.Sync(core, []string{"a", "b"})
	var a, b, direct []Snapshot
	sa := r.Subscribe("a", true, func(s Snapshot) { a = append(a, s) })
	defer sa.Close()
	sb := r.Subscribe("b", true, func(s Snapshot) { b = append(b, s) })
	defer sb.Close()
	sd := r.Subscribe("", false, func(s Snapshot) { direct = append(direct, s) })
	defer sd.Close()
	p.Confirm("a", "handler-A")
	p.Confirm("a", "handler-A")
	p.Confirm("probe", "candidate")
	p.Sync(core, []string{"a", "b", "new-catalog-policy"})
	if len(a) != 2 || len(b) != 1 || len(direct) != 1 {
		t.Fatal("no-op, unrelated inventory or probe rotated a profile")
	}
	p.Confirm("a", "handler-B")
	p.Confirm("a", "handler-A")
	if len(a) != 4 || a[3].Sequence <= a[1].Sequence || a[3].Selected != a[1].Selected {
		t.Fatal("A-B-A resurrected an old epoch")
	}
	p.Sync(Core{PID: 10, StartTicks: 21}, []string{"a", "b"})
	if len(a) != 5 || len(b) != 2 || len(direct) != 1 {
		t.Fatal("core identity must rotate tunnels, not direct upstreams")
	}
}

func TestRouteRegistryRestartAndBoundedCurrentDependencies(t *testing.T) {
	r := New()
	old := r.NewPublisher()
	c := Core{PID: 1, StartTicks: 2}
	old.Sync(c, []string{"a"})
	old.Confirm("a", "first")
	var got Snapshot
	s := r.Subscribe("a", true, func(v Snapshot) { got = v })
	if got.Selected != "first" {
		t.Fatal("DNS restart lost the latest confirmed selection")
	}
	next := r.NewPublisher()
	next.Sync(c, []string{"a"})
	old.Confirm("a", "late")
	old.Sync(Core{PID: 2, StartTicks: 3}, nil)
	old.Close()
	if got.Selected != "first" || got.Core != c {
		t.Fatal("stopped monitor changed the active registry")
	}
	next.Confirm("a", "second")
	for i := range 100 {
		id := fmt.Sprint("ephemeral-", i)
		next.Sync(c, []string{id})
		next.Confirm(id, "tag")
	}
	if len(r.selected) != 2 {
		t.Fatalf("unbounded selection history: %d", len(r.selected))
	}
	s.Close()
	if len(r.selected) != 1 {
		t.Fatal("closed DNS dependency retained history")
	}
	next.Close()
	if len(r.selected) != 0 || len(r.refs) != 0 || len(r.subscribers) != 0 {
		t.Fatal("registry lifetime leaked")
	}
}

func TestRouteSubscriptionIgnoresReorderedCallbacksAndConcurrentRestarts(t *testing.T) {
	r := New()
	p := r.NewPublisher()
	p.Sync(Core{PID: 1, StartTicks: 1}, []string{"a"})
	var last Snapshot
	s := r.Subscribe("a", true, func(v Snapshot) { last = v })
	s.deliver(Snapshot{Sequence: 100, Selected: "new"})
	s.deliver(Snapshot{Sequence: 99, Selected: "old"})
	if last.Selected != "new" {
		t.Fatal("late callback restored a stale route")
	}
	s.Close()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				sub := r.Subscribe("a", true, func(Snapshot) {})
				pub := r.NewPublisher()
				pub.Sync(Core{PID: 2, StartTicks: 2}, []string{"a"})
				pub.Confirm("a", "value")
				sub.Close()
				pub.Close()
			}
		}()
	}
	wg.Wait()
	if len(r.subscribers) != 0 || len(r.refs) != 0 {
		t.Fatal("restart subscriptions leaked")
	}
}
