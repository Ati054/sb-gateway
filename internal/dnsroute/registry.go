// Package dnsroute carries confirmed route observations inside one appliance.
// It performs no RPC, filesystem access or per-query notification.
package dnsroute

import "sync"

type Core struct {
	PID        int
	StartTicks uint64
}

type Snapshot struct {
	Sequence uint64
	Core     Core
	Selected string
}

// Registry keeps only the current producer inventory and live DNS dependencies,
// not catalog nodes or selection history. It belongs to one appliance instance.
type Registry struct {
	mu          sync.Mutex
	sequence    uint64
	core        Core
	publisher   *Publisher
	known       map[string]bool
	selected    map[string]string
	refs        map[string]int
	subscribers map[*Subscription]struct{}
}

type Publisher struct{ registry *Registry }
type Subscription struct {
	registry      *Registry
	detour        string
	coreSensitive bool
	mu            sync.Mutex
	closed, seen  bool
	sequence      uint64
	changed       func(Snapshot)
}

func New() *Registry {
	return &Registry{known: make(map[string]bool), selected: make(map[string]string), refs: make(map[string]int), subscribers: make(map[*Subscription]struct{})}
}

// Replacing a monitor invalidates the previous publisher, preserving observations
// still needed by live DNS profiles. A stopped producer cannot publish late.
func (r *Registry) NewPublisher() *Publisher {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := &Publisher{r}
	r.publisher = p
	return p
}

func (p *Publisher) Sync(core Core, selectors []string) {
	r := p.registry
	r.mu.Lock()
	if r.publisher != p {
		r.mu.Unlock()
		return
	}
	r.known = make(map[string]bool, len(selectors))
	for _, id := range selectors {
		r.known[id] = true
	}
	r.pruneLocked()
	changed := r.core != core
	if changed {
		r.core = core
		r.sequence++
	}
	events := r.eventsLocked("", changed)
	r.mu.Unlock()
	deliver(events)
}

func (p *Publisher) Confirm(selector, runtimeTag string) {
	r := p.registry
	r.mu.Lock()
	if r.publisher != p || !r.known[selector] || runtimeTag == "" || r.selected[selector] == runtimeTag {
		r.mu.Unlock()
		return
	}
	r.selected[selector] = runtimeTag
	r.sequence++
	events := r.eventsLocked(selector, false)
	r.mu.Unlock()
	deliver(events)
}

func (p *Publisher) Close() {
	r := p.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.publisher == p {
		r.publisher = nil
		r.known = make(map[string]bool)
		r.pruneLocked()
	}
}

type event struct {
	subscriber *Subscription
	snapshot   Snapshot
}

func (r *Registry) snapshotLocked(s *Subscription) Snapshot {
	v := Snapshot{Sequence: r.sequence, Selected: r.selected[s.detour]}
	if s.coreSensitive {
		v.Core = r.core
	}
	return v
}
func (r *Registry) eventsLocked(detour string, coreChanged bool) []event {
	var events []event
	for s := range r.subscribers {
		if (coreChanged && s.coreSensitive) || (detour != "" && s.detour == detour) {
			events = append(events, event{s, r.snapshotLocked(s)})
		}
	}
	return events
}
func deliver(events []event) {
	for _, e := range events {
		e.subscriber.deliver(e.snapshot)
	}
}
func (s *Subscription) deliver(v Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || (s.seen && v.Sequence <= s.sequence) {
		return
	}
	s.seen, s.sequence = true, v.Sequence
	s.changed(v)
}

// Subscribe synchronously delivers the latest observation. Callbacks run without
// the registry lock, initiate no DNS exchanges, and never re-enter their subscription.
func (r *Registry) Subscribe(detour string, coreSensitive bool, changed func(Snapshot)) *Subscription {
	s := &Subscription{registry: r, detour: detour, coreSensitive: coreSensitive, changed: changed}
	r.mu.Lock()
	r.subscribers[s] = struct{}{}
	if detour != "" {
		r.refs[detour]++
	}
	v := r.snapshotLocked(s)
	r.mu.Unlock()
	s.deliver(v)
	return s
}
func (s *Subscription) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.subscribers, s)
	if s.detour != "" {
		r.refs[s.detour]--
		if r.refs[s.detour] == 0 {
			delete(r.refs, s.detour)
		}
	}
	r.pruneLocked()
}
func (r *Registry) pruneLocked() {
	for id := range r.selected {
		if !r.known[id] && r.refs[id] == 0 {
			delete(r.selected, id)
		}
	}
}
