package policydns

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestSharedDNSWaitersDoNotConsumeWorkOrQueueSlots(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &gatedQueryUpstream{started: make(chan struct{}, 32), release: make(chan struct{})}
	s := burstService(ctx, backend, 4, time.Second)
	ownerQuery := dnsQuery(1, "shared.example.test")
	owner := s.admitQuery("lane", ownerQuery)
	done := make(chan []byte, 17)
	go func() { answer, _ := s.resolveAdmitted(owner, "lane", ownerQuery); done <- answer }()
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("owner did not start")
	}
	var waiting sync.WaitGroup
	for i := range 15 {
		q := dnsQuery(uint16(i+2), "shared.example.test")
		a := s.admitQuery("lane", q)
		if !a.shared || a.immediate {
			t.Fatalf("copy %d did not join", i)
		}
		waiting.Add(1)
		go func() { defer waiting.Done(); answer, _ := s.resolveAdmitted(a, "lane", q); done <- answer }()
	}
	overflow := s.admitQuery("lane", dnsQuery(99, "shared.example.test"))
	if !overflow.immediate {
		t.Fatal("per-key duplicate cap was not enforced")
	}
	if len(s.limit) != 1 || len(s.pending) != 0 {
		t.Fatal("duplicates consumed upstream capacity")
	}
	q := dnsQuery(100, "independent.example.test")
	a := s.admitQuery("lane", q)
	if a.queued || a.immediate || a.shared {
		t.Fatal("copies blocked independent lookup")
	}
	go func() { answer, _ := s.resolveAdmitted(a, "lane", q); done <- answer }()
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("independent query stalled")
	}
	close(backend.release)
	seen := make(map[uint16]bool)
	for range 17 {
		select {
		case answer := <-done:
			if len(answer) < 12 || binary.BigEndian.Uint16(answer[2:4])&15 != 0 {
				t.Fatalf("invalid response: %x", answer)
			}
			seen[binary.BigEndian.Uint16(answer[:2])] = true
		case <-time.After(time.Second):
			t.Fatal("shared queries did not finish")
		}
	}
	waiting.Wait()
	if len(seen) != 17 || backend.calls.Load() != 2 || s.queryBytes != 0 || s.sharedQueries != 0 || len(s.limit) != 0 || len(s.pending) != 0 {
		t.Fatal("IDs, coalescing or admission leaked")
	}
}

func TestDNSByteAdmissionAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := burstService(ctx, &countingUpstream{}, 2, time.Second)
	s.limit <- struct{}{}
	s.limit <- struct{}{}
	queries := make([][]byte, 3)
	admitted := make([]queryAdmission, 3)
	for i := range queries {
		m := new(dns.Msg)
		m.SetQuestion(fmt.Sprintf("large-%d.example.test.", i), dns.TypeA)
		m.SetEdns0(65535, true)
		m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: make([]byte, 60000)}}
		q, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		queries[i], admitted[i] = q, s.admitQuery("lane", q)
	}
	if !admitted[0].queued || !admitted[1].queued || !admitted[2].immediate || s.queryBytes > 2*maxDNSMessage {
		t.Fatal("retained-byte admission failed")
	}
	cancel()
	for i := range 2 {
		_, _ = s.resolveAdmitted(admitted[i], "lane", queries[i])
	}
	if s.queryBytes != 0 || len(s.pending) != 0 || len(s.runtime.flights.flights) != 0 {
		t.Fatal("cancelled admission leaked")
	}
}

func TestDNSLargeVLESSQueriesPreserveWANByteAllowance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := burstService(ctx, &countingUpstream{}, 2, time.Second)
	s.runtime.servers["fast"] = &countingUpstream{}
	s.runtime.lanes["fast"] = &lane{id: "fast", final: "fast"}
	m := new(dns.Msg)
	m.SetQuestion("large.example.test.", dns.TypeA)
	m.SetEdns0(65535, true)
	m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: make([]byte, 60000)}}
	q, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	a := s.admitQuery("lane", q)
	if a.immediate {
		t.Fatal("first large packet refused")
	}
	if !s.admitQuery("lane", q).immediate {
		t.Fatal("one profile consumed another profiles byte allowance")
	}
	wan := dnsQuery(44, "fast.example.test")
	w := s.admitQuery("fast", wan)
	if w.immediate || w.queued {
		t.Fatal("large VLESS packet blocked WAN")
	}
	answer, err := s.resolveAdmitted(w, "fast", wan)
	if err != nil || len(answer) < 12 || binary.BigEndian.Uint16(answer[2:4])&15 != 0 {
		t.Fatal("WAN answer failed")
	}
	_, _ = s.resolveAdmitted(a, "lane", q)
	if s.queryBytes != 0 || s.routes["wan"].bytes != 0 || s.routes["fast"].bytes != 0 {
		t.Fatal("profile bytes leaked")
	}
}
