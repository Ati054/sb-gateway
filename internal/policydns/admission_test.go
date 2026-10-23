package policydns

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestBusyWorkersKeepCachedUDPAndTCPAnswers(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			backend := &countingUpstream{}
			l := &lane{id: "lane", final: "wan", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
			r := &runtime{lanes: map[string]*lane{"lane": l}, servers: map[string]upstream{"wan": backend}, cache: newResponseCache(16, 1<<20, time.Hour), timeout: time.Second}
			s := &service{runtime: r, limit: make(chan struct{}, 2), tcpLimit: make(chan struct{}, 2), udpBuffers: sync.Pool{New: func() any { return new([maxDNSMessage]byte) }}}
			s.pending = make(chan struct{}, 2)
			for range cap(s.pending) {
				s.pending <- struct{}{}
			}
			if _, err := r.resolve(context.Background(), "lane", dnsQuery(123, "cached.example.com")); err != nil {
				t.Fatal(err)
			}
			for range cap(s.limit) {
				s.limit <- struct{}{}
			}
			var address string
			var closeListener func()
			if network == "udp" {
				socket, err := net.ListenPacket(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				closeListener = func() { _ = socket.Close() }
				address = socket.LocalAddr().String()
				s.wait.Add(1)
				go s.serveUDP("lane", socket)
			} else {
				listener, err := net.Listen(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				closeListener = func() { _ = listener.Close() }
				address = listener.Addr().String()
				s.wait.Add(1)
				go s.serveTCP("lane", listener)
			}
			defer func() { closeListener(); s.wait.Wait() }()
			client := &dns.Client{Net: network, Timeout: time.Second}
			for i, name := range []string{"cached.example.com", "uncached.example.com", "cached.example.com"} {
				request := new(dns.Msg)
				request.SetQuestion(name+".", dns.TypeA)
				request.Id = uint16(400 + i)
				answer, _, err := client.Exchange(request, address)
				if err != nil {
					t.Fatal(err)
				}
				want := dns.RcodeSuccess
				if i == 1 {
					want = dns.RcodeServerFailure
				}
				if answer.Id != request.Id || answer.Rcode != want {
					t.Fatalf("query %s: id=%d rcode=%d want %d", name, answer.Id, answer.Rcode, want)
				}
			}
			if backend.calls.Load() != 1 {
				t.Fatal("busy path started an upstream query")
			}
		})
	}
}

func TestBusyCachePreservesLaneAndRuleDecisions(t *testing.T) {
	a := &lane{id: "a", final: "wan", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	b := &lane{id: "b", final: "reject", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	c := &lane{id: "c", final: "wan", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	d := &lane{id: "d", final: "proxy", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	r := &runtime{lanes: map[string]*lane{"a": a, "b": b, "c": c, "d": d}, servers: map[string]upstream{"wan": &countingUpstream{}, "proxy": &countingUpstream{}}, cache: newResponseCache(16, 1<<20, time.Hour)}
	query := dnsQuery(77, "cached.example.com")
	key, err := normalizedQueryKey("wan", query)
	if err != nil {
		t.Fatal(err)
	}
	r.cache.putOwned(key, dnsAResponse(query, 60), time.Minute, time.Now())
	s := &service{runtime: r}
	for _, test := range []struct {
		lane string
		want uint16
	}{{"a", 0}, {"b", 5}, {"c", 0}, {"d", 2}, {"missing", 2}} {
		response := s.overloadResponse(test.lane, query)
		if len(response) < 12 || binary.BigEndian.Uint16(response[2:4])&15 != test.want {
			t.Fatalf("lane %s: %x", test.lane, response)
		}
	}
	a.exact["cached.example.com"] = ruleDecision{reject: true}
	if binary.BigEndian.Uint16(s.overloadResponse("a", query)[2:4])&15 != 5 {
		t.Fatal("cached answer bypassed rejection")
	}
	delete(a.exact, "cached.example.com")
	r.cache.putOwned(key, dnsAResponse(query, 60), time.Minute, time.Now().Add(-2*time.Minute))
	if binary.BigEndian.Uint16(s.overloadResponse("a", query)[2:4])&15 != 2 {
		t.Fatal("busy path silently treated an expired answer as fresh")
	}
}
