package policydns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type burstUpstream struct {
	active atomic.Int32
	peak   atomic.Int32
	calls  atomic.Int32
}

func (backend *burstUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	active := backend.active.Add(1)
	defer backend.active.Add(-1)
	backend.calls.Add(1)
	for previous := backend.peak.Load(); active > previous; previous = backend.peak.Load() {
		if backend.peak.CompareAndSwap(previous, active) {
			break
		}
	}
	select {
	case <-time.After(40 * time.Millisecond):
		return dnsAResponse(query, 60), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*burstUpstream) close() {}

func burstService(ctx context.Context, backend upstream, workers int, timeout time.Duration) *service {
	l := &lane{id: "lane", final: "wan", exact: map[string]ruleDecision{}, suffix: map[string]ruleDecision{}}
	return &service{
		ctx: ctx,
		runtime: &runtime{lanes: map[string]*lane{"lane": l}, servers: map[string]upstream{"wan": backend},
			cache: newResponseCache(32, 1<<20, time.Hour), timeout: timeout},
		limit: make(chan struct{}, workers), pending: make(chan struct{}, workers*4), tcpLimit: make(chan struct{}, 16),
		udpBuffers: sync.Pool{New: func() any { return new([maxDNSMessage]byte) }},
	}
}

func TestDNSBurstQueuesWithoutIncreasingUpstreamConcurrency(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			backend := &burstUpstream{}
			s := burstService(ctx, backend, 2, time.Second)
			var address string
			var closeListener func() error
			if network == "udp" {
				listener, err := net.ListenPacket(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address, closeListener = listener.LocalAddr().String(), listener.Close
				s.wait.Add(1)
				go s.serveUDP("lane", listener)
			} else {
				listener, err := net.Listen(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				address, closeListener = listener.Addr().String(), listener.Close
				s.wait.Add(1)
				go s.serveTCP("lane", listener)
			}
			defer func() { cancel(); _ = closeListener(); s.wait.Wait() }()
			start := make(chan struct{})
			results := make(chan error, 8)
			for i := range 8 {
				go func() {
					<-start
					question := new(dns.Msg)
					question.SetQuestion(fmt.Sprintf("burst-%d.example.com.", i), dns.TypeA)
					answer, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(question, address)
					if err == nil && (answer.Rcode != dns.RcodeSuccess || answer.Id != question.Id) {
						err = fmt.Errorf("invalid burst response: rcode=%d id=%d", answer.Rcode, answer.Id)
					}
					results <- err
				}()
			}
			close(start)
			for range 8 {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			if backend.calls.Load() != 8 || backend.peak.Load() != 2 || len(s.limit) != 0 || len(s.pending) != 0 {
				t.Fatalf("unbounded or leaked work: calls=%d peak=%d active=%d pending=%d", backend.calls.Load(), backend.peak.Load(), len(s.limit), len(s.pending))
			}
		})
	}
}

func TestDNSQueueIsBoundedAndMalformedOverflowDoesNotBorrowWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := burstService(ctx, &countingUpstream{}, 2, time.Second)
	s.limit <- struct{}{}
	s.limit <- struct{}{}
	query := dnsQuery(1, "queued.example.com")
	admissions := make([]queryAdmission, cap(s.pending))
	for i := range admissions {
		admissions[i] = s.admitQuery("lane", query)
		if !admissions[i].queued || admissions[i].immediate {
			t.Fatal("burst did not enter bounded queue")
		}
	}
	for _, payload := range [][]byte{query, {1, 2, 3}} {
		admission := s.admitQuery("lane", payload)
		if !admission.immediate || admission.queued {
			t.Fatal("full queue admitted extra work")
		}
		if _, err := s.resolveAdmitted(admission, "lane", payload); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.pending) != cap(s.pending) || len(s.limit) != 2 {
		t.Fatal("overflow changed admission ownership")
	}
	cancel()
	for _, admission := range admissions {
		if _, err := s.resolveAdmitted(admission, "lane", query); !errors.Is(err, context.Canceled) {
			t.Fatalf("shutdown did not cancel queued work: %v", err)
		}
	}
	if len(s.pending) != 0 || len(s.limit) != 2 {
		t.Fatal("shutdown leaked queue slots or released another worker")
	}
}

func TestExpiredQueuedDNSCannotStartAnotherUpstreamBudget(t *testing.T) {
	backend := &countingUpstream{}
	s := burstService(context.Background(), backend, 1, time.Second)
	s.limit <- struct{}{}
	query := dnsQuery(22, "expired.example.com")
	admission := s.admitQuery("lane", query)
	if !admission.queued {
		t.Fatal("query did not queue")
	}
	admission.deadline = time.Now().Add(-time.Second)
	<-s.limit
	answer, err := s.resolveAdmitted(admission, "lane", query)
	if err != nil || len(answer) < 12 || binary.BigEndian.Uint16(answer[2:4])&15 != dns.RcodeServerFailure {
		t.Fatalf("expired response: %x, %v", answer, err)
	}
	if backend.calls.Load() != 0 || len(s.pending) != 0 || len(s.limit) != 0 {
		t.Fatal("expired query started upstream work or leaked admission")
	}
}

type deadlineUpstream struct{ deadline time.Time }

func (backend *deadlineUpstream) exchange(ctx context.Context, query []byte) ([]byte, error) {
	backend.deadline, _ = ctx.Deadline()
	return dnsAResponse(query, 60), nil
}

func (*deadlineUpstream) close() {}

func TestQueuedDNSPreservesOriginalDeadline(t *testing.T) {
	backend := &deadlineUpstream{}
	s := burstService(context.Background(), backend, 1, time.Second)
	s.limit <- struct{}{}
	query := dnsQuery(23, "deadline.example.com")
	admission := s.admitQuery("lane", query)
	if !admission.queued {
		t.Fatal("query did not queue")
	}
	time.Sleep(20 * time.Millisecond)
	<-s.limit
	if _, err := s.resolveAdmitted(admission, "lane", query); err != nil {
		t.Fatal(err)
	}
	if !backend.deadline.Equal(admission.deadline) {
		t.Fatal("queue wait incorrectly restarted the upstream timeout")
	}
}
