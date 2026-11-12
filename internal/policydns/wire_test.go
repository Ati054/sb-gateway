package policydns

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type questionlessUpstream struct{ calls atomic.Int32 }

func (u *questionlessUpstream) exchange(_ context.Context, wire []byte) ([]byte, error) {
	u.calls.Add(1)
	request := new(dns.Msg)
	if err := request.Unpack(wire); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Extra = request.Extra
	// Even an upstream answer with a TTL must not cache a questionless probe.
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "answer.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 1)}}
	return response.Pack()
}
func (*questionlessUpstream) close() {}

func questionlessQuery(t *testing.T, id uint16, edns bool) []byte {
	t.Helper()
	message := &dns.Msg{MsgHdr: dns.MsgHdr{Id: id, RecursionDesired: true}}
	if edns {
		message.SetEdns0(1232, false)
		message.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0011223344556677"}}
	}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestQuestionlessProbeUsesAuthorizedFinalWithoutCaching(t *testing.T) {
	wan, proxy := &questionlessUpstream{}, &questionlessUpstream{}
	r := sharedQueryRuntime(t, map[string]upstream{"wan": wan, "proxy": proxy},
		laneConfig{ID: "wan", Final: "wan"}, laneConfig{ID: "proxy", Final: "proxy"}, laneConfig{ID: "blocked", Final: "reject"})
	// No domain exists to match, even if a compiled map contains an empty key.
	r.lanes["proxy"].exact[""] = ruleDecision{reject: true}
	for _, edns := range []bool{false, true} {
		for _, id := range []uint16{11, 12} {
			query := questionlessQuery(t, id, edns)
			answer, err := r.resolve(t.Context(), "proxy", query)
			if err != nil || !matchingQuestion(query, answer) || answer[3]&15 != 0 {
				t.Fatalf("questionless probe failed: %v, %x", err, answer)
			}
			if responseTTL(answer) != 0 {
				t.Fatal("questionless answer became cacheable")
			}
		}
	}
	if proxy.calls.Load() != 4 || wan.calls.Load() != 0 {
		t.Fatal("probe was cached or escaped its resolver policy")
	}
	answer, err := r.resolve(t.Context(), "blocked", questionlessQuery(t, 13, true))
	if err != nil || len(answer) < 12 || answer[3]&15 != dns.RcodeRefused || proxy.calls.Load() != 4 || wan.calls.Load() != 0 {
		t.Fatal("questionless probe bypassed a final reject")
	}
}

func TestMalformedDNSIsRejectedBeforeUpstream(t *testing.T) {
	backend := &questionlessUpstream{}
	r := sharedQueryRuntime(t, map[string]upstream{"wan": backend}, laneConfig{ID: "lane", Final: "wan"})
	message := &dns.Msg{Question: []dns.Question{{Name: "one.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, {Name: "two.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}}
	twoQuestions, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	missingAdditional := dnsQuery(20, "missing.example")
	missingAdditional[11] = 1
	for _, query := range [][]byte{twoQuestions, missingAdditional, questionlessQuery(t, 21, true)[:15]} {
		answer, err := r.resolve(t.Context(), "lane", query)
		if err != nil || len(answer) < 12 || answer[3]&15 != dns.RcodeFormatError {
			t.Fatalf("malformed query did not receive FORMERR: %v, %x", err, answer)
		}
	}
	if backend.calls.Load() != 0 {
		t.Fatal("malformed query reached upstream")
	}
}

func TestQuestionlessResponseRequiresMatchingHeaderAndSections(t *testing.T) {
	query := questionlessQuery(t, 31, true)
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	if !matchingQuestion(query, response) {
		t.Fatal("valid empty-question response rejected")
	}
	for _, mutate := range []func([]byte){func(p []byte) { p[0]++ }, func(p []byte) { p[2] ^= 8 }, func(p []byte) { p[5] = 1 }, func(p []byte) { p[9] = 1 }} {
		other := append([]byte(nil), response...)
		mutate(other)
		if matchingQuestion(query, other) {
			t.Fatal("mismatched questionless response accepted")
		}
	}
}

func TestUDPTruncationMustMatchRequestBeforeTCPFallback(t *testing.T) {
	query := dnsQuery(60, "truncated.example")
	response := append([]byte(nil), query[:12]...)
	response[2] |= 0x82
	response[5] = 0 // A header-only TC response has no question.
	if !truncatedDNSReply(query, response) {
		t.Fatal("valid truncated header did not request TCP")
	}
	for _, mutate := range []func([]byte){func(p []byte) { p[0]++ }, func(p []byte) { p[2] ^= 8 }, func(p []byte) { p[2] &= 0x7f }} {
		other := append([]byte(nil), response...)
		mutate(other)
		if truncatedDNSReply(query, other) {
			t.Fatal("unrelated truncated response requested TCP")
		}
	}
}

func writeDNSFrame(t *testing.T, conn net.Conn, query []byte) {
	t.Helper()
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if err := writeAll(conn, append(frame, query...)); err != nil {
		t.Fatal(err)
	}
}

func readDNSFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err := io.ReadFull(conn, wire); err != nil {
		t.Fatal(err)
	}
	return wire
}

func checkIgnoredResponseThenProbe(t *testing.T, conn net.Conn, tcp bool) {
	t.Helper()
	response := dnsQuery(40, "ignored.example")
	response[2] |= 0x80
	conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if tcp {
		writeDNSFrame(t, conn, response)
	} else if _, err := conn.Write(response); err != nil {
		t.Fatal(err)
	}
	var buffer [maxDNSMessage]byte
	if n, err := conn.Read(buffer[:]); err == nil || n != 0 {
		t.Fatal("incoming DNS response produced a response or empty TCP frame")
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	for index, edns := range []bool{false, true} {
		query := questionlessQuery(t, uint16(41+index), edns)
		var answer []byte
		if tcp {
			writeDNSFrame(t, conn, query)
			answer = readDNSFrame(t, conn)
		} else {
			if _, err := conn.Write(query); err != nil {
				t.Fatal(err)
			}
			n, err := conn.Read(buffer[:])
			if err != nil {
				t.Fatal(err)
			}
			answer = buffer[:n]
		}
		if !matchingQuestion(query, answer) || answer[3]&15 != 0 {
			t.Fatal("valid probe after ignored response failed")
		}
	}
}

func TestDNSIngressIgnoresResponsesAndForwardsQuestionlessProbes(t *testing.T) {
	for _, network := range []string{"udp4", "udp6", "tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			backend := &questionlessUpstream{}
			r := sharedQueryRuntime(t, map[string]upstream{"wan": backend}, laneConfig{ID: "lane", Final: "wan"})
			r.timeout = 2 * time.Second
			s, cancel := managedTestService(r)
			address := "127.0.0.1:0"
			if network[len(network)-1] == '6' {
				address = "[::1]:0"
			}
			var closeListener func() error
			if network[:3] == "udp" {
				listener, err := net.ListenPacket(network, address)
				if err != nil {
					cancel()
					t.Skip(err)
				}
				address, closeListener = listener.LocalAddr().String(), listener.Close
				s.wait.Add(1)
				go s.serveUDP("lane", listener)
			} else {
				listener, err := net.Listen(network, address)
				if err != nil {
					cancel()
					t.Skip(err)
				}
				address, closeListener = listener.Addr().String(), listener.Close
				s.wait.Add(1)
				go s.serveTCP("lane", listener)
			}
			t.Cleanup(func() { cancel(); closeListener(); s.wait.Wait() })
			conn, err := net.Dial(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			checkIgnoredResponseThenProbe(t, conn, network[:3] == "tcp")
			if backend.calls.Load() != 2 {
				t.Fatal("ignored response was admitted or probe was cached")
			}
		})
	}
}

func TestFreshDNSIngressPermitsQuestionlessAndIgnoresResponses(t *testing.T) {
	var calls atomic.Int32
	forwarder := startFreshDoH(t, func(query *dns.Msg) *dns.Msg {
		calls.Add(1)
		response := new(dns.Msg)
		response.SetReply(query)
		response.Extra = query.Extra
		return response
	})
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			conn, err := net.Dial(network, forwarder.Address())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			checkIgnoredResponseThenProbe(t, conn, network == "tcp")
		})
	}
	if calls.Load() != 4 {
		t.Fatal("fresh bridge admitted an incoming response or cached a probe")
	}
}
