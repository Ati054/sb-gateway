package policydns

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	"testing"
)

func TestTruncatedReplyBindsQuestionBeforeTCP(t *testing.T) {
	q := dnsQuery(81, "correct.example")
	for _, kind := range []string{"name", "type", "class", "count", "incomplete-question"} {
		t.Run(kind, func(t *testing.T) {
			a := append([]byte(nil), q...)
			a[2] |= 0x82
			switch kind {
			case "name":
				a[13] ^= 1
			case "type":
				a[len(a)-3] ^= 1
			case "class":
				a[len(a)-1] ^= 1
			case "count":
				a[5] = 2
			case "incomplete-question":
				a = a[:13]
			}
			if truncatedDNSReply(q, a) {
				t.Fatal("unrelated TC requested another transport")
			}
		})
	}
	a := append([]byte(nil), q...)
	a[2] |= 0x82
	a[7] = 1
	a = append(a, 0xc0) // an RR truncated inside its owner name
	if !truncatedDNSReply(q, a) {
		t.Fatal("valid TC with partial RR was rejected")
	}
	a = append([]byte(nil), q[:12]...)
	a[2] |= 0x82
	a[4] = 0
	a[5] = 0
	if !truncatedDNSReply(q, a) {
		t.Fatal("header-only TC was rejected")
	}
}

func TestIQueryHandledLocallyBeforeRoutesAndCache(t *testing.T) {
	backend := &questionlessUpstream{}
	r := sharedQueryRuntime(t, map[string]upstream{"wan": backend}, laneConfig{ID: "allowed", Final: "wan"}, laneConfig{ID: "blocked", Final: "reject"})
	m := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 82, Opcode: dns.OpcodeIQuery, RecursionDesired: true}, Answer: []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "value.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{192, 0, 2, 8}}}}
	q, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range []string{"allowed", "blocked"} {
		a, err := r.resolve(t.Context(), lane, q)
		if err != nil || len(a) != 12 || binary.BigEndian.Uint16(a[:2]) != 82 || a[2]&0x80 == 0 || (a[2]>>3)&15 != 1 || a[3]&15 != dns.RcodeNotImplemented {
			t.Fatalf("IQUERY not handled locally: %v %x", err, a)
		}
		for _, b := range a[4:] {
			if b != 0 {
				t.Fatal("IQUERY response echoed a record")
			}
		}
	}
	if backend.calls.Load() != 0 {
		t.Fatal("IQUERY reached upstream")
	}
	bad := append([]byte(nil), q...)
	bad = bad[:len(bad)-1]
	a, _ := r.resolve(t.Context(), "allowed", bad)
	if len(a) < 12 || a[3]&15 != dns.RcodeFormatError {
		t.Fatal("IQUERY bypassed section validation")
	}
	q[2] |= 0x80
	a, _ = r.resolve(t.Context(), "allowed", q)
	if a != nil {
		t.Fatal("responded to response")
	}
}

func TestGoAwayRejectionsNeverReplay(t *testing.T) {
	for _, code := range []http2.ErrCode{http2.ErrCodeEnhanceYourCalm, http2.ErrCodeInadequateSecurity, http2.ErrCodeHTTP11Required} {
		//lint:ignore SA1019 Exercise compatibility with existing typed transports.
		typed := http2.GoAwayError{ErrCode: code}
		plain := errors.New("http2: server sent GOAWAY and closed the connection; LastStreamID=1, ErrCode=" + code.String() + ", debug=\"ErrCode=NO_ERROR\"")
		for _, err := range []error{typed, http2.ConnectionError(code), plain} {
			if dohConnectionClosed(err) {
				t.Fatalf("replayed HTTP2 rejection: %v", err)
			}
		}
	}
	if dohConnectionClosed(errors.New("remote says http2: server sent GOAWAY and closed the connection; LastStreamID=1, ErrCode=NO_ERROR")) {
		t.Fatal("untrusted substring triggered replay")
	}
	if dohConnectionClosed(context.Canceled) {
		t.Fatal("client cancellation triggered replay")
	}
}

func TestTruncatedQuestionUsesDNSOctetCaseRules(t *testing.T) {
	for _, tc := range []struct {
		query, answer string
		want          bool
	}{
		{"Correct.Example", "correct.example", true},
		{"\u00c5.example", "\u00e5.example", false},
		{"K.example", "\u212a.example", false},
	} {
		q, a := dnsQuery(83, tc.query), dnsQuery(83, tc.answer)
		a[2] |= 0x82
		if got := truncatedDNSReply(q, a); got != tc.want {
			t.Errorf("question %q vs %q: got %v want %v", tc.query, tc.answer, got, tc.want)
		}
	}
}
