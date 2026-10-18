package policydns

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/miekg/dns"
)

func TestRefusalProducesCompleteDNSMessage(t *testing.T) {
	for _, edns := range []bool{false, true} {
		request := new(dns.Msg)
		request.SetQuestion("MiXeD.example.invalid.", dns.TypeAAAA)
		request.Id = 317
		request.CheckingDisabled = true
		request.AuthenticatedData = true
		request.Authoritative = true
		request.Truncated = true
		if edns {
			request.SetEdns0(1232, true)
			request.IsEdns0().Option = []dns.EDNS0{
				&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"},
				&dns.EDNS0_PADDING{Padding: make([]byte, 32)},
			}
		}
		query, err := request.Pack()
		if err != nil {
			t.Fatal(err)
		}
		original := bytes.Clone(query)
		for _, failure := range []bool{false, true} {
			wantCode := dns.RcodeRefused
			if failure {
				wantCode = dns.RcodeServerFailure
			}
			wire := refusal(query, failure)
			var response dns.Msg
			if err := response.Unpack(wire); err != nil {
				t.Fatalf("edns=%v failure=%v: %v", edns, failure, err)
			}
			if response.Id != request.Id || response.Rcode != wantCode || !response.Response || !response.RecursionAvailable {
				t.Fatalf("unexpected response header: %+v", response.MsgHdr)
			}
			if response.AuthenticatedData || response.Authoritative || response.Truncated || !response.RecursionDesired || !response.CheckingDisabled {
				t.Errorf("request-only flags leaked into response: %+v", response.MsgHdr)
			}
			if len(response.Question) != 1 || response.Question[0] != request.Question[0] || len(response.Answer)+len(response.Ns)+len(response.Extra) != 0 {
				t.Errorf("unexpected response sections: %+v", response)
			}
			canonical, err := response.Pack()
			if err != nil || !bytes.Equal(canonical, wire) {
				t.Errorf("EDNS or other undeclared bytes remain: wire=%d canonical=%d err=%v", len(wire), len(canonical), err)
			}
			if !bytes.Equal(query, original) {
				t.Fatal("query buffer mutated")
			}
		}
	}
}

func TestRefusalMalformedQuestionHasValidHeaderOnlyReply(t *testing.T) {
	query := dnsQuery(771, "truncated.example.invalid")
	query = query[:len(query)-2]
	for _, failure := range []bool{false, true} {
		wire := refusal(query, failure)
		var response dns.Msg
		if len(wire) != 12 || response.Unpack(wire) != nil || response.Id != 771 || len(response.Question) != 0 {
			t.Fatalf("invalid malformed-question reply: bytes=%d message=%+v", len(wire), response)
		}
	}
	if refusal(query[:11], true) != nil {
		t.Fatal("short header should not produce a reply")
	}
}

func TestRefusalIgnoresUntrustedSectionCounts(t *testing.T) {
	query := dnsQuery(17, "counts.example.invalid")
	for offset := 6; offset < 12; offset += 2 {
		binary.BigEndian.PutUint16(query[offset:offset+2], 65535)
	}
	var response dns.Msg
	wire := refusal(query, true)
	if err := response.Unpack(wire); err != nil || len(response.Question) != 1 || len(wire) != len(query) {
		t.Fatalf("section counts affected response: bytes=%d message=%+v err=%v", len(wire), response, err)
	}
}

func FuzzRefusalWireMessage(f *testing.F) {
	f.Add(dnsQuery(1, "example.invalid"), true)
	f.Add([]byte{}, false)
	request := new(dns.Msg)
	request.SetQuestion("edns.example.invalid.", dns.TypeA)
	request.SetEdns0(1232, true)
	query, _ := request.Pack()
	f.Add(query, true)
	f.Fuzz(func(t *testing.T, query []byte, failure bool) {
		if len(query) > maxDNSMessage {
			t.Skip()
		}
		original := bytes.Clone(query)
		wire := refusal(query, failure)
		if len(query) < 12 {
			if wire != nil {
				t.Fatal("short header produced a response")
			}
			return
		}
		var response dns.Msg
		if err := response.Unpack(wire); err != nil {
			t.Fatal(err)
		}
		if response.Id != binary.BigEndian.Uint16(query) {
			t.Fatal("transaction ID changed")
		}
		canonical, err := response.Pack()
		if err != nil || !bytes.Equal(canonical, wire) || !bytes.Equal(query, original) {
			t.Fatal("noncanonical response or mutated query")
		}
	})
}
