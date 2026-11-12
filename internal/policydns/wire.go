package policydns

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/net/dns/dnsmessage"
)

// A response arriving at a resolver's request socket must never receive a
// response of its own, including when the rest of its header is incomplete.
func dnsResponsePacket(message []byte) bool {
	return len(message) >= 3 && message[2]&0x80 != 0
}

// Walk every declared section without allocating resource records. In
// particular, QDCOUNT=0 is valid for header-only and EDNS DNS probes.
func validDNSWire(message []byte) bool {
	if len(message) < 12 || len(message) > maxDNSMessage {
		return false
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(message); err != nil {
		return false
	}
	if parser.SkipAllQuestions() != nil || parser.SkipAllAnswers() != nil ||
		parser.SkipAllAuthorities() != nil || parser.SkipAllAdditionals() != nil {
		return false
	}
	return true
}

func replayableDNSQuery(query []byte) bool {
	if len(query) < 12 || query[2]&0xf8 != 0 || query[4] != 0 || query[5] > 1 {
		return false
	}
	if query[5] == 0 {
		return true
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(query); err != nil {
		return false
	}
	question, err := parser.Question()
	return err == nil && question.Type != 251 && question.Type != 252
}

func truncatedDNSReply(query, response []byte) bool {
	if !validDNSWire(query) || dnsResponsePacket(query) || len(response) < 12 || len(response) > maxDNSMessage ||
		response[2]&0x82 != 0x82 || query[2]&0x78 != response[2]&0x78 || !bytes.Equal(query[:2], response[:2]) {
		return false
	}
	questions := binary.BigEndian.Uint16(response[4:6])
	// A header-only TC response has no question. The connected upstream
	// socket, ID and opcode still bind it to this exchange.
	if questions == 0 {
		return true
	}
	if questions != 1 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return false
	}
	var q, a dnsmessage.Parser
	if _, err := q.Start(query); err != nil {
		return false
	}
	if _, err := a.Start(response); err != nil {
		return false
	}
	want, err := q.Question()
	if err != nil {
		return false
	}
	got, err := a.Question()
	// RR sections may be incomplete when TC is set; the question may not.
	return err == nil && equalDNSName(&want.Name, &got.Name) &&
		want.Type == got.Type && want.Class == got.Class
}

// RFC 4343 case-insensitivity applies to ASCII letters, not Unicode folding.
func equalDNSName(a, b *dnsmessage.Name) bool {
	if a.Length != b.Length {
		return false
	}
	for i := 0; i < int(a.Length); i++ {
		x, y := a.Data[i], b.Data[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
