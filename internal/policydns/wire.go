package policydns

import (
	"bytes"

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
	return len(query) >= 12 && len(response) >= 12 && response[2]&0x82 == 0x82 &&
		query[2]&0x78 == response[2]&0x78 && bytes.Equal(query[:2], response[:2])
}
