package main

import (
	"bytes"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestRunDNSProbeUDPAndTCP(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		network := network
		t.Run(network, func(t *testing.T) {
			address, stop := startDNSProbeServer(t, network)
			defer stop()
			output := captureStdout(t, func() error {
				return runDNSProbe([]string{"--address", address, "--network", network, "--name", "example.com", "--timeout", "2s"})
			})
			if !strings.Contains(output, "DNS_PROBE=PASS") || !strings.Contains(output, "answers=1") {
				t.Fatalf("unexpected output %q", output)
			}
		})
	}
}

func TestRunDNSProbeRejectsUnsafeArguments(t *testing.T) {
	for _, arguments := range [][]string{
		{},
		{"--address", "127.0.0.1:53", "--network", "tls"},
		{"--address", "127.0.0.1:53", "--name", "not a name"},
		{"--address", "127.0.0.1:53", "--timeout", "31s"},
	} {
		if err := runDNSProbe(arguments); err == nil {
			t.Fatalf("arguments were accepted: %#v", arguments)
		}
	}
}

func startDNSProbeServer(t *testing.T, network string) (string, func()) {
	t.Helper()
	handler := dns.HandlerFunc(func(response dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(192, 0, 2, 1),
		})
		_ = response.WriteMsg(reply)
	})
	server := &dns.Server{Net: network, Handler: handler}
	if network == "udp" {
		connection, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.PacketConn = connection
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server.Listener = listener
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	if network == "udp" {
		return server.PacketConn.LocalAddr().String(), func() { _ = server.Shutdown() }
	}
	return server.Listener.Addr().String(), func() { _ = server.Shutdown() }
}

func captureStdout(t *testing.T, action func() error) string {
	t.Helper()
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	err = action()
	_ = writer.Close()
	os.Stdout = previous
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_, _ = output.ReadFrom(reader)
	_ = reader.Close()
	return output.String()
}
