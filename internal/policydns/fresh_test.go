package policydns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startFreshDoH(t *testing.T, handler func(*dns.Msg) *dns.Msg) *FreshResolver {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		queryBody, err := io.ReadAll(request.Body)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if query.Unpack(queryBody) != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := handler(query).Pack()
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(response)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	forwarder, err := StartFreshResolver(context.Background(), FreshResolverConfig{
		Type: "https", Server: host, ServerName: "example.com", ServerPort: port, Path: "/dns-query", DoTFallback: true,
	}, FreshResolverOptions{Workers: 2, TCPSessions: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	forwarder.upstream.(*dohUpstream).transport.TLSClientConfig.RootCAs = roots
	t.Cleanup(func() { _ = forwarder.Close() })
	return forwarder
}

func freshQuery(t *testing.T, resolver *FreshResolver, network, name string, ednsSize uint16) *dns.Msg {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	if ednsSize != 0 {
		query.SetEdns0(ednsSize, false)
	}
	client := &dns.Client{Net: network, Timeout: time.Second}
	deadline := time.Now().Add(time.Second)
	for {
		response, _, err := client.Exchange(query, resolver.Address())
		if err == nil {
			return response
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func txtValue(response *dns.Msg) string {
	for _, answer := range response.Answer {
		if txt, ok := answer.(*dns.TXT); ok && len(txt.Txt) != 0 {
			return txt.Txt[0]
		}
	}
	return ""
}

func TestFreshResolverBypassesStaleLocalNegativeAndDoesNotCache(t *testing.T) {
	stalePacket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stale := &dns.Server{PacketConn: stalePacket, Handler: dns.HandlerFunc(func(writer dns.ResponseWriter, query *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Rcode = dns.RcodeNameError
		_ = writer.WriteMsg(response)
	})}
	go func() { _ = stale.ActivateAndServe() }()
	t.Cleanup(func() { _ = stale.Shutdown() })

	var value atomic.Value
	value.Store("fresh-one")
	var upstreamCalls atomic.Int32
	forwarder := startFreshDoH(t, func(query *dns.Msg) *dns.Msg {
		upstreamCalls.Add(1)
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{value.Load().(string)}}}
		return response
	})

	staleQuery := new(dns.Msg)
	staleQuery.SetQuestion("_acme-challenge.example.test.", dns.TypeTXT)
	staleResponse, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(staleQuery, stalePacket.LocalAddr().String())
	if err != nil || staleResponse.Rcode != dns.RcodeNameError {
		t.Fatalf("stale local resolver did not return NXDOMAIN: response=%v err=%v", staleResponse, err)
	}
	if response := freshQuery(t, forwarder, "udp", "_acme-challenge.example.test", 0); response.Rcode != dns.RcodeSuccess || txtValue(response) != "fresh-one" {
		t.Fatalf("fresh resolver did not reach encrypted upstream: %#v", response)
	}
	value.Store("fresh-two")
	if response := freshQuery(t, forwarder, "udp", "_acme-challenge.example.test", 0); response.Rcode != dns.RcodeSuccess || txtValue(response) != "fresh-two" {
		t.Fatalf("fresh resolver cached the old TXT answer: %#v", response)
	}
	if calls := upstreamCalls.Load(); calls != 2 {
		t.Fatalf("fresh resolver upstream calls=%d, want 2", calls)
	}
}

func TestFreshResolverTruncatesUDPAndServesFullTCP(t *testing.T) {
	chunks := []string{strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255), strings.Repeat("x", 255)}
	forwarder := startFreshDoH(t, func(query *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(query)
		response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: chunks}}
		return response
	})
	if response := freshQuery(t, forwarder, "udp", "large.example.test", dns.MinMsgSize); !response.Truncated {
		t.Fatalf("large UDP response was not truncated: size=%d", response.Len())
	}
	if response := freshQuery(t, forwarder, "tcp", "large.example.test", 0); response.Truncated || len(response.Answer) != 1 {
		t.Fatalf("large TCP response was truncated or incomplete: %#v", response)
	}
}

func TestFreshResolverDoHVerifiesCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	host, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	forwarder, err := StartFreshResolver(context.Background(), FreshResolverConfig{
		Type: "https", Server: host, ServerName: "example.com", ServerPort: port, Path: "/dns-query", DoTFallback: true,
	}, FreshResolverOptions{Workers: 1, TCPSessions: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forwarder.Close() })
	if response := freshQuery(t, forwarder, "udp", "doh.example.test", 0); response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("DoH accepted an untrusted certificate: %#v", response)
	}
}

func TestFreshResolverDoTVerifiesCertificate(t *testing.T) {
	certificateServer := httptest.NewUnstartedServer(http.NotFoundHandler())
	certificateServer.StartTLS()
	certificate := certificateServer.TLS.Certificates[0]
	certificateAuthority := certificateServer.Certificate()
	certificateServer.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var answered atomic.Int32
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer connection.Close()
				header := make([]byte, 2)
				if _, readErr := io.ReadFull(connection, header); readErr != nil {
					return
				}
				payload := make([]byte, binary.BigEndian.Uint16(header))
				if _, readErr := io.ReadFull(connection, payload); readErr != nil {
					return
				}
				query := new(dns.Msg)
				if query.Unpack(payload) != nil {
					return
				}
				answered.Add(1)
				response := new(dns.Msg)
				response.SetReply(query)
				response.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"dot-ok"}}}
				body, _ := response.Pack()
				binary.BigEndian.PutUint16(header, uint16(len(body)))
				_, _ = connection.Write(append(header, body...))
			}()
		}
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	config := FreshResolverConfig{Type: "tls", Server: host, ServerName: "example.com", ServerPort: port}
	options := FreshResolverOptions{Workers: 2, TCPSessions: 1, Timeout: time.Second}
	untrusted, err := StartFreshResolver(context.Background(), config, options)
	if err != nil {
		t.Fatal(err)
	}
	if response := freshQuery(t, untrusted, "udp", "dot.example.test", 0); response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("DoT accepted an untrusted certificate: %#v", response)
	}
	_ = untrusted.Close()

	forwarder, err := StartFreshResolver(context.Background(), config, options)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificateAuthority)
	forwarder.upstream.(*tcpUpstream).tlsConfig.RootCAs = roots
	t.Cleanup(func() { _ = forwarder.Close() })
	if response := freshQuery(t, forwarder, "udp", "dot.example.test", 0); response.Rcode != dns.RcodeSuccess || txtValue(response) != "dot-ok" || answered.Load() != 1 {
		t.Fatalf("DoT forwarding failed: response=%#v calls=%d", response, answered.Load())
	}
}

func TestFreshResolverCancelsAndBoundsRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	forwarder, err := StartFreshResolver(ctx, FreshResolverConfig{Type: "https", Server: "127.0.0.1", ServerName: "example.com", ServerPort: 443, Path: "/dns-query", DoTFallback: true}, FreshResolverOptions{Workers: 1, TCPSessions: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	forwarder.limit <- struct{}{}
	if response := freshQuery(t, forwarder, "udp", "limit.example.test", 0); response.Rcode != dns.RcodeServerFailure {
		t.Fatalf("unbounded request was not refused: %#v", response)
	}
	<-forwarder.limit
	address := forwarder.Address()
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if dialErr != nil {
			break
		}
		_ = connection.Close()
		if time.Now().After(deadline) {
			t.Fatal("fresh resolver listener remained reachable after cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := forwarder.Close(); err != nil {
		t.Fatal(err)
	}
}
