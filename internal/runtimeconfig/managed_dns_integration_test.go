package runtimeconfig

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestManagedDNSPinnedCoreTCPUDPSourceIsolation(t *testing.T) {
	binary := os.Getenv("XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set XRAY_TEST_BINARY to the pinned Xray binary")
	}
	var queries atomic.Int64
	serve := func(answer string) string {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err != nil {
			tcp.Close()
			t.Fatal(err)
		}
		handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
			queries.Add(1)
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP(answer)}}
			_ = writer.WriteMsg(response)
		})
		for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
			started, finished := make(chan struct{}), make(chan struct{})
			server.NotifyStartedFunc = func() { close(started) }
			go func() { _ = server.ActivateAndServe(); close(finished) }()
			<-started
			t.Cleanup(func() { _ = server.Shutdown(); <-finished })
		}
		return tcp.Addr().String()
	}
	specific, broad := serve("192.0.2.10"), serve("192.0.2.20")
	inbound, rules := managedDNSIngress("127.0.0.1", []map[string]any{
		{"type": "field", "inboundTag": []string{"tun-routeros"}, "source": []string{"127.0.0.1/32"}, "port": "53", "outboundTag": "specific"},
		{"type": "field", "inboundTag": []string{"tun-routeros"}, "source": []string{"127.0.0.0/30"}, "port": "53", "outboundTag": "broad"},
	})
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	inbound["port"] = port
	config := map[string]any{
		"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{inbound},
		"outbounds": []any{
			map[string]any{"tag": "specific", "protocol": "freedom", "settings": map[string]any{"redirect": specific}},
			map[string]any{"tag": "broad", "protocol": "freedom", "settings": map[string]any{"redirect": broad}},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		"routing": map[string]any{"rules": rules},
	}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xray.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "run", "-config", path)
	logPath := filepath.Join(t.TempDir(), "xray.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			output, _ := os.ReadFile(logPath)
			t.Fatalf("core did not open the managed DNS listener: %s", output)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// TCP can bind before UDP. Confirm the UDP data path, not just a socket.
	for {
		request := new(dns.Msg)
		request.SetQuestion("ready.example.test.", dns.TypeA)
		client := dns.Client{Net: "udp", Timeout: 100 * time.Millisecond}
		if response, _, err := client.Exchange(request, address); err == nil && len(response.Answer) == 1 {
			break
		}
		if time.Now().After(deadline) {
			output, _ := os.ReadFile(logPath)
			t.Fatalf("core did not open the UDP DNS data path: %s", output)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, network := range []string{"udp", "tcp"} {
		for _, source := range []struct{ ip, answer string }{{"127.0.0.1", "192.0.2.10"}, {"127.0.0.2", "192.0.2.20"}, {"127.0.0.4", ""}} {
			var local net.Addr = &net.UDPAddr{IP: net.ParseIP(source.ip)}
			if network == "tcp" {
				local = &net.TCPAddr{IP: net.ParseIP(source.ip)}
			}
			client := dns.Client{Net: network, Timeout: 500 * time.Millisecond, Dialer: &net.Dialer{LocalAddr: local, Timeout: 500 * time.Millisecond}}
			request := new(dns.Msg)
			request.SetQuestion("probe.example.test.", dns.TypeA)
			before := queries.Load()
			response, _, err := client.Exchange(request, address)
			if source.answer == "" {
				if err == nil || queries.Load() != before {
					t.Fatalf("%s unknown source reached a resolver", network)
				}
				continue
			}
			if err != nil || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != source.answer {
				output, _ := os.ReadFile(logPath)
				t.Fatalf("%s source %s selected the wrong DNS lane: %v / %v / %s", network, source.ip, response, err, output)
			}
		}
	}
}
