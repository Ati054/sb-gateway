package policydns

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestPooledUpstreamHonorsCancellation(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			idle := make(chan net.Conn, 1)
			idle <- client
			var resolver upstream
			if protocol == "udp" {
				resolver = &udpUpstream{address: "127.0.0.1:1", timeout: 5 * time.Second, idle: idle}
			} else {
				resolver = &tcpUpstream{address: "127.0.0.1:1", timeout: 5 * time.Second, idle: idle}
			}
			defer resolver.close()
			query := dnsQuery(1, "cancel.example")
			received := make(chan struct{})
			go func() {
				size := len(query)
				if protocol == "tcp" {
					size += 2
				}
				_, _ = io.ReadFull(server, make([]byte, size))
				close(received)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := resolver.exchange(ctx, query); done <- err }()
			select {
			case <-received:
			case <-time.After(time.Second):
				t.Fatal("query did not reach upstream")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("pooled upstream ignored cancellation")
			}
		})
	}
}

func TestServeCancellationDoesNotWaitForUpstreamTimeout(t *testing.T) {
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	config := rawConfig{
		TimeoutSeconds: 5,
		Servers:        map[string]serverConfig{"wan": {Type: "udp", Server: "127.0.0.1", ServerPort: blackhole.LocalAddr().(*net.UDPAddr).Port}},
		Lanes:          []laneConfig{{ID: "lane", Host: "127.0.0.1", Port: port, Final: "wan"}},
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy-dns.json")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, path, Options{Workers: 2, TCPSessions: 2, CacheEntries: 16, CacheBytes: 4096})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := ProbeListeners(context.Background(), path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS listener did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	client, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	idleTCP, err := net.Dial("tcp", client.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer idleTCP.Close()
	if _, err := client.Write(dnsQuery(1, "cancel.example")); err != nil {
		t.Fatal(err)
	}
	_ = blackhole.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := blackhole.ReadFrom(make([]byte, 512)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS shutdown waited for an external upstream timeout")
	}
	_ = idleTCP.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := idleTCP.Read(make([]byte, 1)); err == nil {
		t.Fatal("old TCP session survived shutdown")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("idle TCP session was not canceled")
	}
	udp, err := net.ListenPacket("udp", client.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", client.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
}

func TestPooledUpstreamStopsPreviousCancellationBeforeReuse(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			idle := make(chan net.Conn, 1)
			idle <- client
			var resolver upstream
			if protocol == "udp" {
				resolver = &udpUpstream{timeout: time.Second, idle: idle}
			} else {
				resolver = &tcpUpstream{timeout: time.Second, idle: idle}
			}
			defer resolver.close()
			query := dnsQuery(1, "reuse.example")
			go func() {
				for range 2 {
					size := len(query)
					if protocol == "tcp" {
						size += 2
					}
					if _, err := io.ReadFull(server, make([]byte, size)); err != nil {
						return
					}
					answer := dnsAResponse(query, 60)
					if protocol == "tcp" {
						answer = append([]byte{byte(len(answer) >> 8), byte(len(answer))}, answer...)
					}
					if err := writeAll(server, answer); err != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if _, err := resolver.exchange(ctx, query); err != nil {
				t.Fatal(err)
			}
			cancel()
			if len(idle) != 1 {
				t.Fatal("successful connection was not pooled")
			}
			ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
			defer cancel2()
			if _, err := resolver.exchange(ctx2, query); err != nil {
				t.Fatalf("late cancellation broke reused connection: %v", err)
			}
		})
	}
}
