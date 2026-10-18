//go:build xray_multicall

package runtimeconfig

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func TestPolicyDNSPinnedCoreReleasesIdleUDP(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		t.Run(fmt.Sprintf("legacy=%v", legacy), func(t *testing.T) {
			endpoint, peers := policyDNSEchoEndpoint(t)
			artifacts, err := CompilePolicyDNS(PolicyDNSSource{
				Servers: []PolicyDNSSourceServer{{Tag: "direct", Type: "udp", Server: "127.0.0.1"}},
				Final:   "direct",
			}, PolicyDNSCompileOptions{})
			if err != nil {
				t.Fatal(err)
			}
			outbound := artifacts.XrayOutbounds[0]
			settings := objectValue(outbound["settings"])
			settings["redirect"] = endpoint.String()
			settings["finalRules"] = []any{map[string]any{
				"action": "allow", "network": "udp", "ip": []string{"127.0.0.0/8"}, "port": strconv.Itoa(endpoint.Port),
			}}
			if legacy {
				delete(settings, "userLevel")
			}
			reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			address := reservation.LocalAddr().(*net.UDPAddr)
			reservation.Close()
			// Shorten only the test clock; production rendering is checked separately.
			config := map[string]any{
				"log": map[string]any{"loglevel": "none"},
				"policy": map[string]any{"levels": map[string]any{
					"0":                              map[string]any{"connIdle": 3},
					strconv.Itoa(policyDNSUserLevel): map[string]any{"connIdle": 1},
				}},
				"inbounds": []any{map[string]any{
					"tag": "dns", "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": address.Port,
					"settings": map[string]any{"address": "127.0.0.1", "port": 53, "network": "udp"},
				}},
				"outbounds": []any{outbound},
			}
			body, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			instance, err := core.StartInstance("json", body)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { instance.Close() })
			time.Sleep(100 * time.Millisecond)
			baseline := runtime.NumGoroutine()
			clients := make([]*net.UDPConn, 0, 40)
			for i := 0; i < cap(clients); i++ {
				client, err := net.DialUDP("udp4", nil, address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				clients = append(clients, client)
				policyDNSEchoExchange(t, client, peers)
			}
			active := runtime.NumGoroutine()
			if active < baseline+70 {
				t.Fatalf("test did not establish enough independent sessions: baseline=%d active=%d", baseline, active)
			}
			for _, client := range clients {
				client.Close()
			}
			deadline := time.Now().Add(4 * time.Second)
			for !legacy && runtime.NumGoroutine() > baseline+30 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if legacy {
				time.Sleep(1500 * time.Millisecond)
			}
			after := runtime.NumGoroutine()
			t.Logf("goroutines baseline=%d active=%d idle=%d", baseline, active, after)
			if legacy && after < baseline+70 || !legacy && after > baseline+30 {
				t.Fatalf("unexpected idle retention: legacy=%v baseline=%d after=%d", legacy, baseline, after)
			}
			if legacy {
				// The negative control uses a shorter ordinary idle too, so it
				// cannot leave five-minute sessions behind in the test process.
				deadline := time.Now().Add(6 * time.Second)
				for runtime.NumGoroutine() > baseline+30 && time.Now().Before(deadline) {
					time.Sleep(50 * time.Millisecond)
				}
				if runtime.NumGoroutine() > baseline+30 {
					t.Fatal("negative-control sessions did not drain")
				}
			}
			if !legacy {
				client, err := net.DialUDP("udp4", nil, address)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				peer := policyDNSEchoExchange(t, client, peers)
				for i := 0; i < 10; i++ {
					time.Sleep(250 * time.Millisecond)
					if next := policyDNSEchoExchange(t, client, peers); next != peer {
						t.Fatalf("active session was replaced: %s -> %s", peer, next)
					}
				}
			}
		})
	}
}

func policyDNSEchoEndpoint(t *testing.T) (*net.UDPAddr, <-chan string) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	peers := make(chan string, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var body [512]byte
		for {
			n, peer, err := server.ReadFromUDP(body[:])
			if err != nil {
				return
			}
			peers <- peer.String()
			if _, err := server.WriteToUDP(body[:n], peer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { server.Close(); <-done })
	return server.LocalAddr().(*net.UDPAddr), peers
}

func policyDNSEchoExchange(t *testing.T, client *net.UDPConn, peers <-chan string) string {
	t.Helper()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	const request = "policy-dns-idle-regression"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	var body [512]byte
	n, err := client.Read(body[:])
	if err != nil || string(body[:n]) != request {
		t.Fatalf("UDP echo: %q %v", body[:n], err)
	}
	select {
	case peer := <-peers:
		return peer
	case <-time.After(2 * time.Second):
		t.Fatal("missing UDP backend peer")
		return ""
	}
}
