//go:build linux

package watchdog

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestSocketDiagRequestsArePortAndStateFiltered(t *testing.T) {
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		for _, protocol := range []string{"tcp", "udp"} {
			body, state, err := socketDiagRequest(protocol, 1053, family)
			if err != nil || len(body) != 56 || body[0] != family || binary.BigEndian.Uint16(body[8:10]) != 1053 ||
				binary.NativeEndian.Uint32(body[4:8]) != 1<<state {
				t.Fatalf("unfiltered query: %x %v", body, err)
			}
			if protocol == "tcp" && (body[1] != unix.IPPROTO_TCP || state != 10) ||
				protocol == "udp" && (body[1] != unix.IPPROTO_UDP || state != 7) {
				t.Fatal("query accepted connected rather than listening sockets")
			}
		}
	}
	for _, port := range []int{-1, 0, 65536} {
		if _, _, err := socketDiagRequest("udp", port, unix.AF_INET); err == nil {
			t.Fatal("invalid port was accepted")
		}
	}
	if _, _, err := socketDiagRequest("sctp", 1053, unix.AF_INET); err == nil {
		t.Fatal("invalid protocol was accepted")
	}
	if _, _, err := socketDiagRequest("udp", 1053, unix.AF_UNSPEC); err == nil {
		t.Fatal("unfiltered address family was accepted")
	}
}

func TestSocketDiagRejectsIncompleteOrUnrelatedReplies(t *testing.T) {
	body := make([]byte, 72)
	body[0], body[1] = unix.AF_INET, 7
	binary.BigEndian.PutUint16(body[4:6], 1053)
	valid := netlink.Message{Header: netlink.Header{Type: socketDiagByFamily}, Data: body}
	if found, err := socketDiagReply([]netlink.Message{valid}, unix.AF_INET, 7, 1053); err != nil || !found {
		t.Fatalf("valid listener rejected: %v %v", found, err)
	}
	if found, err := socketDiagReply(nil, unix.AF_INET, 7, 1053); err != nil || found {
		t.Fatal("empty completed dump did not confirm absence")
	}
	for _, change := range []func(*netlink.Message){
		func(m *netlink.Message) { m.Data = m.Data[:71] },
		func(m *netlink.Message) { m.Header.Type = netlink.Noop },
		func(m *netlink.Message) { m.Header.Flags |= netlink.DumpInterrupted },
		func(m *netlink.Message) { m.Data[0] = unix.AF_INET6 },
		func(m *netlink.Message) { m.Data[1] = 1 },
		func(m *netlink.Message) { binary.BigEndian.PutUint16(m.Data[4:6], 1054) },
	} {
		invalid := valid
		invalid.Data = append([]byte(nil), body...)
		change(&invalid)
		if found, err := socketDiagReply([]netlink.Message{invalid}, unix.AF_INET, 7, 1053); err == nil || found {
			t.Fatal("invalid dump became a positive or definite negative proof")
		}
	}
}

func TestSocketDiagLiveListenersAndCancellation(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network[3] == '6' {
				address = "[::1]:0"
			}
			var closeListener func() error
			var port int
			if network[:3] == "tcp" {
				listener, err := net.Listen(network, address)
				if err != nil {
					if network == "tcp6" && (errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.EAFNOSUPPORT)) {
						t.Skip("IPv6 loopback is unavailable")
					}
					t.Fatal(err)
				}
				closeListener, port = listener.Close, listener.Addr().(*net.TCPAddr).Port
			} else {
				listener, err := net.ListenPacket(network, address)
				if err != nil {
					if network == "udp6" && (errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.EAFNOSUPPORT)) {
						t.Skip("IPv6 loopback is unavailable")
					}
					t.Fatal(err)
				}
				closeListener, port = listener.Close, listener.LocalAddr().(*net.UDPAddr).Port
			}
			defer closeListener()
			found, err := probeListeningPort(context.Background(), network[:3], port)
			if err != nil || !found {
				t.Fatalf("open listener not found: %v %v", found, err)
			}
			_ = closeListener()
			found, err = probeListeningPort(context.Background(), network[:3], port)
			if err != nil || found {
				t.Fatalf("closed listener retained: %v %v", found, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probeListeningPort(ctx, "udp", 1053); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled query continued: %v", err)
	}
}

func FuzzSocketDiagReply(f *testing.F) {
	f.Add([]byte{})
	body := make([]byte, 72)
	body[0], body[1] = unix.AF_INET, 7
	binary.BigEndian.PutUint16(body[4:6], 1053)
	f.Add(body)
	f.Fuzz(func(t *testing.T, body []byte) {
		found, err := socketDiagReply([]netlink.Message{{Header: netlink.Header{Type: socketDiagByFamily}, Data: body}}, unix.AF_INET, 7, 1053)
		if found && (err != nil || len(body) < 72 || body[0] != unix.AF_INET || body[1] != 7 || binary.BigEndian.Uint16(body[4:6]) != 1053) {
			t.Fatal("unrelated or incomplete data became a listener proof")
		}
	})
}

func TestSocketDiagListenerDuringUDPChurn(t *testing.T) {
	if os.Getenv("SB_TEST_LISTENER_CHURN") != "1" {
		t.Skip("isolated UDP churn test disabled")
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			connections := make([]net.PacketConn, 256)
			defer func() {
				for _, connection := range connections {
					if connection != nil {
						_ = connection.Close()
					}
				}
			}()
			for n := 0; ctx.Err() == nil; n++ {
				index := n % len(connections)
				if connections[index] != nil {
					_ = connections[index].Close()
				}
				connection, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return
				}
				connections[index] = connection
			}
		})
	}
	defer func() { cancel(); workers.Wait() }()
	omissions := 0
	for range 200 {
		ports, err := procListeningPorts("udp")
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := ports[port]; !exists {
			omissions++
		}
		found, err := probeListeningPort(ctx, "udp", port)
		if err != nil || !found {
			t.Fatalf("stable listener lost during churn: %v %v", found, err)
		}
	}
	t.Logf("live proc-table omissions=%d; all 200 targeted listener checks succeeded", omissions)
}
