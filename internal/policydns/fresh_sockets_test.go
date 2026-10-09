package policydns

import (
	"errors"
	"net"
	"testing"
)

func TestFreshSocketsRetryCollisionAndCloseReservation(t *testing.T) {
	var reservations []net.Listener
	listenTCP := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen(network, address)
		if err == nil {
			reservations = append(reservations, listener)
		}
		return listener, err
	}
	listenUDP := func(network, address string) (net.PacketConn, error) {
		if len(reservations) == 1 {
			return nil, errors.New("UDP port collision fixture")
		}
		return net.ListenPacket(network, address)
	}
	packet, listener, err := listenFreshResolverSockets(listenTCP, listenUDP)
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	defer listener.Close()
	if len(reservations) != 2 {
		t.Fatalf("reservations = %d", len(reservations))
	}
	if packet.LocalAddr().String() != listener.Addr().String() {
		t.Fatal("UDP/TCP ports differ")
	}
	if _, err := reservations[0].Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("failed reservation remained open: %v", err)
	}
}

func TestFreshSocketsBoundFailureAndReleaseAllReservations(t *testing.T) {
	var reservations []net.Listener
	listenTCP := func(network, address string) (net.Listener, error) {
		listener, err := net.Listen(network, address)
		if err == nil {
			reservations = append(reservations, listener)
		}
		return listener, err
	}
	failure := errors.New("UDP bind failure fixture")
	packet, listener, err := listenFreshResolverSockets(listenTCP, func(string, string) (net.PacketConn, error) { return nil, failure })
	if packet != nil || listener != nil || !errors.Is(err, failure) {
		t.Fatalf("unexpected result: %v / %v / %v", packet, listener, err)
	}
	if len(reservations) != 8 {
		t.Fatalf("unbounded/incorrect retry count: %d", len(reservations))
	}
	for _, reservation := range reservations {
		if _, err := reservation.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("failed reservation remained open: %v", err)
		}
	}
}
