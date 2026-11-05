// Package netpolicy defines the socket policy for gateway-owned TCP listeners.
package netpolicy

import (
	"context"
	"fmt"
	"net"
)

// TCPListenConfig explicitly disables MPTCP even when ambient GODEBUG enables
// it. This sets a socket policy; it does not inspect or fix the host kernel.
func TCPListenConfig() net.ListenConfig {
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	return config
}

// ListenTCP preserves net.Listen's address and keepalive defaults while applying
// the gateway's explicit policy. UDP and Unix sockets do not use this helper.
func ListenTCP(network, address string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("unsupported TCP listener network %q", network)
	}
	config := TCPListenConfig()
	return config.Listen(context.Background(), network, address)
}
