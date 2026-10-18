//go:build linux

package watchdog

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const socketDiagByFamily = 20

func socketDiagRequest(protocol string, port int, family byte) ([]byte, byte, error) {
	if port < 1 || port > 65535 || (family != unix.AF_INET && family != unix.AF_INET6) {
		return nil, 0, errors.New("invalid listener query")
	}
	var transport, state byte
	switch protocol {
	case "tcp":
		transport, state = unix.IPPROTO_TCP, 10 // TCP_LISTEN
	case "udp":
		transport, state = unix.IPPROTO_UDP, 7 // TCP_CLOSE: unconnected UDP
	default:
		return nil, 0, errors.New("invalid listener protocol")
	}
	// Linux UAPI inet_diag_req_v2; the kernel filters the local port and state.
	request := make([]byte, 56)
	request[0], request[1] = family, transport
	binary.NativeEndian.PutUint32(request[4:8], 1<<state)
	binary.BigEndian.PutUint16(request[8:10], uint16(port))
	for n := 48; n < 56; n++ {
		request[n] = 0xff // INET_DIAG_NOCOOKIE
	}
	return request, state, nil
}

func socketDiagReply(messages []netlink.Message, family, state byte, port int) (bool, error) {
	present := false
	for _, message := range messages {
		if message.Header.Flags&netlink.DumpInterrupted != 0 {
			return false, errors.New("listener dump interrupted")
		}
		if message.Header.Type == netlink.Done {
			continue
		}
		body := message.Data
		if message.Header.Type != socketDiagByFamily || len(body) < 72 || body[0] != family || body[1] != state ||
			int(binary.BigEndian.Uint16(body[4:6])) != port {
			return false, errors.New("invalid listener reply")
		}
		present = true
	}
	return present, nil
}

func probeListeningPort(parent context.Context, protocol string, port int) (bool, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	connection, err := netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
	if err != nil {
		return false, errors.Join(err, ctx.Err())
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return false, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	var failures error
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		request, state, err := socketDiagRequest(protocol, port, family)
		if err != nil {
			return false, err
		}
		messages, err := connection.Execute(netlink.Message{Header: netlink.Header{
			Type: socketDiagByFamily, Flags: netlink.Request | netlink.Dump,
		}, Data: request})
		if err == nil {
			var present bool
			present, err = socketDiagReply(messages, family, state, port)
			if err == nil && present {
				return true, nil
			}
		}
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("listener family %d: %w", family, err))
		}
		if ctx.Err() != nil {
			return false, errors.Join(failures, ctx.Err())
		}
	}
	return false, failures
}
