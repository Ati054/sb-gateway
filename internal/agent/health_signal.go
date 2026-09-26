package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

type xrayFailureSignal struct {
	Version int    `json:"v"`
	PID     int    `json:"pid"`
	Tag     string `json:"tag"`
	Stage   string `json:"stage"`
}

// The socket lives in /run, not on the SSD. It is an optional wake-up hint:
// dropping it must never turn an unavailable path into a healthy one or stop
// the existing periodic HTTPS checks.
func listenXrayFailureSignals(ctx context.Context, path string) (<-chan xrayFailureSignal, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode().Type() != os.ModeSocket {
			return nil, nil, fmt.Errorf("Xray failure signal path is not a socket")
		}
		connection, dialErr := net.DialTimeout("unixgram", path, 20*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, nil, fmt.Errorf("Xray failure signal socket is already owned")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, nil, fmt.Errorf("Xray failure signal socket ownership is uncertain: %w", dialErr)
		}
		if current, statErr := os.Lstat(path); statErr != nil || !os.SameFile(info, current) {
			return nil, nil, fmt.Errorf("Xray failure signal socket changed before stale cleanup")
		}
		if err := os.Remove(path); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, nil, err
	}
	owned, _ := os.Lstat(path)
	signals := make(chan xrayFailureSignal, 32)
	var once sync.Once
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	closeSocket := func() {
		once.Do(func() {
			stop()
			_ = listener.Close()
			if current, err := os.Lstat(path); err == nil && owned != nil && os.SameFile(owned, current) {
				_ = os.Remove(path)
			}
		})
	}
	go func() {
		defer close(signals)
		var buffer [513]byte
		for {
			count, _, err := listener.ReadFromUnix(buffer[:])
			if err != nil {
				return
			}
			if count == 0 || count > 512 {
				continue
			}
			var signal xrayFailureSignal
			if json.Unmarshal(buffer[:count], &signal) != nil || !validXrayFailureSignal(signal) {
				continue
			}
			select {
			case signals <- signal:
			default: // bounded, non-blocking; the periodic probe is the fallback
			}
		}
	}()
	return signals, closeSocket, nil
}

func validXrayFailureSignal(signal xrayFailureSignal) bool {
	return signal.Version == 1 && signal.PID > 0 && signal.Tag != "" && len(signal.Tag) <= 200 &&
		strings.TrimSpace(signal.Tag) == signal.Tag && (signal.Stage == "dial" || signal.Stage == "handshake")
}

// Only the currently selected, confirmed handler may advance a sheet's
// liveness check. Versioned dynamic tags and the Xray PID reject late events
// from retired handlers, probes, and previous core processes.
func (controller *healthController) acceptXrayFailureSignal(now time.Time, signal xrayFailureSignal, runtime *xraySelectorRuntime) bool {
	if !validXrayFailureSignal(signal) || signal.PID != runtime.xrayPID ||
		(runtime.opts.XrayReadyFile != "" && readyProcessPID(runtime.opts.XrayReadyFile, "xray") != signal.PID) {
		return false
	}
	if controller.forceLiveness == nil {
		controller.forceLiveness = make(map[string]bool)
	}
	if controller.lastSignalAt == nil {
		controller.lastSignalAt = make(map[string]time.Time)
	}
	accepted := false
	for policyID, item := range controller.state {
		if item == nil || !item.RuntimeConfirmed || item.Selected == "" || item.Selected == "block" ||
			item.RuntimeSelected != item.Selected {
			continue
		}
		contract, exists := runtime.pool.HealthPolicies[policyID]
		if !exists || !contains(contract.Candidates, item.Selected) ||
			runtime.policyRuntimeTag(policyID, item.Selected) != signal.Tag ||
			now.Sub(controller.lastSignalAt[policyID]) < time.Second {
			continue
		}
		controller.lastSignalAt[policyID] = now
		controller.forceLiveness[policyID] = true
		if controller.priorityPolicy == "" {
			controller.priorityPolicy = policyID
		}
		accepted = true
	}
	return accepted
}
