//go:build linux

package watchdog

import (
	"errors"
	"syscall"
)

func terminateContainer() error {
	return syscall.Kill(1, syscall.SIGTERM)
}

func processIDExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
