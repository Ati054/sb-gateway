//go:build !linux

package watchdog

import (
	"errors"
	"os"
)

func terminateContainer() error {
	return errors.New("container termination is supported only on Linux")
}

func processIDExists(pid int) bool {
	_, err := os.FindProcess(pid)
	return err == nil
}
