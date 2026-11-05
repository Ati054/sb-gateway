//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package subscriptioncatalog

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockManifest(file *os.File, exclusive bool) error {
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	err := unix.Flock(int(file.Fd()), mode|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return ErrBusy
	}
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS) {
		return ErrLeaseUnsupported
	}
	return storageError(err)
}

func unlockManifest(file *os.File) error {
	return storageError(unix.Flock(int(file.Fd()), unix.LOCK_UN))
}
