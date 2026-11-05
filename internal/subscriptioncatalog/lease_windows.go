package subscriptioncatalog

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Reserve one byte beyond the bounded manifest, so Windows mandatory byte-range
// locking does not interfere with manifest JSON reads through another handle.
func manifestLockOffset() windows.Overlapped { return windows.Overlapped{OffsetHigh: 1} }

func lockManifest(file *os.File, exclusive bool) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	offset := manifestLockOffset()
	err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &offset)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrBusy
	}
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		return ErrLeaseUnsupported
	}
	return storageError(err)
}

func unlockManifest(file *os.File) error {
	offset := manifestLockOffset()
	return storageError(windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &offset))
}
