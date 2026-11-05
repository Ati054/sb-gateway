//go:build linux

package controlplane

import (
	"os"

	"golang.org/x/sys/unix"
)

func dropRecoveryFileCache(file *os.File) {
	if file == nil {
		return
	}
	_ = unix.Fadvise(int(file.Fd()), 0, 0, unix.FADV_DONTNEED)
}

func dropRecoveryFileRange(file *os.File, offset, length int64) {
	if file != nil && offset >= 0 && length > 0 {
		_ = unix.Fadvise(int(file.Fd()), offset, length, unix.FADV_DONTNEED)
	}
}
