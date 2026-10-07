//go:build linux

package controlplane

import (
	"os"

	"golang.org/x/sys/unix"
)

func discardImageUploadCache(file *os.File, offset, length int64) error {
	return unix.Fadvise(int(file.Fd()), offset, length, unix.FADV_DONTNEED)
}
