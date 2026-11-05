//go:build linux

package recovery

import (
	"os"

	"golang.org/x/sys/unix"
)

func dropRestoreFileRange(file *os.File, offset, length int64) {
	if file != nil && offset >= 0 && length > 0 {
		_ = unix.Fadvise(int(file.Fd()), offset, length, unix.FADV_DONTNEED)
	}
}
