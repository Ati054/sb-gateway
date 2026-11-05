//go:build linux

package subscriptioncatalog

import (
	"os"

	"golang.org/x/sys/unix"
)

func adviseCatalogCache(file *os.File, offset, length int64) {
	// Advisory only: unsupported filesystems can decline it. Writers must have
	// successfully synced their dirty ranges before requesting cache release.
	_ = unix.Fadvise(int(file.Fd()), offset, length, unix.FADV_DONTNEED)
}
