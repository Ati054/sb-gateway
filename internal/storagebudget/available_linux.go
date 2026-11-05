//go:build linux

package storagebudget

import (
	"golang.org/x/sys/unix"
	"math"
)

func availableBytes(path string) (uint64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, ErrUnavailable
	}
	if stat.Bsize <= 0 {
		return 0, ErrUnavailable
	}
	block := uint64(stat.Bsize)
	if stat.Bavail > math.MaxUint64/block {
		return math.MaxUint64, nil
	}
	return stat.Bavail * block, nil
}
