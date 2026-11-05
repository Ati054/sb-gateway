//go:build !linux && !windows

package storagebudget

func availableBytes(string) (uint64, error) { return 0, ErrUnavailable }
