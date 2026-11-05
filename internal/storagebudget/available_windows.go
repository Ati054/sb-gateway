//go:build windows

package storagebudget

import "golang.org/x/sys/windows"

func availableBytes(path string) (uint64, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, ErrUnavailable
	}
	var available, total, free uint64
	if err = windows.GetDiskFreeSpaceEx(pointer, &available, &total, &free); err != nil {
		return 0, ErrUnavailable
	}
	return available, nil
}
