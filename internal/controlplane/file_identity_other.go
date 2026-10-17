//go:build !windows

package controlplane

import "os"

func statFileIdentity(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
