//go:build !linux

package controlplane

import "os"

func discardImageUploadCache(_ *os.File, _, _ int64) error {
	return nil
}
