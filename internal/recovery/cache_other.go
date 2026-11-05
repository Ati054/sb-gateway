//go:build !linux

package recovery

import "os"

func dropRestoreFileRange(*os.File, int64, int64) {}
