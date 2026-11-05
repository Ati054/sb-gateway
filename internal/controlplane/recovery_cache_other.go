//go:build !linux

package controlplane

import "os"

func dropRecoveryFileCache(*os.File) {}

func dropRecoveryFileRange(*os.File, int64, int64) {}
