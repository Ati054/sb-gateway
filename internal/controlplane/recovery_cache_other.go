//go:build !linux

package controlplane

import "os"

func dropRecoveryFileCache(*os.File) {}
