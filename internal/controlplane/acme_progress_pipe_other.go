//go:build !linux

package controlplane

import "os"

func newACMEProgressPipe() (*os.File, *os.File, bool) { return nil, nil, false }
