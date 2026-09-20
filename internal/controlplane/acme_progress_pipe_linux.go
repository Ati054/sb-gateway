//go:build linux

package controlplane

import (
	"os"
	"syscall"
)

func newACMEProgressPipe() (*os.File, *os.File, bool) {
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, false
	}
	if syscall.SetNonblock(int(writer.Fd()), true) != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, nil, false
	}
	return reader, writer, true
}
