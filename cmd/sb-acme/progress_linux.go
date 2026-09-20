//go:build linux

package main

import (
	"os"
	"syscall"
)

func newWorkerProgressReporter() *progressReporter {
	if os.Getenv("SB_ACME_PROGRESS_FD") != "3" {
		return &progressReporter{}
	}
	var stat syscall.Stat_t
	if syscall.Fstat(3, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFIFO || syscall.SetNonblock(3, true) != nil {
		return &progressReporter{}
	}
	return &progressReporter{write: func(body []byte) { _, _ = syscall.Write(3, body) }}
}
