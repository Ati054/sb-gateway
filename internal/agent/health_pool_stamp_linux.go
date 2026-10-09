package agent

import (
	"fmt"
	"os"
	"syscall"
)

func healthPoolChangeStamp(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", stat.Ctim.Sec, stat.Ctim.Nsec)
	}
	return ""
}
