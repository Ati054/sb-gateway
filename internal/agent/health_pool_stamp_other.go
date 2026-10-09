//go:build !linux

package agent

import (
	"fmt"
	"os"
)

func healthPoolChangeStamp(info os.FileInfo) string {
	return fmt.Sprint(info.Sys())
}
