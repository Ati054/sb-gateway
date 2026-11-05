//go:build !linux

package healthsnapshot

import (
	"fmt"
	"os"
)

func Stamp(info os.FileInfo) string {
	return fmt.Sprintf("%d:%d:%v", info.Size(), info.ModTime().UnixNano(), info.Sys())
}
