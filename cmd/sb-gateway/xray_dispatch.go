package main

import (
	"os"
	"path/filepath"
	"runtime"
)

func isXrayAlias(executable string) bool {
	name := filepath.Base(executable)
	return name == "xray" || (runtime.GOOS == "windows" && name == "xray.exe")
}

func dispatchXrayAlias() bool {
	if !isXrayAlias(os.Args[0]) {
		return false
	}
	runXrayMain()
	return true
}
