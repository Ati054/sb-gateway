package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/memorybudget"
)

func isXrayAlias(executable string) bool {
	name := filepath.Base(executable)
	return name == "xray" || (runtime.GOOS == "windows" && name == "xray.exe")
}

func dispatchXrayAlias() bool {
	if !isXrayAlias(os.Args[0]) {
		return false
	}
	role := xrayMemoryRole(os.Args[1:])
	requested := os.Getenv("GOMEMLIMIT")
	if role == memorybudget.Xray {
		requested = os.Getenv("SB_XRAY_GOMEMLIMIT")
	}
	memorybudget.Configure(role, requested)
	runXrayMain()
	return true
}

func xrayMemoryRole(arguments []string) memorybudget.Role {
	if len(arguments) > 0 && arguments[0] != "run" && !strings.HasPrefix(arguments[0], "-") {
		return memorybudget.Worker
	}
	for _, arg := range arguments {
		if arg == "-test" || arg == "--test" || arg == "-test=true" || arg == "--test=true" {
			return memorybudget.Worker
		}
	}
	return memorybudget.Xray
}
