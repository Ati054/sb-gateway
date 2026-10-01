package runtimeproof

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Reuse startup's validation only for the same live core, process generation,
// readiness marker and config bytes. Missing or stale proof falls back to -test.
func XrayValidated(proofPath, readyPath, configPath, procRoot, signature string) bool {
	link, err := os.Lstat(proofPath)
	if err != nil || !link.Mode().IsRegular() {
		return false
	}
	file, err := os.Open(proofPath)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256 {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(body) > 256 {
		return false
	}
	proof := strings.Fields(string(body))
	if len(proof) != 3 || len(signature) != 64 || proof[2] != signature {
		return false
	}
	pid, err := strconv.Atoi(proof[0])
	if err != nil || pid <= 0 || strconv.Itoa(pid) != proof[0] {
		return false
	}
	started, err := strconv.ParseUint(proof[1], 10, 64)
	if err != nil || started == 0 {
		return false
	}
	return XrayGeneration(readyPath, configPath, procRoot) == proof[0]+" "+proof[1]
}

// XrayGeneration identifies the live core independently of config changes made
// by hot updates; these must not erase the history of previous routing updates.
func XrayGeneration(readyPath, configPath, procRoot string) string {
	ready, err := os.ReadFile(readyPath)
	if err != nil {
		return ""
	}
	pidText := strings.TrimSpace(string(ready))
	pid, err := strconv.Atoi(pidText)
	if err != nil || pid <= 0 || strconv.Itoa(pid) != pidText {
		return ""
	}
	process := filepath.Join(procRoot, pidText)
	stat, err := os.ReadFile(filepath.Join(process, "stat"))
	if err != nil {
		return ""
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return ""
	}
	fields := strings.Fields(string(stat)[end+1:])
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return ""
	}
	started, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || started == 0 {
		return ""
	}
	command, err := os.ReadFile(filepath.Join(process, "cmdline"))
	if err != nil {
		return ""
	}
	args := strings.Split(strings.TrimSuffix(string(command), "\x00"), "\x00")
	if len(args) != 4 || filepath.Base(args[0]) != "xray" || args[1] != "run" ||
		args[2] != "-config" || args[3] != configPath {
		return ""
	}
	return pidText + " " + fields[19]
}
