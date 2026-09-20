package controlplane

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
)

var appliancePersistentMounts = []string{"/config", "/data", "/logs", "/state"}

func appliancePersistentMountsWritable() (bool, []string) {
	// The production image fixes this path. Keep ordinary developer/test servers
	// independent from RouterOS container mount topology.
	if runtime.GOOS != "linux" || os.Getenv("SB_GATEWAY_STATE_DIR") != "/state/control-plane" {
		return true, nil
	}
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return false, append([]string(nil), appliancePersistentMounts...)
	}
	defer file.Close()
	return persistentMountsWritableFrom(file, appliancePersistentMounts)
}

func persistentMountsWritableFrom(reader io.Reader, required []string) (bool, []string) {
	writable := make(map[string]bool, len(required))
	wanted := make(map[string]struct{}, len(required))
	for _, mount := range required {
		wanted[mount] = struct{}{}
	}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		mount := decodeProcMountField(fields[1])
		if _, exists := wanted[mount]; !exists {
			continue
		}
		readWrite, readOnly := false, false
		for _, option := range strings.Split(fields[3], ",") {
			readWrite = readWrite || option == "rw"
			readOnly = readOnly || option == "ro"
		}
		writable[mount] = readWrite && !readOnly
	}
	blocked := make([]string, 0)
	for _, mount := range required {
		if !writable[mount] {
			blocked = append(blocked, mount)
		}
	}
	sort.Strings(blocked)
	return scanner.Err() == nil && len(blocked) == 0, blocked
}

func decodeProcMountField(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}
