package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/dnsroute"
)

func dnsCoreIdentity(root string, pid int) (dnsroute.Core, error) {
	if pid <= 0 {
		return dnsroute.Core{}, errors.New("DNS route core identity unavailable")
	}
	file, err := os.Open(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return dnsroute.Core{}, errors.New("DNS route core identity unavailable")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(body) > 4096 {
		return dnsroute.Core{}, errors.New("DNS route core identity invalid")
	}
	s := string(body)
	end := strings.LastIndex(s, ") ")
	if end < 0 || !strings.HasPrefix(s, strconv.Itoa(pid)+" (") {
		return dnsroute.Core{}, errors.New("DNS route core identity invalid")
	}
	fields := strings.Fields(s[end+2:])
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return dnsroute.Core{}, errors.New("DNS route core identity invalid")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return dnsroute.Core{}, errors.New("DNS route core identity invalid")
	}
	return dnsroute.Core{PID: pid, StartTicks: start}, nil
}

func (runtime *xraySelectorRuntime) syncDNSRoutes() error {
	if runtime.dnsPublisher == nil {
		return nil
	}
	core, err := dnsCoreIdentity("/proc", runtime.xrayPID)
	if err != nil {
		return err
	}
	if core == runtime.dnsCore && runtime.dnsPool == runtime.poolSignature {
		return nil
	}
	selectors := make([]string, 0, len(runtime.pool.Policies))
	for id := range runtime.pool.Policies {
		selectors = append(selectors, id)
	}
	runtime.dnsPublisher.Sync(core, selectors)
	runtime.dnsCore, runtime.dnsPool = core, runtime.poolSignature
	return nil
}

func (runtime *xraySelectorRuntime) publishDNSSelection(selector, runtimeTag string) {
	if runtime.dnsPublisher == nil || runtime.probeSelector != "" {
		return
	}
	if _, policy := runtime.pool.Policies[selector]; !policy {
		return
	}
	runtime.dnsPublisher.Confirm(selector, runtimeTag)
}
