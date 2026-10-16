//go:build sb_cpu_lab

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"
)

const labCPUProfileRequest = "/run/sb-gateway/lab-cpu-profile-request"
const labCPUProfileDirectory = "/logs/lab-cpu-profile"
const labMemoryLimitRequest = "/run/sb-gateway/lab-gateway-limit-request"

var labCPUProfileToken = regexp.MustCompile(`^[a-zA-Z0-9-]{1,48}$`)

func init() {
	if os.Getenv("SB_LAB_CPU_PROFILE") != "1" || filepath.Base(os.Args[0]) == "xray" || len(os.Args) < 2 || os.Args[1] != "appliance" {
		return
	}
	go watchLabCPUProfileRequests()
}

func watchLabCPUProfileRequests() {
	duration := 60
	if value, err := strconv.Atoi(os.Getenv("SB_LAB_CPU_PROFILE_SECONDS")); err == nil && value >= 10 && value <= 120 {
		duration = value
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := ""
	lastMemory := ""
	var previousLimit int64
	memoryChanged := false
	for range ticker.C {
		if os.Getenv("SB_LAB_GATEWAY_LIMIT") == "1" {
			if body, err := readLabMemoryRequest(labMemoryLimitRequest); err == nil {
				token, target, valid := parseLabMemoryRequest(string(body))
				if valid && token != lastMemory {
					lastMemory = token
					if target == 0 {
						if memoryChanged {
							debug.SetMemoryLimit(previousLimit)
							memoryChanged = false
						}
						log.Printf("lab-memory-limit: restored id=%s", token)
					} else if previous, err := applyLabGatewayMemoryLimit("/sys/fs/cgroup", debug.SetMemoryLimit); err != nil {
						log.Printf("lab-memory-limit: refused id=%s", token)
					} else {
						if !memoryChanged {
							previousLimit = previous
						}
						memoryChanged = true
						log.Printf("lab-memory-limit: enabled id=%s bytes=%d", token, target)
					}
				}
			}
		}
		file, err := os.Open(labCPUProfileRequest)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(file, 129))
		_ = file.Close()
		id := strings.TrimSpace(string(body))
		if err != nil || !validLabCPUProfileID(id) || id == last {
			continue
		}
		last = id
		if err := os.MkdirAll(labCPUProfileDirectory, 0700); err != nil {
			log.Printf("lab-cpu-profile: directory unavailable")
			continue
		}
		name := filepath.Join(labCPUProfileDirectory, id+"-"+strconv.Itoa(os.Getpid())+".pprof")
		log.Printf("lab-cpu-profile: starting id=%s seconds=%d", id, duration)
		if err := writeLabCPUProfile(name, time.Duration(duration)*time.Second); err != nil {
			log.Printf("lab-cpu-profile: failed id=%s", id)
			continue
		}
		log.Printf("lab-cpu-profile: completed id=%s", id)
	}
}

func validLabCPUProfileID(id string) bool { return labCPUProfileToken.MatchString(id) }

func readLabMemoryRequest(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil || len(body) > 128 {
		return nil, fmt.Errorf("invalid diagnostic memory request")
	}
	return body, nil
}

func parseLabMemoryRequest(body string) (string, int64, bool) {
	parts := strings.Split(strings.TrimSpace(body), ":")
	if len(parts) != 2 || !validLabCPUProfileID(parts[0]) {
		return "", 0, false
	}
	switch parts[1] {
	case "110":
		return parts[0], 110 << 20, true
	case "restore":
		return parts[0], 0, true
	default:
		return "", 0, false
	}
}

func applyLabGatewayMemoryLimit(root string, setLimit func(int64) int64) (int64, error) {
	values := make(map[string]int64)
	for _, name := range []string{"memory.high", "memory.max", "memory.current"} {
		file, err := os.Open(filepath.Join(root, name))
		if err != nil {
			return 0, err
		}
		body, err := io.ReadAll(io.LimitReader(file, 65))
		_ = file.Close()
		if err != nil || len(body) > 64 {
			return 0, fmt.Errorf("invalid diagnostic cgroup counter")
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
		if err != nil || value < 0 {
			return 0, fmt.Errorf("unavailable diagnostic cgroup counter")
		}
		values[name] = value
	}
	high, max, used := values["memory.high"], values["memory.max"], values["memory.current"]
	if high < (256<<20) || max < (320<<20) || high > max || used > high-(48<<20) {
		return 0, fmt.Errorf("diagnostic controller limit lacks headroom")
	}
	return setLimit(110 << 20), nil
}

func writeLabCPUProfile(name string, duration time.Duration) error {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		return err
	}
	time.Sleep(duration)
	pprof.StopCPUProfile()
	return file.Close()
}
