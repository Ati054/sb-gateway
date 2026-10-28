package appliance

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A successful signal alone does not prove activation: wait for a new live
// worker under the same master, preserving Apply and proxy connections.
func reloadNginx(ctx context.Context, binary, config string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pidBody, err := os.ReadFile("/run/nginx.pid")
	if err != nil {
		return fmt.Errorf("read nginx master: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBody)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("invalid nginx master PID")
	}
	workers := func() (map[string]bool, error) { return nginxWorkers("/proc", pid) }
	run := func(args ...string) error {
		body, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx reload command: %w: %.2048s", err, body)
		}
		return nil
	}
	return reloadNginxWith(ctx, config, workers, run)
}

func reloadNginxWith(ctx context.Context, config string, workers func() (map[string]bool, error), run func(...string) error) error {
	before, err := workers()
	if err != nil {
		return err
	}
	if len(before) == 0 {
		return fmt.Errorf("nginx has no serving workers")
	}
	if err := run("-t", "-c", config); err != nil {
		return err
	}
	if err := run("-s", "reload", "-c", config); err != nil {
		return err
	}
	for {
		after, err := workers()
		if err != nil {
			return err
		}
		for pid := range after {
			if !before[pid] {
				return nil
			}
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("nginx new worker: %w", ctx.Err())
		case <-timer.C:
		}
	}
}

func nginxWorkers(proc string, master int) (map[string]bool, error) {
	root := filepath.Join(proc, strconv.Itoa(master))
	// RouterOS does not expose task/PID/children. Enumerate stat PPIDs instead;
	// this scan runs only on a configuration reload, never in health polling.
	masterStat, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return nil, fmt.Errorf("read nginx master: %w", err)
	}
	_, state, valid := nginxProcessParent(masterStat)
	if !valid || state == "Z" || state == "X" {
		return nil, fmt.Errorf("nginx master is not live")
	}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	workers := make(map[string]bool)
	for _, entry := range entries {
		child := entry.Name()
		pid, err := strconv.Atoi(child)
		if err != nil || pid <= 1 || !entry.IsDir() {
			continue
		}
		childRoot := filepath.Join(proc, child)
		stat, err := os.ReadFile(filepath.Join(childRoot, "stat"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		parent, state, valid := nginxProcessParent(stat)
		if !valid || parent != master || state == "Z" || state == "X" {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(childRoot, "cmdline"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if strings.Trim(string(cmdline), " \x00") != "nginx: worker process" {
			continue
		}
		workers[child] = true
	}
	return workers, nil
}

func nginxProcessParent(stat []byte) (int, string, bool) {
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return 0, "", false
	}
	fields := strings.Fields(string(stat)[end+1:])
	if len(fields) < 2 {
		return 0, "", false
	}
	parent, err := strconv.Atoi(fields[1])
	return parent, fields[0], err == nil && parent >= 0
}
