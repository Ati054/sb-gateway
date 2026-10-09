package applyguard

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Active recognizes only a live, bounded runtime-restart guard. A durable
// Apply journal is not a guard: hot selector activation needs the agent alive.
func Active(path string, now time.Time) bool {
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && active(data, now, processExists)
}

func active(data []byte, now time.Time, alive func(int) bool) bool {
	fields := strings.Fields(string(data))
	if len(fields) < 2 || len(fields) > 3 {
		return false
	}
	pid, errPID := strconv.ParseInt(fields[0], 10, 32)
	started, errStarted := strconv.ParseInt(fields[1], 10, 64)
	refreshed := started
	var errRefreshed error
	if len(fields) == 3 {
		refreshed, errRefreshed = strconv.ParseInt(fields[2], 10, 64)
	}
	if errPID != nil || errStarted != nil || errRefreshed != nil || pid < 1 {
		return false
	}
	age, heartbeat := now.Unix()-started, now.Unix()-refreshed
	return refreshed >= started && age >= 0 && age <= 1800 && heartbeat >= 0 && heartbeat <= 90 && alive(int(pid))
}
