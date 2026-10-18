package runtimeproof

import (
	"os"
	"strconv"
	"strings"
	"time"
)

func ReadinessLeaseTTL(intervalSeconds int) int {
	if intervalSeconds <= 5 {
		return 15
	}
	if intervalSeconds >= 448 {
		return 900
	}
	return intervalSeconds*2 + 5
}

func ReadinessLeaseAge(path string, now time.Time) (int64, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return -1, false
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 12 {
		return -1, false
	}
	issued, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return -1, false
	}
	age := now.Unix() - issued
	if age < 0 {
		return -1, false
	}
	return age, true
}
