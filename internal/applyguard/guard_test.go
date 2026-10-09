package applyguard

import (
	"testing"
	"time"
)

func TestGuardRequiresBoundedLiveHeartbeat(t *testing.T) {
	now := time.Unix(2000, 0)
	for _, test := range []struct {
		name, body  string
		alive, want bool
	}{
		{"current", "42 1900 1990", true, true},
		{"legacy", "42 1990", true, true},
		{"dead owner", "42 1900 1990", false, false},
		{"expired heartbeat", "42 1900 1900", true, false},
		{"expired operation", "42 100 1990", true, false},
		{"future start", "42 2001 2001", true, false},
		{"future heartbeat", "42 1900 2001", true, false},
		{"heartbeat before start", "42 1990 1980", true, false},
		{"invalid pid", "0 1900 1990", true, false},
		{"invalid record", "42 1900 1990 extra", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := active([]byte(test.body), now, func(pid int) bool { return pid == 42 && test.alive }); got != test.want {
				t.Fatalf("active=%v want=%v", got, test.want)
			}
		})
	}
}
