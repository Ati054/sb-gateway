package runtimeproof

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadinessLeaseTTL(t *testing.T) {
	for _, test := range []struct{ interval, want int }{{0, 15}, {1, 15}, {5, 15}, {6, 17}, {30, 65}, {300, 605}, {447, 899}, {448, 900}, {1000, 900}} {
		if got := ReadinessLeaseTTL(test.interval); got != test.want {
			t.Fatalf("interval=%d: TTL=%d want=%d", test.interval, got, test.want)
		}
	}
}

func TestReadinessLeaseAgeRejectsMissingMalformedAndFutureMarkers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	now := time.Unix(100, 0)
	if age, valid := ReadinessLeaseAge(path, now); valid || age != -1 {
		t.Fatal("missing lease was accepted")
	}
	for _, test := range []struct {
		body  string
		age   int64
		valid bool
	}{{"100\n", 0, true}, {" 85\n", 15, true}, {"84", 16, true}, {"101", -1, false}, {"", -1, false}, {"bad", -1, false}, {"1234567890123", -1, false}} {
		if err := os.WriteFile(path, []byte(test.body), 0600); err != nil {
			t.Fatal(err)
		}
		if age, valid := ReadinessLeaseAge(path, now); age != test.age || valid != test.valid {
			t.Fatalf("body=%q: age=%d valid=%t", test.body, age, valid)
		}
	}
}
