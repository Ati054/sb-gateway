package watchdog

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

func TestLiveLeaseRenewsAfterOneFailedCheckWithoutReAdmission(t *testing.T) {
	r := &runner{opts: Options{MarkerFile: filepath.Join(t.TempDir(), "ready")}}
	current := settings{interval: 5 * time.Second, recoveryThreshold: 3}
	if err := publishLease(r.opts.MarkerFile, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	// A failed cycle at105 does not renew the lease. A comprehensive success
	// at110 must refresh it, not wait until the old heartbeat expires at115.
	for _, second := range []int64{110, 115, 120} {
		now := time.Unix(second, 0)
		threshold := recoverySuccessThreshold(current.recoveryThreshold, true, r.liveLease(current, now))
		if threshold != 1 {
			t.Fatalf("successful live heartbeat was delayed until %d confirmations", threshold)
		}
		if err := publishLease(r.opts.MarkerFile, now); err != nil {
			t.Fatal(err)
		}
		if !r.liveLease(current, now.Add(4*time.Second)) {
			t.Fatal("admitted traffic lost readiness between successful cycles")
		}
	}
}

func TestWithdrawnOrExpiredLeaseStillRequiresRecoveryThreshold(t *testing.T) {
	for _, mode := range []string{"missing", "cleared", "expired", "future", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			r := &runner{opts: Options{MarkerFile: filepath.Join(t.TempDir(), "ready")}}
			current := settings{interval: 5 * time.Second, recoveryThreshold: 3}
			now := time.Unix(100, 0)
			switch mode {
			case "cleared":
				if err := publishLease(r.opts.MarkerFile, now); err != nil {
					t.Fatal(err)
				}
				r.clearLease()
			case "expired":
				if err := publishLease(r.opts.MarkerFile, now.Add(-16*time.Second)); err != nil {
					t.Fatal(err)
				}
			case "future":
				if err := publishLease(r.opts.MarkerFile, now.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(r.opts.MarkerFile, []byte("not-ready"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if r.liveLease(current, now) {
				t.Fatal("invalid lease was treated as live")
			}
			threshold := recoverySuccessThreshold(current.recoveryThreshold, true, false)
			for successes := 1; successes <= 3; successes++ {
				admitted := successes >= threshold
				if admitted != (successes == 3) {
					t.Fatal("recovery hysteresis was bypassed")
				}
			}
		})
	}
}

func TestSuccessfulLeaseIsDatedAtPublication(t *testing.T) {
	r := &runner{opts: Options{MarkerFile: filepath.Join(t.TempDir(), "ready")}}
	beforePublication := time.Now()
	if err := r.publishReadyLease(); err != nil {
		t.Fatal(err)
	}
	afterPublication := time.Now()
	age, valid := runtimeproof.ReadinessLeaseAge(r.opts.MarkerFile, afterPublication)
	issued := afterPublication.Unix() - age
	if !valid || issued < beforePublication.Unix() || issued > afterPublication.Unix() {
		t.Fatalf("fresh readiness lease was not published: age=%d valid=%t", age, valid)
	}
}
