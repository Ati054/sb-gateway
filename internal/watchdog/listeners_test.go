package watchdog

import (
	"context"
	"errors"
	"testing"
)

func TestMissingListenerRequiresIndependentConfirmation(t *testing.T) {
	for _, test := range []struct {
		name          string
		known, found  bool
		failure       error
		wantProbeRuns int
	}{
		{name: "known listener", known: true},
		{name: "live table omitted listener", found: true, wantProbeRuns: 1},
		{name: "listener really closed", wantProbeRuns: 1},
		{name: "confirmation unavailable", failure: context.DeadlineExceeded, wantProbeRuns: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ports := make(map[int]struct{})
			if test.known {
				ports[1053] = struct{}{}
			}
			runs := 0
			probe := func(ctx context.Context, protocol string, port int) (bool, error) {
				runs++
				if protocol != "udp" || port != 1053 {
					t.Fatal("confirmation queried an unrelated listener")
				}
				return test.found, test.failure
			}
			present, err := verifyMissingListener(context.Background(), "udp", 1053, ports, probe)
			if present != (test.known || test.found) || !errors.Is(err, test.failure) || runs != test.wantProbeRuns {
				t.Fatalf("present=%v err=%v probe runs=%d", present, err, runs)
			}
			if test.found && err == nil {
				_, _ = verifyMissingListener(context.Background(), "udp", 1053, ports, probe)
				if runs != 1 {
					t.Fatal("confirmed listener was queried again within one inventory")
				}
			}
		})
	}
}
