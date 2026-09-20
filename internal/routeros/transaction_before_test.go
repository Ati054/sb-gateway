package routeros

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRuntimeGuardRunsAfterArmBeforeRouterOSRules(t *testing.T) {
	for _, fail := range []bool{false, true} {
		rest := &fakeTransactionREST{}
		transaction := &Transaction{rest: rest, run: rest.runSSHScript}
		_, err := transaction.ApplyDelta(context.Background(), "apply", "rollback", TransactionOptions{SchedulerGuardOnly: true, BeforeApply: func(context.Context) error {
			rest.events = append(rest.events, "origin-guard")
			if fail {
				return errors.New("guard failed")
			}
			return nil
		}, HealthCheck: func(context.Context) error { return nil }})
		if (err != nil) != fail {
			t.Fatal(err)
		}
		events := strings.Join(rest.events, "|")
		arm, guard, apply := strings.Index(events, "arm:"), strings.Index(events, "origin-guard"), strings.Index(events, "run:SB-GATEWAY-apply")
		if arm < 0 || guard < arm || (!fail && apply < guard) || (fail && apply >= 0) {
			t.Fatal(events)
		}
	}
}
