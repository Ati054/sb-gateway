package routeros

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/applytiming"
)

func TestTransactionTimingPreservesGuardAndFailureOrder(t *testing.T) {
	for _, failDisarm := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "restore"}[failDisarm], func(t *testing.T) {
			rest := &fakeTransactionREST{}
			if failDisarm {
				rest.disarmError = errors.New("disarm rejected")
			}
			transaction := &Transaction{rest: rest, run: rest.runSSHScript}
			var records [][]byte
			ctx, finish := applytiming.Begin(context.Background(), "0123456789abcdef", func(body []byte) { records = append(records, body) })
			_, err := transaction.ApplyDelta(ctx, "apply", "rollback", TransactionOptions{
				SchedulerGuardOnly: true,
				HealthCheck:        func(context.Context) error { rest.events = append(rest.events, "health"); return nil },
				Finalize:           func(context.Context) error { rest.events = append(rest.events, "finalize"); return nil },
			})
			outcome := applytiming.Success
			if err != nil {
				outcome = applytiming.Error
			}
			finish(outcome)
			if (err != nil) != failDisarm || len(records) != 1 {
				t.Fatalf("failure=%t records=%d", err != nil, len(records))
			}
			want := []string{"prepare:rollback", "prepare:apply", "arm:SB-GATEWAY-rollback-0123456789ab", "run:SB-GATEWAY-apply-0123456789ab", "health", "disarm:SB-GATEWAY-safe-rollback-1234abcd"}
			if failDisarm {
				want = append(want, "run:SB-GATEWAY-rollback-0123456789ab", "settled")
			} else {
				want = append(want, "finalize")
			}
			if !sameStrings(rest.events, want) {
				t.Fatalf("guard/finalization order changed: %v", rest.events)
			}
			var record struct {
				Stages []struct {
					Stage string `json:"stage"`
					Count int    `json:"count"`
				} `json:"stages"`
			}
			if err := json.Unmarshal(records[0], &record); err != nil {
				t.Fatal(err)
			}
			wantStages := []string{"routeros_prepare_arm", "routeros_execute", "guard_disarm"}
			var stages []string
			for _, stage := range record.Stages {
				stages = append(stages, stage.Stage)
				if stage.Count != 1 {
					t.Fatal("duplicate span")
				}
			}
			if !sameStrings(stages, wantStages) {
				t.Fatalf("missing stage split: %s", records[0])
			}
		})
	}
}
