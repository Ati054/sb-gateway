package agent

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestXrayOutboundDeadlineRetryRequiresConfirmedAbsence(t *testing.T) {
	for _, scenario := range []string{"absent", "ack-lost", "cancelled", "rejected", "unconfirmed", "still-absent"} {
		t.Run(scenario, func(t *testing.T) {
			runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
			runtime.pool = healthPool{Outbounds: map[string]json.RawMessage{"node": json.RawMessage(`{"protocol":"freedom"}`)}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runtime.probeContext = ctx
			adds, lists := 0, 0
			installed := false
			runtime.command = func(_ context.Context, timeout time.Duration, _ string, args ...string) ([]byte, error) {
				if timeout != 5*time.Second {
					t.Fatalf("unexpected command deadline=%s", timeout)
				}
				switch args[1] {
				case "ado":
					adds++
					if adds > 2 {
						t.Fatal("unbounded add retry")
					}
					if adds == 1 {
						switch scenario {
						case "ack-lost":
							installed = true
						case "cancelled":
							cancel()
						case "rejected":
							return nil, errors.New("invalid config")
						}
						return nil, context.DeadlineExceeded
					}
					installed = scenario != "still-absent"
					return nil, nil
				case "lso":
					lists++
					if scenario == "unconfirmed" {
						return nil, errors.New("API unavailable")
					}
					if installed {
						return outboundTagsJSON("tag"), nil
					}
					return outboundTagsJSON(), nil
				default:
					t.Fatalf("unexpected operation=%s", args[1])
					return nil, nil
				}
			}
			err := runtime.ensureOutbound("node", "tag")
			success := scenario == "absent" || scenario == "ack-lost"
			if (err == nil) != success || runtime.loadedDynamic["tag"] != success {
				t.Fatalf("scenario=%s adds=%d lists=%d installed=%t loaded=%t err=%v", scenario, adds, lists, installed, runtime.loadedDynamic["tag"], err)
			}
			wantAdds := 1
			if scenario == "absent" || scenario == "still-absent" {
				wantAdds = 2
			}
			if adds != wantAdds {
				t.Fatalf("adds=%d want=%d", adds, wantAdds)
			}
		})
	}
}
