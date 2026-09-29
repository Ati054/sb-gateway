package controlplane

import (
	"context"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestHotPolicyActivationIgnoresLocalPoliciesWithoutHealthSelectors(t *testing.T) {
	render := func(member string) string {
		config := map[string]any{
			"reverse_vless_exits": []any{
				map[string]any{"id": "first", "enabled": true},
				map[string]any{"id": "second", "enabled": true},
			},
			"policies": []any{
				map[string]any{"id": "route", "enabled": true, "mode": "priority", "selection_order": []any{"reverse:" + member}},
				map[string]any{"id": "direct-only", "enabled": true, "mode": "direct"},
				map[string]any{"id": "empty", "enabled": true, "mode": "best", "selection_order": []any{"reverse:missing"}},
			},
			"local_clients": []any{
				map[string]any{"policy_id": "route", "enabled": true},
				map[string]any{"policy_id": "direct-only", "enabled": true},
				map[string]any{"policy_id": "empty", "enabled": true},
			},
		}
		body, err := runtimeconfig.BuildXrayHealthPool(config, nil, map[string]any{"outbounds": []any{map[string]any{"tag": "block"}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	previous, target := render("first"), render("second")
	for _, method := range []string{"apply", "subscription"} {
		t.Run(method, func(t *testing.T) {
			runtime, candidate, controller := hotPolicyFixtureWithPools(t, previous, target)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			stamp := testPoolStamp(t, runtime.options.XrayHealthPool)
			go func() {
				var err error
				if method == "subscription" {
					_, err = runtime.activateSubscription(ctx, candidate)
				} else {
					_, err = runtime.activate(ctx, candidate)
				}
				done <- err
			}()
			waitTestPool(t, runtime.options.XrayHealthPool, target, stamp, done)
			// Only the actual health selector appears in the acknowledgement.
			acknowledgeTestPool(t, runtime, map[string]string{"route": "reverse-vless-second"})
			if err := <-done; err != nil {
				t.Fatalf("unmanaged local policy held an unrelated hot activation: %v", err)
			}
			if len(controller.restarts) != 0 {
				t.Fatal("hot activation unexpectedly restarted a process")
			}
		})
	}
}
