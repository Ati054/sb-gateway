package controlplane

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

// Opt-in read-only replay of a local lab model without secret values.
// Outputs only counts/comparisons, never model contents; skipped in CI.
func TestSubscriptionLiveModelDiagnostic(t *testing.T) {
	path := os.Getenv("SB_LAB_SUBSCRIPTION_MODEL")
	if path == "" {
		t.Skip("local lab model not selected")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var model map[string]any
	if err = json.Unmarshal(body, &model); err != nil {
		t.Fatal(err)
	}
	c := model["config"].(map[string]any)
	metadata := model["metadata"].(map[string]any)
	old := objectNodes(model["snapshot"].(map[string]any)["nodes"])
	fresh := runtimeSubscriptionNodes(c, model["inventory"].(map[string]any))
	previousEndpoints, err := runtimeconfig.RouterOSEndpointBypass(c, old)
	if err != nil {
		t.Fatal(err)
	}
	desiredEndpoints, err := runtimeconfig.RouterOSEndpointBypass(c, fresh)
	if err != nil {
		t.Fatal(err)
	}
	patched, err := runtimeconfig.UpdateRouterOSEndpointSource(subscriptionText(metadata["routeros_source"]), previousEndpoints, desiredEndpoints)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := runtimeconfig.UpdateRouterOSEndpointSource(patched, desiredEndpoints, previousEndpoints)
	if err != nil || restored != metadata["routeros_source"] {
		t.Fatal("endpoint roundtrip changed unrelated rules")
	}
	t.Log("endpoint-only update and rollback preserve all unrelated committed rules")
	for label, nodes := range map[string][]map[string]any{"old": old, "new": fresh} {
		source, err := runtimeconfig.RenderRouterOSTrafficCandidate(c, nodes, os.Getenv("SB_LAB_RULESETS"))
		if err != nil {
			t.Fatal(err)
		}
		committed := subscriptionText(metadata["routeros_source"])
		t.Logf("%s: nodes=%d sourceEqual=%v committedBytes=%d renderedBytes=%d", label, len(nodes), source == committed, len(committed), len(source))
		a, b := strings.Split(committed, "\n"), strings.Split(source, "\n")
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] != b[i] {
				t.Logf("first differing line %d: oldLength=%d newLength=%d", i+1, len(a[i]), len(b[i]))
				break
			}
		}
	}
}
