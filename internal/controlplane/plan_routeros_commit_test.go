package controlplane

import (
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestPlanUsesCommittedRouterOSSourceOnRendererUpgrade(t *testing.T) {
	server := newTestServer(t)
	config := routerOSReadyConfig(t)
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	source, err := runtimeconfig.RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, committed := range []string{"", strings.Replace(source, "# SB-GATEWAY generated candidate", "# previous renderer candidate", 1), source} {
		if err := server.repository.commitActive(commitMetadata{Revision: revision, RouterOSSource: committed, Actor: "test"}); err != nil {
			t.Fatal(err)
		}
		plan, err := server.buildPlan(config)
		if err != nil {
			t.Fatal(err)
		}
		changed := committed != source
		if plan["routeros_changed"] != changed || plan["idempotent"] == changed {
			t.Fatalf("committed source comparison changed=%v plan=%v", changed, plan["apply_mode"])
		}
	}
	if _, exists := publicApplyMetadata(map[string]any{"routeros_source": source, "revision": revision})["routeros_source"]; exists {
		t.Fatal("large internal script leaked into polling response")
	}
}
