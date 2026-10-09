package controlplane

import (
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestManagedDNSUpgradeOffersApplyWithoutConfigurationEdits(t *testing.T) {
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
	legacy := strings.ReplaceAll(source, `comment="SB-GATEWAY managed DNS`, `comment="legacy DNS`)
	legacyRecovery := strings.ReplaceAll(source, `find where dst-address~":53\$"`, `find where connection-mark=no-mark and dst-address~":53\$"`)
	if legacyRecovery == source {
		t.Fatal("fixture must retain the actual watchdog recovery loop")
	}
	legacyPorts := strings.ReplaceAll(source, "find where dst-port=53", "find where dst-address")
	if legacyPorts == source {
		t.Fatal("fixture must retain the split-port conntrack selector")
	}
	for _, test := range []struct {
		name, source string
		update       bool
	}{
		{"older renderer", legacy, true},
		{"older recovery filter", legacyRecovery, true},
		{"older endpoint format", legacyPorts, true},
		{"updated renderer", source, false},
		{"no committed traffic script", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := server.repository.commitActive(commitMetadata{Revision: revision, RouterOSSource: test.source, Actor: "test"}); err != nil {
				t.Fatal(err)
			}
			for _, dirty := range []bool{false, true} {
				draft := cloneJSONObject(config)
				pendingConfig := 0
				if dirty {
					draft["schema_version"] = 99
					pendingConfig = 1
				}
				envelope, err := server.draftEnvelope(draft)
				if err != nil {
					t.Fatal(err)
				}
				overview, err := server.overviewPayload(draft)
				if err != nil {
					t.Fatal(err)
				}
				for _, payload := range []map[string]any{envelope, overview} {
					pending := pendingConfig
					if test.update {
						pending = 1
					}
					if payload["runtime_update_required"] != test.update ||
						payload["runtime_update_only"] != (test.update && !dirty) ||
						payload["pending_change_count"] != pending ||
						payload["pending_config_change_count"] != pendingConfig {
						t.Fatalf("incorrect upgrade state for dirty=%v: %v", dirty, payload["runtime_update_required"])
					}
				}
			}
		})
	}
	if managedDNSRulesNeedUpdate("", map[string]any{"routeros_source": legacy}) {
		t.Fatal("unconfigured installation must not report an active runtime upgrade")
	}
}
