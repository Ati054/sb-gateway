package controlplane

import "testing"

func TestRuntimeBuildInfoCoreVersionFallbackAndOverride(t *testing.T) {
	for _, value := range []struct{ environment, want string }{
		{"", "26.10.31"},
		{"26.10.31", "26.10.31"},
		{"custom-core", "custom-core"},
	} {
		t.Run(value.environment, func(t *testing.T) {
			t.Setenv("SB_XRAY_VERSION", value.environment)
			info := runtimeBuildInfo()
			if info["active_core_version"] != value.want || objectAt(info, "bundled_core_versions")["xray"] != value.want {
				t.Fatalf("core version lost its source fallback or explicit override: %v", info)
			}
		})
	}
}
