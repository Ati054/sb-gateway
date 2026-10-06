package controlplane

import (
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func normalizeConfigCompatibility(config map[string]any) {
	normalizeXHTTPModeCompatibility(config)
	runtimeconfig.NormalizeURLTestPolicies(config)
}

// Clean snapshots are read-only views; legacy cleanup uses a detached copy.
func publicSelectorHealth(selectors map[string]any) map[string]any {
	if !selectorHealthNeedsCleanup(selectors) {
		return selectors
	}
	result := cloneJSONObject(selectors)
	for _, raw := range result {
		item, _ := raw.(map[string]any)
		for field := range item {
			if retiredSelectorHealthField(field) {
				delete(item, field)
			}
		}
		thresholds, _ := item["quality_thresholds"].(map[string]any)
		for field := range thresholds {
			if retiredQualityThreshold(field) {
				delete(thresholds, field)
			}
		}
		comparison, _ := item["optimization_last_result"].(map[string]any)
		delete(comparison, "active_speed_bps")
		delete(comparison, "candidate_speed_bps")
	}
	return result
}

func selectorHealthNeedsCleanup(selectors map[string]any) bool {
	for _, raw := range selectors {
		item, _ := raw.(map[string]any)
		for field := range item {
			if retiredSelectorHealthField(field) {
				return true
			}
		}
		thresholds, _ := item["quality_thresholds"].(map[string]any)
		for field := range thresholds {
			if retiredQualityThreshold(field) {
				return true
			}
		}
		comparison, _ := item["optimization_last_result"].(map[string]any)
		for _, field := range []string{"active_speed_bps", "candidate_speed_bps"} {
			if _, exists := comparison[field]; exists {
				return true
			}
		}
	}
	return false
}

func retiredSelectorHealthField(field string) bool {
	return strings.HasPrefix(field, "speed_") || strings.HasPrefix(field, "last_speed_") ||
		field == "optimization_speed_degraded" || field == "optimization_active_bps" || field == "optimization_budget_after" || field == "outage_penalty" || field == "cooldown_until"
}

func retiredQualityThreshold(field string) bool {
	return strings.HasPrefix(field, "speed_") || field == "active_speed_seconds" || field == "backup_speed_seconds" ||
		field == "max_latency_ms" || field == "cooldown_seconds" || field == "switch_cooldown_seconds"
}
