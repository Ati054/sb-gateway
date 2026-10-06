package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLegacyPolicyControlsCannotOverrideFixedSafety(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		var policy healthPolicy
		if err := json.Unmarshal([]byte(`{"failure_threshold":1,"recovery_threshold":20,"quality_window":60,"max_packet_loss_percent":100,"max_latency_ms":1,"failure_retry_interval_seconds":10,"block_recovery_interval_seconds":60,"backup_check_interval_seconds":86400,"full_scan_interval_seconds":86400,"max_active_candidates":1,"max_probe_candidates":1,"switch_cooldown":86400,"switch_cooldown_seconds":86400,"active_check_interval_seconds":60,"active_liveness_interval_seconds":7}`), &policy); err != nil {
			t.Fatal(err)
		}
		p := policySettings(policy, mode)
		if p.failureThreshold != 3 || p.recoveryThreshold != 3 || p.failureRetry != 2 || p.blockRecovery != 15 ||
			p.backup != 120 || p.shortlist != 10 || p.active != 60 || p.liveness != 7 {
			t.Fatalf("%s legacy controls changed effective safety: %+v", mode, p)
		}
		body, err := json.Marshal(policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"failure_threshold", "recovery_threshold", "quality_window", "max_packet_loss_percent", "max_latency_ms", "backup_check_interval_seconds", "full_scan_interval_seconds", "max_active_candidates", "max_probe_candidates", "switch_cooldown"} {
			if strings.Contains(string(body), key) {
				t.Fatalf("%s retired key survived serialization: %s", mode, key)
			}
		}
	}
}

func TestSelectionUsesLatestQualityDelayNotHistoricalMedian(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, runtime, item := livenessFixture(t, mode)
			oldDelay := 1900
			item.Samples["de"] = []healthSample{
				{At: 997, OK: true, DelayMS: &oldDelay},
				{At: 998, OK: true, DelayMS: &oldDelay},
				{At: 999, OK: true, DelayMS: &oldDelay},
			}
			item.DailySamples["de"] = append([]healthSample(nil), item.Samples["de"]...)
			runtime.probes["de"] = successfulEvidence(400)
			controller.regularNext["europe"] = time.Time{}
			if err := controller.Tick(time.Unix(1060, 0)); err != nil {
				t.Fatal(err)
			}
			if got := item.MedianDelayMS["de"]; got == nil || *got != 400 || len(item.Samples["de"]) != 1 {
				t.Fatalf("latest delay not used: delay=%v samples=%v", got, item.Samples["de"])
			}
			if stats := item.DailyStats["de"]; stats.MedianMS == nil || *stats.MedianMS != 1900 {
				t.Fatalf("historical statistics were overwritten: %+v", stats)
			}
		})
	}
}
