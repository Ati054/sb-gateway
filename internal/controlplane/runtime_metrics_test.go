package controlplane

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRuntimeMetricsRequiresSession(t *testing.T) {
	server := newTestServer(t)
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/diagnostics/runtime", nil, nil)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "cpu-seconds") {
		t.Fatalf("unauthenticated metrics: %d", response.Code)
	}
}

func TestRuntimeMetricsAreNumericAndDoNotExposeEnvironment(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	t.Setenv("SB_RUNTIME_METRICS_SECRET_SENTINEL", "must-not-escape")
	var startedAt string
	for i := 0; i < 2; i++ {
		response := performRequest(t, server, http.MethodGet, apiPrefix+"/diagnostics/runtime", nil, nil, cookie)
		if response.Code != http.StatusOK {
			t.Fatalf("metrics status: %d", response.Code)
		}
		var result struct {
			Process string             `json:"process"`
			PID     int                `json:"pid"`
			Started string             `json:"started_at"`
			Metrics map[string]float64 `json:"metrics"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Process != "controller" || result.PID <= 0 || len(result.Metrics) != 16 {
			t.Fatalf("incomplete runtime metrics: %+v", result)
		}
		if _, err := time.Parse(time.RFC3339Nano, result.Started); err != nil || (startedAt != "" && startedAt != result.Started) {
			t.Fatal("process generation is missing or changed between samples")
		}
		startedAt = result.Started
		for name, value := range result.Metrics {
			if value < 0 || (!strings.HasPrefix(name, "/cpu/") && !strings.HasPrefix(name, "/gc/") && !strings.HasPrefix(name, "/memory/") && !strings.HasPrefix(name, "/sched/")) {
				t.Fatalf("unexpected metric: %s=%v", name, value)
			}
		}
		if strings.Contains(response.Body.String(), "must-not-escape") {
			t.Fatal("environment escaped numeric diagnostic")
		}
	}
}
