package controlplane

import (
	"net/http"
	"os"
	"runtime/metrics"
	"time"
)

var runtimeMetricsStartedAt = time.Now().UTC().Format(time.RFC3339Nano)

// Numeric controller counters only. No profile, heap objects, configuration,
// environment or credentials are exposed, and no collection is forced.
func (server *Server) runtimeMetrics(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	names := []string{
		"/cpu/classes/gc/mark/assist:cpu-seconds",
		"/cpu/classes/gc/mark/idle:cpu-seconds",
		"/cpu/classes/gc/total:cpu-seconds",
		"/cpu/classes/scavenge/total:cpu-seconds",
		"/cpu/classes/user:cpu-seconds",
		"/gc/cycles/total:gc-cycles",
		"/gc/cycles/forced:gc-cycles",
		"/gc/gogc:percent",
		"/gc/gomemlimit:bytes",
		"/gc/heap/live:bytes",
		"/gc/heap/allocs:bytes",
		"/gc/heap/goal:bytes",
		"/memory/classes/total:bytes",
		"/memory/classes/heap/released:bytes",
		"/sched/goroutines:goroutines",
		"/sched/gomaxprocs:threads",
	}
	samples := make([]metrics.Sample, len(names))
	for i, name := range names {
		samples[i].Name = name
	}
	metrics.Read(samples)
	values := make(map[string]any, len(samples))
	for _, sample := range samples {
		switch sample.Value.Kind() {
		case metrics.KindUint64:
			values[sample.Name] = sample.Value.Uint64()
		case metrics.KindFloat64:
			values[sample.Name] = sample.Value.Float64()
		}
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"process": "controller", "pid": os.Getpid(),
		"started_at": runtimeMetricsStartedAt,
		"sampled_at": time.Now().UTC().Format(time.RFC3339Nano), "metrics": values,
	})
}
