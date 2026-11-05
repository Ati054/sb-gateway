package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var benchmarkCheckpointProjection any
var benchmarkCheckpointBytes []byte

// benchmarkMatureCheckpointStates contains only generated endpoint names and
// deterministic latency values. Both modes share the identical cold graph:
// 24 nodes per policy, 30 daily reservoirs of 256 values, 1440 daily samples,
// and three short samples. Warm adds only its bounded planning metadata.
func benchmarkMatureCheckpointStates(policies int) (healthState, healthState) {
	now := time.Date(2026, time.January, 31, 12, 0, 0, 0, time.UTC)
	cold, warm := healthState{}, healthState{}
	for policy := 0; policy < policies; policy++ {
		id := fmt.Sprintf("synthetic-policy-%02d", policy)
		item := newPolicyHealthState()
		item.CandidateNodes, item.CandidateLabels = map[string]healthNode{}, map[string]string{}
		item.QualityOK, item.AvailabilityOK = map[string]bool{}, map[string]bool{}
		item.Mode, item.LatencyMeasurement, item.CandidateCount = "best", latencyMeasurement, 24
		item.RuntimeConfirmed, item.CheckedAt = true, now.Format(time.RFC3339Nano)
		item.RuntimeObservedAt = item.CheckedAt
		for node := 0; node < 24; node++ {
			name := fmt.Sprintf("synthetic-node-%02d", node)
			item.CandidateNodes[name] = healthNode{Label: name, Protocol: "vless", Transport: "ws", Fingerprint: name}
			item.CandidateLabels[name] = name
			item.QualityOK[name], item.AvailabilityOK[name] = true, true
			item.Recoveries[name], item.LastProbeAt[name] = 3, float64(now.Unix())
			item.DailySamples[name] = make([]healthSample, 1440)
			for sample := range item.DailySamples[name] {
				delay := 100 + (sample*79+node*13)%900
				at := float64(now.Add(-time.Duration(1439-sample) * time.Minute).Unix())
				item.DailySamples[name][sample] = healthSample{At: at, ObservedAt: at, OK: true, DelayMS: &delay}
			}
			item.Samples[name] = item.DailySamples[name][1437:]
			item.HistoryDays[name] = make(map[string]dayBucket, 30)
			for day := 0; day < 30; day++ {
				bucket := dayBucket{Samples: 1440, Successes: 1440, LatencySamples: make([]int, 256)}
				for sample := range bucket.LatencySamples {
					bucket.LatencySamples[sample] = 100 + (sample*83+day*11+node)%900
				}
				item.HistoryDays[name][now.AddDate(0, 0, -day).Format("2006-01-02")] = bucket
			}
			if node == 0 {
				item.Selected, item.RuntimeSelected = name, name
			}
		}
		cold[id] = item
		copy := *item
		copy.WarmPlanningMarker = string(qualityMeasurementWarm)
		copy.WarmPlanningSignature = "synthetic-generation"
		copy.WarmPlanningSamples = make(map[string][]healthSample, 24)
		copy.WarmPlanningLastProbeAt = make(map[string]float64, 24)
		for node, samples := range item.Samples {
			copy.WarmPlanningSamples[node] = samples
			copy.WarmPlanningLastProbeAt[node] = float64(now.Unix())
		}
		warm[id] = &copy
	}
	return cold, warm
}

// BenchmarkMatureHealthCheckpoint separates projection, encoding, durable
// pre-encoded writes, and the real readiness+checkpoint publication path.
// Setup is excluded; payload-B/op is encoded size, B/op is allocated memory.
// CPU, GC and fsync results depend on architecture, GOMEMLIMIT, filesystem and
// concurrent work. They are not a measured router workload or DNS benchmark.
// A short bounded run is:
// go test ./internal/agent -run '^$' -bench '^BenchmarkMatureHealthCheckpoint$' -benchtime=3x -benchmem
func BenchmarkMatureHealthCheckpoint(b *testing.B) {
	for _, policies := range []int{1, 6} {
		b.Run(fmt.Sprintf("policies%d/nodes24", policies), func(b *testing.B) {
			cold, warm := benchmarkMatureCheckpointStates(policies)
			for _, mode := range []struct {
				name  string
				state healthState
			}{{"cold", cold}, {"warm", warm}} {
				b.Run(mode.name, func(b *testing.B) {
					body, err := json.Marshal(healthCheckpointProjection(mode.state))
					if err != nil {
						b.Fatal(err)
					}
					encoded := append(body, '\n')
					for _, stage := range []string{"projection", "encode", "fsync-encoded", "publish"} {
						b.Run(stage, func(b *testing.B) {
							path := filepath.Join(b.TempDir(), "selector-health.json")
							b.ReportAllocs()
							if stage != "projection" {
								b.SetBytes(int64(len(encoded)))
							}
							b.ResetTimer()
							b.ReportMetric(float64(len(encoded)), "payload-B/op")
							cpuBefore, measureCPU := benchmarkPublicationCPU()
							for iteration := 0; iteration < b.N; iteration++ {
								switch stage {
								case "projection":
									benchmarkCheckpointProjection = healthCheckpointProjection(mode.state)
								case "encode":
									benchmarkCheckpointBytes, err = json.Marshal(healthCheckpointProjection(mode.state))
								case "fsync-encoded":
									err = benchmarkWriteCheckpointBytes(path, encoded)
								case "publish":
									err = publishHealthState(path, mode.state)
								}
								if err != nil {
									b.Fatal(err)
								}
							}
							b.StopTimer()
							if cpuAfter, ok := benchmarkPublicationCPU(); measureCPU && ok && cpuAfter >= cpuBefore {
								b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
							}
						})
					}
				})
			}
		})
	}
}

// Test-only copy of writeJSONAtomic's filesystem sequence, without encoding.
// Its target always belongs to b.TempDir. No production or runtime file is used.
func benchmarkWriteCheckpointBytes(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".checkpoint-benchmark.*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(body)
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(name, path)
}
