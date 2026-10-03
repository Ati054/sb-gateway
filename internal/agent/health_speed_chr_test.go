//go:build linux

package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Provider traffic uses copied handlers in a separate core, never live
// gateway selectors. Accounting includes the running gateway background load.
func TestCHRSpeedProviderCPU(t *testing.T) {
	ctx, cancel := chrSpeedContext(t)
	defer cancel()
	fixture := newCHRSpeedFixture(t, ctx, true)
	t.Logf("SPEED_ENV cpus=%d provider_nodes=%d bytes_per_probe=%d window_seconds=15 sequential=true background_cli_slots=%d cpu_scope=whole_container_including_live_gateway cadence_wall_time_verified=false", runtime.NumCPU(), len(fixture.providers), defaultSpeedBytes, cap(xrayProbeCommandSlots))
	for _, phase := range []string{"idle-before", "real-provider-downloads", "idle-after"} {
		if !t.Run(phase, func(t *testing.T) {
			chrSpeedMeasurePhase(t, ctx, fixture, phase, func(work *chrSpeedWork) {
				if phase != "real-provider-downloads" {
					chrSpeedWait(t, ctx, 20*time.Second)
					return
				}
				for round := 0; round < 2; round++ {
					for _, node := range fixture.providers {
						started := time.Now()
						speed, err := fixture.core.Throughput(node, defaultSpeedBytes)
						work.record(speed, err, time.Since(started), defaultSpeedBytes)
						if (err != nil && !errors.Is(err, errSpeedWindowComplete)) || speed <= 0 {
							t.Fatal("provider speed probe failed; endpoint and raw error withheld")
						}
					}
				}
			})
		}) {
			return
		}
	}
}

// Scenario clocks, seeded baseline dates and HTTPS quality are synthetic.
// Throughput and byte/resource accounting are real loopback HTTP through the
// isolated core. This is not a wall-time cadence or provider-TLS benchmark.
func TestCHRSpeedControlledScenarios(t *testing.T) {
	ctx, cancel := chrSpeedContext(t)
	defer cancel()
	fixture := newCHRSpeedFixture(t, ctx, false)
	t.Log("SPEED_ENV scenario_clock=fake scenario_quality=synthetic400ms scenario_speed=real_loopback_http independent_history_seeded=true cadence_wall_time_verified=false")
	var baseline int64
	if !t.Run("stable", func(t *testing.T) {
		chrSpeedMeasurePhase(t, ctx, fixture, "controlled-stable", func(work *chrSpeedWork) {
			baseline = fixture.sample(t, "active", 18_000_000, work)
			p := chrSpeedPolicy("best", 50)
			item, now := chrSpeedSeed(baseline)
			for i := 0; i < 3; i++ {
				speed := fixture.sample(t, "active", 18_000_000, work)
				updateSpeedHistory(now.Add(time.Duration(i)*5*time.Minute), "active", []string{"active"}, []string{"active"}, map[string]int64{"active": speed}, map[string]string{"active": "ok"}, item, p)
				if item.SpeedDegradation != nil {
					t.Fatal("controlled stable samples started a degradation episode")
				}
			}
			t.Log("SPEED_SCENARIO name=stable switches=0 clock=fake")
		})
	}) {
		return
	}
	for _, scenario := range []struct {
		name, mode string
		drop       int
		unstable   bool
	}{
		{"persistent-drop", "best", 50, false},
		{"spiking-reserve", "best", 50, true},
		{"priority-disabled", "priority", 0, false},
		{"priority-drop", "priority", 30, false},
	} {
		if !t.Run(scenario.name, func(t *testing.T) {
			chrSpeedMeasurePhase(t, ctx, fixture, scenario.name, func(work *chrSpeedWork) {
				chrSpeedScenario(t, fixture, work, baseline, scenario.mode, scenario.drop, scenario.unstable)
			})
		}) {
			return
		}
	}
}

func chrSpeedContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	if os.Getenv("SB_CHR_SPEED_MATRIX") != "1" {
		t.Skip("opt-in pinned CHR speed benchmark")
	}
	if os.Getenv("SB_TEST_XRAY") != "/usr/local/bin/xray" || runtime.GOARCH != "arm64" {
		t.Fatal("expected the CHR container's pinned ARM64 core")
	}
	return context.WithTimeout(context.Background(), 9*time.Minute)
}

type chrSpeedFixture struct {
	core      *xraySelectorRuntime
	ctx       context.Context
	providers []string
	endpoint  *httptest.Server
	requests  atomic.Int64
	served    atomic.Int64
	inFlight  atomic.Int64
	peak      atomic.Int64
}

func newCHRSpeedFixture(t *testing.T, ctx context.Context, providers bool) *chrSpeedFixture {
	t.Helper()
	fixture := &chrSpeedFixture{ctx: ctx}
	var source healthPool
	live := map[string]any{}
	if providers {
		var state healthState
		if readJSON("/config/generated/urltest-pool.json", &source) != nil || readJSON("/state/control-plane/selector-health.json", &state) != nil || readJSON("/config/generated/xray.json", &live) != nil {
			t.Fatal("cannot read CHR-local runtime inventory")
		}
		for _, node := range sortedKeys(source.Outbounds) {
			for _, item := range state {
				if item.AvailabilityOK[node] && item.QualityOK[node] {
					fixture.providers = append(fixture.providers, node)
					break
				}
			}
			if len(fixture.providers) == 3 {
				break
			}
		}
		if len(fixture.providers) != 3 {
			t.Fatal("speed matrix requires three locally known healthy provider endpoints")
		}
	}
	fixture.endpoint = httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(fixture.endpoint.Close)
	root := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal("cannot encode private isolated fixture")
		}
		path := filepath.Join(root, name)
		if os.WriteFile(path, body, 0600) != nil {
			t.Fatal("cannot write private isolated fixture")
		}
		return path
	}
	ports := map[int]bool{}
	port := func() int {
		t.Helper()
		for {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal("cannot allocate isolated loopback port")
			}
			value := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
			if !ports[value] {
				ports[value] = true
				return value
			}
		}
	}
	apiPort, proxyPort := port(), port()
	apiAddress := fmt.Sprintf("127.0.0.1:%d", apiPort)
	selector := "outbound-health-background"
	nodes := append(append([]string{}, fixture.providers...), "active", "a", "b")
	pool := healthPool{Version: 4, BaseOutboundTags: []string{"speed-fixture-direct"}, Policies: map[string][]string{selector: nodes}, Outbounds: map[string]json.RawMessage{}}
	for _, node := range fixture.providers {
		pool.Outbounds[node] = source.Outbounds[node]
	}
	for _, node := range []string{"active", "a", "b"} {
		body, err := json.Marshal(map[string]any{"tag": node, "protocol": "freedom"})
		if err != nil {
			t.Fatal(err)
		}
		pool.Outbounds[node] = body
	}
	poolPath := write("pool.json", pool)
	config := write("xray.json", map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"api": map[string]any{"tag": "api", "services": []string{"RoutingService", "HandlerService"}},
		"dns": live["dns"], "policy": live["policy"], "stats": map[string]any{},
		"inbounds": []any{
			map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}},
			map[string]any{"tag": selector, "listen": "127.0.0.1", "port": proxyPort, "protocol": "http", "settings": map[string]any{}},
		},
		"outbounds": []any{map[string]any{"tag": "speed-fixture-direct", "protocol": "freedom"}},
		"routing": map[string]any{
			"balancers": []any{map[string]any{"tag": selector, "selector": []string{"sb-health-" + shortHash(selector, 8) + "-"}, "strategy": map[string]any{"type": "random"}}},
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"},
				map[string]any{"type": "field", "inboundTag": []string{selector}, "balancerTag": selector},
			},
		},
	})
	process := exec.CommandContext(ctx, "/usr/local/bin/xray", "run", "-config", config)
	process.Stdout, process.Stderr = io.Discard, io.Discard
	if process.Start() != nil {
		t.Fatal("isolated speed core failed to start")
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	for deadline := time.Now().Add(20 * time.Second); ; {
		conn, err := net.DialTimeout("tcp", apiAddress, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatal("isolated speed core API did not become ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	fixture.core = newXraySelectorRuntime(Options{XrayBinary: "/usr/local/bin/xray", XrayAPIServer: apiAddress, HealthPoolFile: poolPath, ProbeURL: fmt.Sprintf("http://127.0.0.1:%d", proxyPort)})
	fixture.core.probeSelector, fixture.core.probeContext = selector, ctx
	if _, _, err := fixture.core.Reload(); err != nil {
		t.Fatal("isolated speed runtime reload failed")
	}
	for _, node := range nodes {
		if fixture.core.Select(selector, node) != nil {
			t.Fatal("isolated speed handler warmup failed")
		}
	}
	return fixture
}

func (fixture *chrSpeedFixture) serve(w http.ResponseWriter, r *http.Request) {
	size, sizeErr := strconv.Atoi(r.URL.Query().Get("bytes"))
	rate, rateErr := strconv.ParseInt(r.URL.Query().Get("bps"), 10, 64)
	if sizeErr != nil || rateErr != nil || size != defaultSpeedBytes || rate < 128_000 || rate > 100_000_000 {
		http.Error(w, "invalid bounded fixture request", http.StatusBadRequest)
		return
	}
	fixture.requests.Add(1)
	active := fixture.inFlight.Add(1)
	defer fixture.inFlight.Add(-1)
	for old := fixture.peak.Load(); active > old && !fixture.peak.CompareAndSwap(old, active); old = fixture.peak.Load() {
	}
	w.Header().Set("Content-Length", strconv.Itoa(size))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	started := time.Now()
	buffer := make([]byte, 16*1024)
	for sent := 0; sent < size; {
		count := minInt(len(buffer), size-sent)
		due := time.Duration(int64(sent+count) * 8 * int64(time.Second) / rate)
		if pause := due - time.Since(started); pause > 0 {
			timer := time.NewTimer(pause)
			select {
			case <-r.Context().Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		written, err := w.Write(buffer[:count])
		fixture.served.Add(int64(written))
		sent += written
		if err != nil {
			return
		}
		w.(http.Flusher).Flush()
	}
}

func (fixture *chrSpeedFixture) sample(t *testing.T, node string, rate int64, work *chrSpeedWork) int64 {
	t.Helper()
	if fixture.core.Select(fixture.core.probeSelectorName(), node) != nil {
		t.Fatal("isolated controlled selector failed")
	}
	started := time.Now()
	target := fmt.Sprintf("%s/?bytes=%d&bps=%d", fixture.endpoint.URL, defaultSpeedBytes, rate)
	speed, err := measureThroughputOverProxy(fixture.core.requestContext(), fixture.core.opts.ProbeURL, target, defaultSpeedBytes, 15*time.Second)
	work.record(speed, err, time.Since(started), defaultSpeedBytes)
	if err != nil || speed <= 0 {
		t.Fatal("controlled bounded HTTP download failed")
	}
	return speed
}

func chrSpeedPolicy(mode string, drop int) effectivePolicySettings {
	p := policySettings(healthPolicy{SpeedDegradationPercent: &drop, SpeedImprovementPercent: 25}, mode)
	p.speedCandidates, p.shortlist = 2, 3
	if mode == "priority" {
		p.speedImprovement = 99
	}
	return p
}

func chrSpeedSeed(baseline int64) (*policyHealthState, time.Time) {
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	now := time.Unix(50_000, 0)
	for i := 5; i > 0; i-- {
		item.SpeedHistory["active"] = append(item.SpeedHistory["active"], speedSample{At: float64(now.Unix() - int64(i*300)), BPS: baseline})
	}
	return item, now
}

func chrSpeedScenario(t *testing.T, fixture *chrSpeedFixture, work *chrSpeedWork, baseline int64, mode string, drop int, unstable bool) {
	t.Helper()
	p := chrSpeedPolicy(mode, drop)
	item, now := chrSpeedSeed(baseline)
	activeSpeed := fixture.sample(t, "active", 6_000_000, work)
	updateSpeedHistory(now, "active", []string{"active", "a", "b"}, []string{"active"}, map[string]int64{"active": activeSpeed}, map[string]string{"active": "ok"}, item, p)
	if drop == 0 {
		item.Recoveries["a"], item.LastProbeAt["a"] = p.recoveryThreshold, float64(now.Unix())
		delay, faster := 400, baseline
		desired, reason := selectDesired(now, mode, "active", []string{"active", "a"}, nil, nil, map[string]*int{"active": &delay, "a": &delay}, map[string]*int64{"active": &activeSpeed, "a": &faster}, nil, map[string]bool{"active": true, "a": true}, map[string]bool{"active": true, "a": true}, item, p)
		if p.speedEnabled || item.SpeedDegradation != nil || desired != "active" || reason != "" {
			t.Fatal("priority zero enabled speed-driven selection")
		}
		t.Log("SPEED_SCENARIO name=priority-disabled switches=0 clock=fake samples_injected=true routine_download_scheduler_not_exercised=true")
		return
	}
	if item.SpeedDegradation == nil {
		t.Fatalf("controlled drop did not cross configured threshold; baseline_bps=%d active_bps=%d", baseline, activeSpeed)
	}
	candidates, switched := []string{}, ""
	for attempt := 0; attempt < speedCyclePairLimit(p); attempt++ {
		nominee := speedDegradationCandidate(now, "active", []string{"a", "b"}, item, p)
		if nominee == "" {
			t.Fatal("controlled investigation lost its bounded nominee")
		}
		gatePlannedOptimization(now, "active", nominee, "speed-degraded", nil, item, p)
		node := item.OptimizationCandidate
		now = time.Unix(int64(item.OptimizationNextAt), 0)
		activeSpeed = fixture.sample(t, "active", 6_000_000, work)
		rate := int64(12_000_000)
		if mode == "priority" {
			rate = 8_000_000
		} else if node == "b" {
			rate = 18_000_000
			if unstable && item.SpeedDegradation.SurveyComplete {
				rate = 4_000_000
			}
		}
		candidateSpeed := fixture.sample(t, node, rate, work)
		speeds := map[string]int64{"active": activeSpeed, node: candidateSpeed}
		updateSpeedHistory(now, "active", []string{"active", "a", "b"}, []string{"active", node}, speeds, map[string]string{"active": "ok", node: "ok"}, item, p)
		comparison := comparePlannedOptimization(now, "active", node, map[string]probeEvidence{"active": successfulEvidence(400), node: successfulEvidence(400)}, speeds, true, true, item, p)
		candidates = append(candidates, node)
		desired, reason := gatePlannedOptimization(now, "active", nominee, "speed-degraded", comparison, item, p)
		if desired != "active" {
			if reason != "speed-degraded" {
				t.Fatal("unexpected controlled switch reason")
			}
			switched = desired
			break
		}
	}
	want := "b"
	if unstable || mode == "priority" {
		want = "a"
	}
	if switched != want || (mode == "best" && (len(candidates) < 4 || candidates[0] != "a" || candidates[1] != "b")) || (mode == "priority" && strings.Join(candidates, ",") != "a,a") {
		t.Fatalf("controlled scenario selected=%q expected=%q sequence=%v", switched, want, candidates)
	}
	recordSpeedDegradationExit(now, item, "active")
	if !speedProbationActive(now, item, "active", p) {
		t.Fatal("speed exit did not establish return probation")
	}
	// A real spike cannot manufacture three spaced confirmations, even after
	// the fake clock passes the minimum probation duration.
	spike := fixture.sample(t, "active", 18_000_000, work)
	updateSpeedHistory(now.Add(31*time.Minute), switched, []string{"active", "a", "b"}, []string{"active"}, map[string]int64{"active": spike}, map[string]string{"active": "ok"}, item, p)
	if !speedProbationActive(now.Add(31*time.Minute), item, "active", p) {
		t.Fatal("one spike cleared return probation")
	}
	if fixture.core.Select(fixture.core.probeSelectorName(), switched) != nil {
		t.Fatal("isolated selected winner could not be applied")
	}
	t.Logf("SPEED_SCENARIO mode=%s drop=%d unstable_reserve=%t switches=1 selected=%s candidate_sequence=%v spike_return_blocked=true clock=fake quality=synthetic400ms samples=real independent_history_seeded=true", mode, drop, unstable, switched, candidates)
}

type chrSpeedWork struct {
	calls, successes, limited, failures int
	requested                           int64
	durations                           []float64
}

func (work *chrSpeedWork) record(speed int64, err error, elapsed time.Duration, size int) {
	work.calls++
	work.requested += int64(size)
	work.durations = append(work.durations, elapsed.Seconds())
	if errors.Is(err, errSpeedWindowComplete) && speed > 0 {
		work.limited++
	} else if err == nil && speed > 0 {
		work.successes++
	} else {
		work.failures++
	}
}

type chrSpeedMetrics struct {
	cpu, memory, panel     []float64
	panelFailures, missing int
}

func chrSpeedUsage() (int64, error) {
	body, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(body))
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "usage_usec" {
			return strconv.ParseInt(fields[i+1], 10, 64)
		}
	}
	return 0, errors.New("missing usage_usec")
}

func chrSpeedMeasurePhase(t *testing.T, ctx context.Context, fixture *chrSpeedFixture, name string, run func(*chrSpeedWork)) {
	t.Helper()
	started := time.Now()
	beforeCPU, err := chrSpeedUsage()
	if err != nil {
		t.Fatal("container CPU accounting unavailable")
	}
	beforeRequests, beforeBytes := fixture.requests.Load(), fixture.served.Load()
	stop, done := make(chan struct{}), make(chan chrSpeedMetrics, 1)
	go func() {
		metrics := chrSpeedMetrics{}
		// The only insecure TLS target is the pinned local health endpoint.
		panel := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
		defer panel.CloseIdleConnections()
		lastAt, lastCPU := started, beforeCPU
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				done <- metrics
				return
			case <-ctx.Done():
				done <- metrics
				return
			case <-ticker.C:
				nextCPU, cpuErr := chrSpeedUsage()
				now := time.Now()
				if cpuErr != nil || nextCPU < lastCPU {
					metrics.missing++
				} else {
					metrics.cpu = append(metrics.cpu, float64(nextCPU-lastCPU)/now.Sub(lastAt).Seconds()/10000/float64(runtime.NumCPU()))
				}
				lastAt, lastCPU = now, nextCPU
				body, memoryErr := os.ReadFile("/sys/fs/cgroup/memory.current")
				memory, parseErr := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
				if memoryErr != nil || parseErr != nil {
					metrics.missing++
				} else {
					metrics.memory = append(metrics.memory, float64(memory))
				}
				request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:9443/api/health/live", nil)
				if requestErr != nil {
					metrics.panelFailures++
					continue
				}
				requestAt := time.Now()
				response, requestErr := panel.Do(request)
				metrics.panel = append(metrics.panel, float64(time.Since(requestAt).Microseconds())/1000)
				if requestErr != nil {
					metrics.panelFailures++
				} else {
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
					_ = response.Body.Close()
					if response.StatusCode != http.StatusOK {
						metrics.panelFailures++
					}
				}
			}
		}
	}()
	work := &chrSpeedWork{}
	defer func() {
		close(stop)
		metrics := <-done
		elapsed := time.Since(started).Seconds()
		afterCPU, cpuErr := chrSpeedUsage()
		cpuAverage := float64(afterCPU-beforeCPU) / elapsed / 10000 / float64(runtime.NumCPU())
		_, cpuP95, cpuPeak := chrSpeedSummary(metrics.cpu)
		memoryMean, memoryP95, memoryPeak := chrSpeedSummary(metrics.memory)
		panelMean, panelP95, panelPeak := chrSpeedSummary(metrics.panel)
		durationMean, durationP95, durationPeak := chrSpeedSummary(work.durations)
		t.Logf("SPEED_RESULT phase=%s calls=%d successes=%d time_limited=%d failures=%d requested_bytes=%d controlled_requests=%d controlled_served_bytes=%d provider_received_bytes=unavailable elapsed_seconds=%.2f download_mean_seconds=%.3f download_p95_seconds=%.3f download_peak_seconds=%.3f cpu_mean_percent=%.2f cpu_p95_percent=%.2f cpu_peak_percent=%.2f cpu_samples=%d memory_mean_bytes=%.0f memory_p95_bytes=%.0f memory_peak_bytes=%.0f panel_mean_ms=%.2f panel_p95_ms=%.2f panel_peak_ms=%.2f panel_failures=%d accounting_errors=%d controlled_peak_concurrency=%d", name, work.calls, work.successes, work.limited, work.failures, work.requested, fixture.requests.Load()-beforeRequests, fixture.served.Load()-beforeBytes, elapsed, durationMean, durationP95, durationPeak, cpuAverage, cpuP95, cpuPeak, len(metrics.cpu), memoryMean, memoryP95, memoryPeak, panelMean, panelP95, panelPeak, metrics.panelFailures, metrics.missing, fixture.peak.Load())
		if cpuErr != nil || metrics.missing != 0 || len(metrics.cpu) == 0 || len(metrics.panel) == 0 {
			t.Error("missing resource/panel evidence")
		}
		if metrics.panelFailures != 0 || fixture.peak.Load() > 1 {
			t.Error("panel health failed or controlled downloads overlapped")
		}
	}()
	run(work)
	if remaining := 10*time.Second - time.Since(started); remaining > 0 {
		chrSpeedWait(t, ctx, remaining)
	}
}

func chrSpeedSummary(values []float64) (mean, p95, peak float64) {
	if len(values) == 0 {
		return 0, 0, 0
	}
	values = append([]float64{}, values...)
	sort.Float64s(values)
	for _, value := range values {
		mean += value
	}
	index := (95*len(values)+99)/100 - 1
	return mean / float64(len(values)), values[index], values[len(values)-1]
}

func chrSpeedWait(t *testing.T, ctx context.Context, duration time.Duration) {
	t.Helper()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("bounded speed test deadline")
	}
}
