//go:build linux

package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in CHR benchmark. Copies endpoints into a separate loopback-only core;
// never changes the gateway's config, process or live selectors. No credentials
// or core logs leave the container. CPU includes the running gateway background.
func TestCHRQualityConcurrencyMatrix(t *testing.T) {
	chrQualityConcurrency(t, []int{2, 5, 6, 7, 8, 9, 10, 2})
}

func TestCHRQualityConcurrencyFiveConfirmation(t *testing.T) {
	chrQualityConcurrency(t, []int{2, 5, 5, 2})
}

func chrQualityConcurrency(t *testing.T, counts []int) {
	if os.Getenv("SB_CHR_CONCURRENCY_MATRIX") != "1" {
		t.Skip("opt-in pinned CHR benchmark")
	}
	binary := os.Getenv("SB_TEST_XRAY")
	if binary != "/usr/local/bin/xray" {
		t.Fatal("expected the container's pinned core")
	}
	var source healthPool
	if readJSON("/config/generated/urltest-pool.json", &source) != nil {
		t.Fatal("cannot read local pool")
	}
	var state healthState
	if readJSON("/state/control-plane/selector-health.json", &state) != nil {
		t.Fatal("cannot read local health")
	}
	var live map[string]any
	if readJSON("/config/generated/xray.json", &live) != nil {
		t.Fatal("cannot read local core policy")
	}
	nodes := []string{}
	for _, node := range sortedKeys(source.Outbounds) {
		for _, policy := range state {
			if policy.AvailabilityOK[node] && policy.QualityOK[node] {
				nodes = append(nodes, node)
				break
			}
		}
	}
	if len(nodes) < 10 {
		t.Fatal("matrix requires ten distinct reachable provider endpoints")
	}
	root := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if os.WriteFile(path, body, 0600) != nil {
			t.Fatal("cannot write private fixture")
		}
		return path
	}
	usedPorts := map[int]bool{}
	port := func() int {
		t.Helper()
		for {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			value := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
			if !usedPorts[value] {
				usedPorts[value] = true
				return value
			}
		}
	}
	apiPort := port()
	apiAddress := fmt.Sprintf("127.0.0.1:%d", apiPort)
	inbounds := []any{map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}}}
	rules := []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"}}
	balancers := []any{}
	outbounds := []any{map[string]any{"tag": "benchmark-direct", "protocol": "freedom"}}
	pool := healthPool{Version: 4, BaseOutboundTags: []string{"benchmark-direct"}, Policies: map[string][]string{}, Outbounds: map[string]json.RawMessage{}}
	for _, node := range nodes {
		pool.Outbounds[node] = source.Outbounds[node]
	}
	ports := []int{}
	for index := 1; index <= 10; index++ {
		tag := "outbound-health-background"
		if index > 1 {
			tag = fmt.Sprintf("outbound-health-background-%d", index)
		}
		p := port()
		ports = append(ports, p)
		inbounds = append(inbounds, map[string]any{"tag": tag, "listen": "127.0.0.1", "port": p, "protocol": "http", "settings": map[string]any{}})
		balancers = append(balancers, map[string]any{"tag": tag, "selector": []string{"sb-health-" + shortHash(tag, 8) + "-"}, "strategy": map[string]any{"type": "random"}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{tag}, "balancerTag": tag})
		pool.Policies[tag] = nodes
	}
	poolPath := write("pool.json", pool)
	config := write("xray.json", map[string]any{"log": map[string]any{"loglevel": "none"}, "api": map[string]any{"tag": "api", "services": []string{"RoutingService", "HandlerService"}}, "dns": live["dns"], "policy": live["policy"], "stats": map[string]any{}, "inbounds": inbounds, "outbounds": outbounds, "routing": map[string]any{"balancers": balancers, "rules": rules}})
	ctx, cancel := context.WithTimeout(context.Background(), 14*time.Minute)
	defer cancel()
	process := exec.CommandContext(ctx, binary, "run", "-config", config)
	var coreOutput bytes.Buffer
	process.Stdout, process.Stderr = &coreOutput, &coreOutput
	if process.Start() != nil {
		t.Fatal("isolated core start failed")
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	for deadline := time.Now().Add(20 * time.Second); ; {
		conn, err := net.DialTimeout("tcp", apiAddress, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			_ = process.Process.Kill()
			_ = process.Wait()
			diagnostics := []string{}
			for _, label := range []string{"dns", "routing", "balancer", "selector", "outbound", "geosite", "geoip", "file", "not found", "no such", "invalid", "failed", "empty", "permission", "address already in use"} {
				if strings.Contains(strings.ToLower(coreOutput.String()), label) {
					diagnostics = append(diagnostics, label)
				}
			}
			// Redact every fixture string before reporting the startup diagnostic.
			var fixture any
			_ = readJSON(config, &fixture)
			values := []string{config, root}
			var collect func(any)
			collect = func(value any) {
				switch typed := value.(type) {
				case string:
					if typed != "" {
						values = append(values, typed)
					}
				case map[string]any:
					for _, child := range typed {
						collect(child)
					}
				case []any:
					for _, child := range typed {
						collect(child)
					}
				}
			}
			collect(fixture)
			sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
			diagnostic := coreOutput.String()
			for _, value := range values {
				diagnostic = strings.ReplaceAll(diagnostic, value, "[redacted]")
			}
			if len(diagnostic) > 2000 {
				diagnostic = diagnostic[len(diagnostic)-2000:]
			}
			t.Fatalf("isolated core did not become ready; safe error labels=%v redacted_error=%s", diagnostics, diagnostic)
		}
		time.Sleep(100 * time.Millisecond)
	}
	lanes := []*xraySelectorRuntime{}
	for index, p := range ports {
		lane := newXraySelectorRuntime(Options{XrayBinary: binary, XrayAPIServer: apiAddress, HealthPoolFile: poolPath, ProbeURL: fmt.Sprintf("http://127.0.0.1:%d", p)})
		lane.probeSelector = "outbound-health-background"
		if index > 0 {
			lane.probeSelector = fmt.Sprintf("outbound-health-background-%d", index+1)
		}
		lanes = append(lanes, lane)
	}
	responsive := &responsiveSelectorRuntime{selectorRuntime: lanes[0], background: lanes[0], backgrounds: lanes, ctx: ctx, generationPaths: []string{poolPath}}
	if _, _, err := responsive.Reload(); err != nil {
		t.Fatal("isolated runtime reload failed")
	}
	for _, lane := range lanes {
		if lane.Select(lane.probeSelector, nodes[0]) != nil {
			t.Fatal("isolated API selector warmup failed")
		}
	}
	// Warm all handlers before the matrix, so startup is not credited to count=2.
	responsive.backgrounds = lanes[:2]
	warm := responsive.ProbeQualityParallel(nodes)
	usable := []string{}
	classes := map[probeFailureClass]int{}
	preprobeFailures := 0
	for _, node := range nodes {
		if warm[node].OK {
			usable = append(usable, node)
		} else {
			classes[warm[node].Failure]++
			if len(warm[node].Targets) == 0 {
				preprobeFailures++
			}
		}
	}
	if len(usable) < 10 {
		t.Fatalf("only %d endpoints passed fresh warmup; need ten; failure classes=%v preprobe_failures=%d interrupted=%t", len(usable), classes, preprobeFailures, takeProbeInterruption(responsive) != nil)
	}
	nodes = usable[:10]
	usage := func() int64 {
		t.Helper()
		body, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
		if err != nil {
			t.Fatal("missing container CPU accounting")
		}
		fields := strings.Fields(string(body))
		for index := 0; index+1 < len(fields); index += 2 {
			if fields[index] == "usage_usec" {
				value, _ := strconv.ParseInt(fields[index+1], 10, 64)
				return value
			}
		}
		t.Fatal("missing usage_usec")
		return 0
	}
	t.Logf("MATRIX_ENV cpus=%d endpoints=10 rounds=3 period_seconds=20 dynamic_handlers=true background_cli_slots=%d; fixed inventory and request count", runtime.NumCPU(), cap(xrayProbeCommandSlots))
	panel := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer panel.CloseIdleConnections()
	for run, count := range counts {
		started, cpuStart := time.Now(), usage()
		cpuSamples, durations := []float64{}, []float64{}
		peakMemory := int64(0)
		panelTimes := []float64{}
		panelFailures := 0
		stop, metrics := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(metrics)
			lastAt, lastCPU := time.Now(), usage()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					current := usage()
					now := time.Now()
					cpuSamples = append(cpuSamples, float64(current-lastCPU)/now.Sub(lastAt).Seconds()/10000/float64(runtime.NumCPU()))
					lastAt, lastCPU = now, current
					body, _ := os.ReadFile("/sys/fs/cgroup/memory.current")
					memory, _ := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
					if memory > peakMemory {
						peakMemory = memory
					}
					requestAt := time.Now()
					response, err := panel.Get("https://127.0.0.1:9443/api/health/live")
					panelTimes = append(panelTimes, float64(time.Since(requestAt).Microseconds())/1000)
					if err != nil {
						panelFailures++
					} else {
						if response.StatusCode != 200 {
							panelFailures++
						}
						_ = response.Body.Close()
					}
				}
			}
		}()
		successes, probes, preprobe, httpsFailures := 0, 0, 0, 0
		responsive.backgrounds = lanes[:count]
		for round := 0; round < 3; round++ {
			roundStart := time.Now()
			// Ten nodes at every setting; only concurrent worker count differs.
			for _, evidence := range responsive.ProbeQualityParallel(nodes) {
				probes++
				if evidence.OK {
					successes++
				} else if len(evidence.Targets) == 0 {
					preprobe++
				} else {
					httpsFailures++
				}
			}
			if takeProbeInterruption(responsive) != nil {
				close(stop)
				<-metrics
				t.Fatal("matrix interrupted")
			}
			durations = append(durations, time.Since(roundStart).Seconds())
			if wait := time.Duration(round+1)*20*time.Second - time.Since(started); wait > 0 {
				time.Sleep(wait)
			}
		}
		close(stop)
		<-metrics
		elapsed := time.Since(started).Seconds()
		avg := float64(usage()-cpuStart) / elapsed / 10000 / float64(runtime.NumCPU())
		sort.Float64s(cpuSamples)
		peak, p95 := float64(0), float64(0)
		if len(cpuSamples) > 0 {
			peak = cpuSamples[len(cpuSamples)-1]
			p95 = cpuSamples[(len(cpuSamples)-1)*95/100]
		}
		sort.Float64s(durations)
		sort.Float64s(panelTimes)
		panelP95 := float64(0)
		if len(panelTimes) > 0 {
			panelP95 = panelTimes[(len(panelTimes)-1)*95/100]
		}
		t.Logf("MATRIX_RESULT run=%d count=%d probes=%d successes=%d preprobe_failures=%d https_failures=%d cpu_avg_percent=%.2f cpu_p95_percent=%.2f cpu_peak_percent=%.2f memory_peak_bytes=%d round_median_seconds=%.3f round_max_seconds=%.3f elapsed_seconds=%.1f panel_failures=%d panel_p95_ms=%.1f", run, count, probes, successes, preprobe, httpsFailures, avg, p95, peak, peakMemory, durations[len(durations)/2], durations[len(durations)-1], elapsed, panelFailures, panelP95)
		if probes != 30 || successes != 30 {
			t.Errorf("count=%d incomplete successful workload", count)
		}
		if panelFailures > 0 {
			t.Errorf("count=%d panel health failed", count)
		}
		if ctx.Err() != nil {
			t.Fatal("matrix deadline")
		}
	}
}
