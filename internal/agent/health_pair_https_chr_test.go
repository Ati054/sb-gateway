//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type chrPairRequest struct {
	At                   time.Time
	Node, Target, Method string
}
type chrPairTrace struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (trace *chrPairTrace) Write(p []byte) (int, error) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.buffer.Write(p)
}
func (trace *chrPairTrace) String() string {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	return trace.buffer.String()
}

type chrPairOrigin struct {
	mu                             sync.Mutex
	requests                       []chrPairRequest
	sources                        map[string]string
	activeMS, reserveMS, primaryMS atomic.Int64
	failActive, armOutage          atomic.Bool
	failureAt                      atomic.Int64
	qualityInFlight, qualityPeak   atomic.Int64
}

func (origin *chrPairOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodHead {
		current := origin.qualityInFlight.Add(1)
		defer origin.qualityInFlight.Add(-1)
		for previous := origin.qualityPeak.Load(); current > previous && !origin.qualityPeak.CompareAndSwap(previous, current); previous = origin.qualityPeak.Load() {
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	node := origin.sources[host]
	origin.mu.Lock()
	origin.requests = append(origin.requests, chrPairRequest{time.Now(), node, r.URL.Path, r.Method})
	origin.mu.Unlock()
	active := strings.HasSuffix(node, "-active")
	delay := origin.reserveMS.Load()
	if active {
		delay = origin.activeMS.Load()
	}
	if !active && r.Method == http.MethodHead && origin.armOutage.CompareAndSwap(true, false) {
		origin.failureAt.Store(time.Now().UnixNano())
		origin.failActive.Store(true)
		delay = 4500
	}
	if active && origin.failActive.Load() {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	if r.URL.Path == "/gstatic-204" && origin.primaryMS.Load() > 0 {
		delay = origin.primaryMS.Load()
	}
	timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return
	case <-timer.C:
	}
	if r.URL.Path == "/gstatic-204" {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

type chrPairRuntime struct {
	*responsiveSelectorRuntime
	qualityInFlight, qualityPeak atomic.Int64
}

func (runtime *chrPairRuntime) Probe(node string) probeEvidence {
	current := runtime.qualityInFlight.Add(1)
	defer runtime.qualityInFlight.Add(-1)
	for previous := runtime.qualityPeak.Load(); current > previous && !runtime.qualityPeak.CompareAndSwap(previous, current); previous = runtime.qualityPeak.Load() {
	}
	return runtime.responsiveSelectorRuntime.Probe(node)
}

// The controlled reserve proves that the isolated underlay remains reachable.
func (*chrPairRuntime) UnderlayStatus() underlayEvidence {
	return underlayEvidence{Known: true, WANOK: true, DNSOK: true}
}

// Opt-in real-time acceptance against an isolated copy of the image's core.
// No live gateway selectors, provider definitions or filesystem state are used.
func TestCHRPairedHTTPSRuntime(t *testing.T) {
	if os.Getenv("SB_CHR_PAIR_ACCEPTANCE") != "1" {
		t.Skip("opt-in real-time CHR HTTPS acceptance")
	}
	binary := os.Getenv("SB_TEST_XRAY")
	if binary != "/usr/local/bin/xray" {
		t.Fatal("use the installed image core")
	}
	scenario := os.Getenv("SB_CHR_PAIR_SCENARIO")
	if scenario != "healthy" && scenario != "degradation" && scenario != "slow" && scenario != "outage" && scenario != "smoke" && scenario != "callback" {
		t.Fatal("unknown acceptance scenario")
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	var traces chrPairTrace
	oldWriter := log.Writer()
	log.SetOutput(&traces)
	defer log.SetOutput(oldWriter)
	t.Setenv("SB_HEALTH_STAGE_TRACE", "1")
	origin := &chrPairOrigin{sources: map[string]string{}}
	origin.activeMS.Store(75)
	origin.reserveMS.Store(125)
	server := httptest.NewTLSServer(origin)
	defer server.Close()
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	t.Setenv("SSL_CERT_DIR", root)
	previousTargets := append([]struct {
		label, url string
		status     int
	}{}, healthTargets...)
	defer func() { healthTargets = previousTargets }()
	for i := range healthTargets {
		healthTargets[i].url = server.URL + "/" + healthTargets[i].label
	}
	port := func() int {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	apiPort, fastPort, bgPort := port(), port(), port()
	api := fmt.Sprintf("127.0.0.1:%d", apiPort)
	pool := healthPool{Version: 4, ProbeBudget: 1, ProbeLanes: 1, Policies: map[string][]string{}, HealthPolicies: map[string]healthPolicyContract{}, Outbounds: map[string]json.RawMessage{}}
	if scenario == "callback" {
		pool.ProbeBudget = 2
		origin.activeMS.Store(1300)
	}
	outbounds := []any{map[string]any{"tag": "block", "protocol": "blackhole"}}
	balancers := []any{}
	policyCount := 1
	if scenario == "healthy" || scenario == "smoke" || scenario == "callback" {
		policyCount = 3
	}
	nodes := []string{}
	for i := 0; i < policyCount; i++ {
		id := fmt.Sprintf("route-%d", i)
		members := []string{id + "-active", id + "-reserve"}
		contract := healthPolicyContract{Mode: "best", Candidates: members, Nodes: map[string]healthNode{}, Policy: healthPolicy{ActiveCheckSeconds: 60, ActiveLivenessSeconds: 3, ProbeBatchSize: 1, SwitchImprovementMS: 200, LatencyMeasurement: latencyMeasurement}}
		if scenario == "callback" {
			contract.Policy.ProbeBatchSize = 2
		}
		if scenario == "degradation" || scenario == "slow" {
			contract.Policy.ActiveLivenessSeconds = 30
		}
		for j, node := range members {
			source := fmt.Sprintf("127.0.0.%d", 2+i*2+j)
			origin.sources[source] = node
			outbounds = append(outbounds, map[string]any{"tag": node, "protocol": "freedom", "sendThrough": source})
			contract.Nodes[node] = healthNode{Label: node, Fingerprint: "isolated-" + node}
			nodes = append(nodes, node)
		}
		pool.Policies[id] = members
		pool.HealthPolicies[id] = contract
		balancers = append(balancers, map[string]any{"tag": id, "selector": members, "strategy": map[string]any{"type": "random"}})
	}
	pool.BaseOutboundTags = append([]string{"block"}, nodes...)
	inbounds := []any{map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}}}
	rules := []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"}}
	for _, lane := range []struct {
		tag  string
		port int
	}{{"outbound-health-probe", fastPort}, {"outbound-health-background", bgPort}} {
		pool.Policies[lane.tag] = nodes
		inbounds = append(inbounds, map[string]any{"tag": lane.tag, "listen": "127.0.0.1", "port": lane.port, "protocol": "http", "settings": map[string]any{}})
		balancers = append(balancers, map[string]any{"tag": lane.tag, "selector": nodes, "strategy": map[string]any{"type": "random"}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{lane.tag}, "balancerTag": lane.tag})
	}
	write := func(name string, value any) string {
		body, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		p := filepath.Join(root, name)
		if e = os.WriteFile(p, body, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	poolPath := write("pool.json", pool)
	config := write("xray.json", map[string]any{"log": map[string]any{"loglevel": "none"}, "api": map[string]any{"tag": "api", "services": []string{"RoutingService", "HandlerService"}}, "inbounds": inbounds, "outbounds": outbounds, "routing": map[string]any{"balancers": balancers, "rules": rules}})
	core := exec.CommandContext(ctx, binary, "run", "-config", config)
	var coreLog bytes.Buffer
	core.Stdout, core.Stderr = &coreLog, &coreLog
	if err := core.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = core.Process.Kill(); _ = core.Wait() }()
	control, err := newXrayControlClient(api)
	if err != nil {
		t.Fatal(err)
	}
	defer control.close()
	for until := time.Now().Add(20 * time.Second); ; {
		inventory, e := control.outbounds(ctx)
		if e == nil && inventory[nodes[0]] {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("isolated core unavailable: %v %s", e, coreLog.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	newLane := func(port int, tag string) *xraySelectorRuntime {
		r := newXraySelectorRuntime(Options{XrayBinary: binary, XrayAPIServer: api, HealthPoolFile: poolPath, ProbeURL: fmt.Sprintf("http://127.0.0.1:%d", port)})
		r.control = control
		r.probeSelector = tag
		if _, _, e := r.Reload(); e != nil {
			t.Fatal(e)
		}
		return r
	}
	primary, bg := newLane(fastPort, ""), newLane(bgPort, "outbound-health-background")
	responsive := &responsiveSelectorRuntime{selectorRuntime: primary, background: bg, backgrounds: []*xraySelectorRuntime{bg}, ctx: ctx, generationPaths: []string{poolPath}}
	if _, _, err := responsive.Reload(); err != nil {
		t.Fatal(err)
	}
	measuredRuntime := &chrPairRuntime{responsiveSelectorRuntime: responsive}
	controller := &healthController{opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: measuredRuntime, state: healthState{}, stateLoaded: true, warmStarted: map[string]bool{}}
	var events []healthEvent
	controller.eventSink = func(e healthEvent) { events = append(events, e) }
	for id, contract := range pool.HealthPolicies {
		item := newPolicyHealthState()
		item.Mode, item.LatencyMeasurement = "best", latencyMeasurement
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = contract.Candidates[0], contract.Candidates[0], true
		item.CandidateSignature = strings.Join(contract.Candidates, "\n")
		item.CandidateNodes = contract.Nodes
		for _, node := range contract.Candidates {
			for i := 0; i < 3; i++ {
				e := bg.Probe(node)
				if !e.OK || e.DelayMS == nil {
					t.Fatalf("controlled TLS warmup failed for %s: %v", node, e.Failure)
				}
				item.Samples[node] = append(item.Samples[node], healthSample{At: float64(time.Now().Unix()), ObservedAt: qualityObservationAt(time.Now(), e), OK: true, DelayMS: e.DelayMS})
			}
			item.LastProbeAt[node] = float64(time.Now().Add(-time.Minute).Unix())
			item.Recoveries[node] = 3
			item.QualityOK = map[string]bool{}
			item.AvailabilityOK = map[string]bool{}
		}
		for _, node := range contract.Candidates {
			item.QualityOK[node], item.AvailabilityOK[node] = true, true
		}
		controller.state[id], controller.warmStarted[id] = item, true
		if err := primary.Select(id, item.Selected); err != nil {
			t.Fatal(err)
		}
	}
	callbackDelayed := false
	responsive.check = func() error {
		if scenario == "callback" && !callbackDelayed {
			callbackDelayed = true
			time.Sleep(11 * time.Second)
		}
		return controller.checkDuringProbe(time.Now(), pool)
	}
	phaseStart := time.Now()
	duration := 125 * time.Second
	if scenario == "smoke" {
		duration = 15 * time.Second
	}
	if scenario == "callback" {
		duration = 25 * time.Second
	}
	if scenario == "degradation" || scenario == "outage" || scenario == "slow" {
		origin.activeMS.Store(900)
		origin.reserveMS.Store(75)
		duration = 210 * time.Second
	}
	if scenario == "slow" {
		duration = 150 * time.Second
	}
	origin.mu.Lock()
	origin.requests = nil
	origin.mu.Unlock()
	initialCPU := chrPairCPU()
	phaseEnd := phaseStart.Add(duration)
	var confirmations []optimizationComparison
	var confirmationSeconds []float64
	previousConfirmation := 0
	paused, skewSeen, outageArmed := false, false, false
	cycles := 0
	for time.Now().Before(phaseEnd) && ctx.Err() == nil {
		cycles++
		if cycles > 600 {
			t.Fatal("unexpected tight controller loop")
		}
		if err := controller.Tick(time.Now()); err != nil && !errors.Is(err, errHealthYield) {
			t.Fatal(err)
		}
		item := controller.state["route-0"]
		if item.OptimizationChecks > previousConfirmation && item.OptimizationLastResult != nil {
			confirmations = append(confirmations, *item.OptimizationLastResult)
			confirmationSeconds = append(confirmationSeconds, time.Since(phaseStart).Seconds())
		}
		previousConfirmation = item.OptimizationChecks
		if item.Selected == "route-0-reserve" {
			if scenario == "degradation" || scenario == "outage" {
				break
			}
		}
		comparison := item.OptimizationLastResult
		if scenario == "degradation" && len(events) > 0 && events[len(events)-1].Event == "switch" && events[len(events)-1].Comparison != nil {
			break
		}
		if scenario == "slow" && comparison != nil && comparison.Reason == "pair-skew" {
			skewSeen = true
			if controller.nextIntervalAt(time.Now()) <= 0 {
				t.Fatal("completed overdue pair restarted immediately")
			}
			origin.primaryMS.Store(6500)
		}
		if (scenario == "slow" && !paused) || (scenario == "outage" && !outageArmed) {
			if comparison != nil && item.OptimizationCandidate != "" {
				_, a := latestQualityObservation(item, item.Selected)
				_, b := latestQualityObservation(item, item.OptimizationCandidate)
				if a > comparison.ActiveSampleAt && b <= comparison.CandidateSampleAt {
					if scenario == "slow" {
						paused = true
						time.Sleep(11 * time.Second)
					} else {
						outageArmed = true
						origin.armOutage.Store(true)
					}
				}
			}
		}
		wait := controller.nextIntervalAt(time.Now())
		if until := time.Until(phaseEnd); wait > until {
			wait = until
		}
		if !waitForHealthWake(ctx, wait, []string{poolPath}, 100*time.Millisecond, nil, nil) {
			break
		}
	}
	elapsed := time.Since(phaseStart).Seconds()
	origin.mu.Lock()
	received := append([]chrPairRequest{}, origin.requests...)
	origin.mu.Unlock()
	attempts := map[string]int{}
	minutes := map[int]int{}
	quality := map[string][]float64{}
	getCount := 0
	var attemptTimes []float64
	for _, r := range received {
		if r.Method == http.MethodHead {
			quality[r.Node] = append(quality[r.Node], r.At.Sub(phaseStart).Seconds())
		} else {
			getCount++
		}
	}
	for _, line := range strings.Split(traces.String(), "\n") {
		_, body, ok := strings.Cut(line, "agent: health-stage ")
		if !ok {
			continue
		}
		var r healthStageRecord
		if json.Unmarshal([]byte(body), &r) != nil || r.Stage != "https" {
			continue
		}
		at, e := time.Parse(time.RFC3339Nano, r.StartedAt)
		if e != nil || at.Before(phaseStart) {
			continue
		}
		attempts[r.Target]++
		minutes[int(at.Sub(phaseStart)/time.Minute)]++
		attemptTimes = append(attemptTimes, at.Sub(phaseStart).Seconds())
	}
	sort.Float64s(attemptTimes)
	maxRolling, left := 0, 0
	for right, at := range attemptTimes {
		for at-attemptTimes[left] >= 60 {
			left++
		}
		if size := right - left + 1; size > maxRolling {
			maxRolling = size
		}
	}
	switches := []healthEvent{}
	for _, e := range events {
		if e.Event == "switch" {
			switches = append(switches, e)
		}
	}
	report := map[string]any{"scenario": scenario, "elapsed_seconds": elapsed, "cycles": cycles, "https_attempts_by_target": attempts, "https_attempts_by_minute": minutes, "origin_received": len(received), "availability_gets": getCount, "quality_heads_by_node": quality, "cpu_core_percent": 100 * float64(chrPairCPU()-initialCPU) / 1e6 / elapsed, "switches": switches, "first_confirmation_seconds": confirmationSeconds, "confirmations": confirmations, "scheduler_pause_seconds": 0, "overdue_pair_seen": skewSeen}
	report["max_https_attempts_in_rolling_60_seconds"], report["quality_concurrency_peak"] = maxRolling, measuredRuntime.qualityPeak.Load()
	report["origin_quality_concurrency_peak"] = origin.qualityPeak.Load()
	if measuredRuntime.qualityPeak.Load() > 1 || origin.qualityPeak.Load() > 1 {
		t.Fatal("one-slot quality concurrency exceeded")
	}
	if len(switches) > 0 {
		report["switch_after_seconds"] = elapsed
	}
	if paused {
		report["scheduler_pause_seconds"] = 11
	}
	if failureAt := origin.failureAt.Load(); failureAt > 0 {
		report["outage_to_switch_seconds"] = time.Since(time.Unix(0, failureAt)).Seconds()
		report["failure_during_pair"] = outageArmed
	}
	if path := os.Getenv("SB_CHR_PAIR_REPORT"); path != "" {
		if !strings.HasPrefix(path, "/data/sb-chr-pair-") {
			t.Fatal("unsafe report path")
		}
		body, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	body, _ := json.Marshal(report)
	t.Log(string(body))
	switch scenario {
	case "callback":
		if !callbackDelayed || origin.qualityPeak.Load() != 1 {
			t.Fatal("single-lane callback scenario was not exercised")
		}
		for id, contract := range pool.HealthPolicies {
			item := controller.state[id]
			_, activeAt := latestQualityObservation(item, contract.Candidates[0])
			_, reserveAt := latestQualityObservation(item, contract.Candidates[1])
			if activeAt < float64(phaseStart.UnixNano())/1e9 || reserveAt < float64(phaseStart.UnixNano())/1e9 || activeAt-reserveAt > 10 || reserveAt-activeAt > 10 {
				t.Fatalf("single-lane pair delayed behind the active callback for %s: active=%f reserve=%f", id, activeAt, reserveAt)
			}
		}
	case "healthy":
		for _, node := range nodes {
			if len(quality[node]) == 0 {
				t.Fatalf("node starved: %s", node)
			}
			last := float64(0)
			for _, at := range quality[node] {
				if at-last > 100 {
					t.Fatalf("quality gap too long: %s %fs", node, at-last)
				}
				last = at
			}
			if elapsed-last > 100 {
				t.Fatalf("node stopped receiving quality checks: %s", node)
			}
		}
		if len(switches) != 0 {
			t.Fatal("stable healthy origins caused switching")
		}
	case "degradation":
		if controller.state["route-0"].Selected != "route-0-reserve" || len(switches) != 1 || switches[0].Reason != "meaningfully-faster" {
			t.Fatal("persistent degradation was not confirmed")
		}
		if len(confirmations) < 1 || switches[0].Comparison == nil {
			t.Fatal("missing independent pair evidence")
		}
		first, last := confirmations[0], *switches[0].Comparison
		for _, pair := range []optimizationComparison{first, last} {
			delta := pair.ActiveSampleAt - pair.CandidateSampleAt
			if delta > 10 || delta < -10 {
				t.Fatal("accepted pair exceeded timing window")
			}
		}
		if last.ActiveSampleAt <= first.ActiveSampleAt || last.CandidateSampleAt <= first.CandidateSampleAt {
			t.Fatal("confirmation reused measurements")
		}
	case "slow":
		if !paused || !skewSeen {
			t.Fatal("controlled scheduling pause did not exercise an overdue pair")
		}
		if len(switches) != 0 {
			t.Fatal("unqualified slow measurements caused switching")
		}
	case "outage":
		if !outageArmed || origin.failureAt.Load() == 0 || len(switches) != 1 || switches[0].Reason != "active-unavailable" {
			t.Fatal("active outage did not preempt the planned pair")
		}
		if time.Since(time.Unix(0, origin.failureAt.Load())) > 30*time.Second {
			t.Fatal("emergency failover waited too long")
		}
	}
}

func chrPairCPU() int64 {
	body, _ := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	fields := strings.Fields(string(body))
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "usage_usec" {
			v, _ := strconv.ParseInt(fields[i+1], 10, 64)
			return v
		}
	}
	return 0
}
