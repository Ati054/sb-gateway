//go:build linux

package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
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
	mu                                  sync.Mutex
	requests                            []chrPairRequest
	sources                             map[string]string
	activeMS, reserveMS, primaryMS      atomic.Int64
	failActive, armOutage               atomic.Bool
	failPrimaryActive, rejectActiveHEAD atomic.Bool
	failureAt                           atomic.Int64
	slowPrimary, fastest                map[string]bool
	slowEnabled                         atomic.Bool
	qualityInFlight, qualityPeak        atomic.Int64
	commonQueueSince                    atomic.Int64
	healthConnections, bulkConnections  atomic.Int64
	bulkDelayMS                         int
}

type chrPairConnectionKey struct{}
type chrPairConnection struct{ first sync.Once }

func (origin *chrPairOrigin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if connection, ok := r.Context().Value(chrPairConnectionKey{}).(*chrPairConnection); ok {
		connection.first.Do(func() {
			if r.URL.Path == "/cpu-bulk" {
				origin.bulkConnections.Add(1)
			} else {
				origin.healthConnections.Add(1)
			}
		})
	}
	if r.URL.Path == "/cpu-bulk" {
		// A bounded synthetic download shares the selected VLESS path without
		// adding its requests to the health-probe counters.
		w.Header().Set("Content-Length", strconv.Itoa(2<<20))
		chunk := make([]byte, 32<<10)
		for sent := 0; sent < 2<<20; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			timer := time.NewTimer(time.Duration(origin.bulkDelayMS) * time.Millisecond)
			select {
			case <-r.Context().Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		return
	}
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
	if active && ((origin.failPrimaryActive.Load() && r.URL.Path == "/gstatic-204") ||
		(origin.rejectActiveHEAD.Load() && r.Method == http.MethodHead)) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	delay := origin.reserveMS.Load()
	if active {
		delay = origin.activeMS.Load()
	}
	if origin.fastest[node] {
		delay = 75
	}
	if origin.slowEnabled.Load() && origin.slowPrimary[node] && r.Method == http.MethodHead && r.URL.Path == "/gstatic-204" {
		delay = 6500
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
	if since := origin.commonQueueSince.Load(); since > 0 && r.Method == http.MethodHead {
		phase := time.Since(time.Unix(0, since)).Milliseconds() % 6400
		if phase < 2500 {
			delay += 1200 * (2500 - phase) / 2500
		}
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

type chrPairWaveSample struct {
	Node       string    `json:"node"`
	Wave       uint64    `json:"wave"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	OK         bool      `json:"ok"`
}

type chrPairRuntime struct {
	*responsiveSelectorRuntime
	qualityInFlight, qualityPeak atomic.Int64
	waves                        [][]chrPairWaveSample
}

func (runtime *chrPairRuntime) Probe(node string) probeEvidence {
	defer runtime.enterQuality()()
	return runtime.responsiveSelectorRuntime.Probe(node)
}

func (runtime *chrPairRuntime) ProbeWithQualityRequest(node string, request qualityProbeRequest) probeEvidence {
	defer runtime.enterQuality()()
	return runtime.responsiveSelectorRuntime.ProbeWithQualityRequest(node, request)
}

func (runtime *chrPairRuntime) enterQuality() func() {
	current := runtime.qualityInFlight.Add(1)
	for previous := runtime.qualityPeak.Load(); current > previous && !runtime.qualityPeak.CompareAndSwap(previous, current); previous = runtime.qualityPeak.Load() {
	}
	return func() { runtime.qualityInFlight.Add(-1) }
}

func (runtime *chrPairRuntime) ProbeQualityParallel(nodes []string) map[string]probeEvidence {
	return runtime.ProbeQualityParallelWithMeasurement(nodes, qualityMeasurementCold)
}

func (runtime *chrPairRuntime) ProbeQualityParallelWithMeasurement(nodes []string, measurement qualityMeasurement) map[string]probeEvidence {
	result := runtime.responsiveSelectorRuntime.ProbeQualityParallelWithMeasurement(nodes, measurement)
	wave := make([]chrPairWaveSample, 0, len(nodes))
	for _, node := range nodes {
		e := result[node]
		if quality := e.planningQuality(); isPairedPlanningMeasurement(measurement) && quality != nil {
			wave = append(wave, chrPairWaveSample{node, quality.Wave, quality.StartedAt, quality.ObservedAt, e.OK && validPlanningQuality(quality, measurement)})
		} else {
			wave = append(wave, chrPairWaveSample{node, e.QualityWave, e.QualityStartedAt, e.ObservedAt, e.OK && !e.QualityUnmeasured})
		}
	}
	runtime.waves = append(runtime.waves, wave)
	return result
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
	planningOptions := Options{URLTestWarmCompare: os.Getenv("SB_CHR_PAIR_WARM") == "1",
		URLTestPlanningMode: URLTestPlanningMode(os.Getenv("SB_CHR_PAIR_PLANNING_MODE"))}
	if err := planningOptions.validatePlanningMode(); err != nil {
		t.Fatal(err)
	}
	planningMeasurement := planningOptions.planningMeasurement()
	warmCompare := planningMeasurement == qualityMeasurementWarm
	pairedCompare := isPairedPlanningMeasurement(planningMeasurement)
	vlessTransport := os.Getenv("SB_CHR_PAIR_VLESS") == "1"
	cpuComparison := scenario == "cpu"
	vlessVariant := os.Getenv("SB_CHR_PAIR_VLESS_VARIANT")
	if vlessVariant == "" {
		vlessVariant = "ws"
	}
	if vlessVariant != "ws" && (vlessVariant != "tls-vision" || !cpuComparison || !vlessTransport) {
		t.Fatal("CPU VLESS variant must be ws or tls-vision")
	}
	vlessVision := vlessVariant == "tls-vision"
	dynamicHandlers := cpuComparison && os.Getenv("SB_CHR_PAIR_CPU_DYNAMIC") == "1"
	if dynamicHandlers && !vlessTransport {
		t.Fatal("dynamic CPU comparison requires VLESS")
	}
	monitorEnabled := !cpuComparison || os.Getenv("SB_CHR_PAIR_CPU_MONITOR") != "0"
	trafficClients, bulkDelayMS := 1, 20
	if cpuComparison {
		if value := os.Getenv("SB_CHR_PAIR_CPU_CLIENTS"); value != "" {
			trafficClients, _ = strconv.Atoi(value)
		}
		if value := os.Getenv("SB_CHR_PAIR_CPU_CHUNK_DELAY_MS"); value != "" {
			bulkDelayMS, _ = strconv.Atoi(value)
		}
		if trafficClients < 1 || trafficClients > 16 || bulkDelayMS < 1 || bulkDelayMS > 250 {
			t.Fatal("CPU comparison requires 1..16 clients and 1..250 ms chunk pacing")
		}
	}
	inventory := scenario == "inventory" || cpuComparison
	nodeCount := 2
	if inventory {
		nodeCount, _ = strconv.Atoi(os.Getenv("SB_CHR_PAIR_NODES"))
		if !pairedCompare && !cpuComparison || nodeCount != 7 && nodeCount != 10 && nodeCount != 24 {
			t.Fatal("paired inventory requires 7, 10 or 24 nodes")
		}
	}
	if !inventory && scenario != "cohort-spikes" && scenario != "cohort-degradation" && scenario != "healthy" && scenario != "degradation" && scenario != "slow" && scenario != "outage" && scenario != "smoke" && scenario != "callback" && scenario != "soft-six" && scenario != "soft-six-priority" && scenario != "head-get" {
		t.Fatal("unknown acceptance scenario")
	}
	softSix := scenario == "soft-six" || scenario == "soft-six-priority"
	cohort := scenario == "cohort-spikes" || scenario == "cohort-degradation"
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Minute)
	defer cancel()
	var traces chrPairTrace
	oldWriter := log.Writer()
	log.SetOutput(&traces)
	defer log.SetOutput(oldWriter)
	t.Setenv("SB_HEALTH_STAGE_TRACE", "1")
	origin := &chrPairOrigin{sources: map[string]string{}, bulkDelayMS: bulkDelayMS}
	origin.activeMS.Store(75)
	origin.reserveMS.Store(125)
	if cohort {
		origin.reserveMS.Store(75)
	}
	server := httptest.NewUnstartedServer(origin)
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, chrPairConnectionKey{}, &chrPairConnection{})
	}
	server.StartTLS()
	defer server.Close()
	originPort := server.Listener.Addr().(*net.TCPAddr).Port
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(root, "key.pem")
	if vlessTransport {
		key, err := x509.MarshalPKCS8PrivateKey(server.TLS.Certificates[0].PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
			t.Fatal(err)
		}
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
	if cohort {
		pool.ProbeBudget, pool.ProbeLanes = 2, 2
	}
	if inventory {
		pool.ProbeBudget, pool.ProbeLanes = 10, 10
		origin.activeMS.Store(575)
		origin.reserveMS.Store(425)
	}
	if cpuComparison {
		origin.activeMS.Store(425)
	}
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
	if softSix || cohort {
		policyCount = 6
	}
	nodes := []string{}
	vlessPort := port()
	vlessUsers, vlessRules := []any{}, []any{}
	blockedAfterWarmup := map[string]bool{}
	origin.fastest = map[string]bool{}
	for i := 0; i < policyCount; i++ {
		id := fmt.Sprintf("route-%d", i)
		members := []string{id + "-active", id + "-reserve"}
		if inventory {
			members = members[:1]
			for j := 1; j < nodeCount; j++ {
				members = append(members, fmt.Sprintf("%s-reserve-%02d", id, j))
			}
			if !cpuComparison {
				origin.fastest[members[len(members)-1]] = true
			}
			for j := nodeCount / 3; j < nodeCount/3+4 && j < nodeCount-1; j++ {
				blockedAfterWarmup[members[j]] = true
			}
		}
		contract := healthPolicyContract{Mode: "best", Candidates: members, Nodes: map[string]healthNode{}, Policy: healthPolicy{ActiveCheckSeconds: 60, ActiveLivenessSeconds: 3, ProbeBatchSize: 1, SwitchImprovementMS: 200, LatencyMeasurement: latencyMeasurement}}
		if inventory {
			contract.Policy.ProbeBatchSize = 10
		}
		if scenario == "soft-six-priority" {
			contract.Mode = "priority"
		}
		if cohort {
			contract.Policy.ProbeBatchSize, contract.Policy.ActiveCheckSeconds = 2, 6
		}
		if scenario == "callback" {
			contract.Policy.ProbeBatchSize = 2
		}
		if scenario == "degradation" || scenario == "slow" {
			contract.Policy.ActiveLivenessSeconds = 30
		}
		for _, node := range members {
			source := fmt.Sprintf("127.0.0.%d", 2+len(nodes))
			origin.sources[source] = node
			if vlessTransport {
				id := fmt.Sprintf("00000000-0000-4000-8000-%012d", len(nodes)+1)
				email, egress := node+"@example.invalid", "isolated-egress-"+node
				serverUser := map[string]any{"id": id, "email": email}
				clientUser := map[string]any{"id": id, "encryption": "none"}
				if vlessVision {
					serverUser["flow"], clientUser["flow"] = "xtls-rprx-vision", "xtls-rprx-vision"
				}
				vlessUsers = append(vlessUsers, serverUser)
				vlessRules = append(vlessRules, map[string]any{"type": "field", "inboundTag": []string{"isolated-vless"}, "user": []string{email}, "outboundTag": egress})
				outbounds = append(outbounds,
					map[string]any{"tag": egress, "protocol": "freedom", "sendThrough": source, "settings": map[string]any{"finalRules": []any{map[string]any{
						"action": "allow", "network": "tcp", "ip": []string{"127.0.0.1/32"}, "port": strconv.Itoa(originPort),
					}}}},
					map[string]any{"tag": node, "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": vlessPort, "users": []any{clientUser}}}},
						"streamSettings": chrPairVLESSStream(vlessVision, map[string]any{"serverName": "example.com", "alpn": []string{"http/1.1"}, "certificates": []any{map[string]any{"certificateFile": ca, "usage": "verify"}}})})
			} else {
				outbounds = append(outbounds, map[string]any{"tag": node, "protocol": "freedom", "sendThrough": source})
			}
			contract.Nodes[node] = healthNode{Label: node, Fingerprint: "isolated-" + node}
			nodes = append(nodes, node)
		}
		pool.Policies[id] = members
		pool.HealthPolicies[id] = contract
		balancers = append(balancers, map[string]any{"tag": id, "selector": members, "strategy": map[string]any{"type": "random"}})
	}
	pool.BaseOutboundTags = append([]string{"block"}, nodes...)
	origin.slowPrimary = blockedAfterWarmup
	inbounds := []any{map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}}}
	rules := []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"}}
	var providerConfig map[string]any
	if vlessTransport {
		providerInbound := map[string]any{"tag": "isolated-vless", "listen": "127.0.0.1", "port": vlessPort, "protocol": "vless", "settings": map[string]any{"clients": vlessUsers, "decryption": "none"},
			"streamSettings": chrPairVLESSStream(vlessVision, map[string]any{"alpn": []string{"http/1.1"}, "certificates": []any{map[string]any{"certificateFile": ca, "keyFile": keyFile}}})}
		if cpuComparison {
			var providerOutbounds, clientOutbounds []any
			for _, value := range outbounds {
				outbound := value.(map[string]any)
				if tag, _ := outbound["tag"].(string); strings.HasPrefix(tag, "isolated-egress-") {
					providerOutbounds = append(providerOutbounds, value)
				} else {
					clientOutbounds = append(clientOutbounds, value)
				}
			}
			outbounds = clientOutbounds
			providerConfig = map[string]any{"log": map[string]any{"loglevel": "error", "access": "none"}, "inbounds": []any{providerInbound}, "outbounds": providerOutbounds, "routing": map[string]any{"rules": vlessRules}}
		} else {
			inbounds = append(inbounds, providerInbound)
			rules = append(rules, vlessRules...)
		}
	}
	trafficPort := 0
	if cpuComparison && os.Getenv("SB_CHR_PAIR_CPU_TRAFFIC") == "1" {
		trafficPort = port()
		inbounds = append(inbounds, map[string]any{"tag": "isolated-user-traffic", "listen": "127.0.0.1", "port": trafficPort, "protocol": "http", "settings": map[string]any{}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{"isolated-user-traffic"}, "balancerTag": "route-0"})
	}
	backgroundPeerPort := port()
	lanes := []struct {
		tag  string
		port int
	}{{"outbound-health-probe", fastPort}, {"outbound-health-background", bgPort}}
	if cohort {
		lanes = append(lanes, struct {
			tag  string
			port int
		}{"outbound-health-background-2", backgroundPeerPort})
	}
	if inventory {
		for len(lanes) < pool.ProbeLanes+1 {
			lanes = append(lanes, struct {
				tag  string
				port int
			}{fmt.Sprintf("outbound-health-background-%d", len(lanes)), port()})
		}
	}
	for _, lane := range lanes {
		if !dynamicHandlers {
			pool.Policies[lane.tag] = nodes
		}
		inbounds = append(inbounds, map[string]any{"tag": lane.tag, "listen": "127.0.0.1", "port": lane.port, "protocol": "http", "settings": map[string]any{}})
		balancers = append(balancers, map[string]any{"tag": lane.tag, "selector": nodes, "strategy": map[string]any{"type": "random"}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{lane.tag}, "balancerTag": lane.tag})
	}
	var dynamicDefinitions []any
	if dynamicHandlers {
		pool.Outbounds = make(map[string]json.RawMessage, len(nodes))
		var static []any
		for _, value := range outbounds {
			outbound := value.(map[string]any)
			tag, _ := outbound["tag"].(string)
			if contains(nodes, tag) {
				body, err := json.Marshal(outbound)
				if err != nil {
					t.Fatal(err)
				}
				pool.Outbounds[tag] = body
				dynamicDefinitions = append(dynamicDefinitions, value)
			} else {
				static = append(static, value)
			}
		}
		outbounds = static
		pool.BaseOutboundTags = []string{"block"}
		for _, value := range balancers {
			value.(map[string]any)["selector"] = []string{"block"}
		}
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
	coreLogLevel := "warning"
	if os.Getenv("SB_CHR_PAIR_DEBUG") == "1" {
		coreLogLevel = "info"
	}
	coreConfig := map[string]any{"log": map[string]any{"loglevel": coreLogLevel, "access": "none"}, "api": map[string]any{"tag": "api", "services": []string{"RoutingService", "HandlerService"}}, "inbounds": inbounds, "outbounds": outbounds, "routing": map[string]any{"balancers": balancers, "rules": rules}}
	coreBufferKiB := 0
	if cpuComparison && os.Getenv("SB_CHR_PAIR_CORE_BUFFER_KIB") != "" {
		coreBufferKiB, _ = strconv.Atoi(os.Getenv("SB_CHR_PAIR_CORE_BUFFER_KIB"))
		if coreBufferKiB != 4 && coreBufferKiB != 16 && coreBufferKiB != 32 {
			t.Fatal("CPU comparison buffer must be 4, 16 or 32 KiB")
		}
		coreConfig["policy"] = map[string]any{"levels": map[string]any{"0": map[string]any{"bufferSize": coreBufferKiB}}}
	}
	metricsAddress := ""
	if cpuComparison {
		metricsAddress = fmt.Sprintf("127.0.0.1:%d", port())
		coreConfig["metrics"] = map[string]any{"listen": metricsAddress}
		coreConfig["stats"] = map[string]any{}
	}
	config := write("xray.json", coreConfig)
	var preparations atomic.Int64
	var preparedEncoder xrayOutboundEncoder
	if dynamicHandlers {
		preparedEncoder = chrPairPreparedEncoder(t, ctx, binary, root, dynamicDefinitions, &preparations)
	}
	var provider *exec.Cmd
	if providerConfig != nil {
		provider = exec.CommandContext(ctx, binary, "run", "-config", write("provider.json", providerConfig))
		provider.Env = append(os.Environ(), "SB_MEMORY_BUDGET=0", "GOMEMLIMIT=64MiB")
		var providerLog chrPairTrace
		provider.Stdout, provider.Stderr = &providerLog, &providerLog
		if err := provider.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = provider.Process.Kill(); _ = provider.Wait() }()
		until := time.Now().Add(10 * time.Second)
		for {
			connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", vlessPort), 100*time.Millisecond)
			if err == nil {
				connection.Close()
				break
			}
			if time.Now().After(until) {
				t.Fatalf("isolated provider unavailable: %v %s", err, providerLog.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	core := exec.CommandContext(ctx, binary, "run", "-config", config)
	coreMemoryMiB := 0
	if cpuComparison {
		var err error
		coreMemoryMiB, err = strconv.Atoi(os.Getenv("SB_CHR_PAIR_CORE_MEMORY_MIB"))
		if err != nil || coreMemoryMiB < 32 || coreMemoryMiB > 192 {
			t.Fatal("CPU comparison requires an explicit Xray Go budget between 32 and 192 MiB")
		}
		// Only this isolated child uses the explicit comparison budget. The
		// packaged role allocator must not silently cap it to the lab cgroup.
		core.Env = append(os.Environ(), "SB_MEMORY_BUDGET=0", fmt.Sprintf("GOMEMLIMIT=%dMiB", coreMemoryMiB))
	}
	var coreLog chrPairTrace
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
	startupTag := nodes[0]
	if dynamicHandlers {
		startupTag = "block"
	}
	for until := time.Now().Add(20 * time.Second); ; {
		inventory, e := control.outbounds(ctx)
		if e == nil && inventory[startupTag] {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("isolated core unavailable: %v %s", e, coreLog.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	newLane := func(port int, tag string) *xraySelectorRuntime {
		r := newXraySelectorRuntime(Options{XrayBinary: binary, XrayAPIServer: api, HealthPoolFile: poolPath, ProbeURL: fmt.Sprintf("http://127.0.0.1:%d", port)})
		if preparedEncoder != nil {
			r.outboundEncoder = preparedEncoder
		}
		r.control = control
		r.probeSelector = tag
		if _, _, e := r.Reload(); e != nil {
			t.Fatal(e)
		}
		return r
	}
	primary, bg := newLane(fastPort, ""), newLane(bgPort, "outbound-health-background")
	responsive := &responsiveSelectorRuntime{selectorRuntime: primary, background: bg, backgrounds: []*xraySelectorRuntime{bg}, ctx: ctx, generationPaths: []string{poolPath}}
	for _, lane := range lanes[2:] {
		responsive.backgrounds = append(responsive.backgrounds, newLane(lane.port, lane.tag))
	}
	if _, _, err := responsive.Reload(); err != nil {
		t.Fatal(err)
	}
	measuredRuntime := &chrPairRuntime{responsiveSelectorRuntime: responsive}
	controller := &healthController{opts: Options{StateRoot: root, HealthInterval: time.Minute, URLTestWarmCompare: warmCompare,
		URLTestPlanningMode: planningOptions.URLTestPlanningMode}, runtime: measuredRuntime, state: healthState{}, stateLoaded: true, warmStarted: map[string]bool{}}
	var events []healthEvent
	controller.eventSink = func(e healthEvent) { events = append(events, e) }
	for id, contract := range pool.HealthPolicies {
		item := newPolicyHealthState()
		item.Mode, item.LatencyMeasurement = contract.Mode, latencyMeasurement
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = contract.Candidates[0], contract.Candidates[0], true
		item.CandidateSignature = strings.Join(contract.Candidates, "\n")
		item.CandidateNodes = contract.Nodes
		for _, node := range contract.Candidates {
			for i := 0; i < 3; i++ {
				e := bg.Probe(node)
				if !e.OK || e.DelayMS == nil {
					origin.mu.Lock()
					received := append([]chrPairRequest{}, origin.requests...)
					origin.mu.Unlock()
					t.Fatalf("controlled TLS warmup failed for %s: %+v; origin: %+v; stages: %s; isolated core: %s", node, e, received, traces.String(), coreLog.String())
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
		if cpuComparison && os.Getenv("SB_CHR_PAIR_CPU_MATURE") == "1" {
			seedCHRPairHistory(item, contract.Candidates, time.Now())
			refreshHistoryStatistics(item, contract.Candidates, nil, time.Now())
		}
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
	origin.slowEnabled.Store(inventory && !cpuComparison)
	duration := 125 * time.Second
	if inventory {
		duration = 240 * time.Second
	}
	if cpuComparison {
		duration = 125 * time.Second
	}
	if cohort {
		duration = 120 * time.Second
	}
	if scenario == "cohort-spikes" {
		origin.commonQueueSince.Store(phaseStart.UnixNano())
	}
	if scenario == "cohort-degradation" {
		origin.activeMS.Store(575)
	}
	if scenario == "smoke" {
		duration = 30 * time.Second
	}
	if scenario == "callback" {
		duration = 25 * time.Second
	}
	if softSix {
		origin.failPrimaryActive.Store(true)
		duration = 210 * time.Second
	}
	if scenario == "head-get" {
		origin.rejectActiveHEAD.Store(true)
		duration = 75 * time.Second
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
	origin.healthConnections.Store(0)
	origin.bulkConnections.Store(0)
	preparations.Store(0)
	initialCPU := chrPairCPU()
	driverCPU, driverErr := chrPairProcessCPU(os.Getpid())
	if cpuComparison && driverErr != nil {
		t.Fatal(driverErr)
	}
	stopDriverProfile := func() {}
	if cpuComparison && os.Getenv("SB_CHR_PAIR_DRIVER_CPU_PROFILE") != "" {
		name := os.Getenv("SB_CHR_PAIR_DRIVER_CPU_PROFILE")
		if filepath.Dir(name) != "/data" || !strings.HasPrefix(name, "/data/sb-chr-pair-") || !strings.HasSuffix(name, ".pprof") {
			t.Fatal("invalid private driver profile path")
		}
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			file.Close()
			t.Fatal(err)
		}
		var once sync.Once
		stopDriverProfile = func() {
			once.Do(func() {
				pprof.StopCPUProfile()
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		defer stopDriverProfile()
	}
	coreCPU, cpuErr := chrPairProcessCPU(core.Process.Pid)
	if cpuComparison && cpuErr != nil {
		t.Fatal(cpuErr)
	}
	providerCPU := 0.0
	if provider != nil {
		var err error
		providerCPU, err = chrPairProcessCPU(provider.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
	}
	var trafficBytes, trafficErrors atomic.Int64
	trafficCancel := func() {}
	trafficDone := make(chan struct{})
	if trafficPort > 0 {
		trafficContext, cancel := context.WithCancel(ctx)
		trafficCancel = cancel
		transport := server.Client().Transport.(*http.Transport).Clone()
		proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", trafficPort))
		transport.Proxy = http.ProxyURL(proxy)
		transport.MaxIdleConnsPerHost = trafficClients
		client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
		var clients sync.WaitGroup
		for i := 0; i < trafficClients; i++ {
			clients.Add(1)
			go func() {
				defer clients.Done()
				for trafficContext.Err() == nil {
					request, err := http.NewRequestWithContext(trafficContext, http.MethodGet, server.URL+"/cpu-bulk", nil)
					if err != nil {
						trafficErrors.Add(1)
						return
					}
					response, err := client.Do(request)
					if err == nil {
						var count int64
						count, err = io.Copy(io.Discard, response.Body)
						response.Body.Close()
						trafficBytes.Add(count)
						if response.StatusCode != http.StatusOK {
							err = fmt.Errorf("traffic status %d", response.StatusCode)
						}
					}
					if err != nil && trafficContext.Err() == nil {
						trafficErrors.Add(1)
						return
					}
				}
			}()
		}
		go func() { clients.Wait(); transport.CloseIdleConnections(); close(trafficDone) }()
	} else {
		close(trafficDone)
	}
	defer func() { trafficCancel(); <-trafficDone }()
	profileResult := make(chan error, 1)
	if cpuComparison {
		profilePath := os.Getenv("SB_CHR_PAIR_CPU_PROFILE")
		if filepath.Dir(profilePath) != "/data" || !strings.HasPrefix(profilePath, "/data/sb-chr-pair-") || !strings.HasSuffix(profilePath, ".pprof") {
			t.Fatal("CPU comparison requires a private, lab-owned profile path")
		}
		go func() {
			client := &http.Client{Timeout: duration + 15*time.Second}
			response, err := client.Get("http://" + metricsAddress + "/debug/pprof/profile?seconds=120")
			if err != nil {
				profileResult <- err
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				profileResult <- fmt.Errorf("CPU profile status %d", response.StatusCode)
				return
			}
			file, err := os.OpenFile(profilePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				profileResult <- err
				return
			}
			_, copyErr := io.Copy(file, response.Body)
			closeErr := file.Close()
			profileResult <- errors.Join(copyErr, closeErr)
		}()
	}
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
		if monitorEnabled {
			var tickErr error
			pprof.Do(ctx, pprof.Labels("fixture_role", "controller"), func(context.Context) { tickErr = controller.Tick(time.Now()) })
			if err := tickErr; err != nil && !errors.Is(err, errHealthYield) {
				t.Fatal(err)
			}
		}
		item := controller.state["route-0"]
		if item.OptimizationChecks > previousConfirmation && item.OptimizationLastResult != nil {
			confirmations = append(confirmations, *item.OptimizationLastResult)
			confirmationSeconds = append(confirmationSeconds, time.Since(phaseStart).Seconds())
		}
		previousConfirmation = item.OptimizationChecks
		if softSix || scenario == "cohort-degradation" {
			complete := true
			for id, state := range controller.state {
				complete = complete && state.Selected == id+"-reserve"
			}
			if complete {
				break
			}
		}
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
				_, a := latestQualityObservation(warmPlanningView(item), item.Selected)
				_, b := latestQualityObservation(warmPlanningView(item), item.OptimizationCandidate)
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
		if !monitorEnabled {
			wait = time.Second
		}
		if until := time.Until(phaseEnd); wait > until {
			wait = until
		}
		if !waitForHealthWake(ctx, wait, []string{poolPath}, 100*time.Millisecond, nil, nil) {
			break
		}
	}
	trafficCancel()
	<-trafficDone
	stopDriverProfile()
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
	if softSix {
		states := map[string]any{}
		for id, item := range controller.state {
			states[id] = map[string]any{"selected": item.Selected, "failures": item.Failures, "last_probes": item.LastProbeAt, "pending": item.degradedPair, "next_regular": controller.regularNext[id], "checked_at": item.CheckedAt}
		}
		report["policy_state"] = states
	}
	report["max_https_attempts_in_rolling_60_seconds"], report["quality_concurrency_peak"] = maxRolling, measuredRuntime.qualityPeak.Load()
	report["warm_compare"] = warmCompare
	report["planning_mode"] = planningOptions.planningMode()
	report["planning_measurement"] = planningMeasurement
	report["primary_requests_per_healthy_planning_job"] = 1
	if warmCompare {
		report["primary_requests_per_healthy_planning_job"] = 2
	}
	report["vless_variant"] = vlessVariant
	if cpuComparison {
		if err := <-profileResult; err != nil {
			t.Fatal(err)
		}
		coreCPUAfter, err := chrPairProcessCPU(core.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		report["xray_cpu_core_percent"] = 100 * (coreCPUAfter - coreCPU) / elapsed
		driverCPUAfter, err := chrPairProcessCPU(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		report["driver_cpu_core_percent"] = 100 * (driverCPUAfter - driverCPU) / elapsed
		report["monitor_enabled"], report["traffic_clients"] = monitorEnabled, trafficClients
		report["core_buffer_kib"] = coreBufferKiB
		report["mature_history"] = os.Getenv("SB_CHR_PAIR_CPU_MATURE") == "1"
		report["dynamic_handlers"], report["dynamic_handler_preparations"] = dynamicHandlers, preparations.Load()
		report["provider_separate_process"] = provider != nil
		if provider != nil {
			after, err := chrPairProcessCPU(provider.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			report["provider_cpu_core_percent"] = 100 * (after - providerCPU) / elapsed
		}
		if checkpoint, err := os.Stat(statePath(root, "selector-health")); err == nil {
			report["checkpoint_bytes"] = checkpoint.Size()
		}
		report["health_tls_connections"], report["traffic_tls_connections"] = origin.healthConnections.Load(), origin.bulkConnections.Load()
		report["user_traffic_bytes"], report["user_traffic_errors"] = trafficBytes.Load(), trafficErrors.Load()
		report["xray_go_memory_mib"] = coreMemoryMiB
		if trafficPort > 0 && (trafficBytes.Load() == 0 || trafficErrors.Load() != 0) {
			t.Fatal("CPU comparison traffic did not complete successfully")
		}
		if len(switches) != 0 {
			t.Fatal("equal origins caused a switch during the CPU comparison")
		}
	}
	report["vless_ws_tls"] = vlessTransport
	report["nodes_per_policy"] = nodeCount
	report["origin_quality_concurrency_peak"] = origin.qualityPeak.Load()
	if pairedCompare && scenario == "smoke" {
		for id, contract := range pool.HealthPolicies {
			for _, node := range contract.Candidates {
				if len(controller.state[id].WarmPlanningSamples[node]) == 0 {
					t.Fatalf("native smoke did not exercise second-request quality for %s", node)
				}
			}
		}
	}
	if !cohort && !inventory && (measuredRuntime.qualityPeak.Load() > 1 || origin.qualityPeak.Load() > 1) {
		t.Fatal("one-slot quality concurrency exceeded")
	}
	if cohort || inventory && !cpuComparison {
		maxStartSkew := time.Duration(0)
		invalidWaves := 0
		for _, wave := range measuredRuntime.waves {
			if inventory && len(wave) == 2 && (!wave[0].OK || !wave[1].OK) {
				invalidWaves++
				continue
			}
			if len(wave) != 2 || !wave[0].OK || !wave[1].OK || wave[0].Wave == 0 || wave[0].Wave != wave[1].Wave {
				t.Fatalf("comparison was not one successful physical wave: %+v", wave)
			}
			a, b := wave[0], wave[1]
			if !a.StartedAt.Before(b.FinishedAt) || !b.StartedAt.Before(a.FinishedAt) {
				t.Fatalf("native measurement intervals did not overlap: %+v", wave)
			}
			skew := a.StartedAt.Sub(b.StartedAt)
			if skew < 0 {
				skew = -skew
			}
			maxStartSkew = max(maxStartSkew, skew)
		}
		if len(measuredRuntime.waves) < 12 || origin.qualityPeak.Load() != 2 {
			t.Fatal("two physical lines or repeated cohorts were not exercised")
		}
		report["physical_waves"], report["max_start_skew_ms"] = measuredRuntime.waves, float64(maxStartSkew)/float64(time.Millisecond)
		report["invalid_quality_waves"] = invalidWaves
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
	case "inventory":
		want := pool.HealthPolicies["route-0"].Candidates[nodeCount-1]
		if len(switches) != 1 || controller.state["route-0"].Selected != want || switches[0].Reason != "meaningfully-faster" {
			t.Fatal("late fastest candidate was starved or working paths oscillated")
		}
		comparison := switches[0].Comparison
		if comparison == nil || comparison.Measurement != string(planningMeasurement) || comparison.ConfirmationGapMS == nil || *comparison.ConfirmationGapMS < 60000 || *comparison.ConfirmationGapMS > 120000 {
			t.Fatal("inventory did not use two timely production-cadence paired proofs")
		}
		for _, node := range nodes {
			if len(quality[node]) == 0 {
				t.Fatalf("inventory node received no actual HEAD: %s", node)
			}
		}
	case "cohort-spikes":
		if len(switches) != 0 {
			t.Fatal("common short queue moved equal nodes")
		}
	case "cohort-degradation":
		if len(switches) != policyCount {
			t.Fatal("persistent degradation starved a policy")
		}
		for id, state := range controller.state {
			if state.Selected != id+"-reserve" || state.LastSwitchReason != "meaningfully-faster" {
				t.Fatalf("missing sustained-quality switch for %s", id)
			}
		}
	case "head-get":
		if len(switches) != 0 || controller.state["route-0"].Failures["route-0-active"] != 0 {
			t.Fatal("HEAD rejection displaced a route with successful primary GET")
		}
	case "soft-six", "soft-six-priority":
		if len(switches) != policyCount {
			t.Fatalf("soft degradation starved a route: switches=%d want=%d", len(switches), policyCount)
		}
		for id, state := range controller.state {
			if state.Selected != id+"-reserve" || state.LastSwitchReason != "active-degraded" {
				t.Fatalf("missing fresh degradation switch for %s", id)
			}
		}
	case "callback":
		if !callbackDelayed || origin.qualityPeak.Load() != 1 {
			t.Fatal("single-lane callback scenario was not exercised")
		}
		for id, contract := range pool.HealthPolicies {
			item := controller.state[id]
			_, activeAt := latestQualityObservation(warmPlanningView(item), contract.Candidates[0])
			_, reserveAt := latestQualityObservation(warmPlanningView(item), contract.Candidates[1])
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

func seedCHRPairHistory(item *policyHealthState, candidates []string, now time.Time) {
	for nodeIndex, node := range candidates {
		item.DailySamples[node] = make([]healthSample, 1440)
		for i := range item.DailySamples[node] {
			delay := 425 + (i*17+nodeIndex)%40
			item.DailySamples[node][i] = healthSample{At: float64(now.Add(-time.Duration(1439-i) * time.Minute).Unix()), OK: true, DelayMS: &delay}
		}
		item.HistoryDays[node] = make(map[string]dayBucket, 30)
		for day := 0; day < 30; day++ {
			bucket := dayBucket{Samples: 1440, Successes: 1440, LatencySamples: make([]int, 256)}
			for i := range bucket.LatencySamples {
				bucket.LatencySamples[i] = 425 + (i*19+day+nodeIndex)%40
			}
			item.HistoryDays[node][now.UTC().AddDate(0, 0, -day).Format("2006-01-02")] = bucket
		}
	}
}

// The opt-in native fixture runs on the CHR Linux kernel, whose proc accounting
// uses 100 ticks per second. This is per-process CPU, not aggregate cgroup CPU.
func chrPairProcessCPU(pid int) (float64, error) {
	body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(body), ')')
	if end < 0 {
		return 0, errors.New("invalid process CPU stat header")
	}
	fields := strings.Fields(string(body[end+1:]))
	if len(fields) < 13 {
		return 0, errors.New("truncated process CPU stat")
	}
	u, e1 := strconv.ParseFloat(fields[11], 64)
	s, e2 := strconv.ParseFloat(fields[12], 64)
	if e1 != nil || e2 != nil {
		return 0, errors.Join(e1, e2)
	}
	return (u + s) / 100, nil
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
