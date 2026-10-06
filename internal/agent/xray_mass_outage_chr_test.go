//go:build linux

package agent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type massOutageSelectionRuntime struct {
	*responsiveSelectorRuntime
	selected func(string, string)
}

func (r *massOutageSelectionRuntime) Select(selector, node string) error {
	if err := r.responsiveSelectorRuntime.Select(selector, node); err != nil {
		return err
	}
	if r.selected != nil {
		r.selected(selector, node)
	}
	return nil
}

// This measures recovery from a confirmed block, not outage detection. All
// requests traverse an isolated real core. No live config or selector is touched.
func TestXrayTenCandidateMassOutageFastRecovery(t *testing.T) {
	testXrayMassOutageRecovery(t, 10, false, false, false)
}

func TestXrayHundredCandidateMassOutageRecovery(t *testing.T) {
	testXrayMassOutageRecovery(t, 100, false, false, false)
}

func TestXrayHundredCandidateFallbackOutageRecovery(t *testing.T) {
	testXrayMassOutageRecovery(t, 100, false, true, false)
}

func TestXrayHundredDistinctEndpointOutageRecovery(t *testing.T) {
	testXrayMassOutageRecovery(t, 100, false, false, true)
}

func TestXrayHundredDistinctEndpointFallbackRecovery(t *testing.T) {
	testXrayMassOutageRecovery(t, 100, false, true, true)
}

func TestXrayHundredCandidateCompleteOutage(t *testing.T) {
	if os.Getenv("SB_CHR_COMPLETE_OUTAGE") != "1" {
		t.Skip("opt-in pinned CHR complete-outage diagnostic")
	}
	testXrayMassOutageRecovery(t, 100, true, false, false)
}

func testXrayMassOutageRecovery(t *testing.T, count int, allFailed, fallbackOnly, distinctEndpoints bool) {
	binary := os.Getenv("SB_TEST_XRAY")
	if binary == "" {
		t.Skip("set SB_TEST_XRAY to run the real-core integration test")
	}
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()
			const policyID = "mass-route"
			healthySource := fmt.Sprintf("127.0.0.%d", count+1)
			existingSource := fmt.Sprintf("127.0.0.%d", count+2)
			nodes := make([]string, count)
			outbounds := []any{
				map[string]any{"tag": "block", "protocol": "blackhole"},
				map[string]any{"tag": "mass-existing", "protocol": "freedom", "sendThrough": existingSource},
			}
			silentSources := make(map[string]bool, count-1)
			for index := range nodes {
				nodes[index] = fmt.Sprintf("mass-node-%02d", index+1)
				source := fmt.Sprintf("127.0.0.%d", index+2)
				outbounds = append(outbounds, map[string]any{"tag": nodes[index], "protocol": "freedom", "sendThrough": source})
				if allFailed || index < count-1 {
					silentSources[source] = true
				}
			}
			var pending, silentRequests atomic.Int64
			var seenMu sync.Mutex
			seen := make(map[string]bool, count-1)
			sourceRequests := make(map[string]int, count)
			allSilentStarted := make(chan struct{})
			var firstSilentAt time.Time
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				source, _, err := net.SplitHostPort(request.RemoteAddr)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if request.URL.Path == "/client" {
					w.Header().Set("Content-Length", fmt.Sprint(len(source)))
					_, _ = io.WriteString(w, source)
					return
				}
				if silentSources[source] || fallbackOnly && source == healthySource && request.URL.Path == "/health/0" {
					pending.Add(1)
					silentRequests.Add(1)
					defer pending.Add(-1)
					seenMu.Lock()
					if silentSources[source] {
						sourceRequests[source]++
					}
					if firstSilentAt.IsZero() {
						firstSilentAt = time.Now()
					}
					if silentSources[source] && !seen[source] {
						seen[source] = true
						if len(seen) == len(silentSources) {
							close(allSilentStarted)
						}
					}
					seenMu.Unlock()
					select {
					case <-request.Context().Done():
					case <-ctx.Done():
					}
					return
				}
				if source != healthySource {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				// The successful reply cannot race ahead of unstarted dead peers.
				select {
				case <-allSilentStarted:
				case <-request.Context().Done():
					return
				case <-ctx.Done():
					return
				}
				if request.URL.Path == "/health/0" {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			}))
			t.Cleanup(origin.Close)
			oldTargets := healthTargets
			healthTargets = append(healthTargets[:0:0], oldTargets...)
			for index := range healthTargets {
				healthTargets[index].url = fmt.Sprintf("%s/health/%d", origin.URL, index)
			}
			t.Cleanup(func() { healthTargets = oldTargets })
			root := t.TempDir()
			write := func(name string, value any) string {
				t.Helper()
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(root, name)
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			ports := make(map[int]bool)
			port := func() int {
				t.Helper()
				for {
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					value := listener.Addr().(*net.TCPAddr).Port
					_ = listener.Close()
					if !ports[value] {
						ports[value] = true
						return value
					}
				}
			}
			apiPort, clientPort := port(), port()
			apiAddress := fmt.Sprintf("127.0.0.1:%d", apiPort)
			inbounds := []any{
				map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}},
				map[string]any{"tag": "client", "listen": "127.0.0.1", "port": clientPort, "protocol": "http"},
			}
			rules := []any{
				map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"},
				map[string]any{"type": "field", "inboundTag": []string{"client"}, "balancerTag": policyID},
			}
			balancers := []any{map[string]any{"tag": policyID, "selector": []string{"mass-node-", "mass-existing", "block"}, "strategy": map[string]any{"type": "random"}}}
			lanePorts := make([]int, 10)
			laneTags := make([]string, 10)
			for index := range lanePorts {
				lanePorts[index] = port()
				laneTags[index] = "outbound-health-background"
				if index > 0 {
					laneTags[index] = fmt.Sprintf("outbound-health-background-%d", index+1)
				}
				inbounds = append(inbounds, map[string]any{"tag": laneTags[index], "listen": "127.0.0.1", "port": lanePorts[index], "protocol": "http"})
				balancers = append(balancers, map[string]any{"tag": laneTags[index], "selector": []string{"mass-node-"}, "strategy": map[string]any{"type": "random"}})
				rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{laneTags[index]}, "balancerTag": laneTags[index]})
			}
			contract := healthPolicyContract{Mode: mode, Candidates: nodes, Policy: healthPolicy{ProbeBatchSize: 10}}
			pool := healthPool{
				Version: 4, ProbeBudget: 10, Policies: map[string][]string{policyID: nodes},
				HealthPolicies:   map[string]healthPolicyContract{policyID: contract},
				BaseOutboundTags: append(append([]string(nil), nodes...), "block", "mass-existing"),
			}
			if count == 100 {
				host, rawPort, err := net.SplitHostPort(origin.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				originPort, err := strconv.Atoi(rawPort)
				if err != nil {
					t.Fatal(err)
				}
				pool.DialTargets = make(map[string]healthDialTarget, count)
				for _, node := range nodes {
					endpointPort := originPort
					if distinctEndpoints {
						// Independent open TCP endpoints prevent preflight dedup from
						// hiding its cost; full HTTPS still uses isolated core paths.
						listener, err := net.Listen("tcp4", "127.0.0.1:0")
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = listener.Close() })
						endpointPort = listener.Addr().(*net.TCPAddr).Port
					}
					pool.DialTargets[node] = healthDialTarget{Address: host, Port: endpointPort}
				}
			}
			poolPath := write("pool.json", pool)
			config := write("xray.json", map[string]any{
				"log":      map[string]any{"loglevel": "none"},
				"api":      map[string]any{"tag": "api", "services": []string{"RoutingService", "HandlerService"}},
				"inbounds": inbounds, "outbounds": outbounds,
				"routing": map[string]any{"balancers": balancers, "rules": rules},
			})
			command := func(args ...string) *exec.Cmd {
				if runner := os.Getenv("SB_TEST_XRAY_RUNNER"); runner != "" {
					return exec.CommandContext(ctx, runner, append([]string{binary}, args...)...)
				}
				return exec.CommandContext(ctx, binary, args...)
			}
			process := command("run", "-config", config)
			process.Stdout, process.Stderr = io.Discard, io.Discard
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
			for deadline := time.Now().Add(10 * time.Second); ; {
				conn, err := net.DialTimeout("tcp", apiAddress, 100*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					break
				}
				if time.Now().After(deadline) || ctx.Err() != nil {
					t.Fatal("isolated core API did not start")
				}
				time.Sleep(50 * time.Millisecond)
			}
			control, err := newXrayControlClient(apiAddress)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(control.close)
			for deadline := time.Now().Add(10 * time.Second); ; {
				available, err := control.outbounds(ctx)
				if err == nil && available[nodes[count-1]] && available["block"] {
					break
				}
				if time.Now().After(deadline) || ctx.Err() != nil {
					t.Fatalf("isolated core RPC inventory did not become ready: %v", err)
				}
				time.Sleep(50 * time.Millisecond)
			}
			primary := newXraySelectorRuntime(Options{XrayBinary: binary, XrayAPIServer: apiAddress, HealthPoolFile: poolPath})
			primary.control, primary.probeContext = control, ctx
			lanes := make([]*xraySelectorRuntime, 10)
			for index := range lanes {
				lane := newXraySelectorRuntime(Options{XrayBinary: binary, XrayAPIServer: apiAddress, HealthPoolFile: poolPath, ProbeURL: fmt.Sprintf("http://127.0.0.1:%d", lanePorts[index])})
				lane.control, lane.probeContext, lane.probeSelector = control, ctx, laneTags[index]
				if _, _, err := lane.Reload(); err != nil {
					t.Fatal(err)
				}
				if err := lane.Select(lane.probeSelector, nodes[index]); err != nil {
					t.Fatal(err)
				}
				lanes[index] = lane
			}
			responsive := &responsiveSelectorRuntime{
				selectorRuntime: primary, background: lanes[0], backgrounds: lanes,
				ctx: ctx, generationPaths: []string{poolPath},
			}
			if _, _, err := responsive.Reload(); err != nil {
				t.Fatal(err)
			}
			openClient := func() (net.Conn, *bufio.Reader) {
				t.Helper()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", clientPort), 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Listener.Addr(), origin.Listener.Addr())
				reader := bufio.NewReader(conn)
				line, err := reader.ReadString('\n')
				fields := strings.Fields(line)
				if err != nil || len(fields) < 2 || fields[1] != "200" {
					t.Fatalf("client CONNECT failed: %q, %v", line, err)
				}
				for {
					line, err = reader.ReadString('\n')
					if err != nil {
						t.Fatal(err)
					}
					if line == "\r\n" {
						break
					}
				}
				return conn, reader
			}
			checkClient := func(conn net.Conn, reader *bufio.Reader, source string) {
				t.Helper()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := fmt.Fprintf(conn, "GET /client HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Listener.Addr()); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(io.LimitReader(response.Body, 64))
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || string(body) != source {
					t.Fatalf("client path = %q status=%d err=%v, want %q", body, response.StatusCode, err, source)
				}
			}
			// The established client is separate from the failed probe paths.
			if err := primary.Select(policyID, "mass-existing"); err != nil {
				t.Fatal(err)
			}
			existing, existingReader := openClient()
			checkClient(existing, existingReader, existingSource)
			if err := primary.Select(policyID, "block"); err != nil {
				t.Fatal(err)
			}
			var selectedAt time.Time
			var pendingAtSelection int64
			audited := &massOutageSelectionRuntime{responsiveSelectorRuntime: responsive, selected: func(selector, node string) {
				if selector == policyID && node == nodes[count-1] {
					selectedAt, pendingAtSelection = time.Now(), pending.Load()
				}
			}}
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "block", "block", true
			item.Mode, item.CandidateSignature = mode, strings.Join(nodes, "\n")
			if allFailed {
				// A formerly working path gets a hot lane; ordinary nodes must
				// still complete repeated surveys when that hot path also fails.
				item.LastGoodAt[nodes[count-1]] = float64(time.Now().Unix())
				item.LastWorkingSelection = &workingSelection{
					Selected: nodes[count-1], Mode: mode, CandidateSignature: item.CandidateSignature,
				}
			}
			controller := &healthController{
				opts: Options{StateRoot: root, HealthInterval: 3 * time.Second}, runtime: audited,
				state: healthState{policyID: item}, stateLoaded: true, warmStarted: map[string]bool{policyID: true},
			}
			if allFailed {
				cpu := func() int64 {
					t.Helper()
					body, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
					if err != nil {
						t.Fatal(err)
					}
					fields := strings.Fields(string(body))
					for index := 0; index+1 < len(fields); index += 2 {
						if fields[index] == "usage_usec" {
							value, err := strconv.ParseInt(fields[index+1], 10, 64)
							if err != nil {
								t.Fatal(err)
							}
							return value
						}
					}
					t.Fatal("missing container CPU accounting")
					return 0
				}
				cpuPercent := func(start time.Time, before int64) float64 {
					return float64(cpu()-before) / time.Since(start).Seconds() / 10000 / float64(runtime.NumCPU())
				}
				idleStart, idleCPU := time.Now(), cpu()
				time.Sleep(10 * time.Second)
				idlePercent := cpuPercent(idleStart, idleCPU)
				started, beforeCPU := time.Now(), cpu()
				visits := make(map[string]int, count)
				panel := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}}
				defer panel.CloseIdleConnections()
				const cycles = 24
				panelFailures := 0
				for cycle := 0; cycle < cycles; cycle++ {
					if cycle > 0 {
						select {
						case <-time.After(controller.nextInterval()):
						case <-ctx.Done():
							t.Fatal("complete outage survey timed out")
						}
					}
					if err := controller.Tick(time.Now()); err != nil {
						t.Fatal(err)
					}
					if item.Selected != "block" || !item.RuntimeConfirmed {
						t.Fatal("all-failed survey invented a usable path")
					}
					if len(item.ProbedCandidates) > 10 {
						t.Fatal("all-failed survey exceeded node budget")
					}
					for _, node := range item.ProbedCandidates {
						visits[node]++
					}
					response, err := panel.Get("https://127.0.0.1:9443/api/health/live")
					if err != nil {
						panelFailures++
					} else {
						if response.StatusCode != http.StatusOK {
							panelFailures++
						}
						_ = response.Body.Close()
					}
				}
				averageCPU := cpuPercent(started, beforeCPU)
				memory, err := os.ReadFile("/sys/fs/cgroup/memory.current")
				if err != nil {
					t.Fatal(err)
				}
				minVisits := cycles
				for _, node := range nodes {
					minVisits = min(minVisits, visits[node])
				}
				seenMu.Lock()
				originDistinct, originMin := len(sourceRequests), 3*cycles
				for source := range silentSources {
					originMin = min(originMin, sourceRequests[source])
				}
				seenMu.Unlock()
				t.Logf("COMPLETE_OUTAGE_RESULT mode=%s candidates=100 budget=10 cycles=%d history=true distinct=%d min_visits=%d origin_distinct=%d origin_min_requests=%d elapsed_seconds=%.3f idle_cpu_percent=%.2f outage_cpu_percent=%.2f cpus=%d memory_end_bytes=%s panel_failures=%d scope=whole_container_with_live_gateway",
					mode, cycles, len(visits), minVisits, originDistinct, originMin, time.Since(started).Seconds(), idlePercent, averageCPU, runtime.NumCPU(), strings.TrimSpace(string(memory)), panelFailures)
				if len(visits) != count || minVisits < 2 || originDistinct != count || originMin < 6 || panelFailures != 0 {
					t.Fatal("complete outage starved candidates or made the panel unavailable")
				}
				checkClient(existing, existingReader, existingSource)
				return
			}
			started := time.Now()
			tickErr := controller.Tick(started)
			cycles := 1
			for count > 10 && tickErr == nil && item.Selected == "block" && ctx.Err() == nil {
				select {
				case <-time.After(controller.nextInterval()):
				case <-ctx.Done():
					t.Fatal("large-inventory recovery timed out")
				}
				cycles++
				tickErr = controller.Tick(time.Now())
			}
			finished := time.Now()
			seenMu.Lock()
			seenCount, firstSilent := len(seen), firstSilentAt
			seenMu.Unlock()
			selectSeconds, joinSeconds := -1.0, -1.0
			if !selectedAt.IsZero() {
				selectSeconds, joinSeconds = selectedAt.Sub(started).Seconds(), finished.Sub(selectedAt).Seconds()
			}
			t.Logf("MASS_OUTAGE_RESULT mode=%s candidate_count=%d healthy_position=%d probe_budget=10 cycles=%d silent_started=%d silent_requests=%d pending_at_select=%d recovery_seconds=%.3f select_seconds=%.3f join_seconds=%.3f primary_timeout_seconds=%.3f scope=confirmed_block_to_recovery", mode, count, count, cycles, seenCount, silentRequests.Load(), pendingAtSelection, finished.Sub(started).Seconds(), selectSeconds, joinSeconds, availabilityProbeTimeout.Seconds())
			t.Logf("MASS_OUTAGE_DISPATCH full_controller_tick=true distinct_preflight_endpoints=%t fallback_only=%t", distinctEndpoints, fallbackOnly)
			if tickErr != nil {
				t.Fatal(tickErr)
			}
			if item.Selected != nodes[count-1] || item.RuntimeSelected != nodes[count-1] || !item.RuntimeConfirmed || item.LastSwitchReason != "fresh-path-available" {
				t.Fatalf("controller did not recover to last candidate: selected=%q runtime=%q confirmed=%t reason=%q", item.Selected, item.RuntimeSelected, item.RuntimeConfirmed, item.LastSwitchReason)
			}
			// Timed-out earlier CONNECT paths may still wait at this silent
			// origin until Xray closes them. The final nine must be in flight;
			// earlier requests may either have closed or still be pending.
			maxOriginPending := int64(3 * (count - 1))
			if fallbackOnly {
				maxOriginPending++
			}
			if selectedAt.IsZero() || seenCount != count-1 || pendingAtSelection < 9 || pendingAtSelection > maxOriginPending {
				t.Fatal("selection did not occur after surveying the inventory while the final nine silent probes were in flight")
			}
			if count == 10 && (silentRequests.Load() < 9 || silentRequests.Load() > 27 ||
				selectedAt.Sub(firstSilent) >= availabilityProbeTimeout || finished.Sub(started) >= 2*availabilityProbeTimeout) {
				t.Fatal("healthy callback or worker cancellation waited beyond the bounded early-recovery window")
			}
			if firstSilent.IsZero() || finished.Sub(selectedAt) >= time.Second || (count == 100 && (cycles > 10 || finished.Sub(started) >= 90*time.Second)) {
				t.Fatal("large-inventory recovery starved later candidates or delayed cancellation")
			}
			if selected, err := primary.Current(policyID); err != nil || selected != nodes[count-1] {
				t.Fatalf("real core selection = %q, err=%v", selected, err)
			}
			checkClient(existing, existingReader, existingSource)
			fresh, freshReader := openClient()
			checkClient(fresh, freshReader, healthySource)
			t.Logf("real-core client proof: fresh TCP uses candidate %d; unrelated established TCP retains its original egress", count)
		})
	}
}
