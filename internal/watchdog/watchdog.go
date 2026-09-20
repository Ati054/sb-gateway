package watchdog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultInterval          = 5
	defaultFailureThreshold  = 3
	defaultRecoveryThreshold = 3
	defaultRestartBudget     = 6
	defaultDeepInterval      = 30
	defaultStartupGrace      = 30
	controlPlaneThreshold    = 24
	statusHeartbeat          = 30 * time.Second
)

type Options struct {
	TokenFile       string
	ReadyURL        string
	StatusURL       string
	XrayConfig      string
	XrayReadyFile   string
	PolicyDNSConfig string
	RouteTable      string
	RulePriority    string
	TProxyMark      string
	TProxyPort      string
	SettingsFile    string
	MarkerFile      string
	ApplyGuardFile  string
	RestartFile     string
	RestartEvidence string
	XrayBinary      string
}

type settings struct {
	interval          time.Duration
	failureThreshold  int
	recoveryThreshold int
	restartBudget     int
	deepInterval      time.Duration
	startupGrace      time.Duration
}

type runner struct {
	opts Options
	http *http.Client

	restarts               int
	lastPostSignature      string
	lastPostAt             time.Time
	deepHealthy            bool
	deepReasons            []string
	nextDeepProbe          time.Time
	checkedConfigSignature string
	configFileSignature    string
	listenerSignature      string
	dnsFileSignature       string
	dnsSignature           string
	listeners              []listener
	dnsPorts               []int
}

type listener struct {
	protocol string
	port     int
}

type readiness struct {
	Configured bool `json:"configured"`
	Ready      bool `json:"ready"`
}

type statusPayload struct {
	State              string `json:"state"`
	ContainerHealthy   bool   `json:"container_healthy"`
	FailureCount       int    `json:"failure_count"`
	Restarts           int    `json:"restarts"`
	MaxRestartsPerHour int    `json:"max_restarts_per_hour"`
	LastAction         string `json:"last_action"`
}

type restartEvidence struct {
	Timestamp    int64    `json:"timestamp"`
	Reasons      []string `json:"reasons"`
	FailureCount int      `json:"failure_count"`
	Threshold    int      `json:"threshold"`
}

type failureClass string

const (
	failureClassControlPlane failureClass = "control_plane"
	failureClassDataPlane    failureClass = "dataplane"
)

func OptionsFromEnvironment() Options {
	secrets := envOr("SB_GATEWAY_SECRETS_DIR", "/config/secrets")
	host := envOr("SB_GATEWAY_API_HOST", "127.0.0.1")
	port := envOr("SB_GATEWAY_API_PORT", "8080")
	base := "http://" + host + ":" + port
	return Options{
		TokenFile:       filepath.Join(secrets, "management-api-token"),
		ReadyURL:        base + "/api/health/ready",
		StatusURL:       base + "/api/v1/runtime/watchdog",
		XrayConfig:      envOr("SB_XRAY_CONFIG", "/config/generated/xray.json"),
		XrayReadyFile:   envOr("SB_XRAY_READY_FILE", "/run/sb-gateway/xray-selectors-ready"),
		PolicyDNSConfig: envOr("SB_POLICY_DNS_CONFIG", "/config/generated/policy-dns.json"),
		RouteTable:      envOr("SB_TRANSPARENT_ROUTE_TABLE", "1002"),
		RulePriority:    envOr("SB_TRANSPARENT_RULE_PRIORITY", "1100"),
		TProxyMark:      envOr("SB_TPROXY_MARK", "1"),
		TProxyPort:      envOr("SB_TPROXY_PORT", "12345"),
		SettingsFile:    envOr("SB_WATCHDOG_CONFIG", "/config/generated/watchdog.env"),
		MarkerFile:      envOr("SB_WATCHDOG_MARKER", "/run/sb-gateway/router-ready"),
		ApplyGuardFile:  envOr("SB_APPLY_GUARD", "/run/sb-gateway/apply-in-progress"),
		RestartFile:     envOr("SB_WATCHDOG_RESTART_FILE", "/state/watchdog-restarts"),
		RestartEvidence: envOr("SB_WATCHDOG_RESTART_EVIDENCE", "/state/watchdog-last-restart.json"),
		XrayBinary:      envOr("SB_XRAY_BIN", "xray"),
	}
}

func Run(ctx context.Context, opts Options) error {
	r := &runner{
		opts: opts,
		http: &http.Client{Timeout: 10 * time.Second},
	}
	defer r.clearLease()
	r.clearLease()
	current := r.loadSettings()
	if err := r.pruneRestarts(time.Now()); err != nil {
		log.Printf("watchdog: could not initialize restart history: %v", err)
	}
	r.postState(ctx, current, "starting", true, 0, "watchdog_start")
	// run-xray publishes this marker only after the current Xray process has
	// restored its selectors and installed transparent routing.  Treat the
	// configured startup grace as a maximum, not as an unconditional outage:
	// a ready dataplane should enter the first deep check immediately.
	if !waitForStartupReady(ctx, opts.XrayReadyFile, current.startupGrace) {
		return nil
	}

	failures, successes := 0, 0
	leasePublished := false
	var activeFailureClass failureClass
	for {
		now := time.Now()
		if err := r.pruneRestarts(now); err != nil {
			log.Printf("watchdog: could not refresh restart history: %v", err)
		}
		if r.applyActive(now) {
			r.clearLease()
			leasePublished = false
			failures, successes = 0, 0
			activeFailureClass = ""
			r.nextDeepProbe = time.Time{}
			r.postState(ctx, current, "applying", true, 0, "apply_in_progress")
			if !wait(ctx, current.interval) {
				return nil
			}
			continue
		}

		ready, err := r.readiness(ctx)
		if err == nil && !ready.Configured {
			r.clearLease()
			leasePublished = false
			failures, successes = 0, 0
			activeFailureClass = ""
			r.postState(ctx, current, "starting", true, 0, "awaiting_configuration")
			if !wait(ctx, current.interval) {
				return nil
			}
			continue
		}

		reasons := make([]string, 0, 8)
		if err != nil || !ready.Configured {
			reasons = append(reasons, "api_configured")
		}
		if err != nil || !ready.Ready {
			reasons = append(reasons, "api_ready")
		}
		if !processRunning("xray") {
			reasons = append(reasons, "core_process")
		}
		if !regularNonEmpty(opts.XrayConfig) {
			reasons = append(reasons, "core_config")
		}
		now = time.Now()
		if !r.deepHealthy || r.nextDeepProbe.IsZero() || !now.Before(r.nextDeepProbe) {
			r.runDeepProbe(ctx, current, now)
		}
		if !r.deepHealthy {
			if len(r.deepReasons) == 0 {
				reasons = append(reasons, "deep_probe")
			} else {
				reasons = append(reasons, r.deepReasons...)
			}
			r.nextDeepProbe = time.Time{}
		}

		if len(reasons) == 0 {
			failures = 0
			activeFailureClass = ""
			successes++
			recoveryThreshold := recoverySuccessThreshold(current.recoveryThreshold, leasePublished)
			if successes >= recoveryThreshold {
				if err := publishLease(opts.MarkerFile, now); err != nil {
					log.Printf("watchdog: could not publish readiness lease: %v", err)
				} else {
					leasePublished = true
				}
				r.postState(ctx, current, "healthy", true, 0, "dataplane_ready")
			} else {
				r.postState(ctx, current, "recovering", true, 0, "readiness_hysteresis")
			}
		} else {
			successes = 0
			activeFailureClass, failures = nextFailureStreak(activeFailureClass, failures, reasons)
			controlPlaneOnly := controlPlaneOnlyFailure(reasons)
			restartThreshold := failureThresholdForReasons(current.failureThreshold, reasons)
			lastAction := "dataplane_probe_failed"
			if controlPlaneOnly {
				lastAction = "control_plane_probe_failed"
			}
			r.postState(ctx, current, "degraded", false, failures, lastAction)
			log.Printf("watchdog: readiness failure %d/%d; reasons=%s", failures, restartThreshold, strings.Join(reasons, ","))
			if failures >= restartThreshold {
				r.clearLease()
				if err := r.pruneRestarts(now); err != nil {
					log.Printf("watchdog: could not prune restart history: %v", err)
				}
				if r.restarts >= current.restartBudget {
					r.postState(ctx, current, "degraded", false, failures, "restart_budget_exhausted")
					log.Printf("watchdog: restart budget %d/%d exhausted; staying alive for diagnostics while RouterOS remains fail-open", r.restarts, current.restartBudget)
					failures = 0
				} else {
					if err := r.recordRestart(now, reasons, failures, restartThreshold); err != nil {
						log.Printf("watchdog: could not record restart: %v", err)
					}
					r.postState(ctx, current, "tripped", false, failures, "container_restart")
					log.Printf("watchdog: wedged runtime; terminating container PID 1")
					if err := terminateContainer(); err != nil {
						return fmt.Errorf("terminate container PID 1: %w", err)
					}
					return nil
				}
			}
		}

		if !wait(ctx, current.interval) {
			return nil
		}
	}
}

func waitForStartupReady(ctx context.Context, marker string, maximum time.Duration) bool {
	if marker == "" || maximum <= 0 {
		return ctx.Err() == nil
	}
	deadline := time.NewTimer(maximum)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if regularNonEmpty(marker) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return true
		case <-ticker.C:
		}
	}
}

func recoverySuccessThreshold(configured int, leasePublished bool) int {
	if !leasePublished {
		// The first comprehensive success follows the process-bound Xray
		// startup marker, so repeating it only delays restored traffic.
		return 1
	}
	return configured
}

// A temporarily starved management API must not tear down healthy proxy
// sessions. Process, configuration, listener, TPROXY, route and DNS failures keep
// the normal fast threshold. If only the local readiness endpoint is degraded,
// RouterOS can withdraw its readiness lease while the established dataplane is
// given a longer opportunity to recover.
func failureThresholdForReasons(base int, reasons []string) int {
	if !controlPlaneOnlyFailure(reasons) {
		return base
	}
	if base < controlPlaneThreshold {
		return controlPlaneThreshold
	}
	return base
}

func controlPlaneOnlyFailure(reasons []string) bool {
	if len(reasons) == 0 {
		return false
	}
	for _, reason := range reasons {
		if reason != "api_configured" && reason != "api_ready" {
			return false
		}
	}
	return true
}

func classifyFailure(reasons []string) failureClass {
	if controlPlaneOnlyFailure(reasons) {
		return failureClassControlPlane
	}
	return failureClassDataPlane
}

func nextFailureStreak(previous failureClass, count int, reasons []string) (failureClass, int) {
	current := classifyFailure(reasons)
	if current != previous {
		return current, 1
	}
	return current, count + 1
}

func (r *runner) loadSettings() settings {
	values := map[string]string{
		"SB_WATCHDOG_INTERVAL_SECONDS":            envOr("SB_WATCHDOG_INTERVAL_SECONDS", strconv.Itoa(defaultInterval)),
		"SB_WATCHDOG_FAILURE_THRESHOLD":           envOr("SB_WATCHDOG_FAILURE_THRESHOLD", strconv.Itoa(defaultFailureThreshold)),
		"SB_WATCHDOG_RECOVERY_THRESHOLD":          envOr("SB_WATCHDOG_RECOVERY_THRESHOLD", strconv.Itoa(defaultRecoveryThreshold)),
		"SB_WATCHDOG_MAX_RESTARTS_PER_HOUR":       envOr("SB_WATCHDOG_MAX_RESTARTS_PER_HOUR", strconv.Itoa(defaultRestartBudget)),
		"SB_WATCHDOG_DEEP_PROBE_INTERVAL_SECONDS": envOr("SB_WATCHDOG_DEEP_PROBE_INTERVAL_SECONDS", strconv.Itoa(defaultDeepInterval)),
		"SB_WATCHDOG_STARTUP_GRACE_SECONDS":       envOr("SB_WATCHDOG_STARTUP_GRACE_SECONDS", strconv.Itoa(defaultStartupGrace)),
	}
	if parsed, err := parseSettingsFile(r.opts.SettingsFile); err == nil {
		for key, value := range parsed {
			if _, known := values[key]; known && key != "SB_WATCHDOG_STARTUP_GRACE_SECONDS" {
				values[key] = value
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("watchdog: settings ignored: %v", err)
	}
	return settings{
		interval:          time.Duration(boundedInt(values["SB_WATCHDOG_INTERVAL_SECONDS"], defaultInterval, 5, 300)) * time.Second,
		failureThreshold:  boundedInt(values["SB_WATCHDOG_FAILURE_THRESHOLD"], defaultFailureThreshold, 1, 20),
		recoveryThreshold: boundedInt(values["SB_WATCHDOG_RECOVERY_THRESHOLD"], defaultRecoveryThreshold, 1, 20),
		restartBudget:     boundedInt(values["SB_WATCHDOG_MAX_RESTARTS_PER_HOUR"], defaultRestartBudget, 1, 60),
		deepInterval:      time.Duration(boundedInt(values["SB_WATCHDOG_DEEP_PROBE_INTERVAL_SECONDS"], defaultDeepInterval, 10, 300)) * time.Second,
		startupGrace:      time.Duration(boundedInt(values["SB_WATCHDOG_STARTUP_GRACE_SECONDS"], defaultStartupGrace, 0, 300)) * time.Second,
	}
}

func parseSettingsFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := make(map[string]string)
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), "\"'")
		result[key] = value
	}
	return result, nil
}

func (r *runner) readiness(ctx context.Context) (readiness, error) {
	var result readiness
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.opts.ReadyURL, nil)
	if err != nil {
		return result, err
	}
	if token := readToken(r.opts.TokenFile); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := r.http.Do(request)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, fmt.Errorf("readiness returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	return result, nil
}

func (r *runner) postState(ctx context.Context, current settings, state string, healthy bool, failures int, action string) {
	payload := statusPayload{state, healthy, failures, r.restarts, current.restartBudget, action}
	signature := fmt.Sprintf("%s:%t:%d:%d:%d:%s", state, healthy, failures, r.restarts, current.restartBudget, action)
	now := time.Now()
	if signature == r.lastPostSignature && now.Sub(r.lastPostAt) >= 0 && now.Sub(r.lastPostAt) < statusHeartbeat {
		return
	}
	token := readToken(r.opts.TokenFile)
	if token == "" {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.opts.StatusURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := r.http.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		r.lastPostSignature = signature
		r.lastPostAt = now
	}
}

func (r *runner) runDeepProbe(ctx context.Context, current settings, now time.Time) {
	reasons := make([]string, 0, 12)
	mark := func(reason string) { reasons = append(reasons, reason) }
	configFileSignature, configSignature, err := fileSignature(
		r.opts.XrayConfig,
		r.configFileSignature,
		r.listenerSignature,
	)
	if err != nil {
		mark("core_config")
	} else if configSignature != r.listenerSignature {
		parsed, parseErr := parseXrayListeners(r.opts.XrayConfig)
		if parseErr != nil {
			mark("listener_inventory")
		} else {
			r.listeners = parsed
			r.listenerSignature = configSignature
			r.configFileSignature = configFileSignature
		}
	} else {
		r.configFileSignature = configFileSignature
	}
	tcpPorts, tcpErr := procListeningPorts("tcp")
	udpPorts, udpErr := procListeningPorts("udp")
	if tcpErr != nil {
		mark("tcp_listener_inventory")
	}
	if udpErr != nil {
		mark("udp_listener_inventory")
	}
	for _, item := range r.listeners {
		if item.protocol == "udp" {
			if _, ok := udpPorts[item.port]; !ok {
				mark("udp_listener")
			}
		} else if _, ok := tcpPorts[item.port]; !ok {
			mark("tcp_listener")
		}
	}

	dnsFileSignature, dnsSignature, err := fileSignature(
		r.opts.PolicyDNSConfig,
		r.dnsFileSignature,
		r.dnsSignature,
	)
	if err != nil {
		mark("dns_lane_config")
	} else if dnsSignature != r.dnsSignature {
		ports, parseErr := parseDNSPorts(r.opts.PolicyDNSConfig)
		if parseErr != nil {
			mark("dns_lane_inventory")
		} else {
			r.dnsPorts = ports
			r.dnsSignature = dnsSignature
			r.dnsFileSignature = dnsFileSignature
		}
	} else {
		r.dnsFileSignature = dnsFileSignature
	}
	for _, port := range r.dnsPorts {
		if _, ok := tcpPorts[port]; !ok {
			mark("dns_lane_tcp")
		}
		if _, ok := udpPorts[port]; !ok {
			mark("dns_lane_udp")
		}
	}

	if output, err := commandOutput(ctx, 5*time.Second, "ip", "rule", "show"); err != nil || !hasPolicyRule(string(output), r.opts.RulePriority, r.opts.RouteTable, r.opts.TProxyMark) {
		mark("tproxy_policy_rule")
	}
	if output, err := commandOutput(ctx, 5*time.Second, "ip", "route", "show", "table", r.opts.RouteTable); err != nil || !strings.Contains(string(output), "local default dev lo") {
		mark("tproxy_local_route")
	}
	if output, err := commandOutput(ctx, 5*time.Second, "nft", "list", "table", "inet", "sb_gateway_transparent"); err != nil || !hasTransparentRules(string(output), r.opts.TProxyPort) {
		mark("transparent_nft")
	}

	if configSignature != "" && configSignature != r.checkedConfigSignature {
		if _, err := commandOutput(ctx, 60*time.Second, r.opts.XrayBinary, "run", "-test", "-config", r.opts.XrayConfig); err != nil {
			mark("config_validation")
		} else {
			r.checkedConfigSignature = configSignature
		}
	}
	r.deepReasons = reasons
	r.deepHealthy = len(reasons) == 0
	r.nextDeepProbe = now.Add(current.deepInterval)
}

func parseXrayListeners(path string) ([]listener, error) {
	var config struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Network  string `json:"network"`
			Port     int    `json:"port"`
			Settings struct {
				Network string `json:"network"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := readJSON(path, &config); err != nil {
		return nil, err
	}
	result := make([]listener, 0, len(config.Inbounds))
	for _, inbound := range config.Inbounds {
		if inbound.Port < 1 || inbound.Port > 65535 {
			continue
		}
		protocol := "tcp"
		if inbound.Protocol == "hysteria" || inbound.Protocol == "hysteria2" || inbound.Network == "udp" {
			protocol = "udp"
		}
		result = append(result, listener{protocol: protocol, port: inbound.Port})
		if inbound.Protocol == "dokodemo-door" && strings.Contains(inbound.Settings.Network, "udp") {
			result = append(result, listener{protocol: "udp", port: inbound.Port})
		}
	}
	return result, nil
}

func parseDNSPorts(path string) ([]int, error) {
	var config struct {
		Lanes []struct {
			Port json.RawMessage `json:"port"`
		} `json:"lanes"`
	}
	if err := readJSON(path, &config); err != nil {
		return nil, err
	}
	result := make([]int, 0, len(config.Lanes))
	for _, lane := range config.Lanes {
		var port int
		if json.Unmarshal(lane.Port, &port) == nil && port >= 1 && port <= 65535 {
			result = append(result, port)
		}
	}
	return result, nil
}

func procListeningPorts(protocol string) (map[int]struct{}, error) {
	paths := []string{"/proc/net/" + protocol, "/proc/net/" + protocol + "6"}
	result := make(map[int]struct{})
	var firstErr error
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || !strings.Contains(fields[1], ":") {
				continue
			}
			state := fields[3]
			if protocol == "tcp" && state != "0A" {
				continue
			}
			if protocol == "udp" && state != "07" {
				continue
			}
			_, portHex, _ := strings.Cut(fields[1], ":")
			port, parseErr := strconv.ParseInt(portHex, 16, 32)
			if parseErr == nil && port > 0 && port <= 65535 {
				result[int(port)] = struct{}{}
			}
		}
		if err := scanner.Err(); err != nil && firstErr == nil {
			firstErr = err
		}
		_ = file.Close()
	}
	if len(result) > 0 {
		return result, nil
	}
	return result, firstErr
}

func hasPolicyRule(output, priority, table, mark string) bool {
	expectedMark, err := strconv.ParseUint(mark, 10, 32)
	if err != nil {
		return false
	}
	prefix := priority + ":"
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		matchedTable, matchedMark := false, false
		for index := 0; index+1 < len(fields); index++ {
			if fields[index] == "lookup" && fields[index+1] == table {
				matchedTable = true
			}
			if fields[index] == "fwmark" {
				raw, _, _ := strings.Cut(fields[index+1], "/")
				parsed, parseErr := strconv.ParseUint(raw, 0, 32)
				matchedMark = parseErr == nil && parsed == expectedMark
			}
		}
		if matchedTable && matchedMark {
			return true
		}
	}
	return false
}

func hasTransparentRules(output, port string) bool {
	target := "tproxy to :" + port
	return strings.Contains(output, "meta l4proto tcp "+target) &&
		strings.Contains(output, "meta l4proto udp "+target)
}

func (r *runner) applyActive(now time.Time) bool {
	data, err := os.ReadFile(r.opts.ApplyGuardFile)
	if err != nil {
		return false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 || len(fields) > 3 {
		_ = os.Remove(r.opts.ApplyGuardFile)
		return false
	}
	pid64, errPID := strconv.ParseInt(fields[0], 10, 32)
	started, errStarted := strconv.ParseInt(fields[1], 10, 64)
	refreshed := started
	var errRefreshed error
	if len(fields) == 3 {
		refreshed, errRefreshed = strconv.ParseInt(fields[2], 10, 64)
	}
	if errPID != nil || errStarted != nil || errRefreshed != nil {
		_ = os.Remove(r.opts.ApplyGuardFile)
		return false
	}
	totalAge := now.Unix() - started
	heartbeatAge := now.Unix() - refreshed
	pid := int(pid64)
	if totalAge >= 0 && totalAge <= 1800 && heartbeatAge >= 0 && heartbeatAge <= 90 && processExists(pid) {
		return true
	}
	_ = os.Remove(r.opts.ApplyGuardFile)
	return false
}

func processRunning(name string) bool {
	paths, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(data)) == name {
			return true
		}
	}
	return false
}

func processExists(pid int) bool {
	if pid < 1 {
		return false
	}
	return processIDExists(pid)
}

func (r *runner) pruneRestarts(now time.Time) error {
	data, err := os.ReadFile(r.opts.RestartFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cutoff := now.Add(-time.Hour).Unix()
	valid := make([]int64, 0)
	for _, line := range strings.Split(string(data), "\n") {
		value, parseErr := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
		if parseErr == nil && value > cutoff && value <= now.Unix() {
			valid = append(valid, value)
		}
	}
	r.restarts = len(valid)
	normalized := timestampBody(valid)
	if (errors.Is(err, os.ErrNotExist) && len(valid) == 0) ||
		(err == nil && bytes.Equal(data, normalized)) {
		return nil
	}
	return atomicWrite(r.opts.RestartFile, normalized, 0o600)
}

func (r *runner) recordRestart(now time.Time, reasons []string, failures, threshold int) error {
	data, _ := os.ReadFile(r.opts.RestartFile)
	values := make([]int64, 0, r.restarts+1)
	for _, line := range strings.Split(string(data), "\n") {
		value, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
		if err == nil {
			values = append(values, value)
		}
	}
	values = append(values, now.Unix())
	if err := writeTimestamps(r.opts.RestartFile, values); err != nil {
		return err
	}
	r.restarts++
	evidence, err := json.Marshal(restartEvidence{
		Timestamp: now.Unix(), Reasons: append([]string(nil), reasons...),
		FailureCount: failures, Threshold: threshold,
	})
	if err != nil {
		return err
	}
	return atomicWrite(r.opts.RestartEvidence, append(evidence, '\n'), 0o600)
}

func writeTimestamps(path string, values []int64) error {
	return atomicWrite(path, timestampBody(values), 0o600)
}

func timestampBody(values []int64) []byte {
	var body strings.Builder
	for _, value := range values {
		fmt.Fprintf(&body, "%d\n", value)
	}
	return []byte(body.String())
}

func publishLease(path string, now time.Time) error {
	return atomicWrite(path, []byte(strconv.FormatInt(now.Unix(), 10)+"\n"), 0o644)
}

func (r *runner) clearLease() {
	if err := os.Remove(r.opts.MarkerFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("watchdog: could not clear readiness lease: %v", err)
	}
}

func atomicWrite(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func commandOutput(parent context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(io.LimitReader(file, 16<<20)).Decode(destination)
}

func fileSignature(path, previousFileSignature, previousContentSignature string) (string, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", "", errors.New("file is empty or not regular")
	}
	currentFileSignature := fmt.Sprintf("%d|%d", info.ModTime().UnixNano(), info.Size())
	if currentFileSignature == previousFileSignature && previousContentSignature != "" {
		return currentFileSignature, previousContentSignature, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	if len(data) == 0 {
		return "", "", errors.New("file is empty")
	}
	sum := sha256.Sum256(data)
	return currentFileSignature, hex.EncodeToString(sum[:]), nil
}

func regularNonEmpty(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func readToken(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func boundedInt(value string, fallback, minimum, maximum int) int {
	if len(value) > 5 {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func wait(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
