package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type xraySelectorRuntime struct {
	opts              Options
	command           xrayCommandRunner
	pool              healthPool
	poolSignature     string
	poolFileSignature string
	xrayPID           int
	loadedDynamic     map[string]bool
	verifiedDynamic   map[string]time.Time
	activeByPolicy    map[string]string
	activeByNode      map[string]string
	retiredByPolicy   map[string][]string
	selectorMembers   map[string]string
	probeRuntimeTag   string
	probeSelector     string
	probeContext      context.Context
}

func (runtime *xraySelectorRuntime) requestContext() context.Context {
	ctx := context.Background()
	if runtime.probeContext != nil {
		ctx = runtime.probeContext
	}
	if runtime.probeSelector != "" {
		return backgroundXrayCommandContext(ctx)
	}
	return ctx
}

func (runtime *xraySelectorRuntime) probeSelectorName() string {
	if runtime.probeSelector != "" {
		return runtime.probeSelector
	}
	return "outbound-health-probe"
}

type xrayCommandRunner func(context.Context, time.Duration, string, ...string) ([]byte, error)

var (
	underlayWANTargets          = []string{"1.1.1.1:443", "9.9.9.9:443", "www.gstatic.com:443"}
	availabilityProbeTimeout    = 2 * time.Second
	availabilityFallbackTimeout = 3 * time.Second
)

func newXraySelectorRuntime(opts Options) *xraySelectorRuntime {
	return &xraySelectorRuntime{
		opts:            opts,
		command:         runXrayCommand,
		loadedDynamic:   make(map[string]bool),
		verifiedDynamic: make(map[string]time.Time),
		activeByPolicy:  make(map[string]string),
		activeByNode:    make(map[string]string),
		retiredByPolicy: make(map[string][]string),
		selectorMembers: make(map[string]string),
	}
}

func (runtime *xraySelectorRuntime) Reload() (healthPool, bool, error) {
	info, err := os.Stat(runtime.opts.HealthPoolFile)
	if err != nil {
		return healthPool{}, false, err
	}
	fileSignature := fmt.Sprintf("%d|%d", info.ModTime().UnixNano(), info.Size())
	signature := runtime.poolSignature
	changed := runtime.poolSignature == "" || fileSignature != runtime.poolFileSignature
	var body []byte
	if changed {
		body, err = os.ReadFile(runtime.opts.HealthPoolFile)
		if err != nil {
			return healthPool{}, false, err
		}
		sum := sha256.Sum256(body)
		signature = hex.EncodeToString(sum[:])
	}
	pid := readyProcessPID(runtime.opts.XrayReadyFile, "xray")
	if runtime.opts.XrayReadyFile != "" && (pid != runtime.xrayPID || runtime.poolSignature == "") {
		// Only once per core start, not per probe: the startup helper must pin
		// the saved leaf before health may read back and replace persisted state.
		if pid <= 0 {
			return healthPool{}, false, errors.New("Xray startup selectors are not ready")
		}
	}
	pidChanged := pid != runtime.xrayPID
	contractChanged := signature != runtime.poolSignature
	reset := pidChanged || contractChanged
	if changed && signature != runtime.poolSignature {
		var pool healthPool
		if err := json.Unmarshal(body, &pool); err != nil {
			return healthPool{}, false, err
		}
		if pool.Version < 3 {
			return healthPool{}, false, fmt.Errorf("health pool contract predates the 1.6.15 release baseline")
		}
		runtime.pool = pool
		runtime.poolSignature = signature
	}
	if changed {
		runtime.poolFileSignature = fileSignature
	}
	if pidChanged {
		runtime.xrayPID = pid
		runtime.loadedDynamic = make(map[string]bool)
		runtime.verifiedDynamic = make(map[string]time.Time)
		runtime.activeByPolicy = make(map[string]string)
		runtime.activeByNode = make(map[string]string)
		runtime.retiredByPolicy = make(map[string][]string)
		runtime.selectorMembers = make(map[string]string)
		runtime.probeRuntimeTag = ""
	} else if contractChanged {
		// A subscription generation can retire handlers without restarting Xray.
		// Never carry an existence readback across that boundary.
		runtime.verifiedDynamic = make(map[string]time.Time)
	}
	// Retry deferred handler removal during the ordinary health loop, even
	// when the selected node remains stable after a transient Xray API error.
	for policyID := range runtime.retiredByPolicy {
		runtime.pruneRetiredOutbounds(policyID)
	}
	return runtime.pool, reset, nil
}

func xrayStartupReady(path string, pid int) bool {
	ready, err := os.ReadFile(path)
	return err == nil && pid > 0 && strings.TrimSpace(string(ready)) == strconv.Itoa(pid)
}

// The startup helper writes the PID of the long-lived Xray core only after it
// restores selectors and admits traffic. Trust that marker after validating
// the referenced process instead of scanning by comm: short-lived `xray api`
// clients use the same comm and can otherwise be mistaken for the core.
func readyProcessPID(path, name string) int {
	return readyProcessPIDAt("/proc", path, name)
}

func readyProcessPIDAt(root, path, name string) int {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil || pid <= 0 {
		return 0
	}
	directory := filepath.Join(root, strconv.Itoa(pid))
	comm, err := os.ReadFile(filepath.Join(directory, "comm"))
	if err != nil || strings.TrimSpace(string(comm)) != name {
		return 0
	}
	stat, err := os.ReadFile(filepath.Join(directory, "stat"))
	if err != nil {
		return 0
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return 0
	}
	fields := strings.Fields(string(stat)[end+1:])
	if len(fields) == 0 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return 0
	}
	return pid
}

func (runtime *xraySelectorRuntime) Select(selector, member string) error {
	runtimeMember := member
	_, policySelector := runtime.pool.Policies[selector]
	if selector == runtime.probeSelectorName() {
		var err error
		runtimeMember, err = runtime.probeTag(member)
		if err != nil {
			return err
		}
	} else if policySelector && member != "block" && member != "direct-wan" {
		expected := runtime.policyRuntimeTag(selector, member)
		if runtime.selectorMembers[selector] == "" {
			if actual, readErr := runtime.selectedRuntimeMember(selector); readErr == nil {
				runtime.selectorMembers[selector] = actual
			}
		}
		if expected != member && runtime.selectorMembers[selector] == expected {
			// The cold-start helper restores the selected dynamic handler before
			// the agent is admitted. Adopt that live handler instead of asking
			// HandlerService to add the same deterministic tag a second time.
			present, err := runtime.outboundPresent(expected)
			if err != nil {
				return err
			}
			if present {
				runtime.loadedDynamic[expected] = true
				runtime.verifiedDynamic[expected] = time.Now()
			} else if err := runtime.ensureOutbound(member, expected); err != nil {
				// The selector kept its override but its handler disappeared.
				return err
			}
			runtimeMember = expected
		} else {
			var err error
			runtimeMember, err = runtime.policyTag(selector, member)
			if err != nil {
				return err
			}
		}
	}
	if runtime.selectorMembers[selector] == runtimeMember {
		if policySelector {
			return runtime.commitPolicySelection(selector, member, runtimeMember)
		}
		return nil
	}
	if _, err := runtime.command(runtime.requestContext(), 5*time.Second, runtime.opts.XrayBinary, "api", "bo", "--server="+runtime.opts.XrayAPIServer, "-b", selector, runtimeMember); err != nil {
		return fmt.Errorf("Xray rejected selector update: %w", err)
	}
	actual, err := runtime.selectedRuntimeMember(selector)
	if err != nil {
		delete(runtime.selectorMembers, selector)
		return err
	}
	if actual != runtimeMember {
		delete(runtime.selectorMembers, selector)
		return fmt.Errorf("Xray selector %q remained on %q instead of %q", selector, actual, runtimeMember)
	}
	runtime.selectorMembers[selector] = runtimeMember
	if policySelector {
		if err := runtime.commitPolicySelection(selector, member, runtimeMember); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *xraySelectorRuntime) Current(selector string) (string, error) {
	member, err := runtime.selectedRuntimeMember(selector)
	if err != nil {
		return "", err
	}
	if member == "" {
		delete(runtime.selectorMembers, selector)
		return "", nil
	}
	runtime.selectorMembers[selector] = member
	if member == "block" || member == "direct-wan" {
		return member, nil
	}
	if contract, exists := runtime.pool.HealthPolicies[selector]; exists {
		prefix := runtime.pool.PolicyPrefixes[selector]
		if prefix == "" {
			prefix = "sb-urltest-" + shortHash(selector, 12) + "-"
		}
		for _, candidate := range contract.Candidates {
			if member == candidate {
				return candidate, nil
			}
			if member == runtime.dynamicTag(prefix, candidate) {
				if err := runtime.ensureOutbound(candidate, member); err != nil {
					return "", err
				}
				return candidate, nil
			}
		}
		// A freshly published health contract may remove the active candidate.
		// The dynamic outbound is still alive in Xray and all node definitions
		// remain in the pool, so decode it before asking the controller to move.
		for candidate := range runtime.pool.Outbounds {
			if member == runtime.dynamicTag(prefix, candidate) {
				if err := runtime.ensureOutbound(candidate, member); err != nil {
					return "", err
				}
				return candidate, nil
			}
		}
	}
	for node, runtimeTag := range runtime.activeByNode {
		if runtimeTag == member {
			if runtime.pool.Outbounds[node] != nil && !runtime.isBase(node) {
				if runtime.policyRuntimeTag(selector, node) != member {
					return "", errors.New("Xray selected outbound belongs to an obsolete node generation")
				}
				if err := runtime.ensureOutbound(node, member); err != nil {
					return "", err
				}
			}
			return node, nil
		}
	}
	return member, nil
}

func (runtime *xraySelectorRuntime) selectedRuntimeMember(selector string) (string, error) {
	output, err := runtime.command(runtime.requestContext(), 5*time.Second, runtime.opts.XrayBinary, "api", "bi", "--server="+runtime.opts.XrayAPIServer, selector)
	if err != nil {
		return "", errors.New("Xray selector state is unavailable")
	}
	section := false
	for _, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "Selecting Override:") {
			section = true
			continue
		}
		if section && strings.HasPrefix(trimmed, "- Selects:") {
			break
		}
		if !section || trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			return fields[len(fields)-1], nil
		}
	}
	return "", nil
}

func (runtime *xraySelectorRuntime) policyTag(policyID, nodeID string) (string, error) {
	tag := runtime.policyRuntimeTag(policyID, nodeID)
	if tag == nodeID {
		runtime.activeByNode[nodeID] = nodeID
		return nodeID, nil
	}
	if err := runtime.ensureOutbound(nodeID, tag); err != nil {
		return "", err
	}
	return tag, nil
}

func (runtime *xraySelectorRuntime) policyRuntimeTag(policyID, nodeID string) string {
	if runtime.isBase(nodeID) || runtime.pool.Outbounds[nodeID] == nil {
		return nodeID
	}
	prefix := runtime.pool.PolicyPrefixes[policyID]
	if prefix == "" {
		prefix = "sb-urltest-" + shortHash(policyID, 12) + "-"
	}
	return runtime.dynamicTag(prefix, nodeID)
}

// commitPolicySelection retires an old handler only after Xray confirms that
// the selector points at the replacement. Removing it earlier creates a small
// window where new streams have no usable outbound.
func (runtime *xraySelectorRuntime) commitPolicySelection(policyID, nodeID, runtimeTag string) error {
	prefix := runtime.pool.PolicyPrefixes[policyID]
	if prefix == "" {
		prefix = "sb-urltest-" + shortHash(policyID, 12) + "-"
	}
	previous := runtime.activeByPolicy[policyID]
	runtime.activeByPolicy[policyID] = runtimeTag
	if nodeID != "" {
		runtime.activeByNode[nodeID] = runtimeTag
	}
	retired := runtime.retiredByPolicy[policyID]
	// A previously retired handler can become active again. Never remove the
	// newly selected handler while trimming older generations.
	if len(retired) != 0 {
		remaining := retired[:0]
		for _, tag := range retired {
			if tag != runtimeTag {
				remaining = append(remaining, tag)
			}
		}
		retired = remaining
	}
	if previous != "" && previous != runtimeTag && strings.HasPrefix(previous, prefix) {
		if !contains(retired, previous) {
			retired = append(retired, previous)
		}
	}
	runtime.retiredByPolicy[policyID] = retired
	runtime.pruneRetiredOutbounds(policyID)
	return nil
}

func (runtime *xraySelectorRuntime) pruneRetiredOutbounds(policyID string) {
	retired := runtime.retiredByPolicy[policyID]
	// Keep the newest retired handler for existing connections. An older
	// removal failure retains ownership and is retried on the next health tick.
	for len(retired) > 1 {
		if err := runtime.removeOutbound(retired[0]); err != nil {
			break
		}
		retired = retired[1:]
	}
	runtime.retiredByPolicy[policyID] = retired
}

func (runtime *xraySelectorRuntime) probeTag(nodeID string) (string, error) {
	if nodeID == "block" || nodeID == "direct-wan" || runtime.isBase(nodeID) {
		return nodeID, nil
	}
	if tag := runtime.activeByNode[nodeID]; tag != "" {
		if tag == nodeID {
			return tag, nil
		}
		if runtime.loadedDynamic[tag] && time.Since(runtime.verifiedDynamic[tag]) < time.Second {
			return tag, nil
		}
		present, err := runtime.outboundPresent(tag)
		if err != nil {
			return "", err
		}
		if present {
			runtime.loadedDynamic[tag] = true
			runtime.verifiedDynamic[tag] = time.Now()
			return tag, nil
		}
		// A selector can outlive its HandlerService outbound. Probe the
		// current subscription definition instead of reusing that stale tag.
		delete(runtime.activeByNode, nodeID)
		delete(runtime.loadedDynamic, tag)
		delete(runtime.verifiedDynamic, tag)
	}
	if runtime.pool.Outbounds[nodeID] == nil {
		return nodeID, nil
	}
	tag := "sb-urltest-probe-" + runtime.dynamicDigest(nodeID)
	if runtime.probeSelector != "" {
		// Every parallel lane owns and retires only its own dynamic handler.
		// Reusing one tag across lanes lets a later batch remove an outbound
		// which another lane is still probing.
		tag = "sb-health-" + shortHash(runtime.probeSelector, 8) + "-" + runtime.dynamicDigest(nodeID)
	}
	if runtime.probeRuntimeTag != "" && runtime.probeRuntimeTag != tag {
		if err := runtime.removeOutbound(runtime.probeRuntimeTag); err != nil {
			return "", err
		}
	}
	if err := runtime.ensureOutbound(nodeID, tag); err != nil {
		return "", err
	}
	runtime.probeRuntimeTag = tag
	return tag, nil
}

func (runtime *xraySelectorRuntime) dynamicTag(prefix, nodeID string) string {
	return runtimeconfig.DynamicOutboundTag(prefix, nodeID, runtime.pool.Outbounds[nodeID])
}

func (runtime *xraySelectorRuntime) dynamicDigest(nodeID string) string {
	return shortHash(nodeID+"\x00"+string(runtime.pool.Outbounds[nodeID]), 12)
}

func (runtime *xraySelectorRuntime) ensureOutbound(nodeID, tag string) error {
	repair := runtime.loadedDynamic[tag]
	if repair {
		if time.Since(runtime.verifiedDynamic[tag]) < time.Second {
			return nil
		}
		present, err := runtime.outboundPresent(tag)
		if err != nil {
			return err
		}
		if present {
			runtime.verifiedDynamic[tag] = time.Now()
			return nil
		}
		delete(runtime.loadedDynamic, tag)
		delete(runtime.verifiedDynamic, tag)
	}
	// A fresh tag needs only AddOutbound's success acknowledgement. Avoid two
	// full handler listings per candidate during a parallel emergency batch.
	var outbound map[string]any
	if err := json.Unmarshal(runtime.pool.Outbounds[nodeID], &outbound); err != nil {
		return err
	}
	outbound["tag"] = tag
	body, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp("", "sb-urltest-*.json")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(body, '\n')); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	output, commandErr := runtime.command(runtime.requestContext(), 5*time.Second, runtime.opts.XrayBinary, "api", "ado", "--server="+runtime.opts.XrayAPIServer, path)
	if commandErr != nil && !strings.Contains(strings.ToLower(string(output)), "already") {
		return errors.New("Xray rejected dynamic outbound")
	}
	if repair || commandErr != nil {
		present, err := runtime.outboundPresent(tag)
		if err != nil || !present {
			return errors.New("Xray dynamic outbound was not confirmed after add")
		}
	}
	runtime.loadedDynamic[tag] = true
	runtime.verifiedDynamic[tag] = time.Now()
	return nil
}

func (runtime *xraySelectorRuntime) outboundPresent(tag string) (bool, error) {
	output, err := runtime.command(runtime.requestContext(), 5*time.Second, runtime.opts.XrayBinary,
		"api", "lso", "--server="+runtime.opts.XrayAPIServer)
	if err != nil {
		return false, errors.New("Xray outbound list is unavailable")
	}
	var response struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(output, &response) != nil || response.Outbounds == nil {
		return false, errors.New("Xray outbound list is invalid")
	}
	for _, outbound := range response.Outbounds {
		if outbound.Tag == tag {
			return true, nil
		}
	}
	return false, nil
}

func (runtime *xraySelectorRuntime) removeOutbound(tag string) error {
	if tag == "" {
		return nil
	}
	if !runtime.loadedDynamic[tag] {
		return nil
	}
	if _, err := runtime.command(runtime.requestContext(), 5*time.Second, runtime.opts.XrayBinary, "api", "rmo", "--server="+runtime.opts.XrayAPIServer, tag); err != nil {
		// Retain ownership so the next job retries cleanup after cancellation.
		return errors.New("Xray outbound cleanup was not confirmed")
	}
	delete(runtime.loadedDynamic, tag)
	delete(runtime.verifiedDynamic, tag)
	for node, value := range runtime.activeByNode {
		if value == tag {
			delete(runtime.activeByNode, node)
		}
	}
	for selector, member := range runtime.selectorMembers {
		if member == tag {
			delete(runtime.selectorMembers, selector)
		}
	}
	if runtime.probeRuntimeTag == tag {
		runtime.probeRuntimeTag = ""
	}
	return nil
}

func (runtime *xraySelectorRuntime) isBase(tag string) bool {
	for _, value := range runtime.pool.BaseOutboundTags {
		if value == tag {
			return true
		}
	}
	return false
}

func (runtime *xraySelectorRuntime) Probe(candidate string) probeEvidence {
	return runtime.probe(candidate, false)
}

func (runtime *xraySelectorRuntime) ProbeAvailability(candidate string) probeEvidence {
	return runtime.probe(candidate, true)
}

func (runtime *xraySelectorRuntime) probe(candidate string, availabilityOnly bool) probeEvidence {
	evidence := probeEvidence{Targets: make(map[string]*int), TargetFailures: make(map[string]probeFailureClass)}
	// Reverse bridge outbounds exist only while the matching client has an
	// online session. Selecting an offline bridge is accepted by the balancer
	// API but every probe then reaches a non-existent outbound and Xray logs a
	// misleading warning. Treat the online counter as the liveness gate before
	// touching either probe selector.
	if runtime.isReverse(candidate) && !runtime.reverseOnline(candidate) {
		evidence.Failure = probeFailureFatal
		return evidence
	}
	delays := []int{}
	if err := runtime.Select(runtime.probeSelectorName(), candidate); err != nil {
		evidence.Failure = classifyProbeError(err)
		return evidence
	}
	if availabilityOnly {
		return runtime.probeAvailabilityTargets(evidence)
	}
	failures := []probeFailureClass{}
	for _, target := range healthTargets {
		started := time.Now()
		_, err := downloadThroughProxyContext(runtime.requestContext(), runtime.opts.ProbeURL, target.url, 5*time.Second, 1024, target.status)
		delay := maxInt(1, int(time.Since(started).Milliseconds()))
		if err != nil {
			evidence.Targets[target.label] = nil
			classified := classifyProbeError(err)
			evidence.TargetFailures[target.label] = classified
			failures = append(failures, classified)
			// A single public HTTPS target can fail independently of the VLESS
			// node. Confirm an availability failure against another origin before
			// the controller is allowed to move the live selector.
			if len(failures) >= 2 &&
				(classifyTargetFailures(failures) == probeFailureFatal || classifyTargetFailures(failures) == probeFailureTLS) {
				break
			}
		} else {
			copy := delay
			evidence.Targets[target.label] = &copy
			delays = append(delays, delay)
		}
	}
	if len(delays) > 0 {
		value := medianInt(delays)
		evidence.OK = true
		evidence.DelayMS = &value
	} else {
		evidence.Failure = classifyTargetFailures(failures)
	}
	return evidence
}

// Keep the healthy fast path to one request. If it fails, give both remaining
// independent origins a bounded chance in parallel. A slow public endpoint
// must not make a working outbound look dead, and a real outage must not wait
// for three serial HTTP timeouts. Join canceled requests before the selector
// can be reused for another candidate.
func (runtime *xraySelectorRuntime) probeAvailabilityTargets(evidence probeEvidence) probeEvidence {
	type targetResult struct {
		label   string
		delayMS int
		err     error
	}
	probe := func(ctx context.Context, index int, timeout time.Duration) targetResult {
		target := healthTargets[index]
		started := time.Now()
		_, err := downloadThroughProxyContext(ctx, runtime.opts.ProbeURL, target.url, timeout, 1024, target.status)
		return targetResult{label: target.label, delayMS: maxInt(1, int(time.Since(started).Milliseconds())), err: err}
	}
	failures := make([]probeFailureClass, 0, len(healthTargets))
	record := func(result targetResult) bool {
		if result.err == nil {
			delay := result.delayMS
			evidence.Targets[result.label] = &delay
			evidence.OK = true
			evidence.DelayMS = &delay
			return true
		}
		evidence.Targets[result.label] = nil
		failure := classifyProbeError(result.err)
		evidence.TargetFailures[result.label] = failure
		failures = append(failures, failure)
		return false
	}
	if len(healthTargets) == 0 {
		evidence.Failure = probeFailureTransient
		return evidence
	}
	if record(probe(runtime.requestContext(), 0, availabilityProbeTimeout)) {
		return evidence
	}

	// Production has two fallbacks. Cap fanout if more targets are added later.
	count := minInt(len(healthTargets)-1, 2)
	ctx, cancel := context.WithCancel(runtime.requestContext())
	defer cancel()
	results := make(chan targetResult, count)
	for index := 1; index <= count; index++ {
		go func(index int) { results <- probe(ctx, index, availabilityFallbackTimeout) }(index)
	}
	for received := 0; received < count; received++ {
		result := <-results
		if evidence.OK {
			continue // Canceled sibling is not a failed target.
		}
		if record(result) {
			cancel()
		}
	}
	if !evidence.OK {
		evidence.Failure = classifyTargetFailures(failures)
	}
	return evidence
}

func classifyTargetFailures(failures []probeFailureClass) probeFailureClass {
	if len(failures) == 0 {
		return probeFailureTransient
	}
	first := failures[0]
	allSame := true
	for _, failure := range failures[1:] {
		if failure != first {
			allSame = false
		}
	}
	if allSame {
		return first
	}
	// Mixed errors do not prove a fatal node-level failure. In particular a
	// certificate error from one public target must not bypass underlay checks.
	for _, failure := range failures {
		if failure == probeFailureTimeout {
			return probeFailureTimeout
		}
	}
	for _, failure := range failures {
		if failure == probeFailureDNS {
			return probeFailureDNS
		}
	}
	return probeFailureTransient
}

func classifyProbeError(err error) probeFailureClass {
	if err == nil {
		return probeFailureNone
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return probeFailureDNS
	}
	var certificateErr *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var recordErr tls.RecordHeaderError
	if errors.As(err, &certificateErr) || errors.As(err, &unknownAuthority) || errors.As(err, &hostnameErr) || errors.As(err, &recordErr) {
		return probeFailureTLS
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return probeFailureFatal
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return probeFailureTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probeFailureTimeout
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "connection refused"), strings.Contains(message, "no route to host"), strings.Contains(message, "network is unreachable"), strings.Contains(message, "host is unreachable"):
		return probeFailureFatal
	case strings.Contains(message, "certificate"), strings.Contains(message, "tls handshake"), strings.Contains(message, "x509:"):
		return probeFailureTLS
	case strings.Contains(message, "no such host"), strings.Contains(message, "server misbehaving"):
		return probeFailureDNS
	case strings.Contains(message, "timeout"), strings.Contains(message, "timed out"):
		return probeFailureTimeout
	default:
		return probeFailureTransient
	}
}

func (runtime *xraySelectorRuntime) UnderlayStatus() underlayEvidence {
	ctx, cancel := context.WithTimeout(runtime.requestContext(), 2*time.Second)
	defer cancel()
	type result struct {
		kind string
		ok   bool
	}
	results := make(chan result, len(underlayWANTargets)+1)
	for _, address := range underlayWANTargets {
		address := address
		go func() {
			connection, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", address)
			if err == nil {
				_ = connection.Close()
			}
			results <- result{kind: "wan", ok: err == nil}
		}()
	}
	go func() {
		addresses, err := net.DefaultResolver.LookupHost(ctx, "www.gstatic.com")
		results <- result{kind: "dns", ok: err == nil && len(addresses) > 0}
	}()
	status := underlayEvidence{Known: true}
	for received := 0; received < len(underlayWANTargets)+1; received++ {
		select {
		case value := <-results:
			if value.kind == "wan" {
				status.WANOK = status.WANOK || value.ok
			} else {
				status.DNSOK = value.ok
			}
		case <-ctx.Done():
			return status
		}
	}
	return status
}

func (runtime *xraySelectorRuntime) Throughput(candidate string, byteLimit int) (int64, error) {
	if runtime.isReverse(candidate) && !runtime.reverseOnline(candidate) {
		return 0, errors.New("reverse bridge is offline")
	}
	if err := runtime.Select(runtime.probeSelectorName(), candidate); err != nil {
		return 0, err
	}
	byteLimit = maxInt(256*1024, minInt(byteLimit, 10*1024*1024))
	started := time.Now()
	received, err := downloadThroughProxyContext(runtime.requestContext(), runtime.opts.ProbeURL, "https://speed.cloudflare.com/__down?bytes="+strconv.Itoa(byteLimit), 15*time.Second, byteLimit, http.StatusOK)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(started).Seconds()
	if received < minInt(byteLimit, 256*1024) || elapsed <= 0 {
		return 0, errors.New("throughput probe returned too little data")
	}
	return int64(float64(received*8) / elapsed), nil
}

func (runtime *xraySelectorRuntime) isReverse(candidate string) bool {
	for _, contract := range runtime.pool.HealthPolicies {
		if contract.Nodes[candidate].Protocol == "xray-reverse" {
			return true
		}
	}
	return false
}

func (runtime *xraySelectorRuntime) reverseOnline(candidate string) bool {
	body, err := runtime.command(runtime.requestContext(), 3*time.Second, runtime.opts.XrayBinary,
		"api", "statsonline", "--server="+runtime.opts.XrayAPIServer, "-email", candidate)
	if err != nil {
		return false
	}
	var response struct {
		Stat struct {
			Name  string `json:"name"`
			Value int64  `json:"value"`
		} `json:"stat"`
	}
	if json.Unmarshal(body, &response) != nil {
		return false
	}
	return response.Stat.Name == "user>>>"+candidate+">>>online" && response.Stat.Value > 0
}

func probeHTTP(proxyURL, target string, timeout time.Duration, limit int) (int, error) {
	started := time.Now()
	_, err := downloadThroughProxy(proxyURL, target, timeout, limit)
	if err != nil {
		return 0, err
	}
	return maxInt(1, int(time.Since(started).Milliseconds())), nil
}

func downloadThroughProxy(proxyURL, target string, timeout time.Duration, limit int) (int, error) {
	return downloadThroughProxyContext(context.Background(), proxyURL, target, timeout, limit, 0)
}

func downloadThroughProxyContext(ctx context.Context, proxyURL, target string, timeout time.Duration, limit, expectedStatus int) (int, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return 0, err
	}
	transport := &http.Transport{Proxy: http.ProxyURL(parsed), DisableKeepAlives: true, ForceAttemptHTTP2: false}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", "SB-Gateway-Go-Health/1")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || (expectedStatus != 0 && response.StatusCode != expectedStatus) {
		return 0, fmt.Errorf("probe returned unexpected HTTP status %d", response.StatusCode)
	}
	received := 0
	buffer := make([]byte, minInt(64*1024, limit))
	for received < limit {
		wanted := minInt(len(buffer), limit-received)
		count, readErr := response.Body.Read(buffer[:wanted])
		received += count
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return received, readErr
		}
	}
	return received, nil
}

func processPID(name string) int {
	return processPIDAt("/proc", name)
}

func processPIDAt(root, name string) int {
	paths, _ := filepath.Glob(filepath.Join(root, "[0-9]*", "comm"))
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(body)) == name {
			// A stopped core can remain as a zombie until PID 1 reaps it.
			// Its comm still says xray, but it cannot own the API/ready marker.
			stat, err := os.ReadFile(filepath.Join(filepath.Dir(path), "stat"))
			if err != nil {
				continue
			}
			end := strings.LastIndexByte(string(stat), ')')
			if end < 0 {
				continue
			}
			fields := strings.Fields(string(stat)[end+1:])
			if len(fields) == 0 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
				continue
			}
			pid, _ := strconv.Atoi(filepath.Base(filepath.Dir(path)))
			return pid
		}
	}
	return 0
}
func shortHash(value string, length int) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:length]
}
