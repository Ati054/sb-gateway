package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	historyRetentionDays   = 30
	historyReservoir       = 256
	defaultSpeedBytes      = 2 * 1024 * 1024
	outageRetryInterval    = 15 * time.Second
	failureRetryInterval   = 2 * time.Second
	activeLivenessInterval = 3 * time.Second
	outageProbeBatch       = 3
)

var healthTargets = []struct {
	label  string
	url    string
	status int
}{
	{"gstatic-204", "https://www.gstatic.com/generate_204", 204},
	{"cloudflare-trace", "https://www.cloudflare.com/cdn-cgi/trace", 200},
	{"example-web", "https://example.com/", 200},
}

type healthPool struct {
	Version          int                             `json:"version"`
	Policies         map[string][]string             `json:"policies"`
	HealthPolicies   map[string]healthPolicyContract `json:"health_policies"`
	PolicyPrefixes   map[string]string               `json:"policy_prefixes"`
	BaseOutboundTags []string                        `json:"base_outbound_tags"`
	Outbounds        map[string]json.RawMessage      `json:"outbounds"`
}

type healthPolicyContract struct {
	Policy     healthPolicy          `json:"policy"`
	Mode       string                `json:"mode"`
	Groups     []healthGroup         `json:"groups"`
	Candidates []string              `json:"candidates"`
	Nodes      map[string]healthNode `json:"nodes"`
}

type healthGroup struct {
	Selector string   `json:"selector"`
	Members  []string `json:"members"`
}

type healthNode struct {
	SubscriptionID string `json:"subscription_id,omitempty"`
	Label          string `json:"label"`
	Country        string `json:"country"`
	Protocol       string `json:"protocol,omitempty"`
	Transport      string `json:"transport,omitempty"`
}

type healthPolicy struct {
	FailureThreshold          int                 `json:"failure_threshold"`
	RecoveryThreshold         int                 `json:"recovery_threshold"`
	QualityWindow             int                 `json:"quality_window"`
	MaxPacketLossPercent      float64             `json:"max_packet_loss_percent"`
	MaxLatencyMS              int                 `json:"max_latency_ms"`
	SwitchCooldownSeconds     int                 `json:"switch_cooldown_seconds"`
	SwitchCooldown            int                 `json:"switch_cooldown"`
	SwitchImprovementMS       int                 `json:"switch_improvement_ms"`
	SpeedCheckEnabled         *bool               `json:"speed_check_enabled"`
	SpeedImprovementPercent   int                 `json:"speed_improvement_percent"`
	SpeedCheckIntervalSeconds int                 `json:"speed_check_interval_seconds"`
	SpeedProbeBytes           int                 `json:"speed_probe_bytes"`
	SpeedCandidateCount       int                 `json:"speed_candidate_count"`
	ActiveCheckSeconds        int                 `json:"active_check_interval_seconds"`
	BackupCheckSeconds        int                 `json:"backup_check_interval_seconds"`
	FullScanSeconds           int                 `json:"full_scan_interval_seconds"`
	MaxProbeCandidates        int                 `json:"max_probe_candidates"`
	MaxActiveCandidates       int                 `json:"max_active_candidates"`
	ProbeBatchSize            int                 `json:"probe_batch_size"`
	ActiveLivenessSeconds     int                 `json:"active_liveness_interval_seconds"`
	FailureRetrySeconds       int                 `json:"failure_retry_interval_seconds"`
	BlockRecoverySeconds      int                 `json:"block_recovery_interval_seconds"`
	CandidateServiceIDs       []string            `json:"candidate_service_ids"`
	CandidateServiceAccess    map[string][]string `json:"candidate_service_access"`
}

func (policy *healthPolicy) UnmarshalJSON(body []byte) error {
	// Zero explicitly disables a threshold. Omitted fields must instead get
	// the same defaults as the editor, not silently disable anti-flapping.
	type plain healthPolicy
	value := plain{
		MaxPacketLossPercent: 40, MaxLatencyMS: 2000,
		SwitchCooldownSeconds: 600, SwitchImprovementMS: 50,
		SpeedImprovementPercent: 25,
	}
	wire := struct {
		*plain
		Cooldown *int `json:"switch_cooldown_seconds"`
	}{plain: &value}
	if err := json.Unmarshal(body, &wire); err != nil {
		return err
	}
	if wire.Cooldown != nil {
		value.SwitchCooldownSeconds = *wire.Cooldown
	} else if value.SwitchCooldown != 0 {
		value.SwitchCooldownSeconds = value.SwitchCooldown
	}
	*policy = healthPolicy(value)
	return nil
}

type healthState map[string]*policyHealthState

type policyHealthState struct {
	Selected               string                            `json:"selected"`
	Failures               map[string]int                    `json:"failures"`
	AvailabilityFailures   map[string]int                    `json:"availability_failures"`
	Recoveries             map[string]int                    `json:"recoveries"`
	Samples                map[string][]healthSample         `json:"samples"`
	DailySamples           map[string][]healthSample         `json:"daily_samples"`
	HistoryDays            map[string]map[string]dayBucket   `json:"history_days"`
	CooldownUntil          float64                           `json:"cooldown_until"`
	LastProbeAt            map[string]float64                `json:"last_probe_at"`
	SpeedSamplesBPS        map[string][]int64                `json:"speed_samples_bps"`
	LastSpeedProbeAt       map[string]float64                `json:"last_speed_probe_at"`
	CandidateSignature     string                            `json:"candidate_signature"`
	ScanQueue              []string                          `json:"scan_queue"`
	ProbeLane              int                               `json:"probe_lane,omitempty"`
	NextFullScanAt         float64                           `json:"next_full_scan_at"`
	LastSwitchAt           string                            `json:"last_switch_at,omitempty"`
	LastSwitchReason       string                            `json:"last_switch_reason,omitempty"`
	OptimizationBaseline   string                            `json:"optimization_baseline,omitempty"`
	OptimizationCandidate  string                            `json:"optimization_candidate,omitempty"`
	OptimizationChecks     int                               `json:"optimization_checks,omitempty"`
	OptimizationNextAt     float64                           `json:"optimization_next_at,omitempty"`
	OptimizationRetryAfter float64                           `json:"optimization_retry_after,omitempty"`
	OptimizationActiveAt   float64                           `json:"optimization_active_at,omitempty"`
	OptimizationActiveMS   *int                              `json:"optimization_active_ms,omitempty"`
	OptimizationActiveBPS  *int64                            `json:"optimization_active_bps,omitempty"`
	DailyStats             map[string]healthStats            `json:"daily_stats"`
	PeriodStats            map[string]map[string]healthStats `json:"period_stats"`
	DelayMS                map[string]*int                   `json:"delay_ms"`
	MedianDelayMS          map[string]*int                   `json:"median_delay_ms"`
	PacketLossPercent      map[string]float64                `json:"packet_loss_percent"`
	QualityOK              map[string]bool                   `json:"quality_ok"`
	AvailabilityOK         map[string]bool                   `json:"availability_ok"`
	FailureClass           map[string]string                 `json:"failure_class,omitempty"`
	CandidateLabels        map[string]string                 `json:"candidate_labels"`
	CandidateNodes         map[string]healthNode             `json:"candidate_nodes"`
	CandidateGroups        map[string]int                    `json:"candidate_groups"`
	GroupLabels            map[string]string                 `json:"group_labels"`
	CandidateServiceStatus map[string]serviceHealthStatus    `json:"candidate_service_status"`
	Shortlist              []string                          `json:"shortlist"`
	ProbedCandidates       []string                          `json:"probed_candidates"`
	HTTPSProbeTargets      map[string]map[string]*int        `json:"https_probe_targets"`
	SpeedMedianBPS         map[string]*int64                 `json:"speed_median_bps"`
	SpeedProbeTargets      []string                          `json:"speed_probe_targets"`
	Mode                   string                            `json:"mode"`
	CandidateCount         int                               `json:"candidate_count"`
	HealthyReserves        int                               `json:"healthy_reserves"`
	ProbeLimits            probeLimits                       `json:"probe_limits"`
	QualityThresholds      qualityThresholds                 `json:"quality_thresholds"`
	CheckedAt              string                            `json:"checked_at"`
	RuntimeSelected        string                            `json:"runtime_selected,omitempty"`
	RuntimeObservedAt      string                            `json:"runtime_observed_at,omitempty"`
	RuntimeConfirmed       bool                              `json:"runtime_confirmed"`
	RuntimeError           string                            `json:"runtime_error,omitempty"`
	LastWorkingSelection   *workingSelection                 `json:"last_working_selection,omitempty"`
	UnderlayFailure        string                            `json:"underlay_failure,omitempty"`
	UnderlayCheckedAt      string                            `json:"underlay_checked_at,omitempty"`
}

type healthSample struct {
	At      float64 `json:"at,omitempty"`
	OK      bool    `json:"ok"`
	DelayMS *int    `json:"delay_ms"`
}

type dayBucket struct {
	Samples        int   `json:"samples"`
	Successes      int   `json:"successes"`
	Failures       int   `json:"failures"`
	LatencySamples []int `json:"latency_samples"`
}

type healthStats struct {
	Samples                int      `json:"samples"`
	Successes              int      `json:"successes"`
	Failures               int      `json:"failures"`
	LossPercent            *float64 `json:"loss_percent"`
	AvailabilityPercent    *float64 `json:"availability_percent"`
	MedianMS               *int     `json:"median_ms"`
	P95MS                  *int     `json:"p95_ms"`
	Days                   int      `json:"days,omitempty"`
	LatencySampleCount     int      `json:"latency_sample_count,omitempty"`
	PercentilesApproximate bool     `json:"percentiles_approximate,omitempty"`
}

type serviceHealthStatus struct {
	Selector string `json:"selector"`
	Target   string `json:"target"`
	Allowed  bool   `json:"allowed"`
}

type probeLimits struct {
	Batch                int `json:"batch"`
	Shortlist            int `json:"shortlist"`
	ActiveSeconds        int `json:"active_seconds"`
	BackupSeconds        int `json:"backup_seconds"`
	FullScanSeconds      int `json:"full_scan_seconds"`
	LivenessSeconds      int `json:"liveness_seconds"`
	FailureRetrySeconds  int `json:"failure_retry_seconds"`
	BlockRecoverySeconds int `json:"block_recovery_seconds"`
}

type qualityThresholds struct {
	Window                    int     `json:"window"`
	MaxPacketLossPercent      float64 `json:"max_packet_loss_percent"`
	MaxLatencyMS              int     `json:"max_latency_ms"`
	SwitchImprovementMS       int     `json:"switch_improvement_ms"`
	SpeedCheckEnabled         bool    `json:"speed_check_enabled"`
	SpeedImprovementPercent   int     `json:"speed_improvement_percent"`
	SpeedCheckIntervalSeconds int     `json:"speed_check_interval_seconds"`
	SpeedProbeBytes           int     `json:"speed_probe_bytes"`
	SpeedCandidateCount       int     `json:"speed_candidate_count"`
	FailureConfirmations      int     `json:"failure_confirmations"`
	RecoveryConfirmations     int     `json:"recovery_confirmations"`
	CooldownSeconds           int     `json:"cooldown_seconds"`
}

type probeEvidence struct {
	OK      bool
	DelayMS *int
	Targets map[string]*int
	Failure probeFailureClass
}

type selectorRuntime interface {
	Reload() (healthPool, bool, error)
	Current(string) (string, error)
	Select(string, string) error
	Probe(string) probeEvidence
	ProbeAvailability(string) probeEvidence
	Throughput(string, int) (int64, error)
}

type healthController struct {
	priorityPolicy string
	opts           Options
	runtime        selectorRuntime
	warmStarted    map[string]bool
	state          healthState
	stateLoaded    bool
	regularNext    map[string]time.Time
	livenessAt     map[string]time.Time
	yielded        bool
}

func runHealth(ctx context.Context, opts Options) error {
	primary := newXraySelectorRuntime(opts)
	primary.probeContext = ctx
	controller := &healthController{
		opts:        opts,
		runtime:     primary,
		warmStarted: make(map[string]bool),
	}
	backgroundOptions := opts
	backgroundOptions.ProbeURL = envOr("SB_XRAY_BACKGROUND_PROBE_URL", "http://127.0.0.1:19083")
	background := newXraySelectorRuntime(backgroundOptions)
	background.probeSelector = "outbound-health-background"
	backgrounds := []*xraySelectorRuntime{background}
	for index, tag := range []string{"outbound-health-background-2", "outbound-health-background-3"} {
		laneOptions := opts
		laneOptions.ProbeURL = fmt.Sprintf("http://127.0.0.1:%d", 19084+index)
		lane := newXraySelectorRuntime(laneOptions)
		lane.probeSelector = tag
		backgrounds = append(backgrounds, lane)
	}
	controller.runtime = &responsiveSelectorRuntime{
		selectorRuntime: primary, background: background, backgrounds: backgrounds, ctx: ctx,
		generationPaths: []string{opts.HealthPoolFile, opts.XrayReadyFile},
		check:           func() error { return controller.checkDuringProbe(time.Now(), primary.pool) },
	}
	if !wait(ctx, 5*time.Second) {
		return nil
	}
	for {
		if err := controller.Tick(time.Now()); err != nil {
			if errors.Is(err, errHealthYield) {
				continue
			}
			log.Printf("agent: selector health probe failed safely; keeping previous selector: %v", err)
		} else if err := publishHotRuntimeReady(opts); err != nil {
			log.Printf("agent: publish hot runtime readiness: %v", err)
		}
		if !waitForGenerationChange(ctx, controller.nextInterval(), []string{opts.HealthPoolFile, opts.XrayReadyFile}, 500*time.Millisecond) {
			return nil
		}
	}
}

func publishHotRuntimeReady(opts Options) error {
	file, err := os.Open(opts.HealthPoolFile)
	if err != nil {
		return err
	}
	info, statErr := file.Stat()
	digest := sha256.New()
	_, copyErr := io.Copy(digest, io.LimitReader(file, (32<<20)+1))
	closeErr := file.Close()
	if err := errors.Join(statErr, copyErr, closeErr); err != nil {
		return err
	}
	pid := readyProcessPID(opts.XrayReadyFile, "xray")
	if pid <= 0 {
		return errors.New("Xray startup selectors are not ready")
	}
	return writeJSONAtomic(opts.HotRuntimeReadyFile, map[string]any{
		"pool_sha256": hex.EncodeToString(digest.Sum(nil)), "pool_mtime_unix_nano": info.ModTime().UnixNano(), "xray_pid": pid,
	})
}

func (controller *healthController) nextInterval() time.Duration {
	if controller.yielded {
		return 0
	}
	interval := controller.opts.HealthInterval
	for _, item := range controller.state {
		liveness := configuredHealthDuration(item.ProbeLimits.LivenessSeconds, activeLivenessInterval)
		failureRetry := configuredHealthDuration(item.ProbeLimits.FailureRetrySeconds, failureRetryInterval)
		blockRecovery := configuredHealthDuration(item.ProbeLimits.BlockRecoverySeconds, outageRetryInterval)
		if item.Selected != "" && item.Selected != "block" && interval > liveness {
			interval = liveness
		}
		if item.Selected == "block" && interval > blockRecovery {
			interval = blockRecovery
		} else if item.UnderlayFailure != "" && interval > failureRetry {
			interval = failureRetry
		} else if item.Selected != "block" && item.AvailabilityFailures[item.Selected] > 0 && interval > failureRetry {
			interval = failureRetry
		}
	}
	return interval
}

func configuredHealthDuration(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// Walk the whole pool fairly, including nodes outside the regular shortlist.
// LastProbeAt already persists this order; no second queue/cache is needed.
func outageProbeTargets(now time.Time, candidates []string, item *policyHealthState, p effectivePolicySettings) []string {
	result := make([]string, 0, minInt(p.batch, outageProbeBatch))
	interval := minInt(p.backup, p.blockRecovery)
	for len(result) < cap(result) {
		oldest := ""
		for _, candidate := range candidates {
			if contains(result, candidate) || float64(now.Unix())-item.LastProbeAt[candidate] < float64(interval) {
				continue
			}
			if oldest == "" || item.LastProbeAt[candidate] < item.LastProbeAt[oldest] {
				oldest = candidate
			}
		}
		if oldest == "" {
			break
		}
		result = append(result, oldest)
	}
	return result
}

func (controller *healthController) Tick(now time.Time) error {
	controller.yielded = false
	pool, runtimeReset, err := controller.runtime.Reload()
	if err != nil {
		return err
	}
	if runtimeReset {
		controller.warmStarted = make(map[string]bool)
		controller.regularNext = nil
		controller.livenessAt = nil
	}
	if controller.regularNext == nil {
		controller.regularNext = make(map[string]time.Time)
		controller.livenessAt = make(map[string]time.Time)
	}
	stateFile := statePath(controller.opts.StateRoot, "selector-health")
	if !controller.stateLoaded {
		controller.state = make(healthState)
		_ = readJSON(stateFile, &controller.state)
		controller.stateLoaded = true
	}
	managed := make(healthState)
	policyIDs := make([]string, 0, len(pool.HealthPolicies))
	for policyID := range pool.HealthPolicies {
		policyIDs = append(policyIDs, policyID)
	}
	sort.Strings(policyIDs)
	sort.SliceStable(policyIDs, func(i, j int) bool {
		if policyIDs[i] == controller.priorityPolicy || policyIDs[j] == controller.priorityPolicy {
			return policyIDs[i] == controller.priorityPolicy
		}
		urgent := func(id string) bool {
			item := controller.state[id]
			// A policy which has just appeared in the applied contract has no
			// persisted state yet. Run it before routine quality checks for older
			// policies so a newly assigned client does not remain fail-closed while
			// unrelated route lists are being sampled.
			return item == nil || !item.RuntimeConfirmed || item.Selected == "" ||
				item.Selected == "block" || item.AvailabilityFailures[item.Selected] > 0
		}
		return urgent(policyIDs[i]) && !urgent(policyIDs[j])
	})
	var failures []error
	dirty := runtimeReset || len(pool.HealthPolicies) != len(controller.state)
	for _, policyID := range policyIDs {
		if policyID == controller.priorityPolicy {
			controller.priorityPolicy = ""
		}
		contract := pool.HealthPolicies[policyID]
		item := controller.state[policyID]
		if item == nil {
			item = newPolicyHealthState()
		}
		controller.state[policyID] = item
		var err error
		if !controller.warmStarted[policyID] || !now.Before(controller.regularNext[policyID]) || item.Selected == "block" {
			err = controller.tickPolicy(now, policyID, contract, item)
			if !errors.Is(err, errHealthYield) {
				controller.regularNext[policyID] = now.Add(controller.regularInterval(contract))
			}
			dirty = true
		} else {
			var changed bool
			changed, err = controller.tickActiveAvailability(now, policyID, contract, item)
			dirty = dirty || changed
		}
		if errors.Is(err, errHealthYield) {
			controller.regularNext[policyID] = time.Time{}
			controller.yielded = true
			dirty = true
			err = nil
		}
		if err != nil {
			item.RuntimeError = err.Error()
			item.RuntimeConfirmed = false
			item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
			failures = append(failures, fmt.Errorf("policy %s: %w", policyID, err))
			dirty = true
		}
		managed[policyID] = item
		if controller.yielded {
			// Do not start another policy's slow job before handling this failure.
			for _, id := range policyIDs {
				if value := controller.state[id]; value != nil {
					managed[id] = value
				}
			}
			break
		}
	}
	if dirty {
		if err := writeJSONAtomic(stateFile, managed); err != nil {
			failures = append(failures, err)
		}
	}
	controller.state = managed
	return errors.Join(failures...)
}

func (controller *healthController) regularInterval(contract healthPolicyContract) time.Duration {
	qualityInterval := time.Duration(policySettings(contract.Policy, contract.Mode).active) * time.Second
	if controller.opts.HealthInterval <= 0 || qualityInterval < controller.opts.HealthInterval {
		return qualityInterval
	}
	return controller.opts.HealthInterval
}

func newPolicyHealthState() *policyHealthState {
	return &policyHealthState{
		Failures: make(map[string]int), AvailabilityFailures: make(map[string]int), Recoveries: make(map[string]int),
		Samples: make(map[string][]healthSample), DailySamples: make(map[string][]healthSample), HistoryDays: make(map[string]map[string]dayBucket),
		LastProbeAt: make(map[string]float64), SpeedSamplesBPS: make(map[string][]int64), LastSpeedProbeAt: make(map[string]float64),
		FailureClass: make(map[string]string),
	}
}

func (controller *healthController) tickPolicy(now time.Time, policyID string, contract healthPolicyContract, item *policyHealthState) error {
	ensureHealthMaps(item)
	warm := !controller.warmStarted[policyID]
	// Preserve confirmed legacy history before a transient API error can clear it.
	rememberWorkingSelection(contract, item)
	previousSelected, previousConfirmed := item.RuntimeSelected, item.RuntimeConfirmed
	candidates := uniqueCandidates(contract.Candidates)
	if len(candidates) == 0 {
		return nil
	}
	p := policySettings(contract.Policy, contract.Mode)
	if contract.Mode == "priority" {
		// Priority is the user's complete ordered queue, not a top-N pool.
		p.shortlist = len(candidates)
	}
	groupIndex, groupSelector, groupLabels := candidateGroups(contract.Groups, candidates, contract.Mode)
	signature := strings.Join(candidates, "\n")
	selected := item.Selected
	actual, actualErr := controller.runtime.Current(policyID)
	if actualErr != nil {
		item.RuntimeConfirmed = false
		item.RuntimeSelected = ""
		item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return actualErr
	}
	if actual != "" {
		if !contains(candidates, actual) && actual != "block" {
			// This is expected when the user removes the active node. Move once to
			// a measured reserve while the Xray process and established flows stay
			// alive. If no reserve is known, fail closed and let the outage probe
			// find the first currently working candidate below.
			replacement := knownHealthyReplacement(candidates, contract.Mode, groupIndex, item, p)
			if replacement == "" {
				replacement = "block"
			}
			if err := controller.runtime.Select(policyID, replacement); err != nil {
				item.RuntimeConfirmed = false
				item.RuntimeSelected = actual
				item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
				return err
			}
			selected, actual = replacement, replacement
			item.Selected = replacement
			item.RuntimeSelected = replacement
			item.RuntimeConfirmed = true
			item.CooldownUntil = switchCooldownUntil(now, "active-removed", p.cooldown)
			item.LastSwitchAt = now.UTC().Format(time.RFC3339)
			item.LastSwitchReason = "active-removed"
		} else {
			selected = actual
			item.Selected = actual
			item.RuntimeSelected = actual
			item.RuntimeConfirmed = true
		}
	} else {
		item.RuntimeSelected = ""
		item.RuntimeConfirmed = false
	}
	if !contains(candidates, selected) && selected != "block" {
		selected = candidates[0]
	}
	if contract.Mode == "priority" && item.CandidateSignature != "" && item.CandidateSignature != signature && contains(candidates, selected) {
		for _, candidate := range candidates {
			if candidate == selected {
				break
			}
			if item.AvailabilityOK[candidate] {
				selected = candidate
				item.CooldownUntil = 0
				item.LastSwitchAt = now.UTC().Format(time.RFC3339)
				item.LastSwitchReason = "priority-order-updated"
				break
			}
		}
	}
	if !controller.warmStarted[policyID] || !item.RuntimeConfirmed || selected != actual {
		if err := controller.runtime.Select(policyID, selected); err != nil {
			return err
		}
		item.Selected = selected
		item.RuntimeSelected = selected
		item.RuntimeConfirmed = true
	}
	item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	item.RuntimeError = ""
	if item.OptimizationCandidate != "" &&
		(contract.Mode != "best" || item.OptimizationBaseline != selected ||
			item.OptimizationCandidate == selected || !contains(candidates, item.OptimizationCandidate)) {
		clearOptimizationCandidate(item)
		item.OptimizationRetryAfter = 0
	}
	labels := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		labels[candidate] = firstNonEmpty(contract.Nodes[candidate].Label, candidate)
	}
	item.CandidateLabels = labels
	item.CandidateNodes = contract.Nodes
	item.CandidateCount = len(candidates)
	protectRestoredSelection(now, selected, contract, item, p, warm)
	// Publish confirmed membership before slow quality/speed probes. This is
	// one extra atomic write on startup/change, not another polling cache.
	if !controller.warmStarted[policyID] || !previousConfirmed || previousSelected != item.RuntimeSelected || item.CandidateSignature != signature {
		if err := writeJSONAtomic(statePath(controller.opts.StateRoot, "selector-health"), controller.state); err != nil {
			return err
		}
	}
	if item.CandidateSignature != signature {
		item.ScanQueue = append([]string(nil), candidates...)
		item.NextFullScanAt = float64(now.Unix()) + float64(p.fullScan)
	} else if len(item.ScanQueue) == 0 && float64(now.Unix()) >= item.NextFullScanAt {
		item.ScanQueue = append([]string(nil), candidates...)
		item.NextFullScanAt = float64(now.Unix()) + float64(p.fullScan)
	}
	shortlist := workingShortlist(selected, candidates, contract.Mode, groupIndex, item, p)

	probeTargets := []string{}
	optimizationProbeTargets := []string{}
	emergencySwitched := false
	emergencyAttempted := false
	emergencyReason := ""
	outage := selected == "block" || item.AvailabilityFailures[selected] >= p.failureThreshold
	if outage && selected != "block" {
		recoveringFromUnderlay := item.UnderlayFailure != ""
		if controller.suppressForUnderlayFailure(now, probeEvidence{Failure: probeFailureTimeout}, item) {
			// Revalidate the shared underlay at the last responsible moment. The
			// active fast lane may have crossed its threshold just as WAN/DNS became
			// unstable; never turn that race into a node hop.
			item.AvailabilityFailures[selected] = 0
			return nil
		}
		if recoveringFromUnderlay {
			// The shared WAN/DNS path has recovered, but the active-node counter
			// still describes the previous common outage. Re-probe the active node
			// before considering a reserve so recovery cannot cause a stale hop.
			item.AvailabilityFailures[selected] = 0
			outage = false
		}
	}
	if outage {
		emergencyAttempted = true
		if reserve := knownFreshReserve(now, selected, candidates, contract.Mode, groupIndex, item, p); reserve != "" {
			if err := controller.runtime.Select(policyID, reserve); err != nil {
				return err
			}
			emergencySwitched = true
			emergencyReason = "active-unavailable"
			if selected == "block" {
				emergencyReason = "fresh-path-available"
			}
			selected = reserve
			item.Selected = reserve
			item.RuntimeSelected = reserve
			item.RuntimeConfirmed = true
			item.LastSwitchAt = now.UTC().Format(time.RFC3339)
			item.LastSwitchReason = emergencyReason
			item.CooldownUntil = switchCooldownUntil(now, emergencyReason, p.cooldown)
			outage = false
		}
	}
	if outage {
		emergency := p
		if selected != "block" {
			emergency.backup = minInt(p.backup, p.failureRetry)
		}
		probeTargets = outageProbeTargets(now, candidates, item, emergency)
	} else if !emergencySwitched {
		if warm {
			probeTargets = append(probeTargets, selected)
			for _, candidate := range candidates {
				if candidate != selected && len(probeTargets) < p.batch {
					probeTargets = append(probeTargets, candidate)
				}
			}
			item.ScanQueue = without(item.ScanQueue, probeTargets)
		} else {
			probeTargets = regularProbeTargets(now, selected, candidates, shortlist, item, p)
		}
		if item.OptimizationCandidate != "" {
			if !item.AvailabilityOK[item.OptimizationCandidate] ||
				item.Recoveries[item.OptimizationCandidate] < p.recoveryThreshold {
				clearOptimizationCandidate(item)
				item.OptimizationRetryAfter = float64(now.Unix() + int64(p.cooldown))
			} else if float64(now.Unix()) >= item.OptimizationNextAt {
				// A planned optimization gets one bounded comparison lane: the active
				// path plus one candidate. It replaces this tick's normal batch instead
				// of adding work proportional to the subscription size.
				if item.OptimizationActiveMS != nil &&
					float64(now.Unix())-item.OptimizationActiveAt > float64(maxInt(p.active*2, 120)) {
					clearOptimizationActiveSample(item)
				}
				if p.batch >= 2 {
					optimizationProbeTargets = []string{selected, item.OptimizationCandidate}
				} else if item.OptimizationActiveMS == nil {
					optimizationProbeTargets = []string{selected}
				} else {
					optimizationProbeTargets = []string{item.OptimizationCandidate}
				}
				probeTargets = append([]string(nil), optimizationProbeTargets...)
				item.ScanQueue = without(item.ScanQueue, probeTargets)
			}
		}
	}

	measured := make(map[string]probeEvidence)
	if outage {
		var emergencySelected string
		var probeErr error
		measured, emergencySelected, probeErr = controller.probeEmergencyCandidates(policyID, probeTargets, p)
		if probeErr != nil {
			item.ScanQueue = uniqueCandidates(append(probeTargets, item.ScanQueue...))
			return probeErr
		}
		if emergencySelected != "" {
			emergencySwitched = true
			emergencyReason = "active-unavailable"
			if selected == "block" {
				emergencyReason = "fresh-path-available"
			}
			selected = emergencySelected
			item.Selected = emergencySelected
			item.RuntimeSelected = emergencySelected
			item.RuntimeConfirmed = true
			item.LastSwitchAt = now.UTC().Format(time.RFC3339)
			item.LastSwitchReason = emergencyReason
			item.CooldownUntil = switchCooldownUntil(now, emergencyReason, p.cooldown)
			outage = false
		}
	}
	for index := 0; !emergencySwitched && !outage && index < len(probeTargets); index++ {
		candidate := probeTargets[index]
		measured[candidate] = controller.runtime.Probe(candidate)
		if err := takeProbeInterruption(controller.runtime); err != nil {
			item.ScanQueue = uniqueCandidates(append(probeTargets, item.ScanQueue...))
			return err
		}
		if candidate == selected && !measured[candidate].OK {
			item.FailureClass[selected] = string(measured[candidate].Failure)
			if controller.suppressForUnderlayFailure(now, measured[candidate], item) {
				item.AvailabilityFailures[selected] = 0
				delete(measured, candidate)
				continue
			}
		}
		if candidate == selected && !measured[candidate].OK &&
			item.AvailabilityFailures[selected]+1 >= startupFailureConfirmationThreshold(measured[candidate], p.failureThreshold, warm) {
			// Confirmed outage: probe reserves now, not after the backup timer.
			outage = true
			item.AvailabilityFailures[selected] = p.failureThreshold
			if reserve := knownFreshReserve(now, selected, candidates, contract.Mode, groupIndex, item, p); reserve != "" {
				if err := controller.runtime.Select(policyID, reserve); err != nil {
					return err
				}
				emergencySwitched = true
				emergencyReason = "active-unavailable"
				selected = reserve
				item.Selected = reserve
				item.RuntimeSelected = reserve
				item.RuntimeConfirmed = true
				item.LastSwitchAt = now.UTC().Format(time.RFC3339)
				item.LastSwitchReason = emergencyReason
				item.CooldownUntil = switchCooldownUntil(now, emergencyReason, p.cooldown)
				outage = false
				break
			}
			emergency := p
			emergency.backup = minInt(p.backup, p.failureRetry)
			for _, reserve := range outageProbeTargets(now, without(candidates, probeTargets), item, emergency) {
				if len(probeTargets) >= minInt(p.batch, outageProbeBatch) {
					break
				}
				probeTargets = append(probeTargets, reserve)
			}
			break
		}
	}
	if outage && !emergencySwitched && !emergencyAttempted {
		emergencyAttempted = true
		var emergencySelected string
		var probeErr error
		measuredReserves, selectedReserve, err := controller.probeEmergencyCandidates(policyID, without(probeTargets, []string{selected}), p)
		for candidate, evidence := range measuredReserves {
			measured[candidate] = evidence
		}
		emergencySelected, probeErr = selectedReserve, err
		if probeErr != nil {
			item.ScanQueue = uniqueCandidates(append(probeTargets, item.ScanQueue...))
			return probeErr
		}
		if emergencySelected != "" {
			emergencySwitched = true
			emergencyReason = "active-unavailable"
			selected = emergencySelected
			item.Selected = emergencySelected
			item.RuntimeSelected = emergencySelected
			item.RuntimeConfirmed = true
			item.LastSwitchAt = now.UTC().Format(time.RFC3339)
			item.LastSwitchReason = emergencyReason
			item.CooldownUntil = switchCooldownUntil(now, emergencyReason, p.cooldown)
			outage = false
		}
	}
	if outage {
		item.ScanQueue = without(item.ScanQueue, probeTargets)
	}
	controller.warmStarted[policyID] = true

	measuredSpeed := make(map[string]int64)
	speedTargets := []string{}
	selectedEvidence, selectedMeasured := measured[selected]
	if p.speedEnabled && !outage && !emergencySwitched && item.AvailabilityFailures[selected] == 0 && (!selectedMeasured || selectedEvidence.OK) {
		candidatesForSpeed := speedProbeCandidates(now, selected, candidates, measured, item, p)
		if len(optimizationProbeTargets) > 0 {
			candidatesForSpeed = nil
			allAvailable := true
			for _, candidate := range optimizationProbeTargets {
				allAvailable = allAvailable && measured[candidate].OK
			}
			if allAvailable {
				candidatesForSpeed = optimizationProbeTargets
			}
		}
		for _, candidate := range candidatesForSpeed {
			speedTargets = append(speedTargets, candidate)
			speed, speedErr := controller.runtime.Throughput(candidate, p.speedBytes)
			if err := takeProbeInterruption(controller.runtime); err != nil {
				item.ScanQueue = uniqueCandidates(append(probeTargets, item.ScanQueue...))
				return err
			}
			if speedErr == nil && speed > 0 {
				measuredSpeed[candidate] = speed
			}
		}
	}
	// Commit timestamps with the batch results, never for an interrupted batch.
	for candidate := range measured {
		item.LastProbeAt[candidate] = float64(now.Unix())
	}
	for _, candidate := range speedTargets {
		item.LastSpeedProbeAt[candidate] = float64(now.Unix())
	}
	speedMedians := make(map[string]*int64)
	for _, candidate := range candidates {
		values := positiveSpeeds(item.SpeedSamplesBPS[candidate])
		if value, ok := measuredSpeed[candidate]; ok {
			values = append(values, value)
		}
		if len(values) > 5 {
			values = values[len(values)-5:]
		}
		item.SpeedSamplesBPS[candidate] = values
		if len(values) > 0 {
			median := medianInt64(values)
			speedMedians[candidate] = &median
		} else {
			speedMedians[candidate] = nil
		}
	}

	updateHistories(item, candidates, measured, now)
	dailyStats := make(map[string]healthStats)
	period7 := make(map[string]healthStats)
	period30 := make(map[string]healthStats)
	for _, candidate := range candidates {
		dailyStats[candidate] = summarizeSamples(item.DailySamples[candidate])
		period7[candidate] = summarizeDays(item.HistoryDays[candidate], 7, now)
		period30[candidate] = summarizeDays(item.HistoryDays[candidate], historyRetentionDays, now)
	}

	qualityOK := make(map[string]bool)
	availabilityOK := make(map[string]bool)
	losses := make(map[string]float64)
	medians := make(map[string]*int)
	for _, candidate := range candidates {
		samples := append([]healthSample(nil), item.Samples[candidate]...)
		if evidence, ok := measured[candidate]; ok {
			samples = append(samples, healthSample{OK: evidence.OK, DelayMS: evidence.DelayMS})
		}
		if len(samples) > p.qualityWindow {
			samples = samples[len(samples)-p.qualityWindow:]
		}
		item.Samples[candidate] = samples
		failed := 0
		delays := []int{}
		for _, sample := range samples {
			if !sample.OK {
				failed++
			} else if sample.DelayMS != nil {
				delays = append(delays, *sample.DelayMS)
			}
		}
		loss := 100.0
		if len(samples) > 0 {
			loss = float64(failed) * 100 / float64(len(samples))
		}
		losses[candidate] = roundOne(loss)
		var typical *int
		if len(delays) > 0 {
			value := medianInt(delays)
			typical = &value
		}
		medians[candidate] = typical
		latencyOK := p.maxLatency <= 0 || (typical != nil && *typical <= p.maxLatency)
		qualityOK[candidate] = len(samples) > 0 && latencyOK && loss <= p.maxLoss
		if evidence, ok := measured[candidate]; ok {
			if evidence.OK {
				delete(item.FailureClass, candidate)
				if candidate == selected {
					clearUnderlayFailure(item)
				}
			} else {
				item.FailureClass[candidate] = string(evidence.Failure)
			}
			probeQuality := evidence.OK && latencyOK
			if probeQuality && loss <= p.maxLoss {
				item.Failures[candidate] = 0
			} else {
				item.Failures[candidate]++
			}
			if evidence.OK {
				item.AvailabilityFailures[candidate] = 0
			} else {
				threshold := startupFailureConfirmationThreshold(evidence, p.failureThreshold, warm && candidate == selected)
				item.AvailabilityFailures[candidate]++
				if item.AvailabilityFailures[candidate] >= threshold {
					item.AvailabilityFailures[candidate] = p.failureThreshold
				}
			}
			if probeQuality {
				item.Recoveries[candidate]++
			} else {
				item.Recoveries[candidate] = 0
			}
		}
		anySuccess := false
		for _, sample := range samples {
			anySuccess = anySuccess || sample.OK
		}
		if len(samples) > 0 {
			availabilityOK[candidate] = anySuccess && item.AvailabilityFailures[candidate] < p.failureThreshold
		}
		// Give newly discovered good candidates enough independent quality
		// samples to qualify without waiting for another full-scan interval.
		if evidence, ok := measured[candidate]; ok && evidence.OK && item.Recoveries[candidate] > 0 && item.Recoveries[candidate] < p.recoveryThreshold && !contains(item.ScanQueue, candidate) {
			item.ScanQueue = append(item.ScanQueue, candidate)
		}
	}

	desired, reason := selectDesired(now, contract.Mode, selected, candidates, groupIndex, dailyStats, medians, speedMedians, measured, qualityOK, availabilityOK, item, p)
	if emergencySwitched {
		desired, reason = selected, emergencyReason
	}
	var optimizationConfirmed *bool
	optimizationProbedCandidate := ""
	if len(optimizationProbeTargets) == 2 {
		optimizationProbedCandidate = item.OptimizationCandidate
		confirmed := qualityOK[item.OptimizationCandidate] &&
			availabilityOK[item.OptimizationCandidate] &&
			freshOptimizationWin(selected, item.OptimizationCandidate, measured, measuredSpeed, p)
		optimizationConfirmed = &confirmed
	} else if len(optimizationProbeTargets) == 1 && optimizationProbeTargets[0] == selected {
		evidence := measured[selected]
		valid := evidence.OK && evidence.DelayMS != nil
		if p.speedEnabled {
			speed, measuredOK := measuredSpeed[selected]
			valid = valid && measuredOK && speed > 0
		}
		if valid {
			delay := *evidence.DelayMS
			item.OptimizationActiveMS = &delay
			if p.speedEnabled {
				speed := measuredSpeed[selected]
				item.OptimizationActiveBPS = &speed
			}
			item.OptimizationActiveAt = float64(now.Unix())
			item.OptimizationNextAt = float64(now.Unix() + int64(p.active))
		} else {
			optimizationProbedCandidate = item.OptimizationCandidate
			confirmed := false
			optimizationConfirmed = &confirmed
		}
	} else if len(optimizationProbeTargets) == 1 && optimizationProbeTargets[0] == item.OptimizationCandidate {
		optimizationProbedCandidate = item.OptimizationCandidate
		pairMeasured := map[string]probeEvidence{
			selected:                   {OK: item.OptimizationActiveMS != nil, DelayMS: item.OptimizationActiveMS},
			item.OptimizationCandidate: measured[item.OptimizationCandidate],
		}
		pairSpeed := measuredSpeed
		if p.speedEnabled && item.OptimizationActiveBPS != nil {
			pairSpeed = map[string]int64{
				selected:                   *item.OptimizationActiveBPS,
				item.OptimizationCandidate: measuredSpeed[item.OptimizationCandidate],
			}
		}
		confirmed := qualityOK[item.OptimizationCandidate] &&
			availabilityOK[item.OptimizationCandidate] &&
			freshOptimizationWin(selected, item.OptimizationCandidate, pairMeasured, pairSpeed, p)
		optimizationConfirmed = &confirmed
		clearOptimizationActiveSample(item)
	}
	desired, reason = gatePlannedOptimization(now, selected, desired, reason, optimizationProbedCandidate, optimizationConfirmed, item, p)
	serviceStatus := make(map[string]serviceHealthStatus)
	if contract.Mode == "priority" && len(contract.Policy.CandidateServiceIDs) > 0 {
		desiredGroup := groupSelector[desired]
		blockTag := serviceBlockTag(policyID)
		for _, serviceID := range contract.Policy.CandidateServiceIDs {
			selector := serviceSelectorTag(policyID, serviceID)
			allowed := desired != "block" && contains(contract.Policy.CandidateServiceAccess[desiredGroup], serviceID)
			target := blockTag
			if allowed {
				target = desired
			}
			if err := controller.runtime.Select(selector, target); err != nil {
				return err
			}
			serviceStatus[serviceID] = serviceHealthStatus{selector, target, allowed}
		}
	}
	if desired != selected {
		if err := controller.runtime.Select(policyID, desired); err != nil {
			return err
		}
		item.Selected = desired
		item.LastSwitchAt = now.UTC().Format(time.RFC3339)
		item.LastSwitchReason = reason
		item.CooldownUntil = switchCooldownUntil(now, reason, p.cooldown)
	} else {
		item.Selected = selected
	}
	item.RuntimeSelected = item.Selected
	item.RuntimeConfirmed = true
	item.RuntimeError = ""
	item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	delayMap := make(map[string]*int)
	targetsMap := make(map[string]map[string]*int)
	for _, candidate := range candidates {
		if evidence, ok := measured[candidate]; ok {
			delayMap[candidate] = evidence.DelayMS
			targetsMap[candidate] = evidence.Targets
		} else {
			delayMap[candidate] = nil
		}
	}
	item.DailyStats = dailyStats
	item.PeriodStats = map[string]map[string]healthStats{"24h": dailyStats, "7d": period7, "30d": period30}
	item.DelayMS, item.MedianDelayMS, item.PacketLossPercent = delayMap, medians, losses
	item.QualityOK, item.AvailabilityOK = qualityOK, availabilityOK
	item.SpeedMedianBPS = speedMedians
	shortlist = workingShortlist(item.Selected, candidates, contract.Mode, groupIndex, item, p)
	reserves := len(without(shortlist, []string{item.Selected}))
	item.CandidateLabels, item.CandidateGroups, item.GroupLabels = labels, groupIndex, groupLabels
	item.CandidateServiceStatus = serviceStatus
	item.CandidateSignature, item.Shortlist = signature, shortlist
	item.ProbedCandidates, item.HTTPSProbeTargets = probeTargets, targetsMap
	item.SpeedMedianBPS, item.SpeedProbeTargets = speedMedians, speedTargets
	item.Mode, item.CandidateCount, item.HealthyReserves = contract.Mode, len(candidates), reserves
	item.ProbeLimits = probeLimits{
		Batch: p.batch, Shortlist: p.shortlist, ActiveSeconds: p.active,
		BackupSeconds: p.backup, FullScanSeconds: p.fullScan,
		LivenessSeconds: p.liveness, FailureRetrySeconds: p.failureRetry,
		BlockRecoverySeconds: p.blockRecovery,
	}
	item.QualityThresholds = qualityThresholds{p.qualityWindow, p.maxLoss, p.maxLatency, p.improvement, p.speedEnabled, p.speedImprovement, p.speedInterval, p.speedBytes, p.speedCandidates, p.failureThreshold, p.recoveryThreshold, p.cooldown}
	item.CheckedAt = now.UTC().Format(time.RFC3339)
	rememberWorkingSelection(contract, item)
	return nil
}

func protectRestoredSelection(now time.Time, selected string, contract healthPolicyContract, item *policyHealthState, p effectivePolicySettings, warm bool) {
	if !warm || p.cooldown <= 0 || selected == "block" || item.LastWorkingSelection == nil {
		return
	}
	saved := item.LastWorkingSelection
	if saved.Selected != selected || saved.Mode != contract.Mode || !contains(contract.Candidates, selected) {
		return
	}
	if contract.Mode == "priority" && saved.CandidateSignature != strings.Join(uniqueCandidates(contract.Candidates), "\n") {
		return
	}
	until := float64(now.Unix() + int64(p.cooldown))
	if item.CooldownUntil < until {
		item.CooldownUntil = until
	}
}

func switchCooldownUntil(now time.Time, reason string, seconds int) float64 {
	// A new policy may leave block immediately and continue normal optimization.
	// Once a live path fails, however, keep the recovered reserve for the full
	// configured cooldown so an unstable preferred node cannot cause ping-pong.
	if reason == "fresh-path-available" {
		return 0
	}
	return float64(now.Unix() + int64(seconds))
}
