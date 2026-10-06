package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/healthcontract"
)

const (
	historyRetentionDays   = 30
	historyReservoir       = 256
	outageRetryInterval    = 15 * time.Second
	failureRetryInterval   = 2 * time.Second
	activeLivenessInterval = 3 * time.Second
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
	ProbeBudget      int                             `json:"probe_budget,omitempty"`
	ProbeLanes       int                             `json:"probe_lanes,omitempty"`
	Version          int                             `json:"version"`
	Policies         map[string][]string             `json:"policies"`
	HealthPolicies   map[string]healthPolicyContract `json:"health_policies"`
	PolicyPrefixes   map[string]string               `json:"policy_prefixes"`
	BaseOutboundTags []string                        `json:"base_outbound_tags"`
	Outbounds        map[string]json.RawMessage      `json:"outbounds"`
	DialTargets      map[string]healthDialTarget     `json:"dial_targets"`
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
	Fingerprint    string `json:"fingerprint,omitempty"`
}

type healthPolicy = healthcontract.Policy

type healthState map[string]*policyHealthState

type policyHealthState struct {
	LatencyMeasurement     string                            `json:"latency_measurement,omitempty"`
	Selected               string                            `json:"selected"`
	Failures               map[string]int                    `json:"failures"`
	AvailabilityFailures   map[string]int                    `json:"availability_failures"`
	Recoveries             map[string]int                    `json:"recoveries"`
	Samples                map[string][]healthSample         `json:"samples"`
	DailySamples           map[string][]healthSample         `json:"daily_samples"`
	HistoryDays            map[string]map[string]dayBucket   `json:"history_days"`
	LastProbeAt            map[string]float64                `json:"last_probe_at"`
	LastGoodAt             map[string]float64                `json:"last_good_at,omitempty"`
	CandidateSignature     string                            `json:"candidate_signature"`
	ScanQueue              []string                          `json:"scan_queue"`
	LastSwitchAt           string                            `json:"last_switch_at,omitempty"`
	LastSwitchReason       string                            `json:"last_switch_reason,omitempty"`
	OptimizationBaseline   string                            `json:"optimization_baseline,omitempty"`
	OptimizationCandidate  string                            `json:"optimization_candidate,omitempty"`
	OptimizationChecks     int                               `json:"optimization_checks,omitempty"`
	OptimizationLastResult *optimizationComparison           `json:"optimization_last_result,omitempty"`
	LatencyComparisons     map[string]latencyComparison      `json:"latency_comparisons,omitempty"`
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
	OutageProbePending     bool                              `json:"-"`
	OutageBatchStartedAt   time.Time                         `json:"-"`
	LastPreflightAt        float64                           `json:"-"`
	PreflightClosed        map[string]bool                   `json:"-"`
}

type healthSample struct {
	At      float64 `json:"at,omitempty"`
	OK      bool    `json:"ok"`
	DelayMS *int    `json:"delay_ms"`
}

func (item *policyHealthState) UnmarshalJSON(body []byte) error {
	type plain policyHealthState
	var decoded plain
	if err := json.Unmarshal(body, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return err
	}
	*item = policyHealthState(decoded)
	// Comparisons belong to a confirmed live selection, never a saved snapshot.
	item.LatencyComparisons = nil
	// A legacy speed comparison cannot become a latency confirmation on upgrade.
	// Keep availability, history and selected membership.
	for _, key := range []string{"speed_samples_bps", "speed_median_bps", "speed_degradation", "outage_penalty", "optimization_next_at", "optimization_backoff", "optimization_active_ms"} {
		if _, exists := fields[key]; exists {
			clearOptimizationCandidate(item)
			item.OptimizationLastResult = nil
			break
		}
	}
	return nil
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
	LivenessSeconds      int `json:"liveness_seconds"`
	FailureRetrySeconds  int `json:"failure_retry_seconds"`
	BlockRecoverySeconds int `json:"block_recovery_seconds"`
}

type qualityThresholds struct {
	SwitchImprovementMS   int `json:"switch_improvement_ms"`
	FailureConfirmations  int `json:"failure_confirmations"`
	RecoveryConfirmations int `json:"recovery_confirmations"`
}

var errProbeSelectorUnavailable = errors.New("Xray probe selector is unavailable")

type probeEvidence struct {
	QualityUnmeasured    bool
	PrimaryQualityFailed bool
	ObservedAt           time.Time
	Deferred             bool
	LocalFailure         bool
	OK                   bool
	DelayMS              *int
	Targets              map[string]*int
	// TargetFailures contains only fixed health-target labels and failure classes,
	// never endpoint URLs or response bodies.
	TargetFailures map[string]probeFailureClass
	Failure        probeFailureClass
}

type selectorRuntime interface {
	Reload() (healthPool, bool, error)
	Current(string) (string, error)
	Select(string, string) error
	Probe(string) probeEvidence
	ProbeAvailability(string) probeEvidence
}

type policyReconciliation struct {
	Generation         hotRuntimeGeneration
	CandidateSignature string
	Mode               string
	Selected           string
}

type healthController struct {
	probeBudget         *healthProbeBudget
	priorityPolicy      string
	opts                Options
	runtime             selectorRuntime
	warmStarted         map[string]bool
	reconciled          map[string]policyReconciliation
	state               healthState
	stateLoaded         bool
	regularNext         map[string]time.Time
	livenessAt          map[string]time.Time
	forceLiveness       map[string]bool
	lastSignalAt        map[string]time.Time
	yielded             bool
	transitions         map[string]*policyTransition
	processedPool       healthPool
	processedGeneration hotRuntimeGeneration
	eventSink           func(healthEvent)
}

func runHealth(ctx context.Context, opts Options) error {
	control, err := newXrayControlClient(opts.XrayAPIServer)
	if err != nil {
		return fmt.Errorf("initialize Xray control API: %w", err)
	}
	defer control.close()
	signals, closeSignals, signalErr := listenXrayFailureSignals(ctx, opts.XrayFailureSocket)
	if signalErr != nil {
		log.Printf("agent: Xray failure signals unavailable; periodic health checks remain active: %v", signalErr)
	} else {
		defer closeSignals()
	}
	primary := newXraySelectorRuntime(opts)
	primary.control = control
	primary.probeContext = ctx
	controller := &healthController{
		opts:        opts,
		runtime:     primary,
		warmStarted: make(map[string]bool),
	}
	backgroundOptions := opts
	backgroundOptions.ProbeURL = envOr("SB_XRAY_BACKGROUND_PROBE_URL", "http://127.0.0.1:19083")
	background := newXraySelectorRuntime(backgroundOptions)
	background.control = control
	background.probeSelector = "outbound-health-background"
	controller.runtime = &responsiveSelectorRuntime{
		selectorRuntime: primary, background: background, backgrounds: []*xraySelectorRuntime{background}, ctx: ctx,
		laneFactory: func(index int) *xraySelectorRuntime {
			laneOptions := opts
			laneOptions.ProbeURL = fmt.Sprintf("http://127.0.0.1:%d", 19082+index)
			lane := newXraySelectorRuntime(laneOptions)
			lane.control = control
			lane.probeSelector = fmt.Sprintf("outbound-health-background-%d", index)
			return lane
		},
		generationPaths: []string{opts.HealthPoolFile, opts.XrayReadyFile},
		check:           func() error { return controller.checkDuringProbe(time.Now(), primary.pool) },
		signals:         signals,
		acceptSignal: func(signal xrayFailureSignal) bool {
			return controller.acceptXrayFailureSignal(time.Now(), signal, primary)
		},
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
		} else if err := controller.publishHotRuntimeReady(); err != nil {
			log.Printf("agent: publish hot runtime readiness: %v", err)
		}
		if !waitForHealthWake(ctx, controller.nextInterval(), []string{opts.HealthPoolFile, opts.XrayReadyFile}, 500*time.Millisecond, signals,
			func(signal xrayFailureSignal) bool {
				return controller.acceptXrayFailureSignal(time.Now(), signal, primary)
			}) {
			return nil
		}
	}
}

func (controller *healthController) nextInterval() time.Duration {
	return controller.nextIntervalAt(time.Now())
}

func (controller *healthController) nextIntervalAt(now time.Time) time.Duration {
	if controller.yielded {
		return 0
	}
	interval := controller.opts.HealthInterval
	if len(controller.transitions) > 0 && (interval <= 0 || interval > time.Second) {
		interval = time.Second
	}
	for _, item := range controller.state {
		if item == nil {
			continue
		}
		liveness := configuredHealthDuration(item.ProbeLimits.LivenessSeconds, activeLivenessInterval)
		failureRetry := configuredHealthDuration(item.ProbeLimits.FailureRetrySeconds, failureRetryInterval)
		blockRecovery := configuredHealthDuration(item.ProbeLimits.BlockRecoverySeconds, outageRetryInterval)
		if item.Selected != "" && item.Selected != "block" && interval > liveness {
			interval = liveness
		}
		if item.Selected == "block" {
			blockInterval := blockRecovery
			eligible := withoutClosedCandidates(strings.Split(item.CandidateSignature, "\n"), item.PreflightClosed)
			if (item.OutageProbePending || (len(eligible) > 0 && blockedRecoveryHasHistory(item))) && failureRetry < blockInterval {
				blockInterval = failureRetry
			}
			if item.OutageProbePending && !item.OutageBatchStartedAt.IsZero() {
				// A completed slow batch already paid the emergency retry interval.
				elapsed := max(now.Sub(item.OutageBatchStartedAt), time.Duration(0))
				blockInterval = min(blockInterval, max(failureRetry-elapsed, time.Duration(0)))
			}
			if interval > blockInterval {
				interval = blockInterval
			}
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

// In a blocked route, recheck recently working nodes without waiting for an
// entire failed sweep to age out. Reserve a lane for the oldest eligible node
// so a large subscription cannot starve candidates outside the former pool.
func outageProbeTargets(now time.Time, candidates []string, item *policyHealthState, p effectivePolicySettings) []string {
	result := make([]string, 0, p.batch)
	if cap(result) == 0 {
		return result
	}
	interval := p.blockRecovery
	if item.Selected != "block" {
		interval = minInt(p.backup, p.blockRecovery)
	}
	if item.Selected == "block" && blockedRecoveryHasHistory(item) {
		// Keep recent working paths warm, but give a large emergency batch
		// enough lanes to discover never-tested subscription nodes promptly.
		hotLimit := minInt(cap(result)-1, maxInt(2, cap(result)/3))
		// A one-slot configuration alternates lanes only when an ordinary
		// candidate is due; otherwise the fast lane keeps its whole slot.
		if cap(result) == 1 {
			fairDue := false
			for _, candidate := range candidates {
				if item.LastProbeAt[candidate] == 0 || float64(now.Unix())-item.LastProbeAt[candidate] >= float64(interval) {
					fairDue = true
					break
				}
			}
			if !fairDue || (now.Unix()/int64(maxInt(p.failureRetry, 1)))%2 == 0 {
				hotLimit = 1
			}
		}
		lastWorking := ""
		if item.LastWorkingSelection != nil &&
			item.LastWorkingSelection.CandidateSignature == item.CandidateSignature &&
			item.LastWorkingSelection.Mode == item.Mode {
			lastWorking = item.LastWorkingSelection.Selected
		}
		for len(result) < hotLimit {
			oldest := ""
			for _, candidate := range candidates {
				if (item.LastGoodAt[candidate] <= 0 && candidate != lastWorking) ||
					contains(result, candidate) ||
					float64(now.Unix())-item.LastProbeAt[candidate] < float64(p.failureRetry) {
					continue
				}
				if oldest == "" || item.LastProbeAt[candidate] < item.LastProbeAt[oldest] ||
					(item.LastProbeAt[candidate] == item.LastProbeAt[oldest] && item.LastGoodAt[candidate] > item.LastGoodAt[oldest]) {
					oldest = candidate
				}
			}
			if oldest == "" {
				break
			}
			result = append(result, oldest)
		}
	}
	for len(result) < cap(result) {
		oldest := ""
		for _, candidate := range candidates {
			if contains(result, candidate) ||
				(item.LastProbeAt[candidate] != 0 && float64(now.Unix())-item.LastProbeAt[candidate] < float64(interval)) {
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

func blockedRecoveryHasHistory(item *policyHealthState) bool {
	return (item.LastWorkingSelection != nil &&
		item.LastWorkingSelection.Mode == item.Mode &&
		item.LastWorkingSelection.CandidateSignature == item.CandidateSignature) || len(item.LastGoodAt) > 0
}

func (controller *healthController) Tick(now time.Time) error {
	controller.yielded = false
	controller.processedGeneration = hotRuntimeGeneration{}
	for _, item := range controller.state {
		if item != nil {
			item.OutageBatchStartedAt = time.Time{}
		}
	}
	pool, runtimeReset, err := controller.runtime.Reload()
	if err != nil {
		return err
	}
	controller.processedPool = pool
	if source, ok := controller.runtime.(hotRuntimeGenerationSource); ok {
		controller.processedGeneration = source.hotRuntimeGeneration()
	}
	if runtimeReset {
		controller.warmStarted = make(map[string]bool)
		controller.reconciled = nil
		controller.regularNext = nil
		controller.livenessAt = nil
	}
	if controller.regularNext == nil {
		controller.regularNext = make(map[string]time.Time)
		controller.livenessAt = make(map[string]time.Time)
	}
	stateFile := statePath(controller.opts.StateRoot, "selector-health")
	if !controller.stateLoaded {
		loaded := make(healthState)
		if err := readJSON(stateFile, &loaded); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read selector health state: %w", err)
		}
		if loaded == nil {
			return errors.New("read selector health state: null state")
		}
		controller.state = loaded
		controller.stateLoaded = true
	}
	if runtimeReset {
		for _, item := range controller.state {
			if item != nil {
				clearOptimizationCandidate(item)
			}
		}
	}
	managed := make(healthState)
	policyIDs := make([]string, 0, len(pool.HealthPolicies))
	for policyID := range pool.HealthPolicies {
		policyIDs = append(policyIDs, policyID)
	}
	sort.Strings(policyIDs)
	controller.beginProbeBudget(pool, policyIDs)
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
		if urgent(policyIDs[i]) != urgent(policyIDs[j]) {
			return urgent(policyIDs[i])
		}
		first, second := controller.probeBudget.DeferredPolicies[policyIDs[i]], controller.probeBudget.DeferredPolicies[policyIDs[j]]
		firstDue := !first.IsZero() && !now.Before(controller.regularNext[policyIDs[i]])
		secondDue := !second.IsZero() && !now.Before(controller.regularNext[policyIDs[j]])
		if firstDue != secondDue {
			return firstDue
		}
		return firstDue && first.Before(second)
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
		beforeSelected, beforeSwitchAt := item.Selected, item.LastSwitchAt
		var err error
		activeFailures := item.AvailabilityFailures[item.Selected]
		confirmingFailure := activeFailures > 0 && activeFailures < policySettings(contract.Policy, contract.Mode).failureThreshold
		reconciled, hasReconciliation := controller.reconciled[policyID]
		confirmedReconciliation := hasReconciliation && item.RuntimeConfirmed && item.RuntimeSelected == item.Selected &&
			reconciled == (policyReconciliation{controller.processedGeneration, strings.Join(uniqueCandidates(contract.Candidates), "\n"), contract.Mode, item.Selected})
		warmWork := !controller.warmStarted[policyID] && !(confirmingFailure && confirmedReconciliation)
		// Finish a pending fast proof before due quality work. A confirmed outage
		// still enters tickPolicy immediately to probe reserves, not the active.
		if controller.transitions[policyID] != nil || warmWork ||
			(!controller.forceLiveness[policyID] && !confirmingFailure && !now.Before(controller.regularNext[policyID])) || item.Selected == "block" {
			delete(controller.forceLiveness, policyID)
			delete(controller.probeBudget.DeferredPolicies, policyID)
			err = controller.tickPolicy(now, policyID, contract, item)
			if !errors.Is(err, errHealthYield) {
				controller.regularNext[policyID] = now.Add(controller.remainingProbeInterval(now, contract, item))
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
		if errors.Is(err, errPolicyTransitionPending) {
			controller.regularNext[policyID] = time.Time{}
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
		if item.RuntimeConfirmed && item.Selected != beforeSelected {
			// A later policy can spend a whole probe window on routine work. Publish
			// the confirmed route now, retaining unprocessed but still managed state.
			snapshot := make(healthState, len(policyIDs))
			for _, id := range policyIDs {
				if value := controller.state[id]; value != nil {
					snapshot[id] = value
				}
			}
			if err := writeJSONAtomic(stateFile, snapshot); err != nil {
				failures = append(failures, fmt.Errorf("publish policy %s switch: %w", policyID, err))
			}
		}
		if item.RuntimeConfirmed && item.Selected != beforeSelected && item.LastSwitchAt != beforeSwitchAt {
			controller.emitHealthEvent(healthEvent{At: item.LastSwitchAt, Event: "switch", Policy: policyID,
				From: beforeSelected, To: item.Selected, Reason: item.LastSwitchReason,
				Failure:    probeFailureClass(item.FailureClass[beforeSelected]),
				Quality:    switchQualityEvidence(now, item, beforeSelected, item.Selected, item.LastSwitchReason),
				Comparison: switchOptimizationEvidence(item, item.Selected, item.LastSwitchReason)})
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
	if len(controller.probeBudget.Used) > 0 {
		controller.probeBudget.Cursor++
	}
	for id := range controller.transitions {
		if _, exists := pool.HealthPolicies[id]; !exists {
			delete(controller.transitions, id)
		}
	}
	for id := range controller.reconciled {
		if _, exists := pool.HealthPolicies[id]; !exists {
			delete(controller.reconciled, id)
		}
	}
	return errors.Join(failures...)
}

func (controller *healthController) regularInterval(contract healthPolicyContract) time.Duration {
	p := policySettings(contract.Policy, contract.Mode)
	qualityInterval := time.Duration(p.active) * time.Second
	if controller.opts.HealthInterval <= 0 || qualityInterval < controller.opts.HealthInterval {
		return qualityInterval
	}
	return controller.opts.HealthInterval
}

func newPolicyHealthState() *policyHealthState {
	return &policyHealthState{
		Failures: make(map[string]int), AvailabilityFailures: make(map[string]int), Recoveries: make(map[string]int),
		Samples: make(map[string][]healthSample), DailySamples: make(map[string][]healthSample), HistoryDays: make(map[string]map[string]dayBucket),
		LastProbeAt: make(map[string]float64), LastGoodAt: make(map[string]float64),
		FailureClass: make(map[string]string),
	}
}

func (controller *healthController) tickPolicy(now time.Time, policyID string, contract healthPolicyContract, item *policyHealthState) (tickErr error) {
	item.LatencyComparisons = nil
	item.OutageBatchStartedAt = time.Time{}
	trace := beginHealthStage("policy_tick", "controller", policyID, item.Selected)
	defer func() { trace.finish(tickErr == nil) }()
	ensureHealthMaps(item)
	candidates := uniqueCandidates(contract.Candidates)
	warm := !controller.warmStarted[policyID]
	coldSelection := warm && item.Selected == "" && item.LastWorkingSelection == nil && len(item.Samples) == 0
	// Preserve confirmed legacy history before a transient API error can clear it.
	rememberWorkingSelection(contract, item)
	if contract.Policy.LatencyMeasurement != "" && item.LatencyMeasurement != contract.Policy.LatencyMeasurement {
		item.LatencyMeasurement = contract.Policy.LatencyMeasurement
		item.Samples = make(map[string][]healthSample)
		item.LastProbeAt = make(map[string]float64)
		item.Recoveries = make(map[string]int)
		item.Failures = make(map[string]int)
		item.MedianDelayMS = nil
		item.QualityOK = nil
		clearOptimizationCandidate(item)
		item.OptimizationLastResult = nil
	}
	previousSelected, previousConfirmed := item.RuntimeSelected, item.RuntimeConfirmed
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
	replacedRemovedActive := false
	actual, actualErr := controller.runtime.Current(policyID)
	if actualErr != nil {
		item.RuntimeConfirmed = false
		item.RuntimeSelected = ""
		item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return actualErr
	}
	changedOutbounds := invalidateChangedOutboundHealth(item, candidates, contract.Nodes)
	if len(changedOutbounds) > 0 {
		controller.emitHealthEvent(healthEvent{Event: "health-evidence-reset", Policy: policyID,
			Reason: "outbound-changed", Count: len(changedOutbounds)})
		item.LastPreflightAt = 0
		item.PreflightClosed = nil
		item.ScanQueue = uniqueCandidates(append(changedOutbounds, item.ScanQueue...))
	}
	if actual != "" {
		if !contains(candidates, actual) && actual != "block" {
			// A changed eligibility list does not invalidate the running handler.
			// Probe the replacement before withdrawing the working path. Cached
			// reserve quality determines probe order, not present availability.
			replacement, pending, transitionErr := controller.transitionRemovedActive(now, policyID, contract, item, actual, p)
			if transitionErr != nil {
				return transitionErr
			}
			if pending {
				return errPolicyTransitionPending
			}
			if err := controller.runtime.Select(policyID, replacement); err != nil {
				item.RuntimeConfirmed = false
				item.RuntimeSelected = actual
				item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
				return err
			}
			selected, actual = replacement, replacement
			replacedRemovedActive = replacement != "block"
			item.Selected = replacement
			item.RuntimeSelected = replacement
			item.RuntimeConfirmed = true
			item.LastSwitchAt = now.UTC().Format(time.RFC3339)
			item.LastSwitchReason = "active-removed"
			delete(controller.transitions, policyID)
		} else {
			delete(controller.transitions, policyID)
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
	// A parallel transition may finish before a preferred candidate's fresh
	// probe. Do not immediately replace its winner with that candidate's cache.
	if !replacedRemovedActive && contract.Mode == "priority" && item.CandidateSignature != "" && priorityOrderChanged(item.CandidateSignature, candidates) && contains(candidates, selected) {
		for _, candidate := range candidates {
			if candidate == selected {
				break
			}
			if item.AvailabilityOK[candidate] {
				selected = candidate
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
	}
	if item.CandidateSignature != signature {
		pruneRemovedCandidateHealth(item, candidates)
	}
	labels := make(map[string]string, len(candidates))
	nodes := make(map[string]healthNode, len(candidates))
	for _, candidate := range candidates {
		labels[candidate] = firstNonEmpty(contract.Nodes[candidate].Label, candidate)
		nodes[candidate] = contract.Nodes[candidate]
	}
	item.CandidateLabels = labels
	item.CandidateNodes = nodes
	item.CandidateCount = len(candidates)
	// Publish confirmed membership before quality probes. This is
	// one extra atomic write on startup/change, not another polling cache.
	if !controller.warmStarted[policyID] || !previousConfirmed || previousSelected != item.RuntimeSelected || item.CandidateSignature != signature || len(changedOutbounds) > 0 {
		if err := writeJSONAtomic(statePath(controller.opts.StateRoot, "selector-health"), controller.state); err != nil {
			return err
		}
	}
	if item.CandidateSignature != signature {
		item.LastPreflightAt = 0
		item.PreflightClosed = nil
		item.ScanQueue = append([]string(nil), candidates...)
	}
	if item.Mode != "" && item.Mode != contract.Mode {
		clearOptimizationCandidate(item)
	}
	shortlist := workingShortlist(now, selected, candidates, contract.Mode, groupIndex, item, p)
	if controller.reconciled == nil {
		controller.reconciled = make(map[string]policyReconciliation)
	}
	// A canceled warm survey must not repeat slow work before the next fast
	// proof. Persisted confirmation alone cannot establish this startup prefix.
	controller.reconciled[policyID] = policyReconciliation{controller.processedGeneration, signature, contract.Mode, selected}

	probeTargets := []string{}
	emergencySwitched := false
	emergencyAttempted := false
	emergencyReason := ""
	var emergencyBatchStartedAt time.Time
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
		if outage {
			item.Recoveries[selected] = 0
		}
	}
	if outage {
		emergencyAttempted = true
		emergency := p
		if selected != "block" {
			emergency.backup = minInt(p.backup, p.failureRetry)
		}
		probeTargets = controller.emergencyTargets(now, candidates, item, emergency)
		probeTargets = prioritizeEmergencyReserve(probeTargets,
			knownFreshReserve(now, selected, withoutClosedCandidates(candidates, item.PreflightClosed), contract.Mode, groupIndex, item, p), item.PreflightClosed, p.batch)
	} else if !emergencySwitched {
		if warm {
			probeTargets = append(probeTargets, selected)
			for _, candidate := range uniqueCandidates(append(changedOutbounds, candidates...)) {
				if candidate != selected && len(probeTargets) < p.batch {
					probeTargets = append(probeTargets, candidate)
				}
			}
		} else {
			probeTargets = regularProbeTargets(now, selected, candidates, shortlist, item, p)
		}
	}

	if !outage {
		var deferred []string
		probeTargets, deferred = controller.claimProbeTargets(policyID, contract, probeTargets, false)
		item.ScanQueue = uniqueCandidates(append(deferred, item.ScanQueue...))
	}
	measured := make(map[string]probeEvidence)
	if outage {
		var emergencySelected string
		var probeErr error
		if len(probeTargets) > 0 {
			emergencyBatchStartedAt = time.Now()
		}
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
			outage = false
		}
	}
	if !outage && !emergencySwitched && len(probeTargets) > 1 {
		if _, ok := controller.runtime.(parallelQualityRuntime); ok {
			measured = controller.sharedQualityBatch(policyID, contract, probeTargets)
			if err := controller.takeSharedProbeInterruption(); err != nil {
				item.ScanQueue = uniqueCandidates(append(probeTargets, item.ScanQueue...))
				return err
			}
		}
	}
	deferredQuality := []string{}
	for index := 0; !emergencySwitched && !outage && index < len(probeTargets); index++ {
		candidate := probeTargets[index]
		if _, checked := measured[candidate]; !checked {
			measured[candidate] = controller.sharedQualityProbe(policyID, candidate, contract)
		}
		if err := controller.takeSharedProbeInterruption(); err != nil {
			item.ScanQueue = uniqueCandidates(append(probeTargets, item.ScanQueue...))
			return err
		}
		if measured[candidate].Deferred {
			delete(measured, candidate)
			deferredQuality = append(deferredQuality, candidate)
			item.ScanQueue = uniqueCandidates(append([]string{candidate}, item.ScanQueue...))
			controller.deferSharedProbe(policyID)
			continue
		}
		if measured[candidate].LocalFailure {
			return errProbeSelectorUnavailable
		}
		if candidate == selected && !measured[candidate].OK {
			item.FailureClass[selected] = string(measured[candidate].Failure)
			recoveringFromUnderlay := item.UnderlayFailure != ""
			if controller.suppressForUnderlayFailure(now, measured[candidate], item) {
				controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-suppressed", Policy: policyID, Node: selected,
					Failure: measured[candidate].Failure, Underlay: item.UnderlayFailure, Targets: probeTargetResults(measured[candidate])})
				item.AvailabilityFailures[selected] = 0
				delete(measured, candidate)
				continue
			}
			if recoveringFromUnderlay && item.UnderlayFailure == "" && measured[candidate].Failure != probeFailureTLS {
				// Match the fast lane: a first path-level failure just after the
				// common underlay recovers may be stale socket evidence.
				controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-suppressed", Policy: policyID, Node: selected,
					Failure: measured[candidate].Failure, Reason: "underlay-recovered", Targets: probeTargetResults(measured[candidate])})
				item.AvailabilityFailures[selected] = 0
				delete(measured, candidate)
				continue
			}
			controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-failed", Policy: policyID, Node: selected,
				Failure: measured[candidate].Failure, Count: item.AvailabilityFailures[selected] + 1,
				Threshold: startupFailureConfirmationThreshold(measured[candidate], p.failureThreshold, warm), Targets: probeTargetResults(measured[candidate])})
		} else if candidate == selected && measured[candidate].OK && item.AvailabilityFailures[selected] > 0 {
			controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-recovered", Policy: policyID, Node: selected,
				Targets: probeTargetResults(measured[candidate])})
		}
		if candidate == selected && !measured[candidate].OK &&
			item.AvailabilityFailures[selected]+1 >= startupFailureConfirmationThreshold(measured[candidate], p.failureThreshold, warm) {
			// Confirmed outage: probe reserves now, not after the backup timer.
			item.Recoveries[selected] = 0
			outage = true
			item.AvailabilityFailures[selected] = p.failureThreshold
			emergency := p
			emergency.backup = minInt(p.backup, p.failureRetry)
			eligibleReserves := make([]string, 0, len(candidates)-1)
			for _, reserve := range candidates {
				if reserve == selected {
					continue
				}
				if evidence, checked := measured[reserve]; checked && !evidence.OK {
					// A failed full probe in this tick is already fresh evidence.
					continue
				}
				eligibleReserves = append(eligibleReserves, reserve)
			}
			reserves := controller.emergencyTargets(now, eligibleReserves, item, emergency)
			reserves = prioritizeEmergencyReserve(reserves,
				knownFreshReserve(now, selected, withoutClosedCandidates(eligibleReserves, item.PreflightClosed), contract.Mode, groupIndex, item, p), item.PreflightClosed, p.batch)
			probeTargets = append([]string{selected}, reserves...)
			break
		}
	}
	probeTargets = without(probeTargets, deferredQuality)
	if outage && !emergencySwitched && !emergencyAttempted {
		emergencyAttempted = true
		var emergencySelected string
		var probeErr error
		reserveTargets := without(probeTargets, []string{selected})
		if len(reserveTargets) > 0 {
			emergencyBatchStartedAt = time.Now()
		}
		measuredReserves, selectedReserve, err := controller.probeEmergencyCandidates(policyID, reserveTargets, p)
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
			outage = false
		}
	}
	if outage {
		item.ScanQueue = without(item.ScanQueue, probeTargets)
	}
	controller.warmStarted[policyID] = true

	// Commit timestamps with the batch results, never for an interrupted batch.
	for candidate, evidence := range measured {
		item.LastProbeAt[candidate] = float64(now.Unix())
		if evidence.OK {
			item.LastGoodAt[candidate] = float64(now.Unix())
		}
	}

	for candidate, evidence := range measured {
		if evidence.QualityUnmeasured {
			evidence.DelayMS = nil
			measured[candidate] = evidence
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
		if evidence, ok := measured[candidate]; ok && (!evidence.OK || evidence.DelayMS != nil || evidence.QualityUnmeasured) {
			samples = append(samples, healthSample{At: float64(now.Unix()), OK: evidence.OK, DelayMS: evidence.DelayMS})
		}
		if len(samples) > 1 {
			samples = samples[len(samples)-1:]
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
		qualityOK[candidate] = typical != nil && failed == 0
		if evidence, ok := measured[candidate]; ok {
			if evidence.OK {
				delete(item.FailureClass, candidate)
				if candidate == selected {
					clearUnderlayFailure(item)
				}
			} else {
				item.FailureClass[candidate] = string(evidence.Failure)
			}
			// Count independent bad probes. A good current response clears
			// the pending degradation streak; history never controls selection.
			probeQuality := evidence.OK && evidence.DelayMS != nil && !evidence.QualityUnmeasured
			if probeQuality || evidence.OK && evidence.DelayMS == nil && !evidence.PrimaryQualityFailed {
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
			if evidence.OK && evidence.DelayMS == nil {
				// Availability is not a new confirmation of primary-origin quality.
				item.Recoveries[candidate] = 0
			} else if probeQuality {
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
		if evidence, ok := measured[candidate]; ok && evidence.OK {
			availabilityOK[candidate] = true
		}
		// Give newly discovered good candidates enough independent quality
		// samples to qualify without waiting for another full-scan interval.
		if evidence, ok := measured[candidate]; ok && evidence.OK && item.Recoveries[candidate] > 0 && item.Recoveries[candidate] < p.recoveryThreshold && !contains(item.ScanQueue, candidate) {
			item.ScanQueue = append(item.ScanQueue, candidate)
		}
	}

	desired, reason := selectDesired(now, contract.Mode, selected, candidates, groupIndex, dailyStats, medians, measured, qualityOK, availabilityOK, item, p)
	if coldSelection && contract.Mode == "best" && !emergencySwitched {
		// Choose the lowest successful first-batch latency, not a tolerated
		// inventory default. Restarts with working history keep their selection.
		best, delay := "", 0
		for _, candidate := range candidates {
			evidence := measured[candidate]
			if evidence.OK && evidence.DelayMS != nil && *evidence.DelayMS > 0 &&
				(best == "" || *evidence.DelayMS < delay) {
				best, delay = candidate, *evidence.DelayMS
			}
		}
		if best != "" && best != selected {
			desired, reason = best, "initial-lowest-latency"
		}
	}
	if emergencySwitched {
		desired, reason = selected, emergencyReason
	} else if replacedRemovedActive && selected != "block" && item.AvailabilityFailures[selected] < p.failureThreshold {
		// Keep a freshly validated membership replacement for this Tick.
		// Later ticks may optimize it normally;
		// a confirmed failure above still retains the ordinary emergency path.
		desired, reason = selected, ""
	}
	var comparison *optimizationComparison
	if contract.Mode == "best" && reason == "meaningfully-faster" {
		comparison = regularOptimizationComparison(now, selected, desired, measured, item, qualityOK[desired], availabilityOK[desired], p)
	} else if contract.Mode == "best" && item.OptimizationCandidate != "" {
		candidate := item.OptimizationCandidate
		comparison = regularOptimizationComparison(now, selected, candidate, measured, item, qualityOK[candidate], availabilityOK[candidate], p)
	}
	desired, reason = gatePlannedOptimization(now, selected, desired, reason, comparison, item, p)
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
	item.LatencyComparisons = currentLatencyComparisons(now, item, candidates, p)
	shortlist = workingShortlist(now, item.Selected, candidates, contract.Mode, groupIndex, item, p)
	reserves := len(without(shortlist, []string{item.Selected}))
	item.CandidateLabels, item.CandidateGroups, item.GroupLabels = labels, groupIndex, groupLabels
	item.CandidateServiceStatus = serviceStatus
	item.CandidateSignature, item.Shortlist = signature, shortlist
	item.ProbedCandidates, item.HTTPSProbeTargets = probeTargets, targetsMap
	item.Mode, item.CandidateCount, item.HealthyReserves = contract.Mode, len(candidates), reserves
	item.ProbeLimits = probeLimits{
		Batch: p.batch, Shortlist: p.shortlist, ActiveSeconds: p.active,
		BackupSeconds:   p.backup,
		LivenessSeconds: p.liveness, FailureRetrySeconds: p.failureRetry,
		BlockRecoverySeconds: p.blockRecovery,
	}
	// Keep draining eligible, untested candidates at the emergency interval.
	// The cheaper block recovery interval applies after that sweep is exhausted.
	item.OutageProbePending = item.Selected == "block" && len(outageProbeTargets(now, withoutClosedCandidates(candidates, item.PreflightClosed), item, p)) > 0
	if item.OutageProbePending && len(measured) > 0 {
		item.OutageBatchStartedAt = emergencyBatchStartedAt
	}
	item.QualityThresholds = qualityThresholds{SwitchImprovementMS: p.improvement, FailureConfirmations: p.failureThreshold, RecoveryConfirmations: p.recoveryThreshold}
	item.CheckedAt = now.UTC().Format(time.RFC3339)
	rememberWorkingSelection(contract, item)
	return nil
}
