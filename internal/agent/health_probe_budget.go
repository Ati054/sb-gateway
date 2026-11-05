package agent

import (
	"errors"
	"time"
)

const sharedProbeLifetime = 15 * time.Second

var errSharedProbeDeferred = errors.New("shared probe already attempted in this cycle")

func (controller *healthController) deferSharedProbe(policyID string) {
	if controller.probeBudget != nil {
		if _, exists := controller.probeBudget.DeferredPolicies[policyID]; !exists {
			controller.probeBudget.DeferredPolicies[policyID] = time.Now()
		}
	}
}

type sharedProbeResult struct {
	At       time.Time
	Evidence probeEvidence
}

type parallelQualityRuntime interface {
	ProbeQualityParallel([]string) map[string]probeEvidence
}

type requestedQualityRuntime interface {
	ProbeWithQualityRequest(string, qualityProbeRequest) probeEvidence
}

type measuredParallelQualityRuntime interface {
	ProbeQualityParallelWithMeasurement([]string, qualityMeasurement) map[string]probeEvidence
}

func (controller *healthController) probeQuality(policyID, node string, contract healthPolicyContract) probeEvidence {
	measurement := controller.qualityMeasurementForPolicy(policyID, contract)
	if isPairedPlanningMeasurement(measurement) {
		if runtime, ok := controller.runtime.(requestedQualityRuntime); ok {
			return runtime.ProbeWithQualityRequest(node, qualityProbeRequest{Measurement: measurement})
		}
	}
	return controller.runtime.Probe(node)
}

func (controller *healthController) sharedQualityBatch(policyID string, contract healthPolicyContract, nodes []string) map[string]probeEvidence {
	result := make(map[string]probeEvidence, len(nodes))
	needsFreshPair := controller.sharedPairWouldExpire(policyID, contract, nodes) || controller.warmSharedPairBeforePendingInterval(policyID, contract, nodes)
	if needsFreshPair && !controller.refreshUnattemptedWarmTargets(policyID, contract, nodes) {
		// Give the ordinary fair scheduler the whole pair on the next turn.
		// Do not spend requests or retain reservations for an unusable half.
		for _, node := range nodes {
			result[node] = probeEvidence{Deferred: true}
			key := controller.probeKey(policyID, node, contract)
			if !controller.probeBudget.QualityAttempted[key] {
				delete(controller.probeBudget.Used, key)
			}
		}
		controller.deferSharedProbe(policyID)
		return result
	}
	pending := []string{}
	for _, node := range nodes {
		key := controller.probeKey(policyID, node, contract)
		if cached, ok := controller.probeBudget.Quality[key]; ok && time.Since(cached.At) <= sharedProbeLifetime {
			result[node] = cached.Evidence
		} else if controller.probeBudget.QualityAttempted[key] {
			result[node] = probeEvidence{Deferred: true}
		} else {
			pending = append(pending, node)
		}
	}
	legacy, oldParallel := controller.runtime.(parallelQualityRuntime)
	requested, newParallel := controller.runtime.(measuredParallelQualityRuntime)
	if (oldParallel || newParallel) && len(pending) > 1 {
		wave := uint64(0)
		if qualityProbeWidth(controller.runtime) > 1 {
			wave = qualityWaveSequence.Add(1)
		}
		for _, node := range pending {
			controller.probeBudget.QualityAttempted[controller.probeKey(policyID, node, contract)] = true
		}
		var observations map[string]probeEvidence
		if newParallel && isPairedPlanningMeasurement(controller.qualityMeasurementForPolicy(policyID, contract)) {
			observations = requested.ProbeQualityParallelWithMeasurement(pending, controller.qualityMeasurementForPolicy(policyID, contract))
		} else if oldParallel {
			observations = legacy.ProbeQualityParallel(pending)
		} else {
			observations = requested.ProbeQualityParallelWithMeasurement(pending, qualityMeasurementCold)
		}
		for node, evidence := range observations {
			if evidence.QualityWave == 0 {
				evidence.QualityWave = wave
			}
			result[node] = evidence
			if controller.cacheableQualityEvidence(policyID, node, contract, evidence) {
				controller.probeBudget.Quality[controller.probeKey(policyID, node, contract)] = sharedProbeResult{At: probeObservedAt(evidence), Evidence: evidence}
			}
		}
	} else {
		for _, node := range pending {
			result[node] = controller.sharedQualityProbe(policyID, node, contract)
		}
	}
	return result
}

// A valid shared wave may still precede this policy's confirmation interval.
// Consuming it would move the producer clock without earning a proof, making
// the next genuine pair wait an unnecessary full interval or expire the first.
func (controller *healthController) warmSharedPairBeforePendingInterval(policyID string, contract healthPolicyContract, nodes []string) bool {
	item, budget := controller.state[policyID], controller.probeBudget
	if item == nil || budget == nil || len(nodes) != 2 || item.OptimizationChecks == 0 || item.OptimizationLastResult == nil ||
		!isPairedPlanningMeasurement(controller.qualityMeasurementForPolicy(policyID, contract)) ||
		!contains(nodes, item.Selected) || !contains(nodes, item.OptimizationCandidate) {
		return false
	}
	cached, exists := budget.Quality[controller.probeKey(policyID, item.OptimizationCandidate, contract)]
	if !exists || time.Since(cached.At) > sharedProbeLifetime {
		return false
	}
	return controller.warmCachedCandidateBeforeInterval(policyID, item.OptimizationCandidate, contract, cached.Evidence)
}

func (controller *healthController) warmCachedCandidateBeforeInterval(policyID, node string, contract healthPolicyContract, evidence probeEvidence) bool {
	if !isPairedPlanningMeasurement(controller.qualityMeasurementForPolicy(policyID, contract)) {
		return false
	}
	item := controller.state[policyID]
	if item == nil || !isPairedPlanningMeasurement(qualityMeasurement(item.WarmPlanningMarker)) || item.OptimizationChecks == 0 ||
		item.OptimizationLastResult == nil || node != item.OptimizationCandidate || !validPlanningQuality(evidence.planningQuality(), qualityMeasurement(item.WarmPlanningMarker)) {
		return false
	}
	observedAt := float64(evidence.planningQuality().ObservedAt.UnixNano()) / float64(time.Second)
	return !optimizationCandidateIntervalElapsed(item, observedAt, policySettings(contract.Policy, contract.Mode))
}

// A cached side of another physical wave cannot accompany a fresh peer. Only
// unattempted keys may be replaced; an already executed job never runs twice
// in one Tick, and every new physical job must fit the ordinary budget.
func (controller *healthController) refreshUnattemptedWarmTargets(policyID string, contract healthPolicyContract, nodes []string) bool {
	budget := controller.probeBudget
	if budget == nil || len(nodes) < 1 || len(nodes) > 2 || !isPairedPlanningMeasurement(controller.qualityMeasurementForPolicy(policyID, contract)) {
		return false
	}
	needed := 0
	for _, node := range nodes {
		key := controller.probeKey(policyID, node, contract)
		if budget.QualityAttempted[key] {
			return false
		}
		if !budget.Used[key] {
			needed++
		}
	}
	if budget.Limit > 0 && len(budget.Used)+needed > budget.Limit {
		return false
	}
	if budget.Used == nil {
		budget.Used = make(map[string]bool)
	}
	for _, node := range nodes {
		key := controller.probeKey(policyID, node, contract)
		delete(budget.Quality, key)
		budget.Used[key] = true
	}
	return true
}

func (controller *healthController) cacheableQualityEvidence(policyID, node string, contract healthPolicyContract, evidence probeEvidence) bool {
	return evidence.OK && contract.Nodes[node].Fingerprint != "" &&
		(!isPairedPlanningMeasurement(controller.qualityMeasurementForPolicy(policyID, contract)) ||
			!evidence.PrimaryQualityFailed && !evidence.QualityUnmeasured && validPlanningQuality(evidence.planningQuality(), controller.qualityMeasurementForPolicy(policyID, contract)))
}

// Raw results may be shared for longer than the comparison skew. A URLTest
// wave containing its active node must still fit the existing pair window,
// including primary requests which have not started yet.
func (controller *healthController) sharedPairWouldExpire(policyID string, contract healthPolicyContract, nodes []string) bool {
	if contract.Mode == "best" && len(nodes) > 1 && controller.incoherentQualityWave(policyID, contract, nodes) {
		return true
	}
	item := controller.state[policyID]
	lanes := controller.qualitySurveyLanes()
	if contract.Mode != "best" || item == nil || !contains(nodes, item.Selected) || lanes <= 0 || controller.probeBudget == nil {
		return false
	}
	now := time.Now()
	var first, last time.Time
	pending := 0
	for _, node := range nodes {
		key := controller.probeKey(policyID, node, contract)
		cached, ok := controller.probeBudget.Quality[key]
		age := now.Sub(cached.At)
		if !ok || age < 0 || age > sharedProbeLifetime {
			if !controller.probeBudget.QualityAttempted[key] {
				pending++
			}
			continue
		}
		if first.IsZero() || cached.At.Before(first) {
			first = cached.At
		}
		if cached.At.After(last) {
			last = cached.At
		}
	}
	if first.IsZero() {
		return false
	}
	if pending > 0 {
		waves := (pending + lanes - 1) / lanes
		last = now.Add(time.Duration(waves) * qualityProbeTimeout)
	}
	return last.Sub(first) > optimizationPairSkew
}

func probeObservedAt(evidence probeEvidence) time.Time {
	if !evidence.ObservedAt.IsZero() {
		return evidence.ObservedAt
	}
	return time.Now()
}

func (controller *healthController) takeSharedProbeInterruption() error {
	err := takeProbeInterruption(controller.runtime)
	if err != nil && controller.probeBudget != nil {
		// Partial results cannot cross a generation change or policy transition.
		controller.probeBudget.Quality = map[string]sharedProbeResult{}
	}
	return err
}

// Only raw endpoint evidence is shared. Each policy keeps its own thresholds,
// history, priority order and switch confirmations.
type healthProbeBudget struct {
	Limit            int
	Used             map[string]bool
	Quality          map[string]sharedProbeResult
	Cursor           int
	QualityAttempted map[string]bool
	DeferredPolicies map[string]time.Time
}

func (controller *healthController) beginProbeBudget(pool healthPool, policyIDs []string) {
	if controller.probeBudget == nil {
		controller.probeBudget = &healthProbeBudget{Quality: map[string]sharedProbeResult{}}
	}
	budget := controller.probeBudget
	budget.Limit, budget.Used = pool.ProbeBudget, map[string]bool{}
	// A sample can serve different policies once, never another Tick's recovery.
	budget.Quality = map[string]sharedProbeResult{}
	budget.QualityAttempted = map[string]bool{}
	if budget.DeferredPolicies == nil {
		budget.DeferredPolicies = map[string]time.Time{}
	}
	for id := range budget.DeferredPolicies {
		if _, exists := pool.HealthPolicies[id]; !exists {
			delete(budget.DeferredPolicies, id)
		}
	}
	if len(policyIDs) > 1 {
		offset := budget.Cursor % len(policyIDs)
		ordered := append(append([]string{}, policyIDs[offset:]...), policyIDs[:offset]...)
		copy(policyIDs, ordered)
	}
}

func (controller *healthController) probeKey(policyID, node string, contract healthPolicyContract) string {
	prefix := ""
	if isPairedPlanningMeasurement(controller.opts.planningMeasurement()) {
		prefix = string(controller.qualityMeasurementForPolicy(policyID, contract)) + ":" + controller.qualityContextKey() + ":"
	}
	if fingerprint := contract.Nodes[node].Fingerprint; fingerprint != "" {
		return prefix + fingerprint
	}
	// An unverified legacy endpoint cannot share evidence across policies.
	return prefix + policyID + ":" + node
}

func (controller *healthController) claimProbeTargets(policyID string, contract healthPolicyContract, targets []string, atomicPair bool) (accepted, deferred []string) {
	budget := controller.probeBudget
	if budget == nil || budget.Limit <= 0 {
		return targets, nil
	}
	now := time.Now()
	usable := func(key string) (cached, attempted bool) {
		result, ok := budget.Quality[key]
		return ok && now.Sub(result.At) <= sharedProbeLifetime, budget.QualityAttempted[key]
	}
	markDeferred := func() {
		if _, exists := budget.DeferredPolicies[policyID]; !exists {
			budget.DeferredPolicies[policyID] = now
		}
	}
	newKeys := map[string]bool{}
	for _, node := range targets {
		key := controller.probeKey(policyID, node, contract)
		cached, attempted := usable(key)
		if atomicPair && attempted && !cached {
			markDeferred()
			return nil, targets
		}
		if !budget.Used[key] {
			newKeys[key] = true
		}
	}
	// Comparisons are indivisible: consuming half a pair can starve the next list.
	if atomicPair && len(newKeys)+len(budget.Used) > budget.Limit {
		markDeferred()
		return nil, targets
	}
	for _, node := range targets {
		key := controller.probeKey(policyID, node, contract)
		cached, attempted := usable(key)
		if !cached && attempted {
			deferred = append(deferred, node)
		} else if cached || budget.Used[key] || len(budget.Used) < budget.Limit {
			accepted = append(accepted, node)
			if !cached {
				budget.Used[key] = true
			}
		} else {
			deferred = append(deferred, node)
		}
	}
	if len(deferred) > 0 {
		markDeferred()
	}
	return accepted, deferred
}

func (controller *healthController) sharedQualityProbe(policyID, node string, contract healthPolicyContract) probeEvidence {
	budget := controller.probeBudget
	if budget == nil {
		return controller.probeQuality(policyID, node, contract)
	}
	key := controller.probeKey(policyID, node, contract)
	if result, ok := budget.Quality[key]; ok && time.Since(result.At) <= sharedProbeLifetime {
		if !controller.warmCachedCandidateBeforeInterval(policyID, node, contract, result.Evidence) {
			return result.Evidence
		}
		if !controller.refreshUnattemptedWarmTargets(policyID, contract, []string{node}) {
			controller.deferSharedProbe(policyID)
			return probeEvidence{Deferred: true}
		}
	}
	if budget.QualityAttempted[key] {
		return probeEvidence{Deferred: true}
	}
	budget.QualityAttempted[key] = true
	evidence := controller.probeQuality(policyID, node, contract)
	if controller.cacheableQualityEvidence(policyID, node, contract, evidence) {
		budget.Quality[key] = sharedProbeResult{At: probeObservedAt(evidence), Evidence: evidence}
	}
	return evidence
}
