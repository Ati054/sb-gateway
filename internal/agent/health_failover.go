package agent

import "time"

type probeFailureClass string

const (
	probeFailureNone      probeFailureClass = ""
	probeFailureTimeout   probeFailureClass = "timeout"
	probeFailureFatal     probeFailureClass = "fatal-network"
	probeFailureTLS       probeFailureClass = "fatal-tls"
	probeFailureDNS       probeFailureClass = "dns"
	probeFailureTransient probeFailureClass = "transient"
)

type underlayEvidence struct {
	Known bool
	WANOK bool
	DNSOK bool
}

type underlayRuntime interface {
	UnderlayStatus() underlayEvidence
}

type parallelAvailabilityRuntime interface {
	ProbeAvailabilityParallel([]string, func(string, probeEvidence) bool) map[string]probeEvidence
}

func failureConfirmationThreshold(evidence probeEvidence, configured int) int {
	switch evidence.Failure {
	case probeFailureFatal, probeFailureTLS:
		return 1
	case probeFailureTimeout:
		return minInt(configured, 2)
	default:
		return configured
	}
}

func startupFailureConfirmationThreshold(evidence probeEvidence, configured int, warm bool) int {
	threshold := failureConfirmationThreshold(evidence, configured)
	if warm && evidence.Failure != probeFailureTLS && configured > 1 && threshold < 2 {
		// The first active probe after a core restart can race the newly restored
		// dynamic handler and briefly report connection refused/no route. Preserve
		// the confirmed startup selection until one independent fast-lane probe
		// repeats that network failure. A TLS failure remains deterministic and
		// therefore keeps its immediate failover semantics.
		return 2
	}
	return threshold
}

func (controller *healthController) suppressForUnderlayFailure(now time.Time, evidence probeEvidence, item *policyHealthState) bool {
	// A certificate or protocol failure belongs to the selected path. Checking
	// the shared WAN first would only delay a deterministic failover.
	if evidence.Failure == probeFailureTLS {
		item.UnderlayFailure = ""
		item.UnderlayCheckedAt = ""
		return false
	}
	probe, ok := controller.runtime.(underlayRuntime)
	if !ok {
		return false
	}
	status := probe.UnderlayStatus()
	if !status.Known {
		return false
	}
	item.UnderlayCheckedAt = now.UTC().Format(time.RFC3339Nano)
	switch {
	case !status.WANOK:
		item.UnderlayFailure = "wan"
		return true
	case !status.DNSOK:
		item.UnderlayFailure = "dns"
		return true
	default:
		item.UnderlayFailure = ""
		return false
	}
}

func clearUnderlayFailure(item *policyHealthState) bool {
	changed := item.UnderlayFailure != "" || item.UnderlayCheckedAt != ""
	item.UnderlayFailure = ""
	item.UnderlayCheckedAt = ""
	return changed
}

func knownFreshReserve(now time.Time, selected string, candidates []string, mode string, groups map[string]int, item *policyHealthState, p effectivePolicySettings) string {
	fresh := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == selected || !item.AvailabilityOK[candidate] || !item.QualityOK[candidate] ||
			item.AvailabilityFailures[candidate] != 0 || item.Recoveries[candidate] < p.recoveryThreshold ||
			item.MedianDelayMS[candidate] == nil || item.LastProbeAt[candidate] <= 0 ||
			float64(now.Unix())-item.LastProbeAt[candidate] > float64(p.backup) {
			continue
		}
		fresh = append(fresh, candidate)
	}
	if len(fresh) == 0 {
		return ""
	}
	speeds := item.SpeedMedianBPS
	if !p.speedEnabled {
		speeds = nil
	}
	return rankCandidates(fresh, mode, groups, item.DailyStats, item.MedianDelayMS, speeds)[0]
}

func (controller *healthController) probeEmergencyCandidates(policyID string, candidates []string, p effectivePolicySettings) (map[string]probeEvidence, string, error) {
	measured := make(map[string]probeEvidence, len(candidates))
	selected := ""
	var selectErr error
	accept := func(candidate string, evidence probeEvidence) bool {
		if selected != "" || selectErr != nil || !evidence.OK ||
			(p.maxLatency > 0 && (evidence.DelayMS == nil || *evidence.DelayMS > p.maxLatency)) {
			return false
		}
		if err := controller.runtime.Select(policyID, candidate); err != nil {
			selectErr = err
			return false
		}
		selected = candidate
		return true
	}
	if parallel, ok := controller.runtime.(parallelAvailabilityRuntime); ok && len(candidates) > 1 {
		measured = parallel.ProbeAvailabilityParallel(candidates, accept)
	} else {
		for _, candidate := range candidates {
			evidence := controller.runtime.ProbeAvailability(candidate)
			measured[candidate] = evidence
			accept(candidate, evidence)
		}
	}
	if err := takeProbeInterruption(controller.runtime); err != nil {
		return measured, selected, err
	}
	return measured, selected, selectErr
}
