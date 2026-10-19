package agent

import (
	"errors"
	"time"
)

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

type emergencyAvailabilityRuntime interface {
	ProbeEmergencyAvailabilityParallel([]string, func(string, probeEvidence) bool) map[string]probeEvidence
}

type rankedEmergencyAvailabilityRuntime interface {
	ProbeRankedEmergencyAvailabilityParallel([]string, []string, func(string, probeEvidence) bool) map[string]probeEvidence
}

type emergencyCandidateRuntime interface {
	ProbeEmergencyAvailability(string) probeEvidence
}

type reverseSessionRuntime interface {
	reverseOnlineStatus(string) (bool, error)
}

func (controller *healthController) retainTimedOutSelection(selected string, candidates []string, contract healthPolicyContract, item *policyHealthState) (bool, error) {
	if !item.RuntimeConfirmed || selected == "" || selected == "block" ||
		!contains(candidates, selected) || item.FailureClass[selected] != string(probeFailureTimeout) {
		return false, nil
	}
	switch contract.Nodes[selected].Protocol {
	case "vless", "reality":
		return true, nil
	case "xray-reverse":
		// Handler presence alone can outlive a bridge. Never reuse a saved
		// online observation to retain a Reverse path after an HTTP timeout.
		runtime, ok := controller.runtime.(reverseSessionRuntime)
		if !ok {
			return false, nil
		}
		online, err := runtime.reverseOnlineStatus(selected)
		if err != nil {
			if errors.Is(err, errHealthYield) {
				return false, err
			}
			return false, errProbeSelectorUnavailable
		}
		return online, nil
	default:
		return false, nil
	}
}

const emergencyPreferenceWait = time.Second

type emergencyChoice struct {
	preferred    []string
	firstSuccess string
	expired      bool
}

func (choice *emergencyChoice) ready(measured map[string]probeEvidence) (string, probeEvidence) {
	pending := false
	for _, candidate := range choice.preferred {
		evidence, checked := measured[candidate]
		if !checked {
			pending = true
			continue
		}
		if evidence.OK {
			if pending && !choice.expired {
				return "", probeEvidence{}
			}
			return candidate, evidence
		}
	}
	if choice.firstSuccess != "" && (!pending || choice.expired) {
		return choice.firstSuccess, measured[choice.firstSuccess]
	}
	return "", probeEvidence{}
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
	fresh := knownFreshReserves(now, selected, candidates, mode, groups, item, p)
	if len(fresh) == 0 {
		return ""
	}
	return fresh[0]
}

func knownFreshReserves(now time.Time, selected string, candidates []string, mode string, groups map[string]int, item *policyHealthState, p effectivePolicySettings) []string {
	fresh := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == selected || !item.AvailabilityOK[candidate] || !item.QualityOK[candidate] ||
			item.AvailabilityFailures[candidate] != 0 || item.Recoveries[candidate] < p.recoveryThreshold ||
			candidateDelay(candidate, item.MedianDelayMS) <= 0 {
			continue
		}
		// Availability-only probes must not refresh an old quality ranking.
		age, recentQuality := qualitySampleAge(now, item, candidate)
		if !recentQuality || age > float64(p.backup) {
			continue
		}
		fresh = append(fresh, candidate)
	}
	return rankCandidates(fresh, mode, groups, nil, item.MedianDelayMS)
}

// A cached reserve gets the first emergency slot, but must pass a current
// availability probe before Select. The configured batch size still bounds
// work even when several reserves fail together.
func prioritizeEmergencyReserve(targets []string, reserve string, closed map[string]bool, batch int) []string {
	if reserve == "" || closed[reserve] || batch <= 0 {
		return targets
	}
	result := []string{reserve}
	for _, target := range targets {
		if len(result) >= batch {
			break
		}
		if target != reserve {
			result = append(result, target)
		}
	}
	return result
}

func emergencyProbePlan(now time.Time, selected string, targets, candidates []string, groups map[string]int, item *policyHealthState, p effectivePolicySettings) ([]string, []string) {
	if p.mode != "best" {
		return prioritizeEmergencyReserve(targets, knownFreshReserve(now, selected, withoutClosedCandidates(candidates, item.PreflightClosed), p.mode, groups, item, p), item.PreflightClosed, p.batch), nil
	}
	fresh := knownFreshReserves(now, selected, withoutClosedCandidates(candidates, item.PreflightClosed), p.mode, groups, item, p)
	if len(fresh) == 0 {
		return targets, nil
	}
	// Keep one sweep slot so unknown endpoints still get a current probe.
	result := append([]string(nil), fresh[:minInt(len(fresh), maxInt(1, p.batch-1))]...)
	for _, candidate := range targets {
		if len(result) >= p.batch {
			break
		}
		if !contains(result, candidate) {
			result = append(result, candidate)
		}
	}
	preferred := []string{}
	for _, candidate := range fresh {
		if contains(result, candidate) {
			preferred = append(preferred, candidate)
		}
	}
	return result, preferred
}

func (controller *healthController) probeEmergencyCandidates(policyID string, candidates []string, preferred []string) (observations map[string]probeEvidence, chosen string, probeErr error) {
	trace := beginHealthStage("emergency_batch", "controller", policyID, "")
	defer func() { trace.finish(probeErr == nil && chosen != "") }()
	measured := make(map[string]probeEvidence, len(candidates))
	selected := ""
	var selectErr error
	accept := func(candidate string, evidence probeEvidence) bool {
		if selected != "" || selectErr != nil || !evidence.OK {
			return false
		}
		if err := controller.runtime.Select(policyID, candidate); err != nil {
			selectErr = err
			return false
		}
		selected = candidate
		return true
	}
	if ranked, ok := controller.runtime.(rankedEmergencyAvailabilityRuntime); ok && len(preferred) > 0 {
		measured = ranked.ProbeRankedEmergencyAvailabilityParallel(candidates, preferred, accept)
	} else if urgent, ok := controller.runtime.(emergencyAvailabilityRuntime); ok && len(candidates) > 0 {
		measured = urgent.ProbeEmergencyAvailabilityParallel(candidates, accept)
	} else if parallel, ok := controller.runtime.(parallelAvailabilityRuntime); ok && len(candidates) > 1 {
		measured = parallel.ProbeAvailabilityParallel(candidates, accept)
	} else {
		for _, candidate := range candidates {
			evidence := controller.runtime.ProbeAvailability(candidate)
			if evidence.LocalFailure {
				return measured, selected, errProbeSelectorUnavailable
			}
			measured[candidate] = evidence
			if accept(candidate, evidence) {
				break
			}
		}
	}
	if err := takeProbeInterruption(controller.runtime); err != nil {
		return measured, selected, err
	}
	return measured, selected, selectErr
}
