package agent

import (
	"errors"
	"strings"
	"time"
)

var errPolicyTransitionPending = errors.New("policy replacement is still being probed")

// A live hot Apply waits less than this grace and restores the old contract on
// timeout. The independent bound also prevents an abandoned subscription change
// from retaining an ineligible path indefinitely.
const policyTransitionGrace = 2 * time.Minute

type policyTransition struct {
	previous  string
	signature string
	started   time.Time
	remaining []string
}

func (controller *healthController) transitionRemovedActive(now time.Time, policyID string, contract healthPolicyContract, item *policyHealthState, actual string, p effectivePolicySettings) (string, bool, error) {
	if !item.RuntimeConfirmed || item.RuntimeSelected != actual || item.Selected != actual ||
		item.AvailabilityFailures[actual] >= p.failureThreshold {
		delete(controller.transitions, policyID)
		return "block", false, nil
	}
	if controller.transitions == nil {
		controller.transitions = make(map[string]*policyTransition)
	}
	if controller.livenessAt == nil {
		controller.livenessAt = make(map[string]time.Time)
	}
	signature := strings.Join(uniqueCandidates(contract.Candidates), "\n")
	transition := controller.transitions[policyID]
	if transition == nil || transition.previous != actual || transition.signature != signature {
		transition = &policyTransition{previous: actual, signature: signature, started: now}
		controller.transitions[policyID] = transition
	}
	if now.Sub(transition.started) >= policyTransitionGrace {
		delete(controller.transitions, policyID)
		return "block", false, nil
	}
	// Keep checking the old path while preparation is pending. A real outage
	// still follows the ordinary failure confirmation and underlay safeguards.
	livenessContract := contract
	livenessContract.Candidates = append(append([]string(nil), contract.Candidates...), actual)
	if _, err := controller.checkActiveAvailability(now, policyID, livenessContract, item, false); err != nil {
		if item.AvailabilityFailures[actual] >= p.failureThreshold {
			delete(controller.transitions, policyID)
			return "block", false, nil
		}
		return "", false, err
	}
	if len(transition.remaining) == 0 {
		transition.remaining = uniqueCandidates(contract.Candidates)
		if preflight, ok := controller.runtime.(emergencyPreflightRuntime); ok {
			opened, _, err := preflight.PrioritizeEmergency(transition.remaining)
			if err == nil {
				transition.remaining = uniqueCandidates(append(opened, transition.remaining...))
			}
			if err := takeProbeInterruption(controller.runtime); err != nil {
				return "", false, err
			}
		}
		groups, _, _ := candidateGroups(contract.Groups, contract.Candidates, contract.Mode)
		if reserve := knownHealthyReplacement(contract.Candidates, contract.Mode, groups, item, p); reserve != "" {
			transition.remaining = uniqueCandidates(append([]string{reserve}, transition.remaining...))
		}
	}
	count := minInt(maxInt(p.batch, 1), len(transition.remaining))
	targets := append([]string(nil), transition.remaining[:count]...)
	selected := ""
	accept := func(candidate string, evidence probeEvidence) bool {
		item.LastProbeAt[candidate] = float64(now.Unix())
		usable := evidence.OK && (p.maxLatency <= 0 || (evidence.DelayMS != nil && *evidence.DelayMS <= p.maxLatency))
		// A reserve which just failed must not be resurrected by the ordinary
		// priority-reorder branch later in this same Tick.
		if !usable {
			item.AvailabilityOK[candidate] = false
			item.Recoveries[candidate] = 0
		}
		if selected != "" || !usable {
			return false
		}
		selected = candidate
		return true
	}
	if parallel, ok := controller.runtime.(parallelAvailabilityRuntime); ok && len(targets) > 1 {
		parallel.ProbeAvailabilityParallel(targets, accept)
	} else {
		for _, candidate := range targets {
			evidence := controller.runtime.ProbeAvailability(candidate)
			if evidence.LocalFailure {
				return "", false, errProbeSelectorUnavailable
			}
			if accept(candidate, evidence) {
				break
			}
		}
	}
	if err := takeProbeInterruption(controller.runtime); err != nil {
		return "", false, err
	}
	transition.remaining = transition.remaining[count:]
	if selected != "" {
		return selected, false, nil
	}
	item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return "", true, nil
}
