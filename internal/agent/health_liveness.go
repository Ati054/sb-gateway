package agent

import "time"

// The fast lane only checks the active path. It neither scores candidates nor
// drains scan queues, downloads speed samples or rewrites healthy history.
func (controller *healthController) tickActiveAvailability(now time.Time, policyID string, contract healthPolicyContract, item *policyHealthState) (bool, error) {
	return controller.checkActiveAvailability(now, policyID, contract, item, true)
}

func (controller *healthController) checkActiveAvailability(now time.Time, policyID string, contract healthPolicyContract, item *policyHealthState, recoverNow bool) (bool, error) {
	ensureHealthMaps(item)
	selected := item.Selected
	if !contains(contract.Candidates, selected) {
		if !recoverNow {
			return true, errHealthYield
		}
		return true, controller.tickPolicy(now, policyID, contract, item)
	}
	p := policySettings(contract.Policy, contract.Mode)
	interval := time.Duration(p.liveness) * time.Second
	if item.AvailabilityFailures[selected] > 0 {
		interval = time.Duration(p.failureRetry) * time.Second
	}
	last := controller.livenessAt[policyID]
	if full := time.Unix(int64(item.LastProbeAt[selected]), 0); full.After(last) {
		last = full
	}
	forced := controller.forceLiveness[policyID]
	if !forced && now.Sub(last) < interval {
		return false, nil
	}
	delete(controller.forceLiveness, policyID)
	savedChanged := rememberWorkingSelection(contract, item)
	actual, err := controller.runtime.Current(policyID)
	if err != nil {
		item.RuntimeConfirmed = false
		item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return true, err
	}
	if actual != selected {
		controller.livenessAt[policyID] = time.Time{}
		if !recoverNow {
			return true, errHealthYield
		}
		return true, controller.tickPolicy(now, policyID, contract, item)
	}
	statusChanged := !item.RuntimeConfirmed || item.RuntimeError != ""
	if statusChanged {
		item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	item.RuntimeConfirmed = true
	item.RuntimeSelected = actual
	item.RuntimeError = ""
	evidence := controller.runtime.ProbeAvailability(selected)
	controller.livenessAt[policyID] = now
	wasFailed := item.AvailabilityFailures[selected] > 0
	if evidence.OK {
		if wasFailed {
			controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-recovered", Policy: policyID, Node: selected, Targets: probeTargetResults(evidence)})
		}
		item.AvailabilityFailures[selected] = 0
		delete(item.FailureClass, selected)
		savedChanged = clearUnderlayFailure(item) || savedChanged
		savedChanged = rememberWorkingSelection(contract, item) || savedChanged
		// Quality/recovery confirmations are deliberately not accelerated.
		return wasFailed || statusChanged || savedChanged, nil
	}
	item.FailureClass[selected] = string(evidence.Failure)
	recoveringFromUnderlay := item.UnderlayFailure != ""
	if controller.suppressForUnderlayFailure(now, evidence, item) {
		controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-suppressed", Policy: policyID, Node: selected, Failure: evidence.Failure, Underlay: item.UnderlayFailure, Targets: probeTargetResults(evidence)})
		item.AvailabilityFailures[selected] = 0
		return true, nil
	}
	if recoveringFromUnderlay && item.UnderlayFailure == "" && evidence.Failure != probeFailureTLS {
		// The first path-level failure after shared WAN/DNS recovery can be a
		// stale socket or neighbour-resolution result.  Clear the common-outage
		// marker, keep the active route, and require the next independent fast
		// probe to confirm a real node failure.  TLS failures remain immediate:
		// they are deterministic properties of the selected endpoint.
		controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-suppressed", Policy: policyID, Node: selected, Failure: evidence.Failure, Reason: "underlay-recovered", Targets: probeTargetResults(evidence)})
		item.AvailabilityFailures[selected] = 0
		return true, nil
	}
	item.AvailabilityFailures[selected]++
	threshold := failureConfirmationThreshold(evidence, p.failureThreshold)
	controller.emitHealthEvent(healthEvent{At: now.UTC().Format(time.RFC3339Nano), Event: "probe-failed", Policy: policyID, Node: selected, Failure: evidence.Failure, Count: item.AvailabilityFailures[selected], Threshold: threshold, Targets: probeTargetResults(evidence)})
	if item.AvailabilityFailures[selected] >= threshold {
		item.AvailabilityFailures[selected] = p.failureThreshold
		// The failed active must not consume the emergency reserve batch again.
		item.LastProbeAt[selected] = float64(now.Unix())
		if !recoverNow {
			return true, errHealthYield
		}
		return true, controller.tickPolicy(now, policyID, contract, item)
	}
	return true, nil
}
