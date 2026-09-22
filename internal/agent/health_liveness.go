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
	if now.Sub(last) < interval {
		return false, nil
	}
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
		item.AvailabilityFailures[selected] = 0
		delete(item.FailureClass, selected)
		savedChanged = clearUnderlayFailure(item) || savedChanged
		savedChanged = rememberWorkingSelection(contract, item) || savedChanged
		// Quality/recovery confirmations are deliberately not accelerated.
		return wasFailed || statusChanged || savedChanged, nil
	}
	failureCount := 1
	if evidence.Failure == probeFailureTimeout && !wasFailed {
		// A timeout is not deterministic enough for an immediate route change,
		// but waiting for another scheduler cycle needlessly extends an outage.
		// Confirm it with a second independent request in the same fast-lane tick.
		confirmation := controller.runtime.ProbeAvailability(selected)
		if confirmation.OK {
			item.AvailabilityFailures[selected] = 0
			delete(item.FailureClass, selected)
			savedChanged = clearUnderlayFailure(item) || savedChanged
			savedChanged = rememberWorkingSelection(contract, item) || savedChanged
			return statusChanged || savedChanged, nil
		}
		evidence.Failure = strongerProbeFailure(evidence.Failure, confirmation.Failure)
		failureCount++
	}
	item.FailureClass[selected] = string(evidence.Failure)
	recoveringFromUnderlay := item.UnderlayFailure != ""
	if controller.suppressForUnderlayFailure(now, evidence, item) {
		item.AvailabilityFailures[selected] = 0
		return true, nil
	}
	if recoveringFromUnderlay && item.UnderlayFailure == "" && evidence.Failure != probeFailureTLS {
		// The first path-level failure after shared WAN/DNS recovery can be a
		// stale socket or neighbour-resolution result.  Clear the common-outage
		// marker, keep the active route, and require the next independent fast
		// probe to confirm a real node failure.  TLS failures remain immediate:
		// they are deterministic properties of the selected endpoint.
		item.AvailabilityFailures[selected] = 0
		return true, nil
	}
	item.AvailabilityFailures[selected] += failureCount
	threshold := failureConfirmationThreshold(evidence, p.failureThreshold)
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
