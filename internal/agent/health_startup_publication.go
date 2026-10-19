package agent

import "time"

// Re-observe every policy before one policy's survey can delay the others.
// This also prevents the first agent publication from replacing the startup
// helper's fresh proof with old observations loaded from historical state.
func (controller *healthController) publishStartupReadbacks(pool healthPool, policyIDs []string) error {
	managed := make(healthState, len(policyIDs))
	for _, id := range policyIDs {
		item := controller.state[id]
		if item == nil {
			item = newPolicyHealthState()
			controller.state[id] = item
		}
		actual, err := controller.runtime.Current(id)
		observed := &policyHealthState{RuntimeSelected: actual, RuntimeObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		observed.RuntimeConfirmed = err == nil && actual != "" &&
			(actual == "block" || contains(pool.HealthPolicies[id].Candidates, actual))
		if observed.RuntimeConfirmed {
			item.RuntimeObservedAt, item.RuntimeSelected = observed.RuntimeObservedAt, actual
			item.RuntimeConfirmed = true
			item.RuntimeError = ""
		}
		// An ineligible old leaf belongs to the separate hot-transition path;
		// do not erase its working evidence while publishing an unready proof.
		managed[id] = observed
	}
	return publishSelectorReadiness(statePath(controller.opts.StateRoot, "selector-health"), managed)
}
