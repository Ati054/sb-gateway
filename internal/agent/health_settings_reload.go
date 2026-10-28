package agent

import (
	"reflect"
	"time"
)

// Scheduling/tolerance edits do not change a forwarding contract. Keep this
// deliberately strict: endpoints, measurement identity, service permissions,
// candidate order, prefixes and every other pool field must match exactly.
func healthSettingsOnly(previous, target healthPool) bool {
	normalize := func(pool healthPool) healthPool {
		pool.ProbeBudget, pool.ProbeLanes = 0, 0
		policies := make(map[string]healthPolicyContract, len(pool.HealthPolicies))
		for id, contract := range pool.HealthPolicies {
			contract.Policy.ActiveCheckSeconds = 0
			contract.Policy.ActiveLivenessSeconds = 0
			contract.Policy.ProbeBatchSize = 0
			contract.Policy.SwitchImprovementMS = 0
			policies[id] = contract
		}
		pool.HealthPolicies = policies
		return pool
	}
	return reflect.DeepEqual(normalize(previous), normalize(target))
}

// Reuse only a live same-core selection after a new API readback for every
// policy. No HTTP survey is needed to acknowledge a pure scheduling edit.
func (controller *healthController) observeUnchangedHotPolicies(pool healthPool, policyIDs []string) bool {
	if !controller.stateLoaded || len(controller.transitions) > 0 {
		return false
	}
	for _, id := range policyIDs {
		item := controller.state[id]
		if item == nil || !controller.warmStarted[id] || !item.RuntimeConfirmed || item.Selected != item.RuntimeSelected {
			return false
		}
		actual, err := controller.runtime.Current(id)
		if err != nil || actual != item.Selected || (actual != "block" && !contains(pool.HealthPolicies[id].Candidates, actual)) {
			return false
		}
	}
	observed := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range policyIDs {
		controller.state[id].RuntimeObservedAt = observed
	}
	return true
}
