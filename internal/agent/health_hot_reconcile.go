package agent

import (
	"encoding/json"
	"strings"
	"time"
)

// Retain only identical per-policy forwarding inputs under the same core. The
// caller checks the PID; every retained selector still gets a fresh readback.
// A changed endpoint, permission, prefix, order or mode uses full reconciliation.
func (controller *healthController) retainUnchangedHotPolicies(previous, target healthPool) map[string]bool {
	preserved := make(map[string]bool)
	if !controller.stateLoaded {
		return preserved
	}
	for id, contract := range target.HealthPolicies {
		item := controller.state[id]
		if item == nil || !controller.warmStarted[id] || controller.transitions[id] != nil ||
			!item.RuntimeConfirmed || item.Selected != item.RuntimeSelected || item.Mode != contract.Mode ||
			item.CandidateSignature != strings.Join(uniqueCandidates(contract.Candidates), "\n") ||
			!sameHotPolicyContract(previous, target, id) {
			continue
		}
		actual, err := controller.runtime.Current(id)
		if err != nil || actual != item.Selected || (actual != "block" && !contains(contract.Candidates, actual)) {
			continue
		}
		item.RuntimeObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		preserved[id] = true
	}
	return preserved
}

func sameHotPolicyContract(previous, target healthPool, id string) bool {
	if _, ok := previous.HealthPolicies[id]; !ok {
		return false
	}
	if _, ok := target.HealthPolicies[id]; !ok {
		return false
	}
	scope := func(pool healthPool) healthPool {
		contract := pool.HealthPolicies[id]
		pool.HealthPolicies = map[string]healthPolicyContract{id: contract}
		outbounds := make(map[string]json.RawMessage)
		targets := make(map[string]healthDialTarget)
		for _, node := range contract.Candidates {
			if value, ok := pool.Outbounds[node]; ok {
				outbounds[node] = value
			}
			if value, ok := pool.DialTargets[node]; ok {
				targets[node] = value
			}
		}
		pool.Outbounds, pool.DialTargets = outbounds, targets
		return pool
	}
	return healthSettingsOnly(scope(previous), scope(target))
}

func retainedPolicyTimes(previous map[string]time.Time, retained map[string]bool) map[string]time.Time {
	result := make(map[string]time.Time, len(retained))
	for id := range retained {
		if value, ok := previous[id]; ok {
			result[id] = value
		}
	}
	return result
}
