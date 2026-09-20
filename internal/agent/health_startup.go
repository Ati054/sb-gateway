package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

// Durable evidence is independent of the latest control-API observation. The
// contract identity prevents an old successful choice from undoing user edits.
type workingSelection struct {
	Selected           string `json:"selected"`
	Mode               string `json:"mode"`
	CandidateSignature string `json:"candidate_signature"`
}

type startupHealthStateItem struct {
	Selected             string            `json:"selected"`
	Mode                 string            `json:"mode"`
	RuntimeSelected      string            `json:"runtime_selected"`
	RuntimeConfirmed     bool              `json:"runtime_confirmed"`
	CandidateSignature   string            `json:"candidate_signature"`
	AvailabilityOK       map[string]bool   `json:"availability_ok"`
	AvailabilityFailures map[string]int    `json:"availability_failures"`
	Recoveries           map[string]int    `json:"recoveries"`
	Shortlist            []string          `json:"shortlist"`
	LastWorkingSelection *workingSelection `json:"last_working_selection"`
}

func rememberWorkingSelection(contract healthPolicyContract, item *policyHealthState) bool {
	if !item.RuntimeConfirmed || item.RuntimeSelected != item.Selected ||
		!item.AvailabilityOK[item.Selected] || item.Selected == "block" ||
		item.AvailabilityFailures[item.Selected] >= policySettings(contract.Policy, contract.Mode).failureThreshold ||
		!contains(contract.Candidates, item.Selected) || item.Mode != contract.Mode ||
		item.CandidateSignature != strings.Join(uniqueCandidates(contract.Candidates), "\n") {
		return false
	}
	value := workingSelection{item.Selected, item.Mode, item.CandidateSignature}
	if item.LastWorkingSelection != nil && *item.LastWorkingSelection == value {
		return false
	}
	item.LastWorkingSelection = &value
	return true
}

// RestoreXraySelectors performs startup selection and readback in one native
// helper. A successful CLI exit alone is not evidence of an applied override.
func RestoreXraySelectors(ctx context.Context, configPath string, opts Options) error {
	runtime := newXraySelectorRuntime(opts)
	runtime.probeContext = ctx
	return restoreXraySelectors(configPath, opts, runtime)
}

func restoreXraySelectors(configPath string, opts Options, runtime *xraySelectorRuntime) error {
	balancers, err := XrayStartupSelections(configPath, opts)
	if err != nil {
		return err
	}
	for _, balancer := range balancers {
		if err := runtime.Select(balancer.Tag, balancer.Outbound); err != nil {
			return fmt.Errorf("restore selector %s: %w", balancer.Tag, err)
		}
	}
	return nil
}

// XrayStartupSelections restores a confirmed working leaf that still
// belongs to both the current health contract and the rendered balancer.
// Missing/corrupt history is optional: it must not prevent a clean startup.
// Explicit priority reorders remain authoritative, unlike unrelated Applies.
func XrayStartupSelections(configPath string, opts Options) ([]runtimeconfig.Balancer, error) {
	balancers, _, err := runtimeconfig.ReadXray(configPath)
	if err != nil {
		return nil, err
	}
	// Decode only startup fields, not the multi-day sample history or node
	// inventory. Reboot restoration does not need a second telemetry cache.
	var pool struct {
		Version        int `json:"version"`
		HealthPolicies map[string]struct {
			Mode       string                `json:"mode"`
			Candidates []string              `json:"candidates"`
			Groups     []healthGroup         `json:"groups"`
			Nodes      map[string]healthNode `json:"nodes"`
			Policy     struct {
				FailureThreshold       int                 `json:"failure_threshold"`
				CandidateServiceIDs    []string            `json:"candidate_service_ids"`
				CandidateServiceAccess map[string][]string `json:"candidate_service_access"`
			} `json:"policy"`
		} `json:"health_policies"`
	}
	var state map[string]*startupHealthStateItem
	if readJSON(opts.HealthPoolFile, &pool) != nil || pool.Version < 2 {
		return balancers, nil
	}
	if readJSON(statePath(opts.StateRoot, "selector-health"), &state) != nil || state == nil {
		state = make(map[string]*startupHealthStateItem)
	}
	managed := make(map[string]bool)
	for index := range balancers {
		balancer := &balancers[index]
		contract, exists := pool.HealthPolicies[balancer.Tag]
		item := state[balancer.Tag]
		if !exists || (contract.Mode != "best" && contract.Mode != "priority") {
			continue
		}
		candidates := uniqueCandidates(contract.Candidates)
		fallback := ""
		for _, candidate := range candidates {
			if contract.Nodes[candidate].Protocol != "xray-reverse" && contains(balancer.Members, candidate) {
				fallback = candidate
				break
			}
		}
		if fallback == "" {
			if contains(balancer.Members, "block") {
				fallback = "block"
			} else {
				continue
			}
		}
		managed[balancer.Tag] = true
		// A stable rendered selector starts fail-closed. Before transparent
		// routing is admitted, replace that cold default with the first current
		// candidate, or with a measured reserve when history proves one.
		balancer.Outbound = fallback
		selected := ""
		if item != nil {
			// RuntimeSelected is the newest persisted readback from the selector and
			// therefore wins over an older durable fallback. This matters during an
			// image update: the last working record can legitimately lag behind the
			// route that was active immediately before the old container stopped.
			// Never promote an unconfirmed observation; only then fall back to the
			// older known-working selection.
			saved := (*workingSelection)(nil)
			if item.RuntimeConfirmed && item.RuntimeSelected == item.Selected {
				saved = &workingSelection{item.Selected, item.Mode, item.CandidateSignature}
			}
			if saved == nil {
				saved = item.LastWorkingSelection
			}
			if saved != nil && saved.Mode == contract.Mode &&
				(contract.Mode != "priority" || saved.CandidateSignature == strings.Join(candidates, "\n")) &&
				saved.Selected != "block" && contains(candidates, saved.Selected) && contains(balancer.Members, saved.Selected) &&
				contract.Nodes[saved.Selected].Protocol != "xray-reverse" &&
				item.AvailabilityFailures[saved.Selected] < defaultInt(contract.Policy.FailureThreshold, 3, 1, 20) {
				if available, known := item.AvailabilityOK[saved.Selected]; !known || available {
					selected = saved.Selected
				}
			}
			if selected == "" {
				ordered := candidates
				if contract.Mode == "best" {
					ordered = uniqueCandidates(append(append([]string(nil), item.Shortlist...), candidates...))
				}
				threshold := defaultInt(contract.Policy.FailureThreshold, 3, 1, 20)
				for _, candidate := range ordered {
					if contains(candidates, candidate) && contains(balancer.Members, candidate) &&
						contract.Nodes[candidate].Protocol != "xray-reverse" &&
						item.AvailabilityOK[candidate] && item.AvailabilityFailures[candidate] < threshold && item.Recoveries[candidate] > 0 {
						selected = candidate
						break
					}
				}
			}
		}
		if selected == "" {
			selected = fallback
		}
		balancer.Outbound = selected
		// Restore service selectors consistently without widening permissions.
		_, groups, _ := candidateGroups(contract.Groups, contract.Candidates, contract.Mode)
		for _, serviceID := range contract.Policy.CandidateServiceIDs {
			target := serviceBlockTag(balancer.Tag)
			if contains(contract.Policy.CandidateServiceAccess[groups[selected]], serviceID) {
				target = selected
			}
			for serviceIndex := range balancers {
				service := &balancers[serviceIndex]
				if service.Tag == serviceSelectorTag(balancer.Tag, serviceID) && contains(service.Members, target) {
					service.Outbound = target
					managed[service.Tag] = true
				}
			}
		}
	}
	startup := make([]runtimeconfig.Balancer, 0, len(managed))
	for _, balancer := range balancers {
		if managed[balancer.Tag] {
			startup = append(startup, balancer)
		}
	}
	return startup, nil
}
