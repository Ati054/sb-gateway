package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

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

// Membership edits do not reorder the surviving priority queue.
func priorityOrderChanged(signature string, candidates []string) bool {
	if signature == "" {
		return true
	}
	previous := uniqueCandidates(strings.Split(signature, "\n"))
	oldSet, newSet := make(map[string]bool, len(previous)), make(map[string]bool, len(candidates))
	for _, node := range previous {
		oldSet[node] = true
	}
	for _, node := range candidates {
		newSet[node] = true
	}
	oldCommon, newCommon := []string{}, []string{}
	for _, node := range previous {
		if newSet[node] {
			oldCommon = append(oldCommon, node)
		}
	}
	for _, node := range uniqueCandidates(candidates) {
		if oldSet[node] {
			newCommon = append(newCommon, node)
		}
	}
	return !slices.Equal(oldCommon, newCommon)
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
	control, err := newXrayControlClient(opts.XrayAPIServer)
	if err != nil {
		return err
	}
	defer control.close()
	runtime.control = control
	return restoreXraySelectors(configPath, opts, runtime)
}

func restoreXraySelectors(configPath string, opts Options, runtime *xraySelectorRuntime) error {
	plan, err := xrayStartupPlan(configPath, opts)
	if err != nil {
		return err
	}
	if len(plan.Balancers) > 0 && plan.PoolAvailable {
		// Materialize pruned subscription leaves before restoring the override.
		if err := readJSON(opts.HealthPoolFile, &runtime.pool); err != nil {
			return fmt.Errorf("load startup outbound contract: %w", err)
		}
	}
	if len(plan.Reverse) > 0 && opts.StartupReverseWait > 0 {
		// Reverse handlers belong to live sessions, not dynamic subscriptions.
		for _, choice := range plan.Reverse {
			if !contains(runtime.pool.BaseOutboundTags, choice.Outbound) {
				runtime.pool.BaseOutboundTags = append(runtime.pool.BaseOutboundTags, choice.Outbound)
			}
		}
		parent := runtime.requestContext()
		restored := awaitStartupReverse(parent, opts.StartupReverseWait, plan.Reverse, func(ctx context.Context, node string) probeEvidence {
			runtime.probeContext = ctx
			defer func() { runtime.probeContext = parent }()
			if present, err := runtime.outboundPresent(node); err != nil || !present {
				return probeEvidence{LocalFailure: err != nil}
			}
			return runtime.ProbeAvailability(node)
		})
		if err := parent.Err(); err != nil {
			return err
		}
		for index := range plan.Balancers {
			if target := restored[plan.Balancers[index].Tag]; target != "" {
				plan.Balancers[index].Outbound = target
			}
		}
	}
	confirmed := make(healthState, len(plan.Balancers))
	for _, balancer := range plan.Balancers {
		if err := runtime.Select(balancer.Tag, balancer.Outbound); err != nil {
			return fmt.Errorf("restore selector %s: %w", balancer.Tag, err)
		}
		confirmed[balancer.Tag] = &policyHealthState{RuntimeSelected: balancer.Outbound,
			RuntimeConfirmed: true, RuntimeObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	}
	if opts.StateRoot != "" {
		// Publish only live readbacks; startup never rewrites historical health.
		return publishSelectorReadiness(statePath(opts.StateRoot, "selector-health"), confirmed)
	}
	return nil
}

// XrayStartupSelections restores a confirmed working leaf that still
// belongs to both the current health contract and the rendered balancer.
// Missing/corrupt history is optional: it must not prevent a clean startup.
// Explicit priority reorders remain authoritative, unlike unrelated Applies.
func XrayStartupSelections(configPath string, opts Options) ([]runtimeconfig.Balancer, error) {
	plan, err := xrayStartupPlan(configPath, opts)
	return plan.Balancers, err
}

func xrayStartupPlan(configPath string, opts Options) (startupSelectionPlan, error) {
	balancers, _, err := runtimeconfig.ReadXray(configPath)
	if err != nil {
		return startupSelectionPlan{}, err
	}
	// Decode only startup fields, not the multi-day sample history or node
	// inventory. Reboot restoration does not need a second telemetry cache.
	var pool struct {
		Version          int                 `json:"version"`
		Policies         map[string][]string `json:"policies"`
		PolicyPrefixes   map[string]string   `json:"policy_prefixes"`
		BaseOutboundTags []string            `json:"base_outbound_tags"`
		HealthPolicies   map[string]struct {
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
		return startupSelectionPlan{Balancers: balancers}, nil
	}
	if readJSON(statePath(opts.StateRoot, "selector-health"), &state) != nil || state == nil {
		state = make(map[string]*startupHealthStateItem)
	}
	managed := make(map[string]bool)
	reverse := make(map[string]startupReverseChoice)
	for index := range balancers {
		balancer := &balancers[index]
		contract, exists := pool.HealthPolicies[balancer.Tag]
		item := state[balancer.Tag]
		if !exists || (contract.Mode != "best" && contract.Mode != "priority") {
			continue
		}
		candidates := uniqueCandidates(contract.Candidates)
		memberAllowed := func(candidate string) bool {
			if contains(balancer.Members, candidate) {
				return true
			}
			prefix := pool.PolicyPrefixes[balancer.Tag]
			return prefix != "" && contains(balancer.Members, prefix) &&
				contract.Nodes[candidate].Protocol != "xray-reverse" && contains(pool.Policies[balancer.Tag], candidate)
		}
		fallback := ""
		for _, candidate := range candidates {
			if contract.Nodes[candidate].Protocol != "xray-reverse" && memberAllowed(candidate) {
				fallback = candidate
				break
			}
		}
		if fallback == "" {
			if contains(balancer.Members, "block") || contains(pool.BaseOutboundTags, "block") {
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
		preferred := ""
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
				(contract.Mode != "priority" || !priorityOrderChanged(saved.CandidateSignature, candidates)) &&
				saved.Selected != "block" && contains(candidates, saved.Selected) && memberAllowed(saved.Selected) &&
				item.AvailabilityFailures[saved.Selected] < healthFailureConfirmations {
				// An independent bad probe is pending until the failure streak reaches
				// the confirmed-outage sentinel. Restart must not turn that pending
				// evidence into a failover or promote an arbitrary inventory default.
				if available, known := item.AvailabilityOK[saved.Selected]; !known || available || item.AvailabilityFailures[saved.Selected] > 0 {
					preferred = saved.Selected
					if contract.Nodes[preferred].Protocol != "xray-reverse" {
						selected = preferred
					}
				}
			}
			if selected == "" {
				ordered := candidates
				if contract.Mode == "best" {
					ordered = uniqueCandidates(append(append([]string(nil), item.Shortlist...), candidates...))
				}
				threshold := healthFailureConfirmations
				for _, candidate := range ordered {
					if contains(candidates, candidate) && memberAllowed(candidate) &&
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
		if preferred == "" && len(candidates) > 0 {
			preferred = candidates[0]
		}
		// URLTest keeps ordinary qualification; only a priority-selected
		// Reverse or a Reverse-only route waits for a startup reconnection.
		if (contract.Mode == "priority" || len(candidates) == 1) &&
			contract.Nodes[preferred].Protocol == "xray-reverse" && memberAllowed(preferred) &&
			(item == nil || item.AvailabilityFailures[preferred] < healthFailureConfirmations) {
			reverse[balancer.Tag] = startupReverseChoice{Outbound: preferred, Services: make(map[string]string)}
		}
		// Restore service selectors consistently without widening permissions.
		_, groups, _ := candidateGroups(contract.Groups, contract.Candidates, contract.Mode)
		for _, serviceID := range contract.Policy.CandidateServiceIDs {
			target := serviceBlockTag(balancer.Tag)
			if contains(contract.Policy.CandidateServiceAccess[groups[selected]], serviceID) {
				target = selected
			}
			for serviceIndex := range balancers {
				service := &balancers[serviceIndex]
				prefix := pool.PolicyPrefixes[service.Tag]
				serviceAllowed := contains(service.Members, target) || (prefix != "" && contains(service.Members, prefix) && contains(pool.Policies[service.Tag], target))
				if service.Tag == serviceSelectorTag(balancer.Tag, serviceID) && serviceAllowed {
					service.Outbound = target
					managed[service.Tag] = true
					if choice, waiting := reverse[balancer.Tag]; waiting {
						reverseTarget := serviceBlockTag(balancer.Tag)
						if contains(contract.Policy.CandidateServiceAccess[groups[preferred]], serviceID) && contains(service.Members, preferred) {
							reverseTarget = preferred
						}
						choice.Services[service.Tag] = reverseTarget
					}
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
	return startupSelectionPlan{Balancers: startup, Reverse: reverse, PoolAvailable: true}, nil
}
