package agent

import (
	"context"
	"sort"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type startupReverseChoice struct {
	Outbound string
	Services map[string]string
}

type startupSelectionPlan struct {
	Balancers     []runtimeconfig.Balancer
	Reverse       map[string]startupReverseChoice
	PoolAvailable bool
}

func XrayStartupNeedsReverseWait(configPath string, opts Options) (bool, error) {
	plan, err := xrayStartupPlan(configPath, opts)
	return len(plan.Reverse) > 0, err
}

// All routes share one startup window. Reserve time for selector readback;
// expiry is a normal fallback, while parent cancellation still aborts startup.
func awaitStartupReverse(parent context.Context, window time.Duration, choices map[string]startupReverseChoice, probe func(context.Context, string) probeEvidence) map[string]string {
	if deadline, ok := parent.Deadline(); ok {
		window = min(window, max(time.Duration(0), time.Until(deadline)-5*time.Second))
	}
	result := make(map[string]string)
	if window <= 0 || len(choices) == 0 {
		return result
	}
	ctx, cancel := context.WithTimeout(parent, window)
	defer cancel()
	pending := make(map[string]bool)
	nodes := []string{}
	for _, choice := range choices {
		if !pending[choice.Outbound] {
			pending[choice.Outbound] = true
			nodes = append(nodes, choice.Outbound)
		}
	}
	sort.Strings(nodes)
	for len(pending) > 0 && ctx.Err() == nil {
		for _, node := range nodes {
			if !pending[node] || ctx.Err() != nil {
				continue
			}
			if evidence := probe(ctx, node); evidence.OK && !evidence.LocalFailure && !evidence.Deferred && ctx.Err() == nil {
				delete(pending, node)
				for policy, choice := range choices {
					if choice.Outbound == node {
						result[policy] = node
						for selector, target := range choice.Services {
							result[selector] = target
						}
					}
				}
			}
		}
		if len(pending) > 0 && !wait(ctx, time.Second) {
			break
		}
	}
	return result
}
