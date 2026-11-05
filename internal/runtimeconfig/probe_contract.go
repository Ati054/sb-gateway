package runtimeconfig

import "encoding/json"

// XrayProbeContract describes the stable local listeners shared by the core
// and health worker. It is independent of the currently selected candidate.
type XrayProbeContract struct {
	ProbeBudget int `json:"probe_budget"`
	ProbeLanes  int `json:"probe_lanes"`
}

// BuildXrayProbeContract uses the same inventory rules as the corresponding
// runtime renderer. Catalogues are planned from matching metadata only; no
// private provider definition is looked up to count listeners.
func BuildXrayProbeContract(config map[string]any, nodes []map[string]any, catalog RuntimeNodeCatalog) (XrayProbeContract, error) {
	if catalog == nil {
		body, err := BuildXrayHealthPool(config, nodes, map[string]any{})
		if err != nil {
			return XrayProbeContract{}, err
		}
		var contract XrayProbeContract
		err = json.Unmarshal(body, &contract)
		return contract, err
	}
	plan, err := buildCatalogRuntimePlan(config, nodes, catalog)
	if err != nil {
		return XrayProbeContract{}, err
	}
	monitor, err := healthRoutingMonitor(config)
	if err != nil {
		return XrayProbeContract{}, err
	}
	return XrayProbeContract{
		ProbeBudget: monitor.ProbeBudget(),
		ProbeLanes:  len(xrayHealthProbeLanesForConfig(config, plan.inventory)) - 1,
	}, nil
}
