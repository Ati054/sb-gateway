package runtimeconfig

import (
	"strings"
)

type RouterOSDeltaPlan struct {
	ApplyScript    string
	RollbackScript string
	Sections       []string
}

// BuildRouterOSDelta compares complete renderer-owned sections instead of
// producing a fragile line diff. Unknown/partial input and deltas approaching
// the size of the full candidate deliberately fall back to full Apply.
func BuildRouterOSDelta(previousSource, desiredSource string, maximumRatio float64) *RouterOSDeltaPlan {
	if maximumRatio <= 0 || maximumRatio > 1 {
		maximumRatio = 0.8
	}
	previous, ok := splitRouterOSCandidate(previousSource)
	if !ok {
		return nil
	}
	desired, ok := splitRouterOSCandidate(desiredSource)
	if !ok {
		return nil
	}
	selected := make(map[string]bool)
	for _, name := range routerOSSectionOrder {
		selected[name] = previous[name] != desired[name]
	}
	changed := false
	for _, value := range selected {
		changed = changed || value
	}
	// The WireGuard interface inventory is live RouterOS state rather than part
	// of the saved document. Reconcile it whenever any RouterOS change is being
	// applied so a tunnel created after installation can reach the configured
	// router-local panel URL without weakening WAN access.
	if changed && strings.Contains(desired["panel-ingress"], `SB_WIREGUARD_INGRESS`) {
		selected["panel-ingress"] = true
	}
	if selected["panel-ingress"] {
		selected["panel-port-check"] = true
	}
	if selected["core"] || selected["address-lists"] || selected["wireguard-egress"] {
		selected["finalize"] = true
	}
	sections := make([]string, 0, len(routerOSSectionOrder))
	for _, name := range routerOSSectionOrder {
		if selected[name] {
			sections = append(sections, name)
		}
	}
	if len(sections) == 0 {
		return nil
	}
	assemble := func(source map[string]string) string {
		lines := []string{
			"# SB-GATEWAY generated minimal delta; complete managed sections",
			"# SB-GATEWAY delta sections: " + strings.Join(sections, ","),
		}
		for _, name := range sections {
			lines = append(lines, routerOSSectionPrefix+name)
			if !selected["core"] {
				lines = append(lines, routerOSDeltaPrelude(name)...)
			}
			lines = append(lines, source[name])
		}
		return strings.Join(lines, "\n") + "\n"
	}
	apply, rollback := assemble(desired), assemble(previous)
	// ApplyDelta uses RouterOS REST script source; larger payloads must use
	// the existing full-candidate SFTP/import path instead of failing mid-Apply.
	if len(apply) > 16*1024 || len(rollback) > 16*1024 {
		return nil
	}
	if float64(len(apply))/float64(max(1, len(desiredSource))) > maximumRatio ||
		float64(len(rollback))/float64(max(1, len(previousSource))) > maximumRatio {
		return nil
	}
	return &RouterOSDeltaPlan{ApplyScript: apply, RollbackScript: rollback, Sections: sections}
}

func splitRouterOSCandidate(source string) (map[string]string, bool) {
	lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
	if len(lines) == 0 || lines[0] != routerOSCandidateHeader {
		return nil, false
	}
	sections := make(map[string]string, len(routerOSSectionOrder))
	parts := make(map[string][]string, len(routerOSSectionOrder))
	current, order := "", make([]string, 0, len(routerOSSectionOrder))
	validName := make(map[string]bool, len(routerOSSectionOrder))
	for _, name := range routerOSSectionOrder {
		validName[name] = true
	}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, routerOSSectionPrefix) {
			name := strings.TrimPrefix(line, routerOSSectionPrefix)
			if !validName[name] || parts[name] != nil {
				return nil, false
			}
			current = name
			order = append(order, name)
			parts[name] = []string{}
			continue
		}
		if current == "" {
			return nil, false
		}
		parts[current] = append(parts[current], line)
	}
	if len(order) != len(routerOSSectionOrder) {
		return nil, false
	}
	for index, name := range routerOSSectionOrder {
		if order[index] != name || len(parts[name]) == 0 {
			return nil, false
		}
		sections[name] = strings.Join(parts[name], "\n")
	}
	return sections, true
}

func routerOSDeltaPrelude(section string) []string {
	switch section {
	case "address-lists":
		return renderRouterOSFailClosedDrop()
	case "wireguard-egress":
		return []string{
			`:local sbBridge [/interface/bridge/find where comment="SB-GATEWAY container bridge"]`,
			`:if ([:len $sbBridge] != 1) do={ :error "SB-GATEWAY container bridge missing or ambiguous" }`,
			`:local sbBridgeName [/interface/bridge/get $sbBridge name]`,
		}
	default:
		return nil
	}
}
