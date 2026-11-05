package runtimeconfig

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"runtime/debug"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

// One shared typed node index is serialized once in a v5 pool. Policy records
// refer to ordered IDs; they do not repeat node metadata or private definitions.
type catalogHealthNode struct {
	Label          string `json:"label"`
	Country        string `json:"country"`
	Protocol       string `json:"protocol,omitempty"`
	Transport      string `json:"transport,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
}

type catalogPlanNode struct {
	meta       catalogHealthNode
	definition CatalogDefinition
	server     string
	port       int
	static     bool
	owned      bool
}

type catalogRuntimePlan struct {
	nodes             map[string]catalogPlanNode
	order             []string
	groups            map[string][]policyCandidateGroup
	policyEligibility map[string]bool
	inventory         int
	catalogs          map[string]subscriptioncatalog.Ref
}

func buildCatalogRuntimePlan(config map[string]any, legacy []map[string]any, catalog RuntimeNodeCatalog) (catalogRuntimePlan, error) {
	// Admission precedes retained maps and pool encoding. This is a conservative
	// working estimate, not a node quota or a claim about exact Go heap usage.
	budget := CatalogPlanningBudgetBytes()
	return buildCatalogRuntimePlanWithBudget(config, legacy, catalog, budget)
}

// CatalogPlanningBudgetBytes reports the current conservative preparation
// allowance. Callers may reconsider a rejected selection after a budget rise.
func CatalogPlanningBudgetBytes() int64 {
	return max(int64(4<<20), min(int64(64<<20), debug.SetMemoryLimit(-1)/2))
}

// ErrCatalogPlanningBudget is a deterministic runtime-selection rejection.
// Repeating unchanged preparation cannot resolve it; the stored catalog is intact.
var ErrCatalogPlanningBudget = errors.New("catalog runtime preparation exceeds the working-memory budget; narrow the runtime selection")

func buildCatalogRuntimePlanWithBudget(config map[string]any, legacy []map[string]any, catalog RuntimeNodeCatalog, budget int64) (catalogRuntimePlan, error) {
	plan := catalogRuntimePlan{nodes: make(map[string]catalogPlanNode), groups: make(map[string][]policyCandidateGroup), policyEligibility: make(map[string]bool), catalogs: make(map[string]subscriptioncatalog.Ref)}
	charge := func(amount int64) error {
		if amount < 0 || amount > budget {
			return ErrCatalogPlanningBudget
		}
		budget -= amount
		return nil
	}
	for _, ref := range catalog.References() {
		if err := charge(4096); err != nil {
			return plan, err
		}
		plan.catalogs[ref.Generation] = ref
	}
	policies := enabledObjects(config["policies"])
	policyFanout := make(map[string]int, len(policies))
	for _, policy := range policies {
		if textValue(policy["mode"]) == "priority" {
			policyFanout[textValue(policy["id"])] = len(candidateServiceIDs(policy))
		}
	}
	static := make(map[string]bool)
	for _, collection := range []string{"policies", "local_clients", "remote_users"} {
		for _, entity := range enabledObjects(config[collection]) {
			static[textValue(entity["final"])] = true
			for _, target := range stringMap(entity["service_routes"]) {
				static[target] = true
			}
		}
	}
	seen := make(map[[32]byte]struct{})
	groupMembers := make(map[string]map[string][]string)
	visit := func(node map[string]any, definition CatalogDefinition, owned bool) error {
		id := textValue(node["id"])
		if id == "" {
			return nil
		}
		key := sha256.Sum256([]byte(id))
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate runtime catalog node ID")
		}
		if err := charge(64); err != nil {
			return err
		}
		seen[key] = struct{}{}
		if node["enabled"] == false {
			return nil
		}
		refresh := textValue(node["subscription_reserve_id"]) != ""
		if !refresh {
			plan.inventory++
		}
		needed := static[id]
		if !refresh {
			for _, policy := range policies {
				groups := policyCandidateGroups(policy, []map[string]any{node})
				if len(groups) == 0 {
					continue
				}
				policyID := textValue(policy["id"])
				fanout := policyFanout[policyID]
				// IDs are repeated in policies, health candidates and groups, and
				// priority service selectors. Account for encoding/output copies.
				membershipBytes := 96 + int64(len(policyID)+len(groups[0].Selector)) + int64(len(id)+3)*(6+2*int64(fanout))
				if err := charge(membershipBytes); err != nil {
					return err
				}
				if groupMembers[policyID] == nil {
					groupMembers[policyID] = make(map[string][]string)
				}
				groupMembers[policyID][groups[0].Selector] = append(groupMembers[policyID][groups[0].Selector], id)
				plan.policyEligibility[policyID] = true
				needed = true
			}
		}
		if !needed && !owned {
			return nil
		}
		protocol := textValue(node["display_protocol"])
		if protocol == "" {
			protocol = textValue(node["protocol"])
			if reality := objectValue(objectValue(node["tls"])["reality"]); protocol == "vless" && len(reality) != 0 && reality["enabled"] != false {
				protocol = "reality"
			}
		}
		transport := textValue(node["transport_type"])
		if transport == "" {
			transport = textDefault(objectValue(node["transport"])["type"], "tcp")
		}
		fingerprint := definition.Fingerprint
		if fingerprint != "" {
			fingerprint = definition.FingerprintKind + ":" + fingerprint
		}
		port, _ := numericInt(node["server_port"])
		item := catalogPlanNode{meta: catalogHealthNode{Label: textDefault(node["label"], id), Country: textDefault(node["country"], "ZZ"), Protocol: protocol, Transport: transport, SubscriptionID: textValue(node["subscription_id"]), Fingerprint: fingerprint}, definition: definition, server: textValue(node["server"]), port: port, static: static[id], owned: owned}
		if err := charge(catalogPlanNodeWorkingBytes(id, item)); err != nil {
			return err
		}
		plan.nodes[id] = item
		plan.order = append(plan.order, id)
		return nil
	}
	for _, node := range legacy {
		if err := visit(node, CatalogDefinition{}, false); err != nil {
			return plan, err
		}
	}
	if err := catalog.WalkMetadata(context.Background(), func(item RuntimeCatalogNode) error {
		if item.Metadata == nil || !serviceIDPattern.MatchString(item.ID) || !runtimeCatalogDigest(item.Fingerprint) || !runtimeCatalogDigest(item.Generation) {
			return errors.New("invalid runtime catalog metadata")
		}
		if _, ok := plan.catalogs[item.Generation]; !ok {
			return errors.New("runtime catalog reference is missing")
		}
		// Callback metadata is ephemeral. Only compact strings/numbers above
		// survive this callback; nested definition maps are never retained.
		item.Metadata["id"] = item.ID
		return visit(item.Metadata, CatalogDefinition{item.Generation, item.Fingerprint, CatalogFingerprintKind}, false)
	}); err != nil {
		return plan, err
	}
	owned, err := augmentRuntimeNodes(config, nil)
	if err != nil {
		return plan, err
	}
	for _, node := range owned {
		if err := visit(node, CatalogDefinition{}, true); err != nil {
			return plan, err
		}
	}
	for _, policy := range policies {
		id := textValue(policy["id"])
		for _, raw := range stringSlice(policy["selection_order"]) {
			selector := normalizeLocationSelector(raw)
			if members := groupMembers[id][selector]; len(members) > 0 {
				plan.groups[id] = append(plan.groups[id], policyCandidateGroup{selector, members})
				delete(groupMembers[id], selector)
			}
		}
	}
	if catalog.InventoryCount() < 0 {
		return plan, errors.New("invalid catalog inventory count")
	}
	return plan, nil
}

func runtimeCatalogDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range value {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func (plan catalogRuntimePlan) endpointNodes() []map[string]any {
	seen := make(map[string]bool)
	result := make([]map[string]any, 0)
	for _, id := range plan.order {
		node := plan.nodes[id]
		if node.owned || seen[node.server] {
			continue
		}
		address, err := netip.ParseAddr(node.server)
		if err != nil {
			continue
		}
		seen[node.server] = true
		result = append(result, map[string]any{"id": id, "server": address.String()})
	}
	return result
}

// RouterOSEndpointBypassWithCatalog scans matching metadata, not Node/Secrets.
func RouterOSEndpointBypassWithCatalog(config map[string]any, nodes []map[string]any, catalog RuntimeNodeCatalog) ([]string, error) {
	if catalog == nil {
		return RouterOSEndpointBypass(config, nodes)
	}
	plan, err := buildCatalogRuntimePlan(config, nodes, catalog)
	if err != nil {
		return nil, err
	}
	return RouterOSEndpointBypass(config, plan.endpointNodes())
}

func RenderRouterOSTrafficCandidateWithCatalog(config map[string]any, nodes []map[string]any, catalog RuntimeNodeCatalog, ruleSetRoot ...string) (string, error) {
	if catalog == nil {
		return RenderRouterOSTrafficCandidate(config, nodes, ruleSetRoot...)
	}
	plan, err := buildCatalogRuntimePlan(config, nodes, catalog)
	if err != nil {
		return "", err
	}
	return RenderRouterOSTrafficCandidate(config, plan.endpointNodes(), ruleSetRoot...)
}

func decodeCatalogStatic(record subscriptioncatalog.Record) (map[string]any, map[string]string, error) {
	node, secrets, err := decodeValidatedCatalogRecord(record, "")
	if err != nil {
		return nil, nil, err
	}
	node["id"] = record.ID
	return node, secrets, nil
}
