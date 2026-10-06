package runtimeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/healthcontract"
)

// BuildXrayHealthPool renders the selector controller contract from the same
// configuration and node snapshot as xray.json. Keeping both artifacts in one
// native candidate prevents the UI and the running core from observing
// different routing-list generations.
func BuildXrayHealthPool(config map[string]any, providerNodes []map[string]any, xray map[string]any) ([]byte, error) {
	nodes, err := augmentRuntimeNodes(config, providerNodes)
	if err != nil {
		return nil, err
	}
	selectable := make([]map[string]any, 0, len(nodes))
	nodesByID := make(map[string]map[string]any, len(nodes))
	dynamicNodeIDs := make(map[string]struct{})
	for _, node := range nodes {
		if textValue(node["subscription_reserve_id"]) == "" && node["enabled"] != false {
			selectable = append(selectable, node)
			id := textValue(node["id"])
			nodesByID[id] = node
			if id != "" && textValue(node["subscription_id"]) != "" && textValue(node["source_type"]) != "xray-reverse" {
				dynamicNodeIDs[id] = struct{}{}
			}
		}
	}
	// Fingerprint the actual rendered outbound, not a mutable label or a
	// subscription ID. A provider may keep an ID while changing its endpoint.
	endpointFingerprints := make(map[string]string)
	outboundBodies := make(map[string]json.RawMessage)
	for _, outbound := range objectSlice(xray["outbounds"]) {
		tag := textValue(outbound["tag"])
		if tag == "" {
			continue
		}
		body, marshalErr := marshalCanonical(outbound)
		if marshalErr != nil {
			return nil, marshalErr
		}
		sum := sha256.Sum256(body)
		endpointFingerprints[tag] = hex.EncodeToString(sum[:])
		outboundBodies[tag] = json.RawMessage(body)
	}
	dialTargets := make(map[string]any)
	for id, node := range nodesByID {
		if textValue(node["protocol"]) != "vless" {
			continue
		}
		transport := textDefault(objectValue(node["transport"])["type"], "tcp")
		if transport == "kcp" || transport == "quic" {
			continue
		}
		address := textValue(node["server"])
		if _, parseErr := netip.ParseAddr(address); parseErr != nil {
			continue
		}
		port, valid := numericInt(node["server_port"])
		if !valid || port < 1 || port > 65535 || endpointFingerprints[id] == "" {
			continue
		}
		dialTargets[id] = map[string]any{"address": address, "port": port}
	}

	policyMembers := make(map[string][]string)
	policyPrefixes := make(map[string]string)
	healthPolicies := make(map[string]any)
	routingMonitor, err := healthRoutingMonitor(config)
	if err != nil {
		return nil, err
	}
	probeBudget := routingMonitor.ProbeBudget()
	for _, policy := range enabledObjects(config["policies"]) {
		policyID := textValue(policy["id"])
		if policyID == "" {
			continue
		}
		mode := textDefault(policy["mode"], "best")
		if mode == "urltest" {
			mode = "best"
		}
		if mode != "best" && mode != "priority" {
			continue
		}
		groups := policyCandidateGroups(policy, selectable)
		members := make([]string, 0)
		seen := make(map[string]struct{})
		serializedGroups := make([]any, 0, len(groups))
		for _, group := range groups {
			groupMembers := make([]string, 0, len(group.Members))
			for _, member := range group.Members {
				if member == "" || member == "block" {
					continue
				}
				groupMembers = append(groupMembers, member)
				if _, exists := seen[member]; !exists {
					seen[member] = struct{}{}
					members = append(members, member)
				}
			}
			if len(groupMembers) != 0 {
				serializedGroups = append(serializedGroups, map[string]any{
					"selector": group.Selector,
					"members":  groupMembers,
				})
			}
		}
		if len(members) == 0 {
			continue
		}
		inventory := make(map[string]any, len(members))
		for _, member := range members {
			label, country := member, "ZZ"
			protocol, transport := "", ""
			if node := nodesByID[member]; node != nil {
				label = textDefault(node["label"], member)
				country = strings.ToUpper(textDefault(node["country"], "ZZ"))
				protocol = textValue(node["protocol"])
				transport = textDefault(objectValue(node["transport"])["type"], "tcp")
				if reality := objectValue(objectValue(node["tls"])["reality"]); protocol == "vless" && len(reality) != 0 && reality["enabled"] != false {
					protocol = "reality"
				}
			}
			metadata := map[string]any{"label": label, "country": country, "protocol": protocol, "transport": transport, "subscription_id": textValue(nodesByID[member]["subscription_id"])}
			if fingerprint := endpointFingerprints[member]; fingerprint != "" {
				metadata["fingerprint"] = fingerprint
			}
			inventory[member] = metadata
		}
		resolvedPolicy, err := resolveHealthPolicy(policy, routingMonitor)
		if err != nil {
			return nil, fmt.Errorf("health policy %q: %w", policyID, err)
		}
		healthPolicies[policyID] = map[string]any{
			"policy": resolvedPolicy, "mode": mode, "groups": serializedGroups,
			"candidates": members, "nodes": inventory,
		}
		policyMembers[policyID] = append([]string(nil), members...)
		policyPrefixes[policyID] = urlTestPolicyPrefix(policyID)
		if mode == "priority" {
			for _, serviceID := range candidateServiceIDs(policy) {
				selector := policyServiceSelectorTag(policyID, serviceID)
				policyMembers[selector] = append([]string(nil), members...)
				policyPrefixes[selector] = urlTestPolicyPrefix(policyID)
			}
		}
	}
	localPolicySet := make(map[string]bool)
	for _, client := range enabledObjects(config["local_clients"]) {
		policyID := textValue(client["policy_id"])
		// Direct-only and empty policies have no health-worker selector to
		// acknowledge. Scope only contracts actually published in this pool.
		if _, managed := healthPolicies[policyID]; managed {
			localPolicySet[policyID] = true
		}
	}
	localPolicyIDs := make([]string, 0, len(localPolicySet))
	for policyID := range localPolicySet {
		localPolicyIDs = append(localPolicyIDs, policyID)
	}
	sort.Strings(localPolicyIDs)

	baseSet := make(map[string]struct{})
	dynamicOutbounds := make(map[string]json.RawMessage, len(dynamicNodeIDs))
	for _, outbound := range objectSlice(xray["outbounds"]) {
		tag := textValue(outbound["tag"])
		if tag == "" {
			continue
		}
		if _, dynamic := dynamicNodeIDs[tag]; dynamic {
			dynamicOutbounds[tag] = outboundBodies[tag]
			continue
		}
		baseSet[tag] = struct{}{}
	}
	// Reverse leaves are created by live bridge sessions rather than by a
	// static outbound object. They are still base selector members: attempting
	// to synthesize them through HandlerService would create a fake direct path.
	for _, node := range selectable {
		if textValue(node["source_type"]) == "xray-reverse" {
			baseSet[textValue(node["id"])] = struct{}{}
		}
	}
	baseTags := make([]string, 0, len(baseSet))
	for tag := range baseSet {
		if tag != "" {
			baseTags = append(baseTags, tag)
		}
	}
	sort.Strings(baseTags)

	pool := map[string]any{
		"probe_budget": probeBudget,
		"probe_lanes":  len(xrayHealthProbeLanesForConfig(config, healthProbeInventoryCount(nodes))) - 1,
		"version":      4, "policies": policyMembers, "health_policies": healthPolicies,
		"local_policy_ids": localPolicyIDs,
		"policy_prefixes":  policyPrefixes, "base_outbound_tags": baseTags,
		"outbounds": dynamicOutbounds, "dial_targets": dialTargets,
	}
	body, err := marshalCanonical(pool)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func healthRoutingMonitor(config map[string]any) (healthcontract.RoutingMonitor, error) {
	raw := objectValue(config["system"])["routing_monitor"]
	if raw == nil {
		return healthcontract.RoutingMonitor{}, nil
	}
	if _, ok := raw.(map[string]any); !ok {
		return healthcontract.RoutingMonitor{}, errors.New("system.routing_monitor must be an object")
	}
	settings := cloneJSONMap(raw.(map[string]any))
	// Validation treats blank optional numeric inputs as omitted.
	for _, key := range []string{"active_liveness_interval_seconds", "active_quality_interval_seconds", "probe_batch_size"} {
		if settings[key] == "" {
			delete(settings, key)
		}
	}
	body, err := json.Marshal(settings)
	if err != nil {
		return healthcontract.RoutingMonitor{}, fmt.Errorf("system.routing_monitor: %w", err)
	}
	var monitor healthcontract.RoutingMonitor
	if err := json.Unmarshal(body, &monitor); err != nil {
		return monitor, fmt.Errorf("system.routing_monitor: %w", err)
	}
	return monitor, nil
}

func resolveHealthPolicy(raw map[string]any, monitor healthcontract.RoutingMonitor) (healthcontract.Policy, error) {
	settings := cloneJSONMap(raw)
	removeRetiredURLTestSettings(settings)
	if settings["switch_improvement_ms"] == "" {
		delete(settings, "switch_improvement_ms")
	}
	body, err := json.Marshal(settings)
	if err != nil {
		return healthcontract.Policy{}, err
	}
	var policy healthcontract.Policy
	if err := json.Unmarshal(body, &policy); err != nil {
		return policy, err
	}
	if monitor.ActiveLivenessSeconds != nil {
		policy.ActiveLivenessSeconds = *monitor.ActiveLivenessSeconds
	}
	if monitor.ActiveQualitySeconds != nil {
		policy.ActiveCheckSeconds = *monitor.ActiveQualitySeconds
	}
	policy.ProbeBatchSize = monitor.ProbeBudget()
	return policy, nil
}

func healthProbeInventoryCount(nodes []map[string]any) int {
	// Policy membership is hot-updated. Listener allocation follows the stable
	// core inventory so changing eligibility alone cannot force a core restart.
	seen := make(map[string]struct{})
	for _, node := range nodes {
		if node["enabled"] != false && textValue(node["subscription_reserve_id"]) == "" {
			if id := textValue(node["id"]); id != "" && id != "block" && id != "direct-wan" {
				seen[id] = struct{}{}
			}
		}
	}
	return len(seen)
}

func numericInt(value any) (int, bool) {
	switch number := value.(type) {
	case json.Number:
		integer, err := number.Int64()
		return int(integer), err == nil
	case int:
		return number, true
	case int64:
		return int(number), true
	case float64:
		integer := int(number)
		return integer, number == float64(integer)
	default:
		return 0, false
	}
}

// PruneDynamicXrayOutbounds removes subscription-backed leaves from the
// startup Xray graph after their exact definitions have been captured in the
// health-pool contract. The health controller loads only the active leaf and
// one probe leaf through HandlerService, so keeping hundreds of dormant
// provider outbounds in xray.json only consumes RAM and startup CPU.
//
// Balancer selectors are prefixes in Xray. Remove the obsolete exact node IDs
// as well, while preserving the sb-urltest-/sb-subscription-update- prefixes
// and every static RouterOS WireGuard, reverse, direct, block or DNS leaf.
func PruneDynamicXrayOutbounds(xray map[string]any, healthPool []byte) error {
	var contract struct {
		Outbounds map[string]json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(healthPool, &contract); err != nil {
		return errors.New("decode Xray health-pool contract")
	}
	if len(contract.Outbounds) == 0 {
		return nil
	}
	outbounds := objectSlice(xray["outbounds"])
	filtered := make([]any, 0, len(outbounds))
	for _, outbound := range outbounds {
		if _, dynamic := contract.Outbounds[textValue(outbound["tag"])]; dynamic {
			continue
		}
		filtered = append(filtered, outbound)
	}
	xray["outbounds"] = filtered

	routing := objectValue(xray["routing"])
	for _, balancer := range objectSlice(routing["balancers"]) {
		selectors := stringSlice(balancer["selector"])
		kept := make([]any, 0, len(selectors))
		for _, selector := range selectors {
			if _, dynamic := contract.Outbounds[selector]; !dynamic {
				kept = append(kept, selector)
			}
		}
		if len(kept) == 0 {
			return errors.New("dynamic Xray pruning emptied a balancer selector")
		}
		balancer["selector"] = kept
	}
	return nil
}
