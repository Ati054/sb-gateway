package runtimeconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
)

func buildNativeCatalogArtifacts(config map[string]any, legacy []map[string]any, readSecret SecretReader, secretPath SecretPathResolver, options NativeArtifactOptions) (map[string][]byte, error) {
	plan, err := buildCatalogRuntimePlan(config, legacy, options.Catalog)
	if err != nil {
		return nil, err
	}
	static := make([]map[string]any, 0)
	inlineSecrets := make(map[string]string)
	for _, node := range legacy {
		if _, needed := plan.nodes[textValue(node["id"])]; needed {
			static = append(static, node)
		}
	}
	for _, id := range plan.order {
		item := plan.nodes[id]
		if !item.static || item.definition.Generation == "" {
			continue
		}
		record, getErr := options.Catalog.LookupDefinition(context.Background(), id)
		if getErr != nil || record.ID != id {
			return nil, errors.New("referenced catalog definition is unavailable")
		}
		var recordMetadata struct {
			Fingerprint string `json:"definition_fingerprint"`
		}
		if json.Unmarshal(record.Metadata, &recordMetadata) != nil || recordMetadata.Fingerprint != item.definition.Fingerprint {
			return nil, errors.New("referenced catalog definition fingerprint mismatch")
		}
		node, secrets, decodeErr := decodeCatalogStatic(record)
		if decodeErr != nil {
			return nil, decodeErr
		}
		var qualify func(map[string]any)
		qualify = func(value map[string]any) {
			for key, raw := range value {
				if child, ok := raw.(map[string]any); ok {
					qualify(child)
				}
				if strings.HasSuffix(key, "_secret_ref") {
					if reference, ok := raw.(string); ok {
						if secret, exists := secrets[reference]; exists {
							qualified := "catalog-static/" + id + "/" + reference
							inlineSecrets[qualified] = secret
							value[key] = qualified
						}
					}
				}
			}
		}
		qualify(node)
		static = append(static, node)
	}
	resolve := func(reference string) (string, error) {
		if value, ok := inlineSecrets[reference]; ok {
			return value, nil
		}
		return readSecret(reference)
	}
	nodes, err := augmentRuntimeNodes(config, static)
	if err != nil {
		return nil, err
	}
	outbounds, err := BuildXrayOutboundSource(config, nodes, resolve)
	if err != nil {
		return nil, err
	}
	// Dynamic catalog leaves do not appear in the startup graph. Stable prefix
	// membership admits bounded active/probe handlers created by the controller.
	prefixBySelector := make(map[string]string)
	for _, policy := range enabledObjects(config["policies"]) {
		id := textValue(policy["id"])
		prefixBySelector[id] = urlTestPolicyPrefix(id)
		if textValue(policy["mode"]) == "priority" {
			for _, service := range candidateServiceIDs(policy) {
				prefixBySelector[policyServiceSelectorTag(id, service)] = urlTestPolicyPrefix(id)
			}
		}
	}
	filtered := make([]map[string]any, 0, len(outbounds))
	healthMembers := make([]string, 0, len(nodes)+1)
	for _, node := range nodes {
		if node["enabled"] != false && textValue(node["subscription_reserve_id"]) == "" {
			if id := textValue(node["id"]); id != "" {
				healthMembers = append(healthMembers, id)
			}
		}
	}
	healthMembers = append(healthMembers, "sb-urltest-")
	for _, outbound := range outbounds {
		tag := textValue(outbound["tag"])
		if strings.HasPrefix(tag, "outbound-health-") {
			continue
		}
		if prefix := prefixBySelector[tag]; prefix != "" {
			outbound["outbounds"] = append(stringSlice(outbound["outbounds"]), prefix)
		}
		filtered = append(filtered, outbound)
	}
	for _, lane := range xrayHealthProbeLanesForConfig(config, plan.inventory) {
		filtered = append(filtered, map[string]any{"type": "selector", "tag": lane.Tag, "outbounds": healthMembers, "interrupt_exist_connections": false})
	}
	inbound, err := buildXrayInboundSource(config, resolve, secretPath, plan.inventory)
	if err != nil {
		return nil, err
	}
	servers := make([]string, 0, len(plan.nodes))
	for _, id := range plan.order {
		if server := plan.nodes[id].server; server != "" {
			servers = append(servers, server)
		}
	}
	route, err := buildXrayRouteSource(config, nodes, filtered, plan.inventory, plan.policyEligibility, servers)
	if err != nil {
		return nil, err
	}
	inbound.Options.RuleSetRoot = options.RuleSetRoot
	xray, err := RenderXrayCandidate(config, map[string]any{"inbounds": inbound.Inbounds, "outbounds": filtered, "route": route}, inbound.Options)
	if err != nil {
		return nil, err
	}
	pool, err := buildCatalogHealthPool(config, plan, xray.Config, legacy)
	if err != nil {
		return nil, err
	}
	if err := PruneDynamicXrayOutbounds(xray.Config, pool); err != nil {
		return nil, err
	}
	body, err := MarshalXrayCandidate(xray.Config)
	if err != nil {
		return nil, err
	}
	nginx, err := RenderNginxCandidate(config, resolve, secretPath, options.Nginx)
	if err != nil {
		return nil, err
	}
	watchdog, err := RenderWatchdogEnvironment(config)
	if err != nil {
		return nil, err
	}
	telemetry, err := RenderClientTelemetryNFT(config)
	if err != nil {
		return nil, err
	}
	exclusions, err := RenderTransparentExclusions(config)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"xray.json": body, "urltest-pool.json": pool, "policy-dns.json": xray.PolicyDNSBody, "nginx.conf": []byte(nginx), "watchdog.env": watchdog, "client-telemetry.nft": telemetry, "transparent-exclusions.txt": exclusions}, nil
}

func buildCatalogHealthPool(config map[string]any, plan catalogRuntimePlan, xray map[string]any, legacy []map[string]any) ([]byte, error) {
	monitor, err := healthRoutingMonitor(config)
	if err != nil {
		return nil, err
	}
	definitions := make(map[string]CatalogDefinition)
	metadata := make(map[string]catalogHealthNode, len(plan.nodes))
	targets := make(map[string]any)
	legacyDynamic := make(map[string]bool)
	for _, node := range legacy {
		id := textValue(node["id"])
		if _, needed := plan.nodes[id]; needed && textValue(node["subscription_id"]) != "" && textValue(node["subscription_reserve_id"]) == "" && !plan.nodes[id].static {
			legacyDynamic[id] = true
		}
	}
	raw := make(map[string]json.RawMessage)
	base := make(map[string]bool)
	for _, outbound := range objectSlice(xray["outbounds"]) {
		id := textValue(outbound["tag"])
		if id == "" {
			continue
		}
		body, e := marshalCanonical(outbound)
		if e != nil {
			return nil, e
		}
		if legacyDynamic[id] {
			raw[id] = body
		} else {
			base[id] = true
		}
		if item, ok := plan.nodes[id]; ok && item.definition.Generation == "" {
			sum := sha256.Sum256(body)
			item.meta.Fingerprint = hex.EncodeToString(sum[:])
			plan.nodes[id] = item
		}
	}
	for _, id := range plan.order {
		item := plan.nodes[id]
		metadata[id] = item.meta
		if item.definition.Generation != "" && !item.static {
			definitions[id] = item.definition
		}
		if item.meta.Protocol == "xray-reverse" {
			base[id] = true
		}
		if (item.meta.Protocol == "vless" || item.meta.Protocol == "reality") && item.meta.Transport != "kcp" && item.meta.Transport != "quic" && item.port > 0 && item.port <= 65535 {
			if _, e := netip.ParseAddr(item.server); e == nil {
				targets[id] = map[string]any{"address": item.server, "port": item.port}
			}
		}
	}
	policies := make(map[string][]string)
	prefixes := make(map[string]string)
	contracts := make(map[string]any)
	for _, policy := range enabledObjects(config["policies"]) {
		id := textValue(policy["id"])
		mode := textDefault(policy["mode"], "best")
		if mode == "urltest" {
			mode = "best"
		}
		if mode != "best" && mode != "priority" {
			continue
		}
		members := make([]string, 0)
		groups := make([]any, 0)
		for _, group := range plan.groups[id] {
			members = append(members, group.Members...)
			groups = append(groups, map[string]any{"selector": group.Selector, "members": group.Members})
		}
		if len(members) == 0 {
			continue
		}
		resolved, e := resolveHealthPolicy(policy, monitor)
		if e != nil {
			return nil, e
		}
		contracts[id] = map[string]any{"policy": resolved, "mode": mode, "groups": groups, "candidates": members}
		policies[id] = members
		prefixes[id] = urlTestPolicyPrefix(id)
		if mode == "priority" {
			for _, service := range candidateServiceIDs(policy) {
				selector := policyServiceSelectorTag(id, service)
				policies[selector] = members
				prefixes[selector] = urlTestPolicyPrefix(id)
			}
		}
	}
	locals := make(map[string]bool)
	for _, client := range enabledObjects(config["local_clients"]) {
		id := textValue(client["policy_id"])
		if _, ok := contracts[id]; ok {
			locals[id] = true
		}
	}
	localIDs := make([]string, 0, len(locals))
	for id := range locals {
		localIDs = append(localIDs, id)
	}
	sort.Strings(localIDs)
	baseTags := make([]string, 0, len(base))
	for id := range base {
		baseTags = append(baseTags, id)
	}
	sort.Strings(baseTags)
	return marshalCanonical(map[string]any{"version": 5, "probe_budget": monitor.ProbeBudget(), "probe_lanes": len(xrayHealthProbeLanesForConfig(config, plan.inventory)) - 1, "policies": policies, "health_policies": contracts, "policy_prefixes": prefixes, "base_outbound_tags": baseTags, "outbounds": raw, "dial_targets": targets, "local_policy_ids": localIDs, "catalogs": plan.catalogs, "catalog_definitions": definitions, "nodes": metadata})
}
