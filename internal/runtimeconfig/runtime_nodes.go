package runtimeconfig

import (
	"fmt"
	"strings"
)

// augmentRuntimeNodes is the single boundary where configuration-owned exits
// join provider nodes. Callers pass only provider snapshots; Reverse VLESS,
// RouterOS WireGuard and independent refresh reserves are reconstructed from
// the exact configuration generation being rendered.
func augmentRuntimeNodes(config map[string]any, provider []map[string]any) ([]map[string]any, error) {
	result := make([]map[string]any, 0, len(provider)+8)
	seen := make(map[string]struct{}, len(provider)+8)
	appendNode := func(node map[string]any) error {
		id := textValue(node["id"])
		if id == "" {
			return nil
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("duplicate runtime node id %q", id)
		}
		seen[id] = struct{}{}
		result = append(result, node)
		return nil
	}
	for _, node := range provider {
		if err := appendNode(cloneJSONMap(node)); err != nil {
			return nil, err
		}
	}
	for index, reserve := range enabledObjects(config["subscription_reserves"]) {
		if index >= 3 {
			break
		}
		if node := objectValue(reserve["node"]); len(node) != 0 {
			if err := appendNode(cloneJSONMap(node)); err != nil {
				return nil, err
			}
		}
	}
	networking := objectValue(objectValue(config["system"])["networking"])
	wireGuard, err := routerOSWireGuardExits(networking)
	if err != nil {
		return nil, err
	}
	for _, exit := range wireGuard {
		if err := appendNode(map[string]any{
			"id": exit.Tag, "label": "WG · " + exit.Interface, "country": "ZZ", "city": "",
			"protocol": "routeros-wireguard", "wireguard_egress_id": exit.ID,
			"wireguard_interface": exit.Interface, "source_address": exit.SourceAddress,
			"source_type": "routeros-wireguard", "enabled": true,
		}); err != nil {
			return nil, err
		}
	}
	for _, exit := range enabledObjects(config["reverse_vless_exits"]) {
		id := strings.ToLower(textValue(exit["id"]))
		if !serviceIDPattern.MatchString(id) {
			continue
		}
		transportIDs := stringSlice(exit["transport_ids"])
		if len(transportIDs) == 0 && textValue(exit["transport_id"]) != "" {
			transportIDs = []string{textValue(exit["transport_id"])}
		}
		if err := appendNode(map[string]any{
			"id": "reverse-vless-" + id, "label": textDefault(exit["display_name"], id),
			"country": strings.ToUpper(textDefault(exit["country"], "ZZ")), "city": textValue(exit["city"]),
			"protocol": "xray-reverse", "reverse_vless_id": id, "transport_ids": transportIDs,
			"source_type": "xray-reverse", "enabled": true,
		}); err != nil {
			return nil, err
		}
	}
	return result, nil
}
