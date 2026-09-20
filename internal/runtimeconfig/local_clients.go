package runtimeconfig

import "sort"

const allLANSourceScope = "lan-all"

func allLANClient(client map[string]any) bool {
	return textValue(client["source_kind"]) == "lan" && textValue(client["source_scope"]) == allLANSourceScope
}

// Specific local clients must always win over a broad LAN policy, regardless
// of creation order in the saved document.
func enabledLocalClientsSpecificFirst(value any) []map[string]any {
	clients := enabledObjects(value)
	sort.SliceStable(clients, func(left, right int) bool {
		return !allLANClient(clients[left]) && allLANClient(clients[right])
	})
	return clients
}
