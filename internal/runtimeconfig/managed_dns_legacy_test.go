package runtimeconfig

// Legacy fixture retained for pinned-core comparison and migration tests.
// Production uses managedDNSGoIngress.
func managedDNSIngress(containerIP string, dnsRules []map[string]any) (map[string]any, []map[string]any) {
	inbound := map[string]any{
		"tag": managedDNSInbound, "listen": containerIP, "port": ManagedDNSPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1", "port": 53, "network": "tcp,udp"},
		"sniffing": map[string]any{"enabled": false},
	}
	rules := make([]map[string]any, 0)
	for _, rule := range dnsRules {
		if len(stringSlice(rule["source"])) == 0 || !containsText(stringSlice(rule["inboundTag"]), "tun-routeros") {
			continue
		}
		copy := make(map[string]any, len(rule))
		for key, value := range rule {
			copy[key] = value
		}
		copy["inboundTag"] = []string{managedDNSInbound}
		rules = append(rules, copy)
	}
	rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{managedDNSInbound}, "outboundTag": "block"})
	return inbound, rules
}
