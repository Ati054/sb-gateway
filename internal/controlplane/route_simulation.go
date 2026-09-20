package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

type routeDecision struct {
	Action      string  `json:"action"`
	Outbound    *string `json:"outbound"`
	MatchedRule string  `json:"matched_rule"`
	Reason      string  `json:"reason"`
	FailMode    string  `json:"fail_mode"`
	Priority    int     `json:"priority"`
}

type routeSimulator struct {
	rulesetDir string
	catalog    map[string]rulesets.ServicePack
	packs      []rulesets.ServicePack
	ruleCounts map[string]int
}

func (server *Server) simulateRoute(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	decision, err := server.routeSimulator.simulate(config, body)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_simulation", err.Error())
		return
	}
	server.writeJSON(response, http.StatusOK, decision)
}

func newRouteSimulator() (*routeSimulator, error) {
	packs, err := rulesets.Catalog()
	if err != nil {
		return nil, err
	}
	catalog := make(map[string]rulesets.ServicePack, len(packs))
	for _, pack := range packs {
		catalog[pack.ID] = pack
	}
	root := strings.TrimSpace(os.Getenv("SB_RULESET_DIR"))
	if root == "" {
		root = "/config/rulesets"
	}
	return &routeSimulator{rulesetDir: root, catalog: catalog, packs: packs, ruleCounts: rulesets.ReviewedRuleCounts(packs)}, nil
}

func (simulator *routeSimulator) simulate(config, request map[string]any) (routeDecision, error) {
	sourceType := strings.ToLower(strings.TrimSpace(text(request["source_type"])))
	if sourceType != "local" && sourceType != "remote" {
		return routeDecision{}, errors.New("source_type must be local or remote")
	}
	destinationKind := strings.ToLower(strings.TrimSpace(text(request["destination_kind"])))
	if destinationKind == "" {
		destinationKind = "public"
	}
	if destinationKind != "internal" && destinationKind != "service" && destinationKind != "public" {
		return routeDecision{}, errors.New("destination_kind must be internal, service, or public")
	}
	containerHealthy := boolDefault(request, "container_healthy", true)
	vlessHealthy := boolDefault(request, "vless_healthy", true)
	source, err := simulator.resolveSource(config, sourceType, request)
	if err != nil {
		return routeDecision{}, err
	}
	if raw := strings.TrimSpace(text(request["destination_ip"])); raw != "" {
		internal, parseErr := internalDestination(config, raw)
		if parseErr != nil {
			return routeDecision{}, parseErr
		}
		if internal {
			destinationKind = "internal"
		}
	}
	domain := normalizeDomain(firstNonempty(text(request["destination_domain"]), text(request["service"])))
	service := strings.ToLower(strings.TrimSpace(text(request["service"])))

	if !containerHealthy {
		if sourceType == "remote" {
			return decision("drop", "", "container-outage-remote-fail-closed", "Remote VLESS service is unavailable and has no direct fallback.", "closed", 200), nil
		}
		if destinationKind == "internal" {
			return decision("direct-internal", "routeros-routed", "internal-destination-bypass", "Container unavailable; the explicitly routed local network remains reachable.", "closed", 100), nil
		}
		if simulator.outageMode(config, source) == "lan_only" {
			if simulator.exceptionUsesWAN(config, source) && (simulator.outageService(config, source, service, domain) || domain != "" && simulator.directDomain(config, source, domain)) {
				return decision("wan-direct", "home-wan", "container-outage-local-direct-allowlist", "Container unavailable; this destination is in the client's direct-site allowlist.", "closed", 100), nil
			}
			return decision("drop", "", "container-outage-local-fail-open", "Container unavailable; this local client is restricted to LAN-only access.", "closed", 100), nil
		}
		return decision("wan-direct", "home-wan", "container-outage-local-fail-open", "Container unavailable; managed marks are bypassed for local Internet continuity.", "open", 100), nil
	}

	if destinationKind == "internal" {
		if sourceType == "remote" && !boolDefault(source, "allow_internal", true) {
			return decision("drop", "", "internal-destination-bypass", "Remote user is not permitted to reach internal routes.", "closed", 300), nil
		}
		failMode := "open"
		if sourceType == "remote" {
			failMode = "closed"
		}
		return decision("direct-internal", "routeros-routed", "internal-destination-bypass", "Destination is an explicitly routed internal network.", failMode, 300), nil
	}

	if sourceType == "remote" {
		if simulator.directService(config, source, service, domain) {
			return decision("wan-direct", "home-wan", "remote-direct-service", "The service is an explicit direct-WAN exception for this remote identity.", "closed", 400), nil
		}
		if domain != "" && simulator.directDomain(config, source, domain) {
			if !simulator.exceptionUsesWAN(config, source) {
				if !vlessHealthy {
					return decision("drop", "", "remote-direct-domain", "The domain is a VLESS exception, but the assigned VLESS policy is unavailable.", "closed", 400), nil
				}
				return decision("vless", simulator.policyOutbound(config, source), "remote-direct-domain", "The domain is an explicit VLESS exception while ordinary traffic uses WAN.", "closed", 400), nil
			}
			return decision("wan-direct", "home-wan", "remote-direct-domain", "The domain is an explicit direct-WAN exception for this remote identity.", "closed", 400), nil
		}
		if outbound := simulator.serviceOutbound(config, source, service); destinationKind == "service" && outbound != "" {
			if !vlessHealthy {
				return decision("drop", "", "remote-public-vless", "The selected service is a VLESS exception, but its policy is unavailable.", "closed", 400), nil
			}
			return decision("vless", outbound, "remote-public-vless", "The selected service is routed through VLESS while ordinary traffic uses WAN.", "closed", 400), nil
		}
		if simulator.trafficMode(config, source) == "wan_with_vless_exceptions" {
			return decision("wan-direct", "home-wan", "remote-public-vless", "Ordinary remote traffic uses WAN; only selected exceptions use VLESS.", "closed", 400), nil
		}
		if !vlessHealthy {
			return decision("drop", "", "remote-public-vless", "All assigned VLESS outbounds are unavailable; home WAN fallback is forbidden.", "closed", 400), nil
		}
		return decision("vless", simulator.policyOutbound(config, source), "remote-public-vless", "Remote public traffic uses the user's assigned outbound policy.", "closed", 400), nil
	}

	if simulator.directService(config, source, service, domain) {
		return decision("wan-direct", "home-wan", "local-direct-service", "The destination matches an enabled direct-WAN service pack.", "open", 500), nil
	}
	if domain != "" && simulator.directDomain(config, source, domain) {
		if !simulator.exceptionUsesWAN(config, source) {
			if !vlessHealthy {
				return decision("drop", "", "local-direct-domain", "The domain is a VLESS exception, but the assigned VLESS policy is unavailable.", "closed", 600), nil
			}
			return decision("vless", simulator.policyOutbound(config, source), "local-direct-domain", "The domain is an explicit VLESS exception while ordinary traffic uses WAN.", "closed", 600), nil
		}
		return decision("wan-direct", "home-wan", "local-direct-domain", "The destination matches this local client's direct-WAN exception.", "open", 600), nil
	}
	if outbound := simulator.serviceOutbound(config, source, service); destinationKind == "service" && outbound != "" {
		if !vlessHealthy {
			return decision("drop", "", "local-service-vless", "Assigned VLESS is unavailable; the selected exception is blocked instead of leaking to WAN.", "closed", 700), nil
		}
		return decision("vless", outbound, "local-service-vless", "Selected service is routed through the local client's VLESS policy.", "open", 700), nil
	}
	final := simulator.finalOutbound(config, source)
	if final != "direct" && final != "direct-wan" {
		if !vlessHealthy {
			return decision("drop", "", "local-public-wan", "The assigned full-tunnel VLESS policy is unavailable and has no direct leak fallback.", "closed", 800), nil
		}
		return decision("vless", final, "local-public-wan", "Ordinary public traffic uses the local client's full-tunnel VLESS policy.", "closed", 700), nil
	}
	return decision("wan-direct", "home-wan", "local-public-wan", "Ordinary local public traffic uses the home WAN.", "open", 700), nil
}

func decision(action, outbound, rule, reason, failMode string, priority int) routeDecision {
	var selected *string
	if outbound != "" {
		value := outbound
		selected = &value
	}
	return routeDecision{Action: action, Outbound: selected, MatchedRule: rule, Reason: reason, FailMode: failMode, Priority: priority}
}

func (simulator *routeSimulator) resolveSource(config map[string]any, sourceType string, request map[string]any) (map[string]any, error) {
	collection := "remote_users"
	if sourceType == "local" {
		collection = "local_clients"
	}
	sourceID := strings.TrimSpace(text(request["source_id"]))
	sourceIP := strings.TrimSpace(text(request["source_ip"]))
	var address netip.Addr
	var err error
	if sourceIP != "" && sourceType == "local" {
		address, err = netip.ParseAddr(sourceIP)
		if err != nil {
			return nil, errors.New("source_ip is invalid")
		}
	}
	items := objects(config[collection])
	if sourceType == "local" {
		sort.SliceStable(items, func(left, right int) bool {
			leftAll := text(items[left]["source_kind"]) == "lan" && text(items[left]["source_scope"]) == "lan-all"
			rightAll := text(items[right]["source_kind"]) == "lan" && text(items[right]["source_scope"]) == "lan-all"
			return !leftAll && rightAll
		})
	}
	for _, item := range items {
		if !boolDefault(item, "enabled", true) {
			continue
		}
		if sourceID != "" && text(item["id"]) == sourceID {
			return item, nil
		}
		if address.IsValid() {
			for _, value := range stringsOf(item["source_cidrs"]) {
				if prefix, parseErr := netip.ParsePrefix(value); parseErr == nil && prefix.Contains(address) {
					return item, nil
				}
			}
		}
	}
	return map[string]any{"id": firstNonempty(sourceID, "unmatched"), "policy_id": nil}, nil
}

func internalDestination(config map[string]any, value string) (bool, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false, errors.New("destination_ip is invalid")
	}
	for _, network := range objects(config["networks"]) {
		kind := firstNonempty(text(network["kind"]), "internal")
		if !boolDefault(network, "enabled", true) || kind != "internal" && kind != "management" {
			continue
		}
		for _, value := range stringsOf(network["cidrs"]) {
			if prefix, parseErr := netip.ParsePrefix(value); parseErr == nil && prefix.Contains(address) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (simulator *routeSimulator) policy(config, source map[string]any) map[string]any {
	id := text(source["policy_id"])
	for _, policy := range objects(config["policies"]) {
		if text(policy["id"]) == id && boolDefault(policy, "enabled", true) {
			return policy
		}
	}
	return nil
}

func (simulator *routeSimulator) policyOutbound(config, source map[string]any) string {
	policy := simulator.policy(config, source)
	if selected := strings.TrimSpace(text(policy["selected_outbound"])); selected != "" {
		return selected
	}
	if values := stringsOf(policy["outbounds"]); len(values) != 0 {
		return values[0]
	}
	if id := strings.TrimSpace(text(policy["id"])); id != "" {
		return "policy:" + id
	}
	return "policy:default"
}

func (simulator *routeSimulator) trafficMode(config, source map[string]any) string {
	mode := text(simulator.policy(config, source)["traffic_mode"])
	if mode == "vless_with_wan_exceptions" || mode == "wan_with_vless_exceptions" {
		return mode
	}
	return ""
}

func (simulator *routeSimulator) exceptionUsesWAN(config, source map[string]any) bool {
	return simulator.trafficMode(config, source) != "wan_with_vless_exceptions"
}

func (simulator *routeSimulator) finalOutbound(config, source map[string]any) string {
	if final := strings.TrimSpace(text(source["final"])); final != "" {
		return final
	}
	policy := simulator.policy(config, source)
	if policy == nil {
		return "direct"
	}
	if text(policy["traffic_mode"]) == "vless_with_wan_exceptions" {
		return text(policy["id"])
	}
	return firstNonempty(strings.TrimSpace(text(policy["final"])), "direct")
}

func (simulator *routeSimulator) serviceOutbound(config, source map[string]any, service string) string {
	if service == "" {
		return ""
	}
	routes, _ := simulator.policy(config, source)["service_routes"].(map[string]any)
	return strings.TrimSpace(text(routes[service]))
}

func (simulator *routeSimulator) outageMode(config, source map[string]any) string {
	if mode := text(source["container_outage"]); mode == "direct" || mode == "lan_only" {
		return mode
	}
	if mode := text(simulator.policy(config, source)["container_outage"]); mode == "direct" || mode == "lan_only" {
		return mode
	}
	return "direct"
}

func (simulator *routeSimulator) directDomain(config, source map[string]any, destination string) bool {
	values := append(stringsOf(source["direct_domains"]), stringsOf(simulator.policy(config, source)["direct_domains"])...)
	for _, value := range values {
		if suffix := normalizeDomain(value); suffix != "" && (destination == suffix || strings.HasSuffix(destination, "."+suffix)) {
			return true
		}
	}
	return false
}

func (simulator *routeSimulator) directService(config, source map[string]any, service, domain string) bool {
	if boolDefault(simulator.policy(config, source), "torrent_direct", true) {
		for id, pack := range simulator.catalog {
			if !pack.AlwaysDirect {
				continue
			}
			if id == service || domain != "" && (simulator.catalogDomain(id, domain, map[string]bool{}) || simulator.localRuleSetDomain(id, domain)) {
				return true
			}
		}
	}
	selected := append(stringsOf(source["direct_services"]), stringsOf(simulator.policy(config, source)["direct_services"])...)
	allowed := make(map[string]bool, len(simulator.catalog))
	for id := range simulator.catalog {
		allowed[id] = true
	}
	for _, pack := range objects(config["service_packs"]) {
		id := strings.ToLower(strings.TrimSpace(text(pack["id"])))
		if boolDefault(pack, "enabled", true) && entityIDPattern.MatchString(id) {
			allowed[id] = true
		}
	}
	for _, raw := range selected {
		id := strings.ToLower(strings.TrimSpace(raw))
		if !allowed[id] {
			continue
		}
		if id == service || domain != "" && (simulator.catalogDomain(id, domain, map[string]bool{}) || simulator.localRuleSetDomain(id, domain)) {
			return true
		}
	}
	return false
}

func (simulator *routeSimulator) outageService(config, source map[string]any, service, domain string) bool {
	if simulator.directService(config, source, service, domain) {
		return true
	}
	routes, _ := simulator.policy(config, source)["service_routes"].(map[string]any)
	_, exists := routes[service]
	return service != "" && exists
}

func (simulator *routeSimulator) catalogDomain(id, domain string, seen map[string]bool) bool {
	if seen[id] {
		return false
	}
	seen[id] = true
	pack, exists := simulator.catalog[id]
	if !exists {
		return false
	}
	for _, suffix := range pack.FallbackDomains {
		suffix = normalizeDomain(suffix)
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	for _, dependency := range pack.IncludedPackIDs {
		if simulator.catalogDomain(dependency, domain, seen) {
			return true
		}
	}
	return false
}

func (simulator *routeSimulator) localRuleSetDomain(id, domain string) bool {
	if !entityIDPattern.MatchString(id) {
		return false
	}
	path := filepath.Join(simulator.rulesetDir, id+".json")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		return false
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	for _, rule := range objects(payload["rules"]) {
		for _, value := range stringsOf(rule["domain"]) {
			if domain == normalizeDomain(value) {
				return true
			}
		}
		for _, value := range stringsOf(rule["domain_suffix"]) {
			if suffix := normalizeDomain(value); domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return true
			}
		}
		for _, keyword := range stringsOf(rule["domain_keyword"]) {
			if keyword != "" && strings.Contains(domain, strings.ToLower(keyword)) {
				return true
			}
		}
	}
	return false
}

func text(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func boolDefault(object map[string]any, name string, fallback bool) bool {
	value, exists := object[name]
	if !exists {
		return fallback
	}
	result, ok := value.(bool)
	if !ok {
		return fallback
	}
	return result
}

func objects(value any) []map[string]any {
	values, _ := value.([]any)
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if object, ok := value.(map[string]any); ok {
			result = append(result, object)
		}
	}
	return result
}

func stringsOf(value any) []string {
	values, _ := value.([]any)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
