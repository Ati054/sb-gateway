package runtimeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

var serviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var domainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var publicDNSPresets = map[string]struct {
	server     string
	serverName string
}{
	"cloudflare": {server: "1.1.1.1", serverName: "cloudflare-dns.com"},
	"google":     {server: "8.8.8.8", serverName: "dns.google"},
	"yandex":     {server: "77.88.8.8", serverName: "common.dot.dns.yandex.net"},
	"quad9":      {server: "9.9.9.9", serverName: "dns.quad9.net"},
}

// DirectPublicDNSServer returns the normalized encrypted resolver selected by
// dns.direct_resolver. ACME uses this same direct profile for its own fresh
// recursive DNS lane rather than the container's RouterOS resolver cache.
func DirectPublicDNSServer(config map[string]any) (PolicyDNSSourceServer, error) {
	dns := objectValue(config["dns"])
	direct, err := dnsServerFromProfile(objectValue(dns["direct_resolver"]), "direct-public-dns", "direct-wan")
	if err != nil {
		return PolicyDNSSourceServer{}, err
	}
	direct.DoTFallback = direct.Type == "https"
	if direct.ServerPort == 0 {
		switch direct.Type {
		case "https":
			direct.ServerPort = 443
		case "tls":
			direct.ServerPort = 853
		}
	}
	return direct, nil
}

type policyDNSCatalog struct {
	byID         map[string]rulesets.ServicePack
	alwaysDirect []string
}

// RenderPolicyDNS is the complete schema-v1 Go path from the saved control
// plane document to the resolver artifact and its Xray wiring.
func RenderPolicyDNS(config map[string]any, options PolicyDNSCompileOptions) (PolicyDNSArtifacts, []byte, error) {
	source, err := BuildPolicyDNSSource(config, options.Selectable)
	if err != nil {
		return PolicyDNSArtifacts{}, nil, err
	}
	artifacts, err := CompilePolicyDNS(source, options)
	if err != nil {
		return PolicyDNSArtifacts{}, nil, err
	}
	body, err := MarshalPolicyDNS(artifacts.Runtime)
	if err != nil {
		return PolicyDNSArtifacts{}, nil, err
	}
	return artifacts, body, nil
}

var (
	policyDNSCatalogOnce  sync.Once
	policyDNSCatalogValue policyDNSCatalog
	policyDNSCatalogError error
)

// BuildPolicyDNSSource compiles the current schema-v1 configuration directly
// into the normalized DNS source consumed by CompilePolicyDNS. It does no
// migration/default merge and performs no network I/O.
func BuildPolicyDNSSource(config map[string]any, available map[string]struct{}) (PolicyDNSSource, error) {
	dns := objectValue(config["dns"])
	internalServer := strings.TrimSpace(textValue(dns["internal_server"]))
	if address, err := netip.ParseAddr(internalServer); err != nil || !address.IsValid() {
		return PolicyDNSSource{}, errors.New("dns.internal_server must be a valid IP address")
	}
	direct, err := dnsServerFromProfile(objectValue(dns["direct_resolver"]), "direct-public-dns", "direct-wan")
	if err != nil {
		return PolicyDNSSource{}, err
	}
	direct.DoTFallback = true
	updates, err := dnsServerFromProfile(objectValue(dns["vpn_resolver"]), "subscription-update-dns", "subscription-update-egress")
	if err != nil {
		return PolicyDNSSource{}, err
	}
	source := PolicyDNSSource{
		Servers: []PolicyDNSSourceServer{
			{Tag: "routeros-dns", Type: "udp", Server: internalServer, Detour: "direct-wan"},
			direct,
			updates,
		},
		Rules: []PolicyDNSSourceRule{
			{Inbound: []string{"subscription-update-direct"}, Action: "route", Server: "direct-public-dns"},
			{Inbound: []string{"subscription-update-vpn"}, Action: "route", Server: "subscription-update-dns"},
		},
		Final: "direct-public-dns",
	}

	catalog, err := loadPolicyDNSCatalog()
	if err != nil {
		return PolicyDNSSource{}, err
	}
	policies := enabledObjectsByID(config["policies"])
	remoteUsers := enabledObjects(config["remote_users"])
	internalZones := stringSlice(dns["internal_zones"])
	if len(internalZones) != 0 {
		source.Rules = append(source.Rules, PolicyDNSSourceRule{
			Inbound: localTransparentInbounds, DomainSuffix: internalZones,
			Action: "route", Server: "routeros-dns",
		})
		for _, user := range remoteUsers {
			rule := PolicyDNSSourceRule{AuthUser: []string{textValue(user["id"])}, DomainSuffix: internalZones}
			if textValue(user["role"]) == "trusted-full" {
				rule.Action, rule.Server = "route", "routeros-dns"
			} else {
				rule.Action = "reject"
			}
			source.Rules = append(source.Rules, rule)
		}
	}

	dnsTags := make(map[string]string)
	policyServer := func(outbound string) (string, error) {
		if tag := dnsTags[outbound]; tag != "" {
			return tag, nil
		}
		tag := "policy-dns-" + outbound
		server, serverErr := dnsServerFromProfile(objectValue(dns["vpn_resolver"]), tag, outbound)
		if serverErr != nil {
			return "", serverErr
		}
		dnsTags[outbound] = tag
		source.Servers = append(source.Servers, server)
		return tag, nil
	}

	for _, client := range enabledLocalClientsSpecificFirst(config["local_clients"]) {
		policy := policies[textValue(client["policy_id"])]
		identity := PolicyDNSSourceRule{Inbound: localTransparentInbounds, SourceCIDR: stringSlice(client["source_cidrs"])}
		if err := appendEntityDNSRules(&source, client, policy, identity, available, catalog, policyServer, false); err != nil {
			return PolicyDNSSource{}, err
		}
	}
	for _, user := range remoteUsers {
		policyID := textValue(user["policy_id"])
		policy := policies[policyID]
		identity := PolicyDNSSourceRule{AuthUser: []string{textValue(user["id"])}}
		if err := appendEntityDNSRules(&source, user, policy, identity, available, catalog, policyServer, true); err != nil {
			return PolicyDNSSource{}, err
		}
	}
	return source, nil
}

func appendEntityDNSRules(
	source *PolicyDNSSource,
	entity, policy map[string]any,
	identity PolicyDNSSourceRule,
	available map[string]struct{},
	catalog policyDNSCatalog,
	policyServer func(string) (string, error),
	remote bool,
) error {
	policyID := textValue(policy["id"])
	trafficMode := textValue(policy["traffic_mode"])
	for _, service := range candidateServiceIDs(policy) {
		selector := policyServiceSelectorTag(policyID, service)
		if _, ok := available[selector]; !ok || textValue(policy["mode"]) != "priority" {
			continue
		}
		server, err := policyServer(selector)
		if err != nil {
			return err
		}
		rule := identity
		for _, dependency := range serviceRuleSetIDs(service, catalog.byID) {
			rule.RuleSet = append(rule.RuleSet, "service-"+dependency)
		}
		rule.Action, rule.Server = "route", server
		source.Rules = append(source.Rules, rule)
	}
	directServiceIDs, err := directServices(entity, policy, catalog)
	if err != nil {
		return err
	}
	for _, service := range directServiceIDs {
		rule := identity
		rule.RuleSet = []string{"service-" + service}
		rule.Action, rule.Server = "route", "direct-public-dns"
		source.Rules = append(source.Rules, rule)
	}
	if domains := directDomains(entity, policy); len(domains) != 0 {
		rule := identity
		rule.DomainSuffix = domains
		if trafficMode == "wan_with_vless_exceptions" {
			if selectableNonDirect(policyID, available) {
				server, err := policyServer(policyID)
				if err != nil {
					return err
				}
				rule.Action, rule.Server = "route", server
			} else {
				rule.Action = "reject"
			}
		} else {
			rule.Action, rule.Server = "route", "direct-public-dns"
		}
		source.Rules = append(source.Rules, rule)
	}

	serviceRoutes := make(map[string]string)
	for name, outbound := range stringMap(policy["service_routes"]) {
		serviceRoutes[name] = outbound
	}
	for name, outbound := range stringMap(entity["service_routes"]) {
		serviceRoutes[name] = outbound
	}
	names := make([]string, 0, len(serviceRoutes))
	for name := range serviceRoutes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		service, err := canonicalServiceID(name)
		if err != nil {
			return err
		}
		if pack, ok := catalog.byID[service]; ok && pack.AlwaysDirect && boolDefault(policy["torrent_direct"], true) {
			continue
		}
		rule := identity
		rule.RuleSet = []string{"service-" + service}
		outbound := serviceRoutes[name]
		if selectableNonDirect(outbound, available) {
			server, serverErr := policyServer(outbound)
			if serverErr != nil {
				return serverErr
			}
			rule.Action, rule.Server = "route", server
		} else if outbound == "direct-wan" {
			rule.Action, rule.Server = "route", "direct-public-dns"
		} else {
			rule.Action = "reject"
		}
		source.Rules = append(source.Rules, rule)
	}

	rule := identity
	if remote {
		if policy != nil && trafficMode == "wan_with_vless_exceptions" {
			rule.Action, rule.Server = "route", "direct-public-dns"
		} else if selectableNonDirect(policyID, available) {
			server, err := policyServer(policyID)
			if err != nil {
				return err
			}
			rule.Action, rule.Server = "route", server
		} else {
			rule.Action = "reject"
		}
		source.Rules = append(source.Rules, rule)
		return nil
	}

	final := textValue(entity["final"])
	if final == "" {
		if trafficMode == "vless_with_wan_exceptions" {
			final = policyID
		} else {
			final = textValue(policy["final"])
		}
	}
	if final == "" {
		final = "direct"
	}
	if final == "direct" || final == "direct-wan" {
		return nil
	}
	if !selectableNonDirect(final, available) {
		rule.Action = "reject"
		source.Rules = append(source.Rules, rule)
		return nil
	}
	server, err := policyServer(final)
	if err != nil {
		return err
	}
	rule.Action, rule.Server = "route", server
	source.Rules = append(source.Rules, rule)
	return nil
}

func dnsServerFromProfile(profile map[string]any, tag, detour string) (PolicyDNSSourceServer, error) {
	provider := textValue(profile["provider"])
	if provider == "" {
		provider = "cloudflare"
	}
	preset, ok := publicDNSPresets[provider]
	if !ok {
		return PolicyDNSSourceServer{}, fmt.Errorf("unsupported public DNS provider %q", provider)
	}
	protocol := textValue(profile["protocol"])
	if protocol == "" {
		protocol = "doh"
	}
	server := PolicyDNSSourceServer{
		Tag: tag, Server: preset.server, Detour: detour,
		TLS: PolicyDNSSourceTLS{ServerName: preset.serverName},
	}
	switch protocol {
	case "doh":
		server.Type, server.Path = "https", "/dns-query"
	case "dot":
		server.Type, server.ServerPort = "tls", 853
	default:
		return PolicyDNSSourceServer{}, fmt.Errorf("unsupported public DNS protocol %q", protocol)
	}
	return server, nil
}

func loadPolicyDNSCatalog() (policyDNSCatalog, error) {
	policyDNSCatalogOnce.Do(func() {
		packs, err := rulesets.Catalog()
		if err != nil {
			policyDNSCatalogError = err
			return
		}
		result := policyDNSCatalog{byID: make(map[string]rulesets.ServicePack, len(packs))}
		for _, pack := range packs {
			result.byID[pack.ID] = pack
			if pack.AlwaysDirect {
				result.alwaysDirect = append(result.alwaysDirect, pack.ID)
			}
		}
		sort.Strings(result.alwaysDirect)
		policyDNSCatalogValue = result
	})
	return policyDNSCatalogValue, policyDNSCatalogError
}

func candidateServiceIDs(policy map[string]any) []string {
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range stringSlice(policy["candidate_service_ids"]) {
		value = strings.ToLower(strings.TrimSpace(value))
		if !serviceIDPattern.MatchString(value) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func policyServiceSelectorTag(policyID, serviceID string) string {
	digest := sha256.Sum256([]byte(policyID + "\x00" + serviceID))
	return "svc-" + hex.EncodeToString(digest[:])[:20]
}

func directDomains(entity, policy map[string]any) []string {
	result := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range append(stringSlice(policy["direct_domains"]), stringSlice(entity["direct_domains"])...) {
		normalized := normalizeDomainSuffix(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func directServices(entity, policy map[string]any, catalog policyDNSCatalog) ([]string, error) {
	result := make([]string, 0)
	seen := make(map[string]struct{})
	values := append(stringSlice(policy["direct_services"]), stringSlice(entity["direct_services"])...)
	for _, value := range values {
		normalized, err := canonicalServiceID(value)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	if textValue(policy["traffic_mode"]) == "vless_with_wan_exceptions" && boolDefault(policy["torrent_direct"], true) {
		for _, id := range catalog.alwaysDirect {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				result = append(result, id)
			}
		}
	}
	return result, nil
}

func serviceRuleSetIDs(id string, catalog map[string]rulesets.ServicePack) []string {
	result := make([]string, 0)
	visiting := make(map[string]bool)
	var visit func(string)
	visit = func(current string) {
		if visiting[current] {
			return
		}
		for _, existing := range result {
			if existing == current {
				return
			}
		}
		pack, ok := catalog[current]
		if !ok {
			return
		}
		visiting[current] = true
		result = append(result, current)
		for _, dependency := range pack.IncludedPackIDs {
			visit(dependency)
		}
		delete(visiting, current)
	}
	visit(id)
	if len(result) == 0 {
		return []string{id}
	}
	return result
}

func canonicalServiceID(value string) (string, error) {
	normalized := strings.ToLower(value)
	if !serviceIDPattern.MatchString(normalized) || normalized != strings.ToLower(value) {
		return "", errors.New("service rule-set name is invalid")
	}
	return normalized, nil
}

func normalizeDomainSuffix(value string) string {
	raw := strings.ToLower(strings.TrimSpace(value))
	raw = strings.TrimPrefix(raw, "*.")
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if host == "" {
		parsed, err = url.Parse("//" + raw)
		if err != nil {
			return ""
		}
		host = parsed.Hostname()
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) == 0 || len(host) > 253 || !strings.Contains(host, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if !domainLabelPattern.MatchString(label) {
			return ""
		}
	}
	return host
}

func enabledObjects(value any) []map[string]any {
	raw, _ := value.([]any)
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		object := objectValue(item)
		if object == nil || object["enabled"] == false {
			continue
		}
		result = append(result, object)
	}
	return result
}

func enabledObjectsByID(value any) map[string]map[string]any {
	result := make(map[string]map[string]any)
	for _, object := range enabledObjects(value) {
		if id := textValue(object["id"]); id != "" {
			result[id] = object
		}
	}
	return result
}

func objectValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func textValue(value any) string {
	result, _ := value.(string)
	return result
}

func stringSlice(value any) []string {
	if values, ok := value.([]string); ok {
		return append([]string(nil), values...)
	}
	raw, _ := value.([]any)
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

func stringMap(value any) map[string]string {
	raw := objectValue(value)
	result := make(map[string]string, len(raw))
	for key, value := range raw {
		if text, ok := value.(string); ok {
			result[key] = text
		}
	}
	return result
}

func boolDefault(value any, fallback bool) bool {
	result, ok := value.(bool)
	if !ok {
		return fallback
	}
	return result
}

func selectableNonDirect(value string, available map[string]struct{}) bool {
	if value == "" || value == "direct" || value == "direct-wan" || value == "block" {
		return false
	}
	_, ok := available[value]
	return ok
}
