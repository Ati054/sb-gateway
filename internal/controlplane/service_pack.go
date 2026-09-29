package controlplane

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

type servicePackRefreshFunc func(rulesets.ServicePack, string) (map[string]any, error)

func selectedServicePackIDs(config map[string]any) map[string]bool {
	selected := make(map[string]bool)
	for _, section := range []string{"policies", "local_clients", "remote_users"} {
		for _, entity := range objects(config[section]) {
			if entity["enabled"] == false {
				continue
			}
			for _, field := range []string{"direct_services", "candidate_service_ids"} {
				for _, id := range stringsOf(entity[field]) {
					selected[id] = true
				}
			}
			if routes, ok := entity["service_routes"].(map[string]any); ok {
				for id := range routes {
					selected[id] = true
				}
			}
		}
	}
	return selected
}

// A newly selected catalog card must be populated before runtime rendering.
// The monitor's daily refresh may be many hours away, while seed rules contain
// only a small fallback subset of the card.
func (server *Server) refreshNewSelectedCatalogPacks(active, desired map[string]any) error {
	if active == nil {
		return nil // First installation must remain possible without catalog access.
	}
	previous := selectedServicePackIDs(active)
	selected := selectedServicePackIDs(desired)
	catalog, err := rulesets.Catalog()
	if err != nil {
		return err
	}
	byID := make(map[string]rulesets.ServicePack, len(catalog))
	for _, pack := range catalog {
		byID[pack.ID] = pack
	}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		if !previous[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	server.servicePackMu.Lock()
	defer server.servicePackMu.Unlock()
	for _, id := range ids {
		pack, known := byID[id]
		if !known || pack.UpdateMode != "catalog" || pack.UpstreamName == nil {
			continue // Custom and GeoIP packs were validated by the resolver.
		}
		if _, err := server.refreshServicePack(pack, server.opts.Runtime.RuleSetDir); err != nil {
			return fmt.Errorf("selected catalog card %q could not be refreshed: %w", id, err)
		}
	}
	return nil
}

var compoundDomainSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "com.au": true, "com.br": true,
	"com.cn": true, "com.hk": true, "co.jp": true, "co.kr": true,
	"co.nz": true, "co.za": true, "com.sg": true, "com.tr": true,
}

func (server *Server) resolveServicePack(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	source := strings.ToLower(strings.TrimSpace(text(body["upstream_name"])))
	source = strings.TrimPrefix(source, "geosite:")
	if strings.HasPrefix(source, "geoip:") {
		source = "geoip-" + strings.TrimPrefix(source, "geoip:")
	}
	hostname := servicePackHostname(source)
	packID := source
	if hostname != "" {
		packID = registrableLabel(hostname)
	}
	builtin := server.matchBuiltinServicePack(packID, hostname)
	if builtin != nil {
		server.writeJSON(response, http.StatusOK, builtinServicePackResponse(*builtin, server.routeSimulator.ruleCounts))
		return
	}
	if !entityIDPattern.MatchString(packID) {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_service_pack", "Use the catalog identifier, for example avito.")
		return
	}
	name := strings.TrimSpace(text(body["display_name"]))
	if name == "" {
		name = packID
	}
	if len([]rune(name)) > 64 {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_service_pack_name", "Service display name must contain 1 to 64 characters.")
		return
	}
	pack, err := rulesets.CustomPack(packID, name)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_service_pack", "Use the catalog identifier, for example avito.")
		return
	}
	// A second click must not duplicate the same bounded domain-list download
	// and compile burst on a single-core router.
	server.servicePackMu.Lock()
	result, err := server.refreshServicePack(pack, server.opts.Runtime.RuleSetDir)
	server.servicePackMu.Unlock()
	actor := strings.TrimSpace(text(payload["sub"]))
	if err != nil {
		server.audit(request, actor, "service-packs.resolve", "rejected", map[string]any{"id": packID, "error_type": fmt.Sprintf("%T", err)})
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "service_pack_not_found", "The service was not found in the trusted catalog or its rules were rejected.")
		return
	}
	server.audit(request, actor, "service-packs.resolve", "ok", map[string]any{"id": packID, "rules": result["rules"]})
	server.writeJSON(response, http.StatusOK, map[string]any{
		"ok": true, "builtin": false,
		"pack":  map[string]any{"id": pack.ID, "name": pack.Name, "upstream_name": pack.UpstreamName, "enabled": true},
		"rules": result["rules"], "sha256": result["sha256"], "updated_at": result["updated_at"],
	})
}

func servicePackHostname(source string) string {
	if !strings.ContainsAny(source, "./") && !strings.Contains(source, "://") {
		return ""
	}
	value := source
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	return normalizeDomain(parsed.Hostname())
}

func registrableLabel(hostname string) string {
	labels := strings.FieldsFunc(hostname, func(character rune) bool { return character == '.' })
	if len(labels) < 2 {
		return hostname
	}
	index := len(labels) - 2
	suffix := strings.Join(labels[len(labels)-2:], ".")
	if compoundDomainSuffixes[suffix] && len(labels) >= 3 {
		index = len(labels) - 3
	}
	return labels[index]
}

func (server *Server) matchBuiltinServicePack(packID, hostname string) *rulesets.ServicePack {
	if hostname != "" {
		matches := make([]rulesets.ServicePack, 0)
		for _, pack := range server.routeSimulator.packs {
			if strings.HasPrefix(pack.ID, "ru-") || strings.HasSuffix(pack.ID, "-group") {
				continue
			}
			if server.routeSimulator.catalogDomain(pack.ID, hostname, map[string]bool{}) {
				matches = append(matches, pack)
			}
		}
		sort.Slice(matches, func(left, right int) bool {
			leftExact := stringIn(matches[left].FallbackDomains, hostname)
			rightExact := stringIn(matches[right].FallbackDomains, hostname)
			if leftExact != rightExact {
				return leftExact
			}
			leftSuffix := directSuffix(matches[left].FallbackDomains, hostname)
			rightSuffix := directSuffix(matches[right].FallbackDomains, hostname)
			if leftSuffix != rightSuffix {
				return leftSuffix
			}
			if len(matches[left].FallbackDomains) != len(matches[right].FallbackDomains) {
				return len(matches[left].FallbackDomains) < len(matches[right].FallbackDomains)
			}
			return matches[left].ID < matches[right].ID
		})
		if len(matches) != 0 {
			pack := matches[0]
			return &pack
		}
	}
	if pack, exists := server.routeSimulator.catalog[packID]; exists {
		copy := pack
		return &copy
	}
	return nil
}

func builtinServicePackResponse(pack rulesets.ServicePack, counts map[string]int) map[string]any {
	return map[string]any{
		"ok": true, "builtin": true, "rules": counts[pack.ID],
		"pack": map[string]any{"id": pack.ID, "name": pack.Name, "enabled": true, "builtin": true},
	}
}

func stringIn(values []string, wanted string) bool {
	for _, value := range values {
		if normalizeDomain(value) == wanted {
			return true
		}
	}
	return false
}

func directSuffix(values []string, hostname string) bool {
	for _, value := range values {
		suffix := normalizeDomain(value)
		if hostname == suffix || strings.HasSuffix(hostname, "."+suffix) {
			return true
		}
	}
	return false
}
