package runtimeconfig

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

// Emergency DNS remains deliberately bounded to the catalog's maintained
// bootstrap domains, not thousands of geosite entries on a small router.
// Normal operation uses the complete container rulesets, including when all
// proxy candidates are unavailable. This fallback is for container failure.
type routerOSOutageGroup struct {
	Key              string
	Sources, Domains []string
}

var outageDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

// RouterOS match-subdomain supports public suffixes as names. Keep this set
// bounded to reviewed catalog TLDs so a malformed custom single-label value
// cannot unexpectedly intercept a local DNS zone.
var reviewedOutageTopLevelDomains = map[string]bool{
	"moscow": true, "ru": true, "su": true, "tatar": true,
	"xn--80adxhks": true, "xn--80asehdb": true, "xn--80aswg": true,
	"xn--c1avg": true, "xn--d1acj3b": true, "xn--p1acf": true,
	"xn--p1ai": true, "yandex": true, "youtube": true,
}

func normalizeOutageDomain(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", nil
	}
	if domain := normalizeDomainSuffix(trimmed); domain != "" {
		return domain, nil
	}
	topLevel := strings.TrimSuffix(strings.TrimPrefix(trimmed, "*."), ".")
	if reviewedOutageTopLevelDomains[topLevel] && outageDomainPattern.MatchString(topLevel) {
		return topLevel, nil
	}
	return "", fmt.Errorf("unsafe outage domain %q", raw)
}

func routerOSOutageGroups(config map[string]any, ruleSetRoot ...string) ([]routerOSOutageGroup, error) {
	catalog, err := loadPolicyDNSCatalog()
	if err != nil {
		return nil, err
	}
	policies := enabledObjectsByID(config["policies"])
	permissions := map[string]map[string]bool{}
	compiler := policyDNSCompiler{ruleSets: map[string][]policyDNSRuleSetRule{}}
	if len(ruleSetRoot) > 0 {
		compiler.options.RuleSetRoot = ruleSetRoot[0]
	}
	for _, client := range enabledObjects(config["local_clients"]) {
		policy := policies[textValue(client["policy_id"])]
		if textDefault(client["container_outage"], textValue(policy["container_outage"])) != "lan_only" || textValue(policy["traffic_mode"]) == "wan_with_vless_exceptions" {
			continue
		}
		sources := []string{}
		for _, value := range stringSlice(client["source_cidrs"]) {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("outage source: %w", err)
			}
			if prefix.Addr().Is4() {
				sources = append(sources, prefix.Masked().String())
			}
		}
		domains := directDomains(client, policy)
		services, err := directServices(client, policy, catalog)
		if err != nil {
			return nil, err
		}
		for _, service := range services {
			for _, dependency := range serviceRuleSetIDs(service, catalog.byID) {
				pack, known := catalog.byID[dependency]
				if !known {
					pack, err = rulesets.CustomPack(dependency, "")
					if err != nil {
						return nil, err
					}
					entries, loadErr := compiler.loadRuleSet(dependency)
					if loadErr != nil {
						return nil, fmt.Errorf("outage card %s: %w", dependency, loadErr)
					}
					for _, entry := range entries {
						domains = append(domains, entry.DomainSuffix...)
						domains = append(domains, entry.Domain...)
					}
				}
				domains = append(domains, pack.FallbackDomains...)
			}
		}
		for _, rawDomain := range domains {
			domain, normalizeErr := normalizeOutageDomain(rawDomain)
			// Empty values can be present in third-party rule-set payloads. They
			// express no permission and must not make an otherwise valid routing
			// list impossible to Apply. Non-empty malformed domains remain fatal.
			if domain == "" {
				if normalizeErr != nil {
					return nil, normalizeErr
				}
				continue
			}
			if !outageDomainPattern.MatchString(domain) {
				return nil, fmt.Errorf("unsafe outage domain %q", domain)
			}
			if permissions[domain] == nil {
				permissions[domain] = map[string]bool{}
			}
			for _, source := range sources {
				permissions[domain][source] = true
			}
		}
	}
	// RouterOS uses the first matching DNS record. A more specific suffix must
	// inherit its parent's sources, otherwise overlapping client policies break.
	for domain, sources := range permissions {
		parent := domain
		for {
			_, parent, _ = strings.Cut(parent, ".")
			if parent == "" {
				break
			}
			for source := range permissions[parent] {
				sources[source] = true
			}
		}
	}
	grouped := map[string]*routerOSOutageGroup{}
	for domain, sources := range permissions {
		sorted := []string{}
		for source := range sources {
			sorted = append(sorted, source)
		}
		sort.Strings(sorted)
		if len(sorted) == 0 {
			continue
		}
		key := strings.Join(sorted, "\n")
		if grouped[key] == nil {
			grouped[key] = &routerOSOutageGroup{Sources: sorted}
		}
		grouped[key].Domains = append(grouped[key].Domains, domain)
	}
	result := []routerOSOutageGroup{}
	for _, group := range grouped {
		sort.Strings(group.Domains)
		// Changing permissions or domains creates a fresh destination list. Cached
		// addresses from a removed card cannot grant access to the new policy.
		digest := sha256.Sum256([]byte(strings.Join(group.Sources, "\n") + "\n--\n" + strings.Join(group.Domains, "\n")))
		group.Key = fmt.Sprintf("%X", digest[:8])
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key < result[j].Key })
	return result, nil
}

func renderRouterOSOutage(groups []routerOSOutageGroup) []string {
	lines := renderRouterOSFailClosedDrop()
	lines = append(lines, `:local outageDrop $failClosedDrop`)
	rules, sources, dns := []string{}, []string{}, []string{}
	type entry struct{ domain, key string }
	entries := []entry{}
	for _, group := range groups {
		sources = append(sources, "SB-GATEWAY outage source "+group.Key)
		for _, proto := range []string{"TCP", "UDP"} {
			rules = append(rules, "SB-GATEWAY outage direct "+proto+" "+group.Key)
		}
		dns = append(dns, "SB-GATEWAY outage DNS "+group.Key)
		for _, domain := range group.Domains {
			entries = append(entries, entry{domain, group.Key})
		}
	}
	// Short data table plus one loop, not a copy of the RSC program per domain.
	// Keep the normal single-policy delta below RouterOS REST's 16 KiB limit.
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].domain) != len(entries[j].domain) {
			return len(entries[i].domain) < len(entries[j].domain)
		}
		return entries[i].domain < entries[j].domain
	})
	records := make([]string, 0, len(entries))
	for _, item := range entries {
		records = append(records, item.domain+"|"+item.key)
	}
	lines = append(lines, fmt.Sprintf(`:local outageRecords %s`, routerOSArray(records)),
		`:foreach record in=$outageRecords do={ :local outageDomain [:pick $record 0 [:find $record "|"]]; :foreach entry in=[/ip/dns/static/find where name=$outageDomain] do={ :if (([/ip/dns/static/get $entry comment] ~ "^SB-GATEWAY outage DNS ") = false) do={ :error "SB-GATEWAY outage DNS conflicts with an unowned record" } } }`)
	// Revoke obsolete permits before publishing any additions. All cleanup is
	// restricted to owned comments; user DNS/firewall rules are untouched.
	lines = append(lines, renderRouterOSOwnedCleanup("/ip/firewall/filter", "SB-GATEWAY outage direct ", "OutageRules", rules)...)
	lines = append(lines, renderRouterOSOwnedCleanup("/ip/firewall/address-list", "SB-GATEWAY outage source ", "OutageSources", sources)...)
	// Retire DNS-created dynamic addresses along with obsolete owned records.
	lines = append(lines, fmt.Sprintf(`:local outageWantedDNS %s`, routerOSArray(dns)),
		`:foreach entry in=[/ip/dns/static/find where comment~"^SB-GATEWAY outage DNS "] do={ :local keep false; :local c [/ip/dns/static/get $entry comment]; :foreach wanted in=$outageWantedDNS do={ :if ($wanted = $c) do={ :set keep true } }; :if ($keep = false) do={ :local oldList [/ip/dns/static/get $entry address-list]; :if ($oldList ~ "^SB_OUTAGE_DST_[0-9A-F_]+\$") do={ /ip/firewall/address-list/remove [find where list=$oldList and dynamic=yes] } } }`)
	lines = append(lines, renderRouterOSOwnedCleanup("/ip/dns/static", "SB-GATEWAY outage DNS ", "OutageDNS", dns)...)
	if len(groups) > 0 {
		lines = append(lines, `:if ([/ip/dns/get allow-remote-requests] != true) do={ :error "SB-GATEWAY outage exceptions require RouterOS DNS" }`)
	}
	for _, proto := range []string{"tcp", "udp"} {
		comment := "SB-GATEWAY outage DNS " + strings.ToUpper(proto) + " redirect"
		fields := fmt.Sprintf(`chain=dstnat action=redirect src-address-list="SB_FAIL_CLOSED_CLIENTS" connection-mark=no-mark dst-address-type=!local protocol=%s dst-port=53 disabled=no`, proto)
		lines = append(lines, fmt.Sprintf(`:local outageRedirect [/ip/firewall/nat/find where comment="%s"]`, comment),
			`:if ([:len $outageRedirect] > 1) do={ :error "SB-GATEWAY outage DNS redirect ambiguous" }`,
			fmt.Sprintf(`:if ([:len $outageRedirect] = 0) do={ /ip/firewall/nat/add %s place-before=0 comment="%s" } else={ /ip/firewall/nat/set $outageRedirect %s }`, fields, comment, fields))
	}
	for _, group := range groups {
		src, dst := "SB_OUTAGE_SRC_"+group.Key, "SB_OUTAGE_DST_"+group.Key
		lines = append(lines, renderRouterOSAddressList("Outage"+group.Key, src, "SB-GATEWAY outage source "+group.Key, group.Sources)...)
		for _, proto := range []string{"tcp", "udp"} {
			ports := "443"
			if proto == "tcp" {
				ports = "80,443"
			}
			comment := "SB-GATEWAY outage direct " + strings.ToUpper(proto) + " " + group.Key
			fields := fmt.Sprintf(`chain="sb-gateway-forward" action=accept connection-mark=no-mark src-address-list="%s" dst-address-list="%s" out-interface-list=WAN protocol=%s dst-port=%s disabled=no`, src, dst, proto, ports)
			lines = append(lines,
				fmt.Sprintf(`:local outageRule [/ip/firewall/filter/find where comment="%s"]`, comment),
				`:if ([:len $outageRule] > 1) do={ :error "SB-GATEWAY outage rule ambiguous" }`,
				fmt.Sprintf(`:if ([:len $outageRule] = 0) do={ /ip/firewall/filter/add %s place-before=$outageDrop comment="%s" } else={ /ip/firewall/filter/set $outageRule %s; /ip/firewall/filter/move $outageRule destination=$outageDrop }`, fields, comment, fields))
		}
	}
	// Add/move most specific suffixes ahead of broad ones. One record per name,
	// even when multiple policies grant it, avoids first-match list starvation.
	lines = append(lines,
		`:foreach record in=$outageRecords do={`,
		`  :local outageSeparator [:find $record "|"]`,
		`  :local outageDomain [:pick $record 0 $outageSeparator]`,
		`  :local outageKey [:pick $record ($outageSeparator + 1) [:len $record]]`,
		`  :local outageComment ("SB-GATEWAY outage DNS " . $outageKey)`,
		`  :local outageDestination ("SB_OUTAGE_DST_" . $outageKey)`,
		`  :local outageDNS [/ip/dns/static/find where name=$outageDomain and comment=$outageComment]`,
		`  :if ([:len $outageDNS] > 1) do={ :error "SB-GATEWAY outage DNS ambiguous" }`,
		`  :if ([:len $outageDNS] = 0) do={ /ip/dns/static/add name=$outageDomain type=FWD match-subdomain=yes address-list=$outageDestination disabled=no comment=$outageComment; :set outageDNS [/ip/dns/static/find where name=$outageDomain and comment=$outageComment] } else={ /ip/dns/static/set $outageDNS name=$outageDomain type=FWD match-subdomain=yes address-list=$outageDestination disabled=no }`,
		`  :local firstDNS [:pick [/ip/dns/static/find where comment~"^SB-GATEWAY outage DNS "] 0 1]`,
		`  :if ($outageDNS != $firstDNS) do={ /ip/dns/static/move $outageDNS destination=$firstDNS }`,
		`}`)
	return lines
}
