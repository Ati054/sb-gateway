package runtimeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

type SecretReader func(reference string) (string, error)

type policyCandidateGroup struct {
	Selector string
	Members  []string
}

var policyRegionCountries = map[string]map[string]struct{}{
	"europe":  countrySet("AD AL AT AX BA BE BG BY CH CY CZ DE DK EE ES FI FO FR GB GG GI GR HR HU IE IM IS IT JE LI LT LU LV MC MD ME MK MT NL NO PL PT RO RS RU SE SI SJ SK SM UA VA"),
	"asia":    countrySet("AE AF AM AZ BD BH BN BT CN GE HK ID IL IN IQ IR JO JP KG KH KP KR KW KZ LA LB LK MM MN MO MV MY NP OM PH PK PS QA SA SG SY TH TJ TL TM TR TW UZ VN YE"),
	"america": countrySet("AG AI AR AW BB BL BM BO BQ BR BS BZ CA CL CO CR CU CW DM DO EC FK GD GF GL GP GT GY HN HT JM KN KY LC MF MQ MS MX NI PA PE PM PR PY SR SV SX TC TT US UY VC VE VG VI"),
	"africa":  countrySet("AO BF BI BJ BW CD CF CG CI CM CV DJ DZ EG EH ER ET GA GH GM GN GQ GW KE KM LR LS LY MA MG ML MR MU MW MZ NA NE RE RW SC SD SH SL SN SO SS ST SZ TD TG TN TZ UG YT ZA ZM ZW"),
	"oceania": countrySet("AS AU CC CK CX FJ FM GU HM KI MH MP NC NF NR NU NZ PF PG PN PW SB TK TO TV UM VU WF WS"),
}

var policyAllKnownCountries = unionCountrySets(policyRegionCountries)

func BuildXrayOutboundSource(config map[string]any, nodes []map[string]any, readSecret SecretReader) ([]map[string]any, error) {
	if readSecret == nil {
		return nil, errors.New("Xray outbound source requires a secret reader")
	}
	result := []map[string]any{
		{"type": "direct", "tag": "direct-wan"},
		{"type": "block", "tag": "block"},
	}
	nodeTags := make(map[string]struct{})
	refreshOnly := make(map[string]struct{})
	for _, node := range nodes {
		if node["enabled"] == false {
			continue
		}
		tag := textValue(node["id"])
		if !serviceIDPattern.MatchString(tag) {
			continue
		}
		protocol := textDefault(node["protocol"], "vless")
		var outbound map[string]any
		switch protocol {
		case "routeros-wireguard":
			address, err := netip.ParseAddr(textValue(node["source_address"]))
			if err != nil || !address.Is4() {
				continue
			}
			outbound = map[string]any{
				"type": "direct", "tag": tag, "inet4_bind_address": address.String(), "bind_address_no_port": true,
			}
		case "xray-reverse":
			outbound = map[string]any{"type": "direct", "tag": tag}
		case "hysteria2":
			reference := textValue(node["password_secret_ref"])
			if reference == "" {
				continue
			}
			password, err := readSecret(reference)
			if err != nil {
				return nil, fmt.Errorf("read Hysteria 2 secret for %q: %w", tag, err)
			}
			port, err := requiredInteger(node["server_port"])
			if err != nil {
				return nil, fmt.Errorf("node %q server_port: %w", tag, err)
			}
			outbound = map[string]any{
				"type": "hysteria2", "tag": tag, "server": textValue(node["server"]), "server_port": port, "password": password,
			}
			for _, field := range []string{"up_mbps", "down_mbps"} {
				if _, exists := node[field]; exists {
					if value, valueErr := integerDefault(node[field], 0); valueErr == nil {
						outbound[field] = value
					}
				}
			}
			if tls := objectValue(node["tls"]); len(tls) != 0 {
				outbound["tls"] = cloneJSONMap(tls)
			}
			if obfs := objectValue(node["obfs"]); len(obfs) != 0 {
				reference := textValue(node["obfs_password_secret_ref"])
				if reference == "" {
					continue
				}
				password, err := readSecret(reference)
				if err != nil {
					return nil, fmt.Errorf("read Hysteria 2 obfuscation secret for %q: %w", tag, err)
				}
				outbound["obfs"] = map[string]any{"type": "salamander", "password": password}
			}
		case "vless":
			reference := textValue(node["uuid_secret_ref"])
			if reference == "" {
				continue
			}
			uuid, err := readSecret(reference)
			if err != nil {
				return nil, fmt.Errorf("read VLESS secret for %q: %w", tag, err)
			}
			port, err := requiredInteger(node["server_port"])
			if err != nil {
				return nil, fmt.Errorf("node %q server_port: %w", tag, err)
			}
			outbound = map[string]any{
				"type": "vless", "tag": tag, "server": textValue(node["server"]), "server_port": port, "uuid": uuid,
			}
			if flow := textValue(node["flow"]); flow != "" {
				outbound["flow"] = flow
			}
			if tls := objectValue(node["tls"]); len(tls) != 0 {
				outbound["tls"] = cloneJSONMap(tls)
			}
			if transport := objectValue(node["transport"]); len(transport) != 0 {
				outbound["transport"] = cloneJSONMap(transport)
			}
		default:
			continue
		}
		result = append(result, outbound)
		nodeTags[tag] = struct{}{}
		if textValue(node["subscription_reserve_id"]) != "" {
			refreshOnly[tag] = struct{}{}
		}
	}

	allowed := make(map[string]struct{}, len(nodeTags)+1)
	for tag := range nodeTags {
		if _, reserve := refreshOnly[tag]; !reserve {
			allowed[tag] = struct{}{}
		}
	}
	allowed["block"] = struct{}{}

	for _, policy := range enabledObjects(config["policies"]) {
		tag := textValue(policy["id"])
		// Keep the Xray selector membership stable while an operator edits only
		// the policy eligibility/order. Every usable outbound is already present
		// in the same Xray process; the health contract is the authority that
		// chooses among the policy candidates. Putting block first keeps a cold
		// selector fail-closed until startup restoration or health reconciliation
		// applies an eligible leaf.
		selected := stablePolicySelectorMembers(allowed, "block", tag)
		result = append(result, map[string]any{
			"type": "selector", "tag": tag, "outbounds": selected,
			"interrupt_exist_connections": boolDefault(policy["interrupt_exist_connections"], false),
		})
		if textValue(policy["mode"]) != "priority" {
			continue
		}
		serviceIDs := candidateServiceIDs(policy)
		if len(serviceIDs) == 0 {
			continue
		}
		blockTag := policyServiceBlockTag(tag)
		result = append(result, map[string]any{"type": "block", "tag": blockTag})
		for _, serviceID := range serviceIDs {
			// Service access is enforced by the health controller's explicit
			// override. Stable membership prevents a card/access edit from
			// restarting Xray; the safe default remains the service block leaf.
			members := stablePolicySelectorMembers(allowed, blockTag, tag)
			result = append(result, map[string]any{
				"type": "selector", "tag": policyServiceSelectorTag(tag, serviceID),
				"outbounds": members, "interrupt_exist_connections": false,
			})
		}
	}
	health := sortedNodeTags(nodeTags, refreshOnly, map[string]struct{}{"block": {}, "direct-wan": {}})
	if len(health) != 0 {
		for _, lane := range xrayHealthProbeLanesForConfig(config) {
			result = append(result, map[string]any{
				"type": "selector", "tag": lane.Tag, "outbounds": health, "interrupt_exist_connections": false,
			})
		}
	}
	updates := []string{"direct-wan"}
	updates = append(updates, sortedNodeTags(nodeTags, nil, map[string]struct{}{"block": {}, "direct-wan": {}})...)
	updates = append(updates, "sb-subscription-update-")
	result = append(result, map[string]any{
		"type": "selector", "tag": "subscription-update-egress",
		"outbounds": updates, "interrupt_exist_connections": false,
	})
	return result, nil
}

func stablePolicySelectorMembers(allowed map[string]struct{}, blockTag, policyID string) []string {
	members := make([]string, 0, len(allowed)+1)
	for member := range allowed {
		if member == "block" || member == blockTag || member == policyID {
			continue
		}
		members = append(members, member)
	}
	sort.Strings(members)
	return append([]string{blockTag}, members...)
}

func policyCandidateGroups(policy map[string]any, nodes []map[string]any) []policyCandidateGroup {
	selectors := make([]string, 0)
	for _, raw := range stringSlice(policy["selection_order"]) {
		if normalized := normalizeLocationSelector(raw); normalized != "" {
			selectors = append(selectors, normalized)
		}
	}
	if len(selectors) == 0 {
		return nil
	}
	claimed := make(map[string]struct{})
	groups := make([]policyCandidateGroup, 0, len(selectors))
	for _, selector := range selectors {
		kind, value, _ := strings.Cut(selector, ":")
		members := make([]string, 0)
		for _, node := range nodes {
			if node["enabled"] == false {
				continue
			}
			tag := textValue(node["id"])
			if tag == "" {
				continue
			}
			if _, used := claimed[tag]; used {
				continue
			}
			if locationSelectorMatches(kind, value, node, policyAllKnownCountries) {
				members = append(members, tag)
				claimed[tag] = struct{}{}
			}
		}
		if len(members) != 0 {
			groups = append(groups, policyCandidateGroup{Selector: selector, Members: members})
		}
	}
	// Eligibility is the complete user selection. The health controller limits
	// the working shortlist, not the inventory: otherwise failed reserves cannot
	// be replaced and better nodes outside the first N are never discovered.
	return groups
}

func normalizeLocationSelector(value string) string {
	if len(value) > 768 {
		return ""
	}
	if raw, ok := strings.CutPrefix(value, "region:"); ok {
		if _, exists := policyRegionCountries[raw]; exists || raw == "other" {
			return "region:" + raw
		}
		return ""
	}
	if raw, ok := strings.CutPrefix(value, "country:"); ok {
		raw = strings.ToUpper(raw)
		if len(raw) == 2 && raw[0] >= 'A' && raw[0] <= 'Z' && raw[1] >= 'A' && raw[1] <= 'Z' {
			return "country:" + raw
		}
		return ""
	}
	if raw, ok := strings.CutPrefix(value, "location:"); ok {
		raw = strings.ToLower(raw)
		if len(raw) == 16 {
			if _, err := hex.DecodeString(raw); err == nil {
				return "location:" + raw
			}
		}
		return ""
	}
	if raw, ok := strings.CutPrefix(value, "city:"); ok {
		country, encoded, ok := strings.Cut(raw, ":")
		if !ok || (country != "*" && !twoASCIILetters(country)) {
			return ""
		}
		city, err := url.PathUnescape(encoded)
		city = normalizeCity(city)
		if err != nil || city == "" {
			return ""
		}
		return "city:" + strings.ToUpper(country) + ":" + url.PathEscape(city)
	}
	if raw, ok := strings.CutPrefix(value, "wireguard:"); ok {
		raw = strings.ToLower(raw)
		if len(raw) >= 1 && len(raw) <= 32 && hyphenID(raw) {
			return "wireguard:" + raw
		}
		return ""
	}
	if raw, ok := strings.CutPrefix(value, "reverse:"); ok {
		raw = strings.ToLower(raw)
		if serviceIDPattern.MatchString(raw) {
			return "reverse:" + raw
		}
	}
	return ""
}

func locationSelectorMatches(kind, value string, node map[string]any, allKnown map[string]struct{}) bool {
	sourceType := textValue(node["source_type"])
	switch kind {
	case "wireguard":
		return sourceType == "routeros-wireguard" && textValue(node["wireguard_egress_id"]) == value
	case "reverse":
		return sourceType == "xray-reverse" && textValue(node["reverse_vless_id"]) == value
	}
	if sourceType == "routeros-wireguard" || sourceType == "xray-reverse" {
		return false
	}
	country := strings.ToUpper(textValue(node["country"]))
	switch kind {
	case "region":
		if value == "other" {
			_, known := allKnown[country]
			return country == "" || !known
		}
		_, exists := policyRegionCountries[value][country]
		return exists
	case "country":
		return country == value
	case "location":
		for _, field := range []string{"selection_key", "location_key"} {
			if strings.ToLower(textValue(node[field])) == value {
				return true
			}
		}
	case "city":
		cityCountry, encodedCity, ok := strings.Cut(value, ":")
		city, err := url.PathUnescape(encodedCity)
		return ok && err == nil && (cityCountry == "*" || country == cityCountry) && strings.EqualFold(normalizeCity(textValue(node["city"])), city)
	}
	return false
}

func normalizeCity(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" || len(value) > 256 {
		return ""
	}
	for _, character := range value {
		if character < 32 {
			return ""
		}
	}
	value = strings.TrimLeftFunc(value, func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsNumber(character)
	})
	return value
}

func policyServiceBlockTag(policyID string) string {
	digest := sha256.Sum256([]byte(policyID))
	return "svc-block-" + hex.EncodeToString(digest[:])[:16]
}

func sortedNodeTags(tags, excluded, reserved map[string]struct{}) []string {
	result := make([]string, 0, len(tags))
	for tag := range tags {
		if _, skip := excluded[tag]; skip {
			continue
		}
		if _, skip := reserved[tag]; skip {
			continue
		}
		result = append(result, tag)
	}
	sort.Strings(result)
	return result
}

func countrySet(values string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, value := range strings.Fields(values) {
		result[value] = struct{}{}
	}
	return result
}

func unionCountrySets(values map[string]map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{})
	for _, countries := range values {
		for country := range countries {
			result[country] = struct{}{}
		}
	}
	return result
}

func hyphenID(value string) bool {
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
			continue
		}
		return false
	}
	return true
}

func twoASCIILetters(value string) bool {
	if len(value) != 2 {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')) {
			return false
		}
	}
	return true
}

func cloneJSONMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		switch typed := item.(type) {
		case map[string]any:
			result[key] = cloneJSONMap(typed)
		case []any:
			copy := make([]any, len(typed))
			for index, element := range typed {
				if object, ok := element.(map[string]any); ok {
					copy[index] = cloneJSONMap(object)
				} else {
					copy[index] = element
				}
			}
			result[key] = copy
		default:
			result[key] = item
		}
	}
	return result
}
