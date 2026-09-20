package runtimeconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type xrayRuleCompiler struct {
	descriptors map[string]PolicyDNSRuleSetDescriptor
	root        string
	cache       map[string][]map[string]any
}

func ConvertXrayRules(
	values any,
	selectable map[string]struct{},
	ruleSets map[string]PolicyDNSRuleSetDescriptor,
	ruleSetRoot string,
) ([]map[string]any, error) {
	compiler := xrayRuleCompiler{
		descriptors: ruleSets,
		root:        ruleSetRoot,
		cache:       make(map[string][]map[string]any),
	}
	result := make([]map[string]any, 0, len(objectSlice(values))+1)
	for _, raw := range objectSlice(values) {
		action := textValue(raw["action"])
		if action == "sniff" || action == "hijack-dns" {
			continue
		}
		target := ""
		switch action {
		case "reject":
			target = "block"
		case "route":
			target = textDefault(raw["outbound"], "block")
		default:
			continue
		}
		expanded, err := compiler.expand(raw)
		if err != nil {
			return nil, err
		}
		for _, conditions := range expanded {
			rule, err := convertXrayRuleConditions(conditions, target, selectable)
			if err != nil {
				return nil, err
			}
			result = append(result, rule)
		}
	}
	return append(result, map[string]any{
		"type": "field", "network": "tcp,udp", "outboundTag": "block",
	}), nil
}

func convertXrayRuleConditions(conditions map[string]any, target string, selectable map[string]struct{}) (map[string]any, error) {
	rule := map[string]any{"type": "field"}
	copyXrayList(conditions, rule, "inbound", "inboundTag")
	copyXrayList(conditions, rule, "auth_user", "user")
	copyXrayList(conditions, rule, "ip_cidr", "ip")
	copyXrayList(conditions, rule, "source_ip_cidr", "source")
	if protocols := stringOrList(conditions["protocol"]); len(protocols) != 0 {
		rule["protocol"] = protocols
	}
	domains := make([]string, 0)
	for _, value := range stringSlice(conditions["domain_suffix"]) {
		domains = append(domains, "domain:"+value)
	}
	for _, value := range stringSlice(conditions["domain"]) {
		domains = append(domains, "full:"+value)
	}
	if len(domains) != 0 {
		rule["domain"] = domains
	}
	if network := joinStringOrList(conditions["network"]); network != "" {
		rule["network"] = network
	}
	ports := stringOrList(conditions["port"])
	for _, value := range stringOrList(conditions["port_range"]) {
		ports = append(ports, strings.ReplaceAll(value, ":", "-"))
	}
	if len(ports) != 0 {
		rule["port"] = strings.Join(ports, ",")
	}
	if value := conditions["ip_version"]; value != nil {
		version, err := integerDefault(value, 0)
		if err != nil {
			return nil, fmt.Errorf("Xray rule ip_version: %w", err)
		}
		if version == 6 {
			ip, _ := rule["ip"].([]string)
			rule["ip"] = append(ip, "::/0")
		}
	}
	if _, ok := selectable[target]; ok {
		rule["balancerTag"] = target
	} else {
		rule["outboundTag"] = target
	}
	return rule, nil
}

func (compiler *xrayRuleCompiler) expand(raw map[string]any) ([]map[string]any, error) {
	base := cloneWithoutKey(raw, "rule_set")
	tags := stringSlice(raw["rule_set"])
	if len(tags) == 0 {
		return []map[string]any{base}, nil
	}
	result := make([]map[string]any, 0)
	for _, tag := range tags {
		name := strings.TrimPrefix(tag, "service-")
		if descriptor, ok := compiler.descriptors[tag]; ok && descriptor.Path != "" {
			baseName := filepath.Base(descriptor.Path)
			name = strings.TrimSuffix(baseName, filepath.Ext(baseName))
		}
		entries, err := compiler.load(name)
		if err != nil {
			return nil, fmt.Errorf("Xray candidate cannot inline ruleset %q: %w", name, err)
		}
		valid := 0
		for _, entry := range entries {
			merged := cloneWithoutKey(base, "")
			for _, key := range []string{"domain_suffix", "domain", "ip_cidr", "port", "port_range"} {
				if _, exists := entry[key]; exists {
					merged[key] = stringOrList(entry[key])
				}
			}
			if network := entry["network"]; joinStringOrList(network) != "" {
				switch network.(type) {
				case []any, []string:
					merged["network"] = stringOrList(network)
				default:
					merged["network"] = fmt.Sprint(network)
				}
			}
			if !hasXrayMatchCondition(merged) {
				continue
			}
			valid++
			result = append(result, merged)
		}
		if valid == 0 {
			return nil, fmt.Errorf("Xray ruleset %q has no usable match conditions", name)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("Xray routing rule references no usable service rules")
	}
	return result, nil
}

func (compiler *xrayRuleCompiler) load(name string) ([]map[string]any, error) {
	if values, ok := compiler.cache[name]; ok {
		return values, nil
	}
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("invalid ruleset name")
	}
	file, err := os.Open(filepath.Join(compiler.root, name+".json"))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var document struct {
		Rules []map[string]any `json:"rules"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxPolicyDNSRulesetBytes+1))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, errors.New("ruleset contains multiple JSON documents")
		}
		return nil, err
	}
	if info, err := file.Stat(); err == nil && info.Size() > maxPolicyDNSRulesetBytes {
		return nil, errors.New("ruleset exceeds 16 MiB")
	}
	compiler.cache[name] = document.Rules
	return document.Rules, nil
}

func copyXrayList(source, destination map[string]any, sourceKey, destinationKey string) {
	if values := stringSlice(source[sourceKey]); len(values) != 0 {
		destination[destinationKey] = values
	}
}

func cloneWithoutKey(value map[string]any, excluded string) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		if key != excluded {
			result[key] = item
		}
	}
	return result
}

func stringOrList(value any) []string {
	if text, ok := value.(string); ok {
		if text == "" {
			return nil
		}
		return []string{text}
	}
	if number, ok := value.(json.Number); ok {
		return []string{number.String()}
	}
	if number, ok := value.(float64); ok {
		return []string{fmt.Sprint(number)}
	}
	if number, ok := value.(int); ok {
		return []string{fmt.Sprint(number)}
	}
	if number, ok := value.(int64); ok {
		return []string{fmt.Sprint(number)}
	}
	if values, ok := value.([]string); ok {
		return append([]string(nil), values...)
	}
	raw, _ := value.([]any)
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		switch typed := item.(type) {
		case string:
			result = append(result, typed)
		case json.Number:
			result = append(result, typed.String())
		case float64:
			result = append(result, fmt.Sprint(typed))
		case int:
			result = append(result, fmt.Sprint(typed))
		}
	}
	return result
}

func joinStringOrList(value any) string {
	values := stringOrList(value)
	return strings.Join(values, ",")
}

func hasXrayMatchCondition(value map[string]any) bool {
	for _, key := range []string{"domain_suffix", "domain", "ip_cidr", "protocol", "network", "port", "port_range"} {
		if joinStringOrList(value[key]) != "" {
			return true
		}
	}
	return false
}
