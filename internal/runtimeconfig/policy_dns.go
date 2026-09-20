package runtimeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxPolicyDNSRulesetBytes = 16 << 20

// PolicyDNSSource is the validated DNS portion of the renderer source model.
// It intentionally models only the current schema; legacy aliases belong to
// migrations and are not accepted by the Go renderer.
type PolicyDNSSource struct {
	Servers []PolicyDNSSourceServer `json:"servers"`
	Rules   []PolicyDNSSourceRule   `json:"rules"`
	Final   string                  `json:"final"`
}

type PolicyDNSSourceServer struct {
	Tag         string             `json:"tag"`
	Type        string             `json:"type"`
	Server      string             `json:"server"`
	Detour      string             `json:"detour"`
	ServerPort  int                `json:"server_port"`
	Path        string             `json:"path"`
	TLS         PolicyDNSSourceTLS `json:"tls"`
	DoTFallback bool               `json:"dot_fallback"`
}

type PolicyDNSSourceTLS struct {
	ServerName string `json:"server_name"`
}

type PolicyDNSSourceRule struct {
	Inbound      []string `json:"inbound"`
	SourceCIDR   []string `json:"source_ip_cidr"`
	AuthUser     []string `json:"auth_user"`
	Domain       []string `json:"domain"`
	DomainSuffix []string `json:"domain_suffix"`
	RuleSet      []string `json:"rule_set"`
	Action       string   `json:"action"`
	Server       string   `json:"server"`
}

type PolicyDNSRuleSetDescriptor struct {
	Path string `json:"path"`
}

type PolicyDNSCompileOptions struct {
	ExistingInboundPorts []int
	Selectable           map[string]struct{}
	RuleSets             map[string]PolicyDNSRuleSetDescriptor
	RuleSetRoot          string
}

// PolicyDNSArtifacts contains both the Go resolver document and the loopback
// Xray wiring required to preserve the selected route for every DNS request.
type PolicyDNSArtifacts struct {
	Runtime       PolicyDNSRuntime
	XrayInbounds  []map[string]any
	XrayOutbounds []map[string]any
	XrayRules     []map[string]any
}

// Fields are declared in canonical key order so MarshalPolicyDNS is byte-for-
// byte compatible with the current compact, sorted JSON artifact.
type PolicyDNSRuntime struct {
	Lanes          []PolicyDNSLane            `json:"lanes"`
	Servers        map[string]PolicyDNSServer `json:"servers"`
	TimeoutSeconds int                        `json:"timeout_seconds,omitempty"`
	Version        int                        `json:"version"`
}

type PolicyDNSServer struct {
	Detour      string `json:"detour"`
	DoTFallback bool   `json:"dot_fallback,omitempty"`
	Path        string `json:"path"`
	Server      string `json:"server"`
	ServerName  string `json:"server_name"`
	ServerPort  int    `json:"server_port"`
	TunnelHost  string `json:"tunnel_host,omitempty"`
	TunnelPort  int    `json:"tunnel_port,omitempty"`
	Type        string `json:"type"`
}

type PolicyDNSLane struct {
	Final string          `json:"final"`
	Host  string          `json:"host"`
	ID    string          `json:"id"`
	Port  int             `json:"port"`
	Rules []PolicyDNSRule `json:"rules"`
}

type PolicyDNSRule struct {
	Action       string   `json:"action"`
	Domain       []string `json:"domain"`
	DomainSuffix []string `json:"domain_suffix"`
	Server       string   `json:"server"`
}

type policyDNSIdentity struct {
	AuthUser   []string `json:"auth_user,omitempty"`
	Inbound    []string `json:"inbound,omitempty"`
	SourceCIDR []string `json:"source_ip_cidr,omitempty"`
}

func (identity policyDNSIdentity) empty() bool {
	return len(identity.AuthUser) == 0 && len(identity.Inbound) == 0 && len(identity.SourceCIDR) == 0
}

func (identity policyDNSIdentity) size() int {
	return len(identity.AuthUser) + len(identity.Inbound) + len(identity.SourceCIDR)
}

func (identity policyDNSIdentity) fields() int {
	count := 0
	if len(identity.AuthUser) != 0 {
		count++
	}
	if len(identity.Inbound) != 0 {
		count++
	}
	if len(identity.SourceCIDR) != 0 {
		count++
	}
	return count
}

type policyDNSCompiler struct {
	options  PolicyDNSCompileOptions
	usedPort map[int]struct{}
	ruleSets map[string][]policyDNSRuleSetRule
}

type policyDNSRuleSetDocument struct {
	Rules []policyDNSRuleSetRule `json:"rules"`
}

type policyDNSRuleSetRule struct {
	Domain       []string          `json:"domain"`
	DomainSuffix []string          `json:"domain_suffix"`
	IPCIDR       []string          `json:"ip_cidr"`
	Port         []json.RawMessage `json:"port"`
	PortRange    []json.RawMessage `json:"port_range"`
	Protocol     json.RawMessage   `json:"protocol"`
	Network      json.RawMessage   `json:"network"`
}

func (rule policyDNSRuleSetRule) usable() bool {
	return len(rule.Domain) != 0 || len(rule.DomainSuffix) != 0 || len(rule.IPCIDR) != 0 ||
		len(rule.Port) != 0 || len(rule.PortRange) != 0 || nonEmptyJSON(rule.Protocol) || nonEmptyJSON(rule.Network)
}

func nonEmptyJSON(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null")) && !bytes.Equal(trimmed, []byte(`""`)) && !bytes.Equal(trimmed, []byte("[]"))
}

// CompilePolicyDNS performs one bounded compilation pass. Parsed rulesets are
// retained only for this call, avoiding repeated disk/JSON work without keeping
// historical configuration variants resident in the router.
func CompilePolicyDNS(source PolicyDNSSource, options PolicyDNSCompileOptions) (PolicyDNSArtifacts, error) {
	compiler := policyDNSCompiler{
		options:  options,
		usedPort: make(map[int]struct{}, len(options.ExistingInboundPorts)+len(source.Servers)+8),
		ruleSets: make(map[string][]policyDNSRuleSetRule),
	}
	for _, port := range options.ExistingInboundPorts {
		compiler.usedPort[port] = struct{}{}
	}
	return compiler.compile(source)
}

func (compiler *policyDNSCompiler) compile(source PolicyDNSSource) (PolicyDNSArtifacts, error) {
	artifacts := PolicyDNSArtifacts{
		Runtime: PolicyDNSRuntime{
			Lanes:   make([]PolicyDNSLane, 0),
			Servers: make(map[string]PolicyDNSServer, len(source.Servers)),
			Version: 1,
		},
		XrayInbounds:  make([]map[string]any, 0),
		XrayOutbounds: make([]map[string]any, 0),
		XrayRules:     make([]map[string]any, 0),
	}
	servers := make(map[string]PolicyDNSSourceServer, len(source.Servers))
	for _, server := range source.Servers {
		if server.Tag != "" {
			servers[server.Tag] = server
		}
	}
	if len(servers) == 0 {
		return artifacts, nil
	}
	if _, ok := servers[source.Final]; !ok {
		return PolicyDNSArtifacts{}, errors.New("policy DNS final server is missing")
	}

	identities := collectPolicyDNSIdentities(source.Rules)
	for index, identity := range identities {
		port, err := compiler.takePort(30000 + index)
		if err != nil {
			return PolicyDNSArtifacts{}, err
		}
		tag := fmt.Sprintf("dns-policy-lane-%d", index)
		lane := PolicyDNSLane{
			Final: source.Final,
			Host:  "127.0.0.1",
			ID:    tag,
			Port:  port,
			Rules: make([]PolicyDNSRule, 0),
		}
		for _, raw := range source.Rules {
			if !identityApplies(ruleIdentity(raw), identity) {
				continue
			}
			expanded, err := compiler.expand(raw)
			if err != nil {
				return PolicyDNSArtifacts{}, err
			}
			for _, conditions := range expanded {
				suffixes := normalizedDomains(conditions.DomainSuffix)
				exact := normalizedDomains(conditions.Domain)
				if len(suffixes) == 0 && len(exact) == 0 {
					if len(raw.RuleSet) != 0 {
						continue
					}
					if conditions.Action == "reject" {
						lane.Final = "reject"
					} else if conditions.Action == "route" {
						if _, ok := servers[conditions.Server]; ok {
							lane.Final = conditions.Server
						}
					}
					continue
				}
				action := "route"
				if conditions.Action == "reject" {
					action = "reject"
				}
				server := ""
				if _, ok := servers[conditions.Server]; ok {
					server = conditions.Server
				}
				lane.Rules = append(lane.Rules, PolicyDNSRule{Action: action, Domain: exact, DomainSuffix: suffixes, Server: server})
			}
		}
		artifacts.Runtime.Lanes = append(artifacts.Runtime.Lanes, lane)
		artifacts.XrayOutbounds = append(artifacts.XrayOutbounds, map[string]any{
			"tag": tag, "protocol": "freedom",
			"settings": map[string]any{
				"redirect": fmt.Sprintf("127.0.0.1:%d", port),
				"finalRules": []any{map[string]any{
					"action": "allow", "network": "tcp,udp", "ip": []string{"127.0.0.0/8"}, "port": fmt.Sprint(port),
				}},
			},
		})
		route := map[string]any{"type": "field", "network": "tcp,udp", "port": "53", "outboundTag": tag}
		copyIdentityToXray(identity, route)
		artifacts.XrayRules = append(artifacts.XrayRules, route)
	}

	tags := make([]string, 0, len(servers))
	for tag := range servers {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	tunnelRules := make([]map[string]any, 0, len(tags))
	for index, tag := range tags {
		sourceServer := servers[tag]
		port := sourceServer.ServerPort
		if port == 0 {
			switch sourceServer.Type {
			case "tls":
				port = 853
			case "https":
				port = 443
			default:
				port = 53
			}
		}
		detour := sourceServer.Detour
		if detour == "" {
			detour = "direct-wan"
		}
		path := sourceServer.Path
		if path == "" {
			path = "/dns-query"
		}
		runtimeServer := PolicyDNSServer{
			Detour: detour, DoTFallback: sourceServer.DoTFallback, Path: path,
			Server: sourceServer.Server, ServerName: sourceServer.TLS.ServerName,
			ServerPort: port, Type: sourceServer.Type,
		}
		switch sourceServer.Type {
		case "https", "tls":
			tunnelPort, err := compiler.takePort(32000 + index)
			if err != nil {
				return PolicyDNSArtifacts{}, err
			}
			tunnelTag := fmt.Sprintf("dns-upstream-%d", index)
			runtimeServer.TunnelHost = "127.0.0.1"
			runtimeServer.TunnelPort = tunnelPort
			artifacts.XrayInbounds = append(artifacts.XrayInbounds, map[string]any{
				"tag": tunnelTag, "listen": "127.0.0.1", "port": tunnelPort, "protocol": "tunnel",
				"settings": map[string]any{
					"allowedNetwork": "tcp", "rewriteAddress": sourceServer.Server,
					"rewritePort": port, "followRedirect": false,
				},
			})
			route := map[string]any{"type": "field", "inboundTag": []string{tunnelTag}}
			if _, ok := compiler.options.Selectable[detour]; ok {
				route["balancerTag"] = detour
			} else {
				route["outboundTag"] = detour
			}
			tunnelRules = append(tunnelRules, route)
		case "udp":
		default:
			return PolicyDNSArtifacts{}, fmt.Errorf("policy DNS server %q uses unsupported type %q", tag, sourceServer.Type)
		}
		artifacts.Runtime.Servers[tag] = runtimeServer
	}
	artifacts.XrayRules = append(tunnelRules, artifacts.XrayRules...)
	artifacts.Runtime.TimeoutSeconds = 5
	return artifacts, nil
}

func collectPolicyDNSIdentities(rules []PolicyDNSSourceRule) []policyDNSIdentity {
	seen := make(map[string]struct{})
	result := make([]policyDNSIdentity, 0, len(rules)+1)
	for _, rule := range rules {
		identity := ruleIdentity(rule)
		if identity.empty() {
			continue
		}
		key, _ := json.Marshal(identity)
		if _, ok := seen[string(key)]; ok {
			continue
		}
		seen[string(key)] = struct{}{}
		result = append(result, identity)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].size() != result[j].size() {
			return result[i].size() > result[j].size()
		}
		if result[i].fields() != result[j].fields() {
			return result[i].fields() > result[j].fields()
		}
		left, _ := json.Marshal(result[i])
		right, _ := json.Marshal(result[j])
		return bytes.Compare(left, right) < 0
	})
	return append(result, policyDNSIdentity{})
}

func ruleIdentity(rule PolicyDNSSourceRule) policyDNSIdentity {
	return policyDNSIdentity{
		AuthUser: uniqueSorted(rule.AuthUser), Inbound: uniqueSorted(rule.Inbound), SourceCIDR: uniqueSorted(rule.SourceCIDR),
	}
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func identityApplies(expected, actual policyDNSIdentity) bool {
	if expected.empty() {
		return true
	}
	if actual.empty() {
		return false
	}
	return intersectsIfSet(expected.AuthUser, actual.AuthUser) && intersectsIfSet(expected.Inbound, actual.Inbound) && intersectsIfSet(expected.SourceCIDR, actual.SourceCIDR)
}

func intersectsIfSet(expected, actual []string) bool {
	if len(expected) == 0 {
		return true
	}
	for _, left := range expected {
		for _, right := range actual {
			if left == right {
				return true
			}
		}
	}
	return false
}

func normalizedDomains(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func (compiler *policyDNSCompiler) takePort(start int) (int, error) {
	for port := start; port <= 60999; port++ {
		if _, used := compiler.usedPort[port]; used {
			continue
		}
		compiler.usedPort[port] = struct{}{}
		return port, nil
	}
	return 0, errors.New("policy DNS exhausted local ports")
}

func (compiler *policyDNSCompiler) expand(raw PolicyDNSSourceRule) ([]PolicyDNSSourceRule, error) {
	if len(raw.RuleSet) == 0 {
		return []PolicyDNSSourceRule{raw}, nil
	}
	result := make([]PolicyDNSSourceRule, 0)
	for _, tag := range raw.RuleSet {
		name := strings.TrimPrefix(tag, "service-")
		if descriptor, ok := compiler.options.RuleSets[tag]; ok && descriptor.Path != "" {
			base := filepath.Base(descriptor.Path)
			name = strings.TrimSuffix(base, filepath.Ext(base))
		}
		entries, err := compiler.loadRuleSet(name)
		if err != nil {
			return nil, fmt.Errorf("Xray candidate cannot inline ruleset %q: %w", name, err)
		}
		valid := 0
		for _, entry := range entries {
			if !entry.usable() && len(raw.Domain) == 0 && len(raw.DomainSuffix) == 0 {
				continue
			}
			valid++
			merged := raw
			if len(entry.Domain) != 0 {
				merged.Domain = append([]string(nil), entry.Domain...)
			}
			if len(entry.DomainSuffix) != 0 {
				merged.DomainSuffix = append([]string(nil), entry.DomainSuffix...)
			}
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

func (compiler *policyDNSCompiler) loadRuleSet(name string) ([]policyDNSRuleSetRule, error) {
	if entries, ok := compiler.ruleSets[name]; ok {
		return entries, nil
	}
	if name == "" || filepath.Base(name) != name {
		return nil, errors.New("invalid ruleset name")
	}
	path := filepath.Join(compiler.options.RuleSetRoot, name+".json")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var document policyDNSRuleSetDocument
	decoder := json.NewDecoder(io.LimitReader(file, maxPolicyDNSRulesetBytes+1))
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err == nil && info.Size() > maxPolicyDNSRulesetBytes {
		return nil, errors.New("ruleset exceeds 16 MiB")
	}
	compiler.ruleSets[name] = document.Rules
	return document.Rules, nil
}

func copyIdentityToXray(identity policyDNSIdentity, route map[string]any) {
	if len(identity.Inbound) != 0 {
		route["inboundTag"] = append([]string(nil), identity.Inbound...)
	}
	if len(identity.SourceCIDR) != 0 {
		route["source"] = append([]string(nil), identity.SourceCIDR...)
	}
	if len(identity.AuthUser) != 0 {
		route["user"] = append([]string(nil), identity.AuthUser...)
	}
}

func MarshalPolicyDNS(runtime PolicyDNSRuntime) ([]byte, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(runtime); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}
