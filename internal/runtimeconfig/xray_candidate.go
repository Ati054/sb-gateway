package runtimeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
)

type XrayCandidateOptions struct {
	RuleSetRoot           string
	XHTTPExtraByTag       map[string]map[string]any
	RealitySettingsByTag  map[string]map[string]any
	VLESSDecryptionByTag  map[string]string
	HysteriaSettingsByTag map[string]map[string]any
}

type XrayCandidateArtifacts struct {
	Config        map[string]any
	PolicyDNS     PolicyDNSRuntime
	PolicyDNSBody []byte
}

// xrayConnectionBufferKiB overrides Xray's unusually small 4 KiB ARM64
// default. 128 KiB materially reduces copy/wakeup pressure on sustained
// transparent traffic while keeping the worst-case memory cost bounded by the
// RouterOS container's 256 MiB hard limit.
const xrayConnectionBufferKiB = 128

func RenderXrayCandidate(config, sourceModel map[string]any, options XrayCandidateOptions) (XrayCandidateArtifacts, error) {
	sourceInbounds := objectSlice(sourceModel["inbounds"])
	sourceOutbounds := objectSlice(sourceModel["outbounds"])
	sourceRoute := objectValue(sourceModel["route"])
	reverseTags := make(map[string]struct{})
	for _, item := range enabledObjects(config["reverse_vless_exits"]) {
		if id := textValue(item["id"]); id != "" {
			reverseTags["reverse-vless-"+id] = struct{}{}
		}
	}

	networking := objectValue(objectValue(config["system"])["networking"])
	containerAddress := strings.TrimSpace(textValue(networking["container_address"]))
	containerPrefix, err := netip.ParsePrefix(containerAddress)
	if err != nil || !containerPrefix.Addr().Is4() {
		return XrayCandidateArtifacts{}, errors.New("Xray candidate requires a valid container IPv4 address")
	}
	privateAllow, err := DirectPrivateAllowCIDRs(sourceRoute["rules"])
	if err != nil {
		return XrayCandidateArtifacts{}, err
	}
	outboundSet, err := ConvertXrayOutbounds(sourceOutbounds, containerPrefix.Addr().String(), privateAllow, reverseTags)
	if err != nil {
		return XrayCandidateArtifacts{}, err
	}
	addURLTestSelectors(config, outboundSet.Balancers)

	inbounds := make([]map[string]any, 0, len(sourceInbounds)+8)
	for _, value := range sourceInbounds {
		tag := textValue(value["tag"])
		inbound, convertErr := ConvertXrayInbound(value, XrayInboundOptions{
			ReverseTags:      reverseTags,
			XHTTPExtra:       options.XHTTPExtraByTag[tag],
			RealitySettings:  options.RealitySettingsByTag[tag],
			VLESSDecryption:  options.VLESSDecryptionByTag[tag],
			HysteriaSettings: options.HysteriaSettingsByTag[tag],
		})
		if convertErr != nil {
			return XrayCandidateArtifacts{}, convertErr
		}
		inbounds = append(inbounds, inbound)
	}
	ruleSets := xrayRuleSetDescriptors(sourceRoute["rule_set"])
	rules, err := ConvertXrayRules(sourceRoute["rules"], outboundSet.Selectable, ruleSets, options.RuleSetRoot)
	if err != nil {
		return XrayCandidateArtifacts{}, err
	}
	existingPorts := make([]int, 0, len(inbounds))
	for _, inbound := range inbounds {
		if port, ok := inbound["port"].(int); ok {
			existingPorts = append(existingPorts, port)
		}
	}
	dnsArtifacts, dnsBody, err := RenderPolicyDNS(config, PolicyDNSCompileOptions{
		ExistingInboundPorts: existingPorts,
		Selectable:           outboundSet.Selectable,
		RuleSets:             ruleSets,
		RuleSetRoot:          options.RuleSetRoot,
	})
	if err != nil {
		return XrayCandidateArtifacts{}, err
	}
	inbounds = append(inbounds, dnsArtifacts.XrayInbounds...)
	outbounds := append(outboundSet.Outbounds, dnsArtifacts.XrayOutbounds...)
	rules = append(dnsArtifacts.XrayRules, rules...)

	internalServer := textValue(objectValue(config["dns"])["internal_server"])
	if address, parseErr := netip.ParseAddr(internalServer); parseErr != nil || !address.IsValid() {
		return XrayCandidateArtifacts{}, errors.New("Xray candidate requires the confirmed RouterOS DNS address")
	}
	apiInbound := map[string]any{
		"tag": "xray-api", "listen": "127.0.0.1", "port": 10085,
		"protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"},
	}
	inbounds = append(inbounds, apiInbound)
	rules = append([]map[string]any{{
		"type": "field", "inboundTag": []string{"xray-api"}, "outboundTag": "xray-api",
	}}, rules...)
	queryStrategy := "UseIPv4"
	if textDefault(networking["remote_ipv6_mode"], "proxy_only") == "proxy_only" {
		queryStrategy = "UseIP"
	}
	xray := map[string]any{
		"log": map[string]any{
			"access": "none", "error": "/logs/xray-error.log",
			"loglevel": xrayLogLevel(config), "dnsLog": false,
		},
		"api": map[string]any{
			"tag": "xray-api", "services": []string{"RoutingService", "StatsService", "HandlerService"},
		},
		"stats": map[string]any{},
		"dns": map[string]any{
			"servers": []string{internalServer}, "queryStrategy": queryStrategy, "disableCache": false,
		},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{
				"statsUserUplink": true, "statsUserDownlink": true, "statsUserOnline": true,
				"bufferSize": xrayConnectionBufferKiB,
			}},
			"system": map[string]any{
				"statsInboundUplink": false, "statsInboundDownlink": false,
				"statsOutboundUplink": false, "statsOutboundDownlink": false,
			},
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch", "domainMatcher": "hybrid",
			"rules": rules, "balancers": outboundSet.Balancers,
		},
	}
	return XrayCandidateArtifacts{Config: xray, PolicyDNS: dnsArtifacts.Runtime, PolicyDNSBody: dnsBody}, nil
}

func xrayLogLevel(config map[string]any) string {
	level := strings.ToLower(strings.TrimSpace(textValue(objectValue(objectValue(config["system"])["logging"])["xray_level"])))
	switch level {
	case "debug", "info", "warning", "error", "none":
		return level
	default:
		return "warning"
	}
}

func MarshalXrayCandidate(config map[string]any) ([]byte, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func addURLTestSelectors(config map[string]any, balancers []map[string]any) {
	byTag := make(map[string]map[string]any, len(balancers))
	for _, balancer := range balancers {
		if tag := textValue(balancer["tag"]); tag != "" {
			byTag[tag] = balancer
		}
	}
	prefixes := make([]string, 0)
	for _, policy := range enabledObjects(config["policies"]) {
		mode := textDefault(policy["mode"], "best")
		if mode != "best" && mode != "priority" {
			continue
		}
		id := textValue(policy["id"])
		balancer := byTag[id]
		if id == "" || balancer == nil {
			continue
		}
		prefix := urlTestPolicyPrefix(id)
		selectors := stringSlice(balancer["selector"])
		if !containsText(selectors, prefix) {
			selectors = append(selectors, prefix)
			balancer["selector"] = selectors
		}
		prefixes = append(prefixes, prefix)
		if mode == "priority" {
			for _, serviceID := range candidateServiceIDs(policy) {
				service := byTag[policyServiceSelectorTag(id, serviceID)]
				if service == nil {
					continue
				}
				selectors := stringSlice(service["selector"])
				if !containsText(selectors, prefix) {
					service["selector"] = append(selectors, prefix)
				}
			}
		}
	}
	if len(prefixes) == 0 {
		return
	}
	for _, lane := range xrayHealthProbeLanes {
		tag := lane.Tag
		if health := byTag[tag]; health != nil {
			selectors := stringSlice(health["selector"])
			if !containsText(selectors, "sb-urltest-") {
				health["selector"] = append(selectors, "sb-urltest-")
			}
		}
	}
}

func urlTestPolicyPrefix(policyID string) string {
	digest := sha256.Sum256([]byte(policyID))
	return "sb-urltest-" + hex.EncodeToString(digest[:])[:12] + "-"
}

// DynamicOutboundTag is shared by the health worker and the subscription
// fetcher so both address the exact HandlerService generation rendered in the
// health-pool contract.
func DynamicOutboundTag(prefix, nodeID string, outbound json.RawMessage) string {
	digest := sha256.Sum256([]byte(nodeID + "\x00" + string(outbound)))
	return prefix + hex.EncodeToString(digest[:])[:12]
}

func xrayRuleSetDescriptors(value any) map[string]PolicyDNSRuleSetDescriptor {
	result := make(map[string]PolicyDNSRuleSetDescriptor)
	for _, descriptor := range objectSlice(value) {
		if tag := textValue(descriptor["tag"]); tag != "" {
			result[tag] = PolicyDNSRuleSetDescriptor{Path: textValue(descriptor["path"])}
		}
	}
	return result
}

func containsText(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
