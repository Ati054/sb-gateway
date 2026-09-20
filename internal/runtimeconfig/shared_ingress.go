package runtimeconfig

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
)

const RealityCoverPort = 16448

// Shared443 is opt-in. Unrelated ports retain their direct listeners.
func Shared443(config map[string]any) bool {
	return objectValue(config["public_exposure"])["shared_tcp_443"] == true
}

// SubscriptionEndpointEnabled returns true for the established configuration
// contract and only honors an explicit JSON boolean false. Validation reports
// other types; renderers must never treat a string or number as an off switch.
func SubscriptionEndpointEnabled(config map[string]any) bool {
	enabled, exists := objectValue(config["ingress"])["subscription_endpoint_enabled"].(bool)
	return !exists || enabled
}

func RealityBackendPort(kind string) int {
	switch kind {
	case "reality":
		return 16444
	case "reality-grpc":
		return 16445
	case "xhttp-reality":
		return 16446
	}
	return 0
}

type OriginPolicy struct {
	Port                          int
	Host, Profile, Mode, Provider string
	CIDRs                         []string
}

func (p OriginPolicy) Boundary() string {
	switch p.Mode {
	case "auto-cidr":
		return p.Mode + ":" + strings.ToLower(p.Provider)
	case "manual-cidr":
		v := append([]string(nil), p.CIDRs...)
		sort.Strings(v)
		return p.Mode + ":" + strings.Join(v, ",")
	default:
		return "open"
	}
}

func OriginPolicies(config map[string]any) []OriginPolicy {
	var result []OriginPolicy
	for _, t := range enabledObjects(config["transports"]) {
		switch textValue(t["kind"]) {
		case "ws", "grpc", "httpupgrade", "xhttp":
		default:
			continue
		}
		for _, d := range enabledObjects(t["cdn_deployments"]) {
			port, _ := requiredInteger(d["origin_port"])
			provider := strings.ToLower(strings.TrimSpace(textDefault(d["cdn_provider"], textDefault(t["cdn_provider"], "cloudflare"))))
			mode := textValue(d["origin_protection_mode"])
			if mode == "" {
				if provider == "cloudflare" {
					mode = "auto-cidr"
				} else if len(stringSlice(d["origin_allowed_cidrs"])) > 0 {
					mode = "manual-cidr"
				} else {
					mode = "secret-header"
				}
			}
			result = append(result, OriginPolicy{port, strings.ToLower(textValue(d["origin_server_name"])), textValue(d["tls_profile_id"]), mode, provider, stringSlice(d["origin_allowed_cidrs"])})
		}
	}
	i := objectValue(config["ingress"])
	if h := textValue(i["status_hostname"]); h != "" {
		port, _ := integerDefault(i["status_listen_port"], 443)
		mode := "none"
		if boolDefault(i["require_cloudflare_source_ranges"], true) {
			mode = "auto-cidr"
		}
		result = append(result, OriginPolicy{port, strings.ToLower(h), textValue(i["tls_profile_id"]), mode, "cloudflare", nil})
	}
	mode := textDefault(i["subscription_endpoint_mode"], "separate")
	publicHost := textValue(i["subscription_hostname"])
	if SubscriptionEndpointEnabled(config) && publicHost != "" && (mode == "separate" || mode == "direct" || mode == "direct-and-cdn") {
		h := publicHost
		port, _ := integerDefault(i["subscription_listen_port"], 443)
		protection, provider := "none", ""
		if mode == "separate" {
			h = canonicalOriginHostname(textValue(i["subscription_origin_server_name"]))
			protection = textDefault(i["subscription_origin_protection_mode"], "auto-cidr")
			provider = strings.ToLower(strings.TrimSpace(textDefault(i["subscription_cdn_provider"], "cloudflare")))
		}
		result = append(result, OriginPolicy{port, strings.ToLower(h), textDefault(i["subscription_tls_profile_id"], textValue(i["tls_profile_id"])), protection, provider, stringSlice(i["subscription_origin_allowed_cidrs"])})
	}
	return result
}

// Only mixed source boundaries need a second, virtual-host-level IP check.
func SharedOriginPorts(config map[string]any) map[int]bool {
	boundaries := map[int]map[string]bool{}
	for _, p := range OriginPolicies(config) {
		if boundaries[p.Port] == nil {
			boundaries[p.Port] = map[string]bool{}
		}
		boundaries[p.Port][p.Boundary()] = true
	}
	if Shared443(config) {
		for _, t := range enabledObjects(config["transports"]) {
			port, _ := requiredInteger(t["listen_port"])
			if port == 443 && RealityBackendPort(textValue(t["kind"])) != 0 {
				if boundaries[443] == nil {
					boundaries[443] = map[string]bool{}
				}
				boundaries[443]["open"] = true
			}
		}
	}
	result := map[int]bool{}
	for port, b := range boundaries {
		if len(b) > 1 {
			result[port] = true
		}
	}
	return result
}

func ValidateSharedIngress(config map[string]any) error {
	policies := OriginPolicies(config)
	reserved := func(port int) bool {
		return port == 8080 || port == 9080 || port == 9443 || port == 18081 || port == RealityCoverPort || (port >= 11001 && port <= 11004) || (port >= 19080 && port <= 19085)
	}
	for _, p := range policies {
		if reserved(p.Port) {
			return fmt.Errorf("TCP port %d is reserved for an internal gateway service", p.Port)
		}
	}
	for _, t := range enabledObjects(config["transports"]) {
		if RealityBackendPort(textValue(t["kind"])) != 0 {
			port, _ := requiredInteger(t["listen_port"])
			if reserved(port) {
				return fmt.Errorf("TCP port %d is reserved for an internal gateway service", port)
			}
		}
	}
	hosts := map[string]OriginPolicy{}
	for _, p := range policies {
		if p.Mode == "auto-cidr" && !cdnfeed.Supports(p.Provider) {
			return fmt.Errorf("unsupported automatic origin provider %q", p.Provider)
		}
		key := fmt.Sprintf("%d:%s", p.Port, p.Host)
		if old, ok := hosts[key]; ok && (old.Boundary() != p.Boundary() || old.Profile != p.Profile) {
			return fmt.Errorf("origin %s has conflicting protection or TLS profiles; use distinct origin domains", key)
		}
		hosts[key] = p
	}
	if !Shared443(config) {
		return nil
	}
	for _, p := range policies {
		if p.Port >= 16443 && p.Port <= RealityCoverPort {
			return fmt.Errorf("TCP ports 16443–16448 are reserved for internal ingress")
		}
	}
	for _, t := range enabledObjects(config["transports"]) {
		port, _ := requiredInteger(t["listen_port"])
		if textValue(t["kind"]) != "hysteria2" && port >= 16443 && port <= RealityCoverPort {
			return fmt.Errorf("TCP ports 16443–16448 are reserved for internal ingress")
		}
	}
	names := map[string]string{}
	for _, p := range policies {
		if p.Port == 443 {
			names[p.Host] = "HTTPS"
		}
	}
	for _, t := range enabledObjects(config["transports"]) {
		port, _ := requiredInteger(t["listen_port"])
		kind := textValue(t["kind"])
		if port != 443 || RealityBackendPort(kind) == 0 {
			continue
		}
		if textValue(t["wan_destination_address"]) != "" {
			return fmt.Errorf("shared TCP 443 cannot preserve a per-Reality WAN IP binding; use a separate port or remove that binding")
		}
		for _, name := range append([]string{textValue(t["server_name"])}, stringSlice(t["server_names"])...) {
			name = strings.ToLower(strings.TrimSpace(name))
			if !validNginxHostname(name) || strings.Contains(name, "*") {
				return fmt.Errorf("shared TCP 443 requires a concrete SNI for %s", kind)
			}
			if owner, ok := names[name]; ok && owner != kind {
				return fmt.Errorf("shared TCP 443 SNI %q conflicts between %s and %s", name, owner, kind)
			}
			names[name] = kind
		}
	}
	return nil
}

// ValidateDedicatedSubscriptionOrigin is a runtime gate for the explicit
// CDN-origin contract. Drafts may be incomplete until Apply, but a renderer
// must never route a configured separate endpoint through its public edge host.
func ValidateDedicatedSubscriptionOrigin(config map[string]any) error {
	ingress := objectValue(config["ingress"])
	if !SubscriptionEndpointEnabled(config) || textDefault(ingress["subscription_endpoint_mode"], "separate") != "separate" || strings.TrimSpace(textValue(ingress["subscription_hostname"])) == "" {
		return nil
	}
	if !validNginxDNSHostname(canonicalOriginHostname(textValue(ingress["subscription_origin_server_name"]))) {
		return fmt.Errorf("separate subscription endpoint requires a concrete DNS origin hostname")
	}
	return nil
}

func canonicalOriginHostname(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}
