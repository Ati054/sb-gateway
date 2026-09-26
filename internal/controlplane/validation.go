package controlplane

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
	"github.com/sb-gateway/sb-gateway/internal/releasecontract"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const currentSchemaVersion = releasecontract.ConfigSchemaVersion

var (
	entityIDPattern          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`)
	secretRefPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}$`)
	integerRangePattern      = regexp.MustCompile(`^(0|[1-9][0-9]{0,9})(?:-(0|[1-9][0-9]{0,9}))?$`)
	xrayVersionPattern       = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	routerOSInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:+@ -]{0,62}$`)
	httpHeaderNamePattern    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
)

var cloudflareHTTPSPorts = map[int]bool{443: true, 2053: true, 2083: true, 2087: true, 2096: true, 8443: true}

var supportedCDNProviders = map[string]bool{
	"cloudflare": true, "gcore": true, "edgecenter": true, "cdnetworks": true,
	"timeweb": true, "beeline": true, "vk": true, "yandex": true, "custom": true,
}

var requiredObjectSections = []string{
	"dns", "ingress", "public_exposure", "routeros", "security", "storage", "system", "updates", "watchdog",
}

var requiredArraySections = []string{
	"local_clients", "networks", "policies", "remote_users", "reverse_vless_exits", "service_packs",
	"subscription_reserves", "subscriptions", "tls_profiles", "transports",
}

var entityCollections = []string{
	"tls_profiles", "local_clients", "remote_users", "reverse_vless_exits", "networks", "policies",
	"subscriptions", "subscription_reserves", "transports",
}

var supportedTransportKinds = map[string]bool{
	"ws": true, "grpc": true, "httpupgrade": true, "xhttp": true, "reality": true,
	"reality-grpc": true, "grpc-tls": true, "xhttp-reality": true, "hysteria2": true,
}

var reverseTransportKinds = map[string]bool{
	"reality": true, "reality-grpc": true, "xhttp-reality": true,
}

var tlsTransportKinds = map[string]bool{
	"ws": true, "grpc": true, "httpupgrade": true, "xhttp": true,
}

var certificateTransportKinds = map[string]bool{
	"ws": true, "grpc": true, "grpc-tls": true, "httpupgrade": true, "xhttp": true, "hysteria2": true,
}

type validationIssue struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type configValidation struct {
	Valid    bool
	Errors   []validationIssue
	Warnings []validationIssue
	Revision string
	RouterOS map[string]any
}

func validateCurrentConfig(config map[string]any) configValidation {
	revision, _ := revisionFor(config)
	return validateCurrentConfigRevision(config, revision)
}

func validateCurrentConfigRevision(config map[string]any, revision string) configValidation {
	result := configValidation{
		Errors:   make([]validationIssue, 0),
		Warnings: make([]validationIssue, 0),
		Revision: revision,
	}

	if version, ok := jsonInteger(config["schema_version"]); !ok || version != currentSchemaVersion {
		result.add("schema_version", "schema_version", "Only current schema version 1 is supported.")
	}
	for _, name := range requiredObjectSections {
		if _, ok := config[name].(map[string]any); !ok {
			result.add(name, "type", "Required section must be an object.")
		}
	}
	for _, name := range requiredArraySections {
		if _, ok := config[name].([]any); !ok {
			result.add(name, "type", "Required section must be an array.")
		}
	}

	ids := make(map[string]map[string]struct{}, len(entityCollections))
	entities := make(map[string][]map[string]any, len(entityCollections))
	for _, collection := range entityCollections {
		values, ok := config[collection].([]any)
		if !ok {
			continue
		}
		if len(values) > 2048 {
			result.add(collection, "range", "Collection contains too many objects.")
		}
		seen := make(map[string]struct{}, len(values))
		objects := make([]map[string]any, 0, len(values))
		for index, raw := range values {
			path := fmt.Sprintf("%s[%d]", collection, index)
			entity, ok := raw.(map[string]any)
			if !ok {
				result.add(path, "type", "Collection item must be an object.")
				continue
			}
			objects = append(objects, entity)
			id, ok := entity["id"].(string)
			if !ok || !entityIDPattern.MatchString(id) {
				result.add(path+".id", "identifier", "ID must contain 1 to 64 lowercase letters, digits, dots, underscores, or hyphens.")
				continue
			}
			if _, duplicate := seen[id]; duplicate {
				result.add(path+".id", "duplicate", "ID must be unique within the collection.")
				continue
			}
			seen[id] = struct{}{}
		}
		ids[collection] = seen
		entities[collection] = objects
	}
	if len(entities["subscription_reserves"]) > 3 {
		result.add("subscription_reserves", "range", "At most three independent VLESS reserves may be configured.")
	}

	result.validatePorts(config, entities)
	result.validateTransportSettings(config, entities)
	result.validatePolicySettings(entities)
	result.validateClientSettings(entities)
	result.validateEntitySettings(entities)
	result.validateSubscriptionSettings(entities)
	result.validateCIDRs(config, entities)
	result.validateReferences(config, ids, entities)
	result.validateSystemSettings(config)
	result.validateDNS(config)
	result.validateWireGuard(config)
	result.validatePublicExposure(config, entities)
	result.validateSecretReferences(config, "")
	result.RouterOS = routerCompatibility(config)
	result.Valid = len(result.Errors) == 0
	return result
}

func (result *configValidation) validateSystemSettings(config map[string]any) {
	system, ok := config["system"].(map[string]any)
	if !ok {
		return
	}
	if logging, exists := system["logging"]; exists {
		settings, valid := logging.(map[string]any)
		if !valid {
			result.add("system.logging", "type", "Logging settings must be an object.")
		} else {
			result.optionalEnum(settings, "xray_level", "system.logging", map[string]bool{
				"debug": true, "info": true, "warning": true, "error": true, "none": true,
			})
			result.optionalIntegerRange(settings, "xray_debug_timeout_minutes", "system.logging", 1, 60)
		}
	}
	if monitor, exists := system["routing_monitor"]; exists {
		settings, valid := monitor.(map[string]any)
		if !valid {
			result.add("system.routing_monitor", "type", "Routing monitor settings must be an object.")
		} else {
			for _, field := range []struct {
				name    string
				minimum int
				maximum int
			}{
				{"active_liveness_interval_seconds", 2, 30},
				{"failure_retry_interval_seconds", 1, 10},
				{"block_recovery_interval_seconds", 5, 60},
				{"active_quality_interval_seconds", 10, 3600},
				{"reserve_check_interval_seconds", 10, 86400},
				{"full_scan_interval_seconds", 10, 86400},
				{"probe_batch_size", 0, 10},
			} {
				result.optionalIntegerRange(settings, field.name, "system.routing_monitor", field.minimum, field.maximum)
			}
			if retry, retryOK := jsonInteger(settings["failure_retry_interval_seconds"]); retryOK {
				if liveness, livenessOK := jsonInteger(settings["active_liveness_interval_seconds"]); livenessOK && retry > liveness {
					result.add("system.routing_monitor.failure_retry_interval_seconds", "ordering", "Failure retry cannot be slower than active availability checks.")
				}
			}
			if active, activeOK := jsonInteger(settings["active_quality_interval_seconds"]); activeOK {
				if reserve, reserveOK := jsonInteger(settings["reserve_check_interval_seconds"]); reserveOK && reserve < active {
					result.add("system.routing_monitor.reserve_check_interval_seconds", "ordering", "Reserve checks cannot run more often than active quality checks.")
				}
			}
			if reserve, reserveOK := jsonInteger(settings["reserve_check_interval_seconds"]); reserveOK {
				if full, fullOK := jsonInteger(settings["full_scan_interval_seconds"]); fullOK && full < reserve {
					result.add("system.routing_monitor.full_scan_interval_seconds", "ordering", "Full scans cannot run more often than reserve checks.")
				}
			}
		}
	}
	deploymentReady := system["deployment_ready"] == true
	networking, ok := system["networking"].(map[string]any)
	if !ok {
		result.add("system.networking", "type", "Networking settings must be an object.")
	} else {
		result.optionalIntegerRange(networking, "tun_mtu", "system.networking", 1280, 1500)
		result.optionalEnum(networking, "ipv6_mode", "system.networking", map[string]bool{
			"block_managed": true, "disabled": true,
		})
		result.optionalEnum(networking, "remote_ipv6_mode", "system.networking", map[string]bool{
			"proxy_only": true, "disabled": true,
		})
		result.optionalBoolean(networking, "wireguard_egress_enabled", "system.networking")
	}
	management, ok := system["management"].(map[string]any)
	if !ok {
		result.add("system.management", "type", "Management access settings must be an object.")
	} else {
		result.optionalIntegerRange(management, "routeros_panel_port", "system.management", 1024, 65535)
		if port, ok := jsonInteger(management["routeros_panel_port"]); ok && (port == 9443 || port == 18081) {
			result.add("system.management.routeros_panel_port", "reserved", "This port is reserved for an internal gateway service. Choose another panel port.")
		}
		sources, sourcesOK := management["allowed_source_cidrs"].([]any)
		if !sourcesOK {
			result.add("system.management.allowed_source_cidrs", "type", "Management source CIDRs must be an array.")
		} else if deploymentReady && len(sources) == 0 {
			result.add("system.management.allowed_source_cidrs", "required", "Select at least one management source CIDR.")
		}
		interfaces, ok := management["allowed_ingress_interfaces"].([]any)
		if !ok {
			result.add("system.management.allowed_ingress_interfaces", "type", "Management interfaces must be an array.")
		} else {
			if deploymentReady && len(interfaces) == 0 {
				result.add("system.management.allowed_ingress_interfaces", "required", "Select at least one management ingress interface.")
			}
			seen := make(map[string]struct{}, len(interfaces))
			containerBridge, _ := networking["bridge_name"].(string)
			for index, raw := range interfaces {
				name, ok := raw.(string)
				if !ok || !routerOSInterfacePattern.MatchString(name) {
					result.add(fmt.Sprintf("system.management.allowed_ingress_interfaces[%d]", index), "routeros_interface", "RouterOS interface name is invalid.")
					continue
				}
				if _, duplicate := seen[name]; duplicate {
					result.add("system.management.allowed_ingress_interfaces", "duplicate", "Management interfaces must be unique.")
				}
				if containerBridge != "" && name == containerBridge {
					result.add(fmt.Sprintf("system.management.allowed_ingress_interfaces[%d]", index), "scope", "Container bridge cannot be used as a management ingress interface.")
				}
				seen[name] = struct{}{}
			}
		}
	}

	watchdog, ok := config["watchdog"].(map[string]any)
	if ok {
		for _, field := range []struct {
			name    string
			minimum int
			maximum int
		}{
			{"interval_seconds", 5, 300},
			{"failure_threshold", 1, 20},
			{"recovery_threshold", 1, 20},
			{"recovery_cooldown_seconds", 0, 3600},
			{"max_restarts_per_hour", 1, 60},
		} {
			result.optionalIntegerRange(watchdog, field.name, "watchdog", field.minimum, field.maximum)
		}
	}
	storage, ok := config["storage"].(map[string]any)
	result.optionalIntegerRange(nestedObject(config, "updates"), "retain_previous_images", "updates", 0, 1)
	if ok {
		root, _ := storage["root"].(string)
		if strings.TrimSpace(root) != "" {
			if _, err := validateLifecycleStorageRoot(root); err != nil {
				result.add("storage.root", "path", "Storage root must be a dedicated directory on external storage.")
			}
		}
	}
}

func (result *configValidation) validateTransportSettings(config map[string]any, entities map[string][]map[string]any) {
	deploymentReady := nestedObject(config, "system")["deployment_ready"] == true
	enabledHysteria := 0
	loopbackMasquerades := []string{}
	for index, transport := range entities["transports"] {
		path := fmt.Sprintf("transports[%d]", index)
		kind, _ := transport["kind"].(string)
		if kind == "hysteria2" && transport["enabled"] != false {
			enabledHysteria++
			if mode := text(nestedObject(transport, "xray_hysteria", "masquerade")["type"]); mode == "website" || mode == "api" {
				loopbackMasquerades = append(loopbackMasquerades, path+".xray_hysteria.masquerade.type")
			}
		}

		result.optionalEnum(transport, "hostname_mode", path, map[string]bool{"auto": true, "manual": true})
		if text(transport["hostname_mode"]) == "auto" && !directConnectionTransport(transport) {
			result.add(path+".hostname_mode", "unsupported", "Automatic WAN address is only supported for direct transports.")
		}
		if text(transport["hostname_mode"]) == "manual" && directConnectionTransport(transport) && transport["enabled"] != false && !validReverseExportHostname(text(transport["hostname"])) {
			result.add(path+".hostname", "hostname", "Manual connection address requires a valid hostname or IP address.")
		}
		if kind == "ws" || kind == "httpupgrade" {
			result.optionalIntegerRange(transport, "early_data", path, 0, 8192)
		}
		if kind == "ws" {
			result.optionalIntegerRange(transport, "ws_heartbeat_period", path, 0, 86400)
		}
		if kind == "grpc" || kind == "reality-grpc" || kind == "grpc-tls" {
			result.optionalBoolean(transport, "grpc_multi_mode", path)
			result.optionalBoolean(transport, "grpc_permit_without_stream", path)
			result.optionalIntegerRange(transport, "grpc_idle_timeout", path, 0, 86400)
			result.optionalIntegerRange(transport, "grpc_health_check_timeout", path, 1, 86400)
			result.optionalIntegerRange(transport, "grpc_initial_windows_size", path, 0, 2147483647)
		}
		if kind == "grpc" || kind == "grpc-tls" || kind == "reality" || kind == "reality-grpc" || kind == "xhttp-reality" {
			result.validateTCPStabilitySettings(transport, path)
		}
		if kind == "grpc-tls" && transport["enabled"] != false {
			serverName := strings.TrimSpace(text(transport["tls_server_name"]))
			if net.ParseIP(serverName) != nil || strings.Contains(serverName, "*") || !validReverseExportHostname(serverName) {
				result.add(path+".tls_server_name", "hostname", "Enabled gRPC TLS Pin transport requires a concrete TLS server name.")
			}
		}
		if kind == "xhttp" || kind == "xhttp-reality" {
			result.validateXHTTPTransport(transport, path)
		}
		if kind == "reality" || kind == "reality-grpc" || kind == "xhttp-reality" {
			result.validateRealityTransport(transport, path, deploymentReady)
		}
		if kind == "hysteria2" {
			result.validateHysteriaTransport(transport, path, deploymentReady)
		}
		if transport["enabled"] != false && tlsTransportKinds[kind] {
			result.validateCDNDeployments(transport, path)
		}
	}
	if len(loopbackMasquerades) != 0 && enabledHysteria != 1 {
		for _, path := range loopbackMasquerades {
			result.add(path, "conflict", "Managed API or website masquerade requires exactly one enabled Hysteria 2 transport.")
		}
	}
}

func (result *configValidation) validateCDNDeployments(transport map[string]any, path string) {
	deployments, ok := transport["cdn_deployments"].([]any)
	if !ok {
		return
	}
	kind, _ := transport["kind"].(string)
	for index, raw := range deployments {
		deployment, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		deploymentPath := fmt.Sprintf("%s.cdn_deployments[%d]", path, index)
		result.optionalBoolean(deployment, "enabled", deploymentPath)
		provider, providerOK := deployment["cdn_provider"].(string)
		if !providerOK || !supportedCDNProviders[provider] {
			result.add(deploymentPath+".cdn_provider", "enum", "CDN provider is not supported by the runtime generator.")
		}
		if deployment["enabled"] == false {
			continue
		}
		for _, field := range []string{"hostname", "origin_server_name"} {
			value, _ := deployment[field].(string)
			if !validReverseExportHostname(strings.TrimSpace(value)) || strings.Contains(value, "*") {
				result.add(deploymentPath+"."+field, "hostname", "Enabled CDN deployment requires a concrete valid hostname.")
			}
		}
		if raw, exists := deployment["tls_server_name"]; exists && raw != nil {
			value, ok := raw.(string)
			if !ok || (strings.TrimSpace(value) != "" && !validHostOrIP(value)) {
				result.add(deploymentPath+".tls_server_name", "hostname", "Client TLS SNI must be a valid hostname or IP address.")
			}
		}
		for _, field := range []string{"http_host", "grpc_authority"} {
			if raw, exists := deployment[field]; exists && raw != nil {
				value, ok := raw.(string)
				if !ok || (strings.TrimSpace(value) != "" && !validHTTPAuthority(value)) {
					result.add(deploymentPath+"."+field, "authority", "Client Host or authority must be a hostname with an optional port.")
				}
			}
		}
		publicPort, portOK := jsonInteger(deployment["listen_port"])
		if provider == "cloudflare" && portOK {
			if kind == "grpc" && publicPort != 443 {
				result.add(deploymentPath+".listen_port", "provider", "Cloudflare gRPC requires public TCP port 443.")
			} else if kind != "grpc" && !cloudflareHTTPSPorts[publicPort] {
				result.add(deploymentPath+".listen_port", "provider", "Cloudflare HTTPS proxy does not support this public port.")
			}
		}
		protection, _ := deployment["origin_protection_mode"].(string)
		if protection == "secret-header" {
			header := stringDefault(deployment["origin_header_name"], "X-SB-Origin")
			if !httpHeaderNamePattern.MatchString(header) {
				result.add(deploymentPath+".origin_header_name", "header", "Origin protection header name is invalid.")
			}
			reference, _ := deployment["origin_header_secret_ref"].(string)
			if strings.TrimSpace(reference) == "" {
				result.add(deploymentPath+".origin_header_secret_ref", "required", "Secret-header protection requires a stored secret.")
			}
		}
	}
}

func (result *configValidation) validateXHTTPTransport(transport map[string]any, path string) {
	for _, field := range []string{"vless_encryption_enabled", "x_padding_obfs_mode", "no_grpc_header", "no_sse_header"} {
		result.optionalBoolean(transport, field, path)
	}
	result.optionalEnum(transport, "mode", path, map[string]bool{
		"packet-up": true, "stream-up": true, "stream-one": true, "auto": true,
	})
	result.optionalEnum(transport, "vless_encryption_authentication", path, map[string]bool{"mlkem768": true, "x25519": true})
	result.optionalEnum(transport, "uplink_http_method", path, map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true})
	result.optionalEnum(transport, "uplink_data_placement", path, map[string]bool{"header": true, "cookie": true, "body": true, "auto": true})
	result.optionalEnum(transport, "x_padding_placement", path, map[string]bool{"query": true, "queryInHeader": true, "header": true, "cookie": true})
	result.optionalEnum(transport, "x_padding_method", path, map[string]bool{"tokenish": true, "repeat-x": true})
	result.optionalEnum(transport, "session_id_placement", path, map[string]bool{"path": true, "cookie": true, "header": true, "query": true})
	result.optionalEnum(transport, "seq_placement", path, map[string]bool{"path": true, "cookie": true, "header": true, "query": true})

	for _, field := range []string{
		"x_padding_bytes", "uplink_chunk_size", "sc_max_each_post_bytes", "sc_min_posts_interval_ms",
		"sc_stream_up_server_secs", "xmux_max_connections", "xmux_max_concurrency", "xmux_h_max_request_times",
		"xmux_h_max_reusable_secs", "xmux_c_max_reuse_times", "xmux_h_keep_alive_period",
	} {
		result.optionalIntegerRangeText(transport, field, path)
	}
	for _, field := range []struct {
		name    string
		minimum int
		maximum int
	}{
		{"session_id_length", 1, 1048576},
		{"server_max_header_bytes", 1024, 1048576},
		{"sc_max_buffered_posts", 1, 1048576},
	} {
		result.optionalIntegerRange(transport, field.name, path, field.minimum, field.maximum)
	}
	for _, field := range []string{"x_padding_key", "x_padding_header", "uplink_data_key", "session_id_key", "seq_key"} {
		if value, exists := transport[field]; exists {
			text, ok := value.(string)
			if !ok || strings.TrimSpace(text) == "" || len(text) > 256 {
				result.add(path+"."+field, "string", "Value must contain 1 to 256 characters.")
			}
		}
	}
	if headers, exists := transport["headers"]; exists {
		result.stringMap(headers, path+".headers")
	}
	if settings, exists := transport["download_settings"]; exists && settings != nil {
		if _, ok := settings.(map[string]any); !ok {
			result.add(path+".download_settings", "type", "XHTTP downloadSettings must be a JSON object.")
		}
	}
	maxConnections, hasConnections := integerRangeMinimum(transport["xmux_max_connections"])
	maxConcurrency, hasConcurrency := integerRangeMinimum(transport["xmux_max_concurrency"])
	if hasConnections && hasConcurrency && maxConnections > 0 && maxConcurrency > 0 {
		result.add(path+".xmux_max_concurrency", "conflict", "XMUX maxConnections and maxConcurrency cannot both be positive.")
	}
}

func (result *configValidation) validateRealityTransport(transport map[string]any, path string, deploymentReady bool) {
	for _, field := range []string{"reality_show", "reality_mldsa65_enabled"} {
		result.optionalBoolean(transport, field, path)
	}
	result.optionalEnum(transport, "cover_mode", path, map[string]bool{"external": true, "api": true})
	if deploymentReady && transport["enabled"] != false {
		serverName, _ := transport["server_name"].(string)
		if stringDefault(transport["cover_mode"], "external") == "api" {
			if !validReverseExportHostname(strings.TrimSpace(serverName)) || strings.Contains(serverName, "*") {
				result.add(path+".server_name", "hostname", "REALITY API cover requires a concrete DNS hostname from the selected certificate.")
			}
		} else {
			for _, field := range []string{"server_name", "handshake_server"} {
				value, _ := transport[field].(string)
				if !validHostOrIP(value) {
					result.add(path+"."+field, "hostname", "Enabled REALITY transport requires a valid target hostname or IP address.")
				}
			}
		}
	}
	if serverNames, exists := transport["server_names"]; exists {
		values, ok := serverNames.([]any)
		if !ok {
			result.add(path+".server_names", "type", "Additional REALITY SNI values must be an array.")
		} else {
			for nameIndex, raw := range values {
				name, ok := raw.(string)
				if !ok || !validReverseExportHostname(strings.TrimSpace(name)) || strings.Contains(name, "*") {
					result.add(fmt.Sprintf("%s.server_names[%d]", path, nameIndex), "hostname", "REALITY SNI must be a concrete hostname without wildcards.")
				}
			}
		}
	}
	result.optionalIntegerRange(transport, "max_time_diff", path, 0, 86400000)
	result.optionalIntegerRange(transport, "xver", path, 0, 2)
	for _, field := range []string{"min_client_ver", "max_client_ver"} {
		if value, exists := transport[field]; exists && strings.TrimSpace(fmt.Sprint(value)) != "" {
			text, ok := value.(string)
			if !ok || !xrayVersionPattern.MatchString(strings.TrimSpace(text)) {
				result.add(path+"."+field, "version", "Xray version must use x.y.z format.")
			}
		}
	}
	for _, direction := range []string{"upload", "download"} {
		for _, field := range []string{"after_bytes", "bytes_per_sec", "burst_bytes_per_sec"} {
			result.optionalIntegerRange(transport, "reality_fallback_"+direction+"_"+field, path, 0, 2147483647)
		}
	}
}

func (result *configValidation) validateTCPStabilitySettings(transport map[string]any, path string) {
	result.optionalBoolean(transport, "tcp_keep_alive_enabled", path)
	result.optionalIntegerRange(transport, "tcp_keep_alive_idle", path, 1, 86400)
	result.optionalIntegerRange(transport, "tcp_keep_alive_interval", path, 1, 86400)
	result.optionalIntegerRange(transport, "tcp_user_timeout", path, 0, 2147483647)
}

func (result *configValidation) validateHysteriaTransport(transport map[string]any, path string, deploymentReady bool) {
	result.optionalBoolean(transport, "obfs_enabled", path)
	result.optionalBoolean(transport, "tls_pin_certificate", path)
	if deploymentReady && transport["enabled"] != false {
		serverName, _ := transport["tls_server_name"].(string)
		if !validReverseExportHostname(strings.TrimSpace(serverName)) {
			result.add(path+".tls_server_name", "hostname", "Enabled Hysteria 2 transport requires a valid TLS server name.")
		}
	}
	settings, ok := transport["xray_hysteria"].(map[string]any)
	if !ok {
		result.add(path+".xray_hysteria", "type", "Hysteria 2 settings must be an object.")
		return
	}
	result.optionalIntegerRange(settings, "udp_idle_timeout", path+".xray_hysteria", 2, 600)
	if rawHop, exists := settings["udp_hop"]; exists {
		hop, ok := rawHop.(map[string]any)
		if !ok {
			result.add(path+".xray_hysteria.udp_hop", "type", "UDP port hopping settings must be an object.")
		} else {
			hopPath := path + ".xray_hysteria.udp_hop"
			result.optionalBoolean(hop, "enabled", hopPath)
			if excluded, exists := hop["excluded_ports"]; exists {
				if _, ok := excluded.(string); !ok {
					result.add(hopPath+".excluded_ports", "type", "Excluded UDP ports must be a comma-separated string.")
				}
			}
			if hop["enabled"] == true {
				for _, field := range []string{"port_start", "port_end"} {
					if _, exists := hop[field]; !exists {
						result.add(hopPath+"."+field, "required", "UDP hopping port range is required.")
					} else {
						result.optionalIntegerRange(hop, field, hopPath, 1024, 65535)
					}
				}
				for _, field := range []string{"interval_min", "interval_max"} {
					if _, exists := hop[field]; !exists {
						result.add(hopPath+"."+field, "required", "UDP hopping interval is required.")
					} else {
						result.optionalIntegerRange(hop, field, hopPath, 5, 3600)
					}
				}
				start, startOK := jsonInteger(hop["port_start"])
				end, endOK := jsonInteger(hop["port_end"])
				if startOK && endOK && (end < start || end-start > 1000) {
					result.add(hopPath+".port_end", "range", "UDP hopping range must be ordered and contain at most 1001 ports.")
				}
				minimum, minimumOK := jsonInteger(hop["interval_min"])
				maximum, maximumOK := jsonInteger(hop["interval_max"])
				if minimumOK && maximumOK && maximum < minimum {
					result.add(hopPath+".interval_max", "range", "Maximum UDP hopping interval must not be lower than the minimum.")
				}
				if _, err := runtimeconfig.ParseHysteriaUDPHop(transport); err != nil {
					result.add(hopPath, "invalid", err.Error())
				}
			}
		}
	}
	quic, ok := settings["quic_params"].(map[string]any)
	if !ok {
		result.add(path+".xray_hysteria.quic_params", "type", "Hysteria QUIC parameters must be an object.")
	} else {
		result.optionalBoolean(quic, "disable_path_mtu_discovery", path+".xray_hysteria.quic_params")
		result.optionalBoolean(quic, "disable_gso", path+".xray_hysteria.quic_params")
		result.optionalBoolean(quic, "disable_stateless_reset", path+".xray_hysteria.quic_params")
		result.optionalEnum(quic, "congestion", path+".xray_hysteria.quic_params", map[string]bool{"bbr": true, "brutal": true})
		if quic["congestion"] == "brutal" {
			result.optionalBoolean(quic, "brutal_disable_loss_compensation", path+".xray_hysteria.quic_params")
			result.optionalIntegerRange(quic, "brutal_up_mbps", path+".xray_hysteria.quic_params", 1, 100000)
			result.optionalIntegerRange(quic, "brutal_down_mbps", path+".xray_hysteria.quic_params", 1, 100000)
		} else if _, exists := quic["brutal_disable_loss_compensation"]; exists {
			result.add(path+".xray_hysteria.quic_params.brutal_disable_loss_compensation", "conflict", "Brutal loss compensation requires Brutal congestion.")
		}
		for _, field := range []string{"init_stream_receive_window", "max_stream_receive_window", "init_connection_receive_window", "max_connection_receive_window"} {
			result.optionalIntegerRange64(quic, field, path+".xray_hysteria.quic_params", 0, 4294967295)
		}
		result.optionalIntegerZeroOrRange(quic, "max_idle_timeout", path+".xray_hysteria.quic_params", 4, 120)
		result.optionalIntegerZeroOrRange(quic, "keep_alive_period", path+".xray_hysteria.quic_params", 2, 60)
		result.optionalIntegerZeroOrRange(quic, "max_incoming_streams", path+".xray_hysteria.quic_params", 8, 1000000)
	}
	masquerade, ok := settings["masquerade"].(map[string]any)
	if !ok {
		result.add(path+".xray_hysteria.masquerade", "type", "Hysteria masquerade must be an object.")
		return
	}
	result.optionalEnum(masquerade, "type", path+".xray_hysteria.masquerade", map[string]bool{"api": true, "string": true, "proxy": true, "website": true})
	if masquerade["type"] != "proxy" {
		if _, exists := masquerade["x_forwarded"]; exists {
			result.add(path+".xray_hysteria.masquerade.x_forwarded", "conflict", "X-Forwarded is available only for a local masquerade proxy.")
		}
	}
	switch masquerade["type"] {
	case "string":
		result.optionalIntegerRange(masquerade, "status_code", path+".xray_hysteria.masquerade", 100, 599)
		if headers, exists := masquerade["headers"]; exists {
			result.stringMap(headers, path+".xray_hysteria.masquerade.headers")
		}
		if content, ok := masquerade["content"].(string); !ok || len(content) > 8192 {
			result.add(path+".xray_hysteria.masquerade.content", "string", "Masquerade body must be a string up to 8192 bytes.")
		}
	case "proxy":
		result.optionalBoolean(masquerade, "rewrite_host", path+".xray_hysteria.masquerade")
		result.optionalBoolean(masquerade, "x_forwarded", path+".xray_hysteria.masquerade")
		raw, _ := masquerade["url"].(string)
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Hostname() == "" || !isLoopbackHost(parsed.Hostname()) {
			result.add(path+".xray_hysteria.masquerade.url", "url", "Masquerade proxy must use an HTTP loopback URL.")
		} else if parsed.Port() == "18081" {
			result.add(path+".xray_hysteria.masquerade.url", "reserved", "18081 is reserved for the internal website masquerade helper.")
		}
	case "website":
		raw, _ := masquerade["url"].(string)
		if !validWebsiteMasqueradeURL(raw) {
			result.add(path+".xray_hysteria.masquerade.url", "url", "Website masquerade must use a public HTTPS hostname on port 443 without credentials, query, or fragment.")
		}
		if _, valid := websiteBandwidthMbps(masquerade["bandwidth_mbps"]); !valid {
			result.add(path+".xray_hysteria.masquerade.bandwidth_mbps", "range", "Website masquerade bandwidth must be a finite number from 0.1 to 100 Mbps.")
		}
	}
}

func (result *configValidation) validatePolicySettings(entities map[string][]map[string]any) {
	for index, policy := range entities["policies"] {
		path := fmt.Sprintf("policies[%d]", index)
		result.optionalBoolean(policy, "enabled", path)
		result.optionalBoolean(policy, "torrent_direct", path)
		result.optionalBoolean(policy, "pinpoint_domains_enabled", path)
		result.optionalBoolean(policy, "speed_check_enabled", path)
		result.optionalBoolean(policy, "return_to_primary", path)
		result.optionalBoolean(policy, "interrupt_exist_connections", path)
		result.optionalEnum(policy, "mode", path, map[string]bool{"best": true, "priority": true})
		result.optionalEnum(policy, "traffic_mode", path, map[string]bool{
			"vless_with_wan_exceptions": true, "wan_with_vless_exceptions": true,
		})
		result.optionalEnum(policy, "domain_strategy", path, map[string]bool{
			"AsIs": true, "IPIfNonMatch": true, "IPOnDemand": true,
		})
		result.optionalEnum(policy, "on_all_unavailable", path, map[string]bool{"block": true})
		for _, field := range []struct {
			name    string
			minimum int
			maximum int
		}{
			{"quality_window", 3, 60},
			{"max_packet_loss_percent", 0, 100},
			{"max_latency_ms", 0, 30000},
			{"failure_threshold", 1, 20},
			{"recovery_threshold", 1, 20},
			{"switch_cooldown_seconds", 0, 86400},
			{"switch_improvement_ms", 0, 30000},
			{"speed_improvement_percent", 0, 100},
			{"speed_check_interval_seconds", 300, 86400},
			{"speed_probe_bytes", 256 * 1024, 10 * 1024 * 1024},
			{"speed_candidate_count", 1, 5},
			{"active_check_interval_seconds", 1, 3600},
			{"backup_check_interval_seconds", 1, 86400},
			{"full_scan_interval_seconds", 1, 86400},
			{"max_active_candidates", 1, 10},
			{"max_probe_candidates", 1, 10},
			{"probe_batch_size", 1, 10},
		} {
			result.optionalIntegerRange(policy, field.name, path, field.minimum, field.maximum)
		}
		if active, activeOK := jsonInteger(policy["active_check_interval_seconds"]); activeOK {
			if backup, backupOK := jsonInteger(policy["backup_check_interval_seconds"]); backupOK && backup < active {
				result.add(path+".backup_check_interval_seconds", "ordering", "Backup checks cannot run more often than active-node checks.")
			}
		}
		if backup, backupOK := jsonInteger(policy["backup_check_interval_seconds"]); backupOK {
			if full, fullOK := jsonInteger(policy["full_scan_interval_seconds"]); fullOK && full < backup {
				result.add(path+".full_scan_interval_seconds", "ordering", "Full scans cannot run more often than backup checks.")
			}
		}
		for _, field := range []string{"countries", "locations", "selection_order", "outbounds", "direct_domains", "direct_services", "candidate_service_ids", "hidden_service_packs"} {
			if value, exists := policy[field]; exists {
				result.optionalStringArray(value, path+"."+field, 2048)
			}
		}
		if routes, exists := policy["service_routes"]; exists {
			result.stringStringMap(routes, path+".service_routes", 2048)
		}
		if access, exists := policy["candidate_service_access"]; exists {
			entries, ok := access.(map[string]any)
			if !ok {
				result.add(path+".candidate_service_access", "type", "Candidate service access must be an object of string arrays.")
			} else {
				for selector, raw := range entries {
					if strings.TrimSpace(selector) == "" {
						result.add(path+".candidate_service_access", "identifier", "Candidate selector cannot be empty.")
						continue
					}
					result.optionalStringArray(raw, path+".candidate_service_access."+selector, 256)
				}
			}
		}
	}
}

func (result *configValidation) validateClientSettings(entities map[string][]map[string]any) {
	allLANClients := 0
	for index, client := range entities["local_clients"] {
		path := fmt.Sprintf("local_clients[%d]", index)
		result.optionalBoolean(client, "enabled", path)
		result.optionalEnum(client, "source_kind", path, map[string]bool{
			"lan": true, "wireguard": true, "ppp-vpn": true,
		})
		result.optionalEnum(client, "source_scope", path, map[string]bool{
			"lan-all": true,
		})
		if client["source_scope"] == "lan-all" {
			allLANClients++
			if client["source_kind"] != "lan" {
				result.add(path+".source_scope", "scope", "All LAN/Wi-Fi devices can be selected only for a LAN source.")
			}
		}
		result.optionalEnum(client, "container_outage", path, map[string]bool{
			"direct": true, "lan_only": true,
		})
		if refs, exists := client["source_peer_refs"]; exists {
			result.optionalStringArray(refs, path+".source_peer_refs", 2048)
			if client["source_kind"] != "wireguard" {
				if values, ok := refs.([]any); ok && len(values) != 0 {
					result.add(path+".source_peer_refs", "scope", "WireGuard peer references are valid only for a WireGuard source.")
				}
			}
		}
		if client["enabled"] != false {
			policyID, _ := client["policy_id"].(string)
			if strings.TrimSpace(policyID) == "" {
				result.add(path+".policy_id", "required", "Enabled local client requires a routing policy.")
			}
		}
	}
	if allLANClients > 1 {
		result.add("local_clients", "duplicate", "Only one all-LAN/Wi-Fi routing entry is allowed.")
	}

	for index, user := range entities["remote_users"] {
		path := fmt.Sprintf("remote_users[%d]", index)
		for _, field := range []string{
			"enabled", "client_individual_routing", "client_auto_fallback", "client_adblock",
			"happ_include_all_networks", "happ_exclude_local_networks", "happ_exclude_apns",
		} {
			result.optionalBoolean(user, field, path)
		}
		result.optionalEnum(user, "role", path, map[string]bool{
			"trusted-full": true, "trusted-limited": true, "internet-only": true, "disabled": true,
		})
		result.optionalEnum(user, "subscription_format", path, map[string]bool{
			"auto": true, "links": true, "array": true, "xray": true, "singbox": true, "mihomo": true,
		})
		result.optionalEnum(user, "client_tun_stack", path, map[string]bool{
			"auto": true, "system": true, "mixed": true, "gvisor": true,
		})
		result.optionalEnum(user, "client_fingerprint", path, map[string]bool{
			"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true,
			"edge": true, "360": true, "qq": true, "random": true,
		})
		if user["enabled"] != false {
			policyID, _ := user["policy_id"].(string)
			if strings.TrimSpace(policyID) == "" {
				result.add(path+".policy_id", "required", "Enabled remote user requires a routing policy.")
			}
			tunAddress, _ := user["client_tun_address"].(string)
			if strings.TrimSpace(tunAddress) == "" {
				result.add(path+".client_tun_address", "required", "Enabled remote user requires a client TUN address.")
			}
		}
		if user["role"] == "disabled" && user["enabled"] != false {
			result.add(path+".enabled", "conflict", "Disabled remote role cannot be enabled.")
		}
		if user["role"] == "trusted-limited" {
			cidrs, _ := user["allowed_cidrs"].([]any)
			networks, _ := user["allowed_network_ids"].([]any)
			if len(cidrs) == 0 && len(networks) == 0 {
				result.add(path+".allowed_cidrs", "required", "Limited LAN access requires at least one destination network.")
			}
		}
	}
}

func (result *configValidation) validateEntitySettings(entities map[string][]map[string]any) {
	for index, network := range entities["networks"] {
		path := fmt.Sprintf("networks[%d]", index)
		result.optionalBoolean(network, "enabled", path)
		result.optionalEnum(network, "kind", path, map[string]bool{"internal": true, "management": true})
	}
	for index, profile := range entities["tls_profiles"] {
		path := fmt.Sprintf("tls_profiles[%d]", index)
		result.optionalBoolean(profile, "enabled", path)
		result.optionalEnum(profile, "certificate_source", path, map[string]bool{"manual": true, "acme": true, "local-ca": true})
		if text(profile["certificate_source"]) == "local-ca" {
			name := strings.TrimSpace(text(profile["local_ca_server_name"]))
			if net.ParseIP(name) != nil || strings.Contains(name, "*") || !strings.Contains(name, ".") || !validReverseExportHostname(name) {
				result.add(path+".local_ca_server_name", "hostname", "Local CA requires a concrete DNS SNI.")
			}
			for _, field := range []string{"local_ca_certificate_secret_ref", "local_ca_private_key_secret_ref"} {
				if text(profile[field]) == "" {
					result.add(path+"."+field, "required", "Local CA key material is required.")
				}
			}
		}
	}
	for index, transport := range entities["transports"] {
		result.optionalBoolean(transport, "enabled", fmt.Sprintf("transports[%d]", index))
	}
	for index, reverse := range entities["reverse_vless_exits"] {
		result.optionalBoolean(reverse, "enabled", fmt.Sprintf("reverse_vless_exits[%d]", index))
	}
}

func (result *configValidation) validateSubscriptionSettings(entities map[string][]map[string]any) {
	enabledReserves := 0
	for index, reserve := range entities["subscription_reserves"] {
		path := fmt.Sprintf("subscription_reserves[%d]", index)
		result.optionalBoolean(reserve, "enabled", path)
		if reserve["enabled"] != false {
			enabledReserves++
			if node, ok := reserve["node"].(map[string]any); !ok || len(node) == 0 {
				result.add(path+".node", "required", "Enabled VLESS reserve requires a normalized connection node.")
			}
		}
	}

	for index, subscription := range entities["subscriptions"] {
		path := fmt.Sprintf("subscriptions[%d]", index)
		for _, field := range []string{
			"enabled", "refresh_via_direct", "refresh_via_vpn",
			"refresh_via_active_outbounds", "refresh_via_independent_reserves",
		} {
			result.optionalBoolean(subscription, field, path)
		}
		result.optionalIntegerRange(subscription, "refresh_minutes", path, 1, 7*24*60)
		for _, field := range []string{"allowed_countries", "allowed_locations"} {
			if value, exists := subscription[field]; exists {
				result.optionalStringArray(value, path+"."+field, 2048)
			}
		}
		if overrides, exists := subscription["location_overrides"]; exists {
			result.validateLocationOverrides(overrides, path+".location_overrides")
		}
		if subscription["enabled"] == false {
			continue
		}
		direct := subscription["refresh_via_direct"] != false
		vpn := subscription["refresh_via_vpn"] != false
		active := subscription["refresh_via_active_outbounds"] != false
		reserves := subscription["refresh_via_independent_reserves"] == true
		if !direct && (!vpn || (!active && !reserves)) {
			result.add(path+".refresh_via_direct", "route", "Enabled subscription requires at least one usable refresh path.")
		}
		if !direct && vpn && !active && reserves && enabledReserves == 0 {
			result.add(path+".refresh_via_independent_reserves", "reference", "Independent-reserve refresh requires at least one enabled VLESS reserve.")
		}
	}
}

func (result *configValidation) validateLocationOverrides(value any, path string) {
	overrides, ok := value.(map[string]any)
	if !ok {
		result.add(path, "type", "Location overrides must be an object.")
		return
	}
	if len(overrides) > 4096 {
		result.add(path, "range", "At most 4096 location overrides may be configured.")
	}
	for key, raw := range overrides {
		entry, ok := raw.(map[string]any)
		city, cityOK := entry["city"].(string)
		if strings.TrimSpace(key) == "" || !ok || !cityOK || strings.TrimSpace(city) == "" || len(city) > 128 {
			result.add(path+"."+key, "string", "Each location override must contain a non-empty city up to 128 characters.")
		}
	}
}

func (result *configValidation) validateDNS(config map[string]any) {
	dns, ok := config["dns"].(map[string]any)
	if !ok {
		return
	}
	providers := map[string]bool{"cloudflare": true, "google": true, "quad9": true, "yandex": true}
	for _, field := range []string{"force_tcp_for_proxy_services", "hijack_managed_clients", "strict_dns"} {
		result.optionalBoolean(dns, field, "dns")
	}
	for _, profile := range []struct {
		name      string
		protocols map[string]bool
		message   string
	}{
		{"direct_resolver", map[string]bool{"doh": true}, "WAN DNS supports DoH because RouterOS has no native DoT client."},
		{"vpn_resolver", map[string]bool{"doh": true, "dot": true}, "VPN DNS protocol must be DoH or DoT."},
	} {
		path := "dns." + profile.name
		resolver, exists := dns[profile.name].(map[string]any)
		if !exists {
			result.add(path, "type", "DNS resolver profile must be an object.")
			continue
		}
		provider, _ := resolver["provider"].(string)
		if !providers[provider] {
			result.add(path+".provider", "enum", "DNS provider is unsupported.")
		}
		protocol, _ := resolver["protocol"].(string)
		if !profile.protocols[protocol] {
			result.add(path+".protocol", "enum", profile.message)
		}
	}

	deploymentReady := nestedObject(config, "system")["deployment_ready"] == true
	internalServer, _ := dns["internal_server"].(string)
	internalServer = strings.TrimSpace(internalServer)
	if internalServer != "" || deploymentReady {
		if address, err := netip.ParseAddr(internalServer); err != nil || !address.IsValid() {
			result.add("dns.internal_server", "address", "Internal DNS server must be an IP address.")
		}
	}
	zones, ok := dns["internal_zones"].([]any)
	if !ok {
		result.add("dns.internal_zones", "type", "Internal DNS zones must be an array.")
		return
	}
	if len(zones) > 128 {
		result.add("dns.internal_zones", "range", "At most 128 internal DNS zones may be configured.")
	}
	for index, raw := range zones {
		zone, ok := raw.(string)
		zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
		if !ok || net.ParseIP(zone) != nil || !validReverseExportHostname(zone) {
			result.add(fmt.Sprintf("dns.internal_zones[%d]", index), "hostname", "Internal DNS zone must be a valid domain suffix.")
		}
	}
}

// validationFor retains only the current draft result. It prevents repeated
// semantic walks for UI reads without keeping historical configuration variants.
func (server *Server) validationFor(config map[string]any, revision string) configValidation {
	server.validationMu.Lock()
	defer server.validationMu.Unlock()
	if server.validationRevision == revision {
		return server.validationResult
	}
	result := validateCurrentConfigRevision(config, revision)
	server.validationRevision = revision
	server.validationResult = result
	return result
}

func (server *Server) rememberValidation(result configValidation) {
	server.validationMu.Lock()
	server.validationRevision = result.Revision
	server.validationResult = result
	server.validationMu.Unlock()
}

func (result *configValidation) validatePorts(config map[string]any, entities map[string][]map[string]any) {
	ingress, _ := config["ingress"].(map[string]any)
	deploymentReady := nestedObject(config, "system")["deployment_ready"] == true
	for _, field := range []string{"public_listen_port", "status_listen_port", "subscription_listen_port"} {
		result.port(ingress[field], "ingress."+field)
		if port, ok := jsonInteger(ingress[field]); ok && port == 18081 {
			result.add("ingress."+field, "reserved", "18081 is reserved for the internal website masquerade helper.")
		}
	}
	result.optionalIntegerRange(ingress, "subscription_public_port", "ingress", 1, 65535)
	for index, transport := range entities["transports"] {
		path := fmt.Sprintf("transports[%d]", index)
		kind, ok := transport["kind"].(string)
		if !ok || !supportedTransportKinds[kind] {
			result.add(path+".kind", "enum", "Unsupported transport kind.")
		}
		result.port(transport["listen_port"], path+".listen_port")
		if port, ok := jsonInteger(transport["listen_port"]); ok && port == 18081 && kind != "hysteria2" {
			result.add(path+".listen_port", "reserved", "18081 is reserved for the internal website masquerade helper.")
		}
		if value, exists := transport["handshake_port"]; exists {
			result.port(value, path+".handshake_port")
		}
		if tlsTransportKinds[kind] {
			if transport["enabled"] == false {
				continue
			}
			deployments, ok := transport["cdn_deployments"].([]any)
			if !ok {
				if deploymentReady && transport["enabled"] != false {
					result.add(path+".cdn_deployments", "required", "Enabled CDN transport requires at least one explicit deployment.")
				}
				continue
			}
			if deploymentReady && transport["enabled"] != false && len(deployments) == 0 {
				result.add(path+".cdn_deployments", "required", "Enabled CDN transport requires at least one explicit deployment.")
			}
			if len(deployments) > 16 {
				result.add(path+".cdn_deployments", "range", "At most 16 CDN deployments may be configured per transport.")
			}
			seen := make(map[string]struct{}, len(deployments))
			for deploymentIndex, raw := range deployments {
				deploymentPath := fmt.Sprintf("%s.cdn_deployments[%d]", path, deploymentIndex)
				deployment, ok := raw.(map[string]any)
				if !ok {
					result.add(deploymentPath, "type", "CDN deployment must be an object.")
					continue
				}
				id, _ := deployment["id"].(string)
				if !entityIDPattern.MatchString(id) {
					result.add(deploymentPath+".id", "identifier", "CDN deployment ID is invalid.")
				} else if _, exists := seen[id]; exists {
					result.add(deploymentPath+".id", "duplicate", "CDN deployment IDs must be unique within a transport.")
				} else {
					seen[id] = struct{}{}
				}
				result.port(deployment["listen_port"], deploymentPath+".listen_port")
				result.port(deployment["origin_port"], deploymentPath+".origin_port")
			}
		}
	}
	for index, user := range entities["remote_users"] {
		if raw, exists := user["allowed_ports"]; exists {
			values, ok := raw.([]any)
			if !ok {
				result.add(fmt.Sprintf("remote_users[%d].allowed_ports", index), "type", "Allowed ports must be an array.")
				continue
			}
			for portIndex, value := range values {
				result.port(value, fmt.Sprintf("remote_users[%d].allowed_ports[%d]", index, portIndex))
			}
		}
	}
}

func (result *configValidation) validateCIDRs(config map[string]any, entities map[string][]map[string]any) {
	for index, network := range entities["networks"] {
		result.cidrArray(network["cidrs"], fmt.Sprintf("networks[%d].cidrs", index), true)
	}
	for index, client := range entities["local_clients"] {
		result.cidrArray(client["source_cidrs"], fmt.Sprintf("local_clients[%d].source_cidrs", index), true)
	}
	for index, user := range entities["remote_users"] {
		if raw, exists := user["allowed_cidrs"]; exists {
			result.cidrArray(raw, fmt.Sprintf("remote_users[%d].allowed_cidrs", index), false)
		}
		if address, exists := user["client_tun_address"]; exists && address != "" && address != nil {
			if text, ok := address.(string); !ok {
				result.add(fmt.Sprintf("remote_users[%d].client_tun_address", index), "cidr", "Client TUN address must be an IPv4 interface.")
			} else if prefix, err := netip.ParsePrefix(text); err != nil || !prefix.Addr().Is4() || prefix.Bits() > 30 {
				result.add(fmt.Sprintf("remote_users[%d].client_tun_address", index), "cidr", "Client TUN address must be a usable IPv4 interface with prefix /30 or broader.")
			}
		}
	}
	for transportIndex, transport := range entities["transports"] {
		if transport["enabled"] == false {
			continue
		}
		if destination, exists := transport["wan_destination_address"]; exists && strings.TrimSpace(fmt.Sprint(destination)) != "" {
			address, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprint(destination)))
			if err != nil || !address.Is4() {
				result.add(fmt.Sprintf("transports[%d].wan_destination_address", transportIndex), "address", "WAN destination must be one exact IPv4 address.")
			}
		}
		deployments, _ := transport["cdn_deployments"].([]any)
		for deploymentIndex, raw := range deployments {
			deployment, _ := raw.(map[string]any)
			if deployment == nil || deployment["enabled"] == false {
				continue
			}
			path := fmt.Sprintf("transports[%d].cdn_deployments[%d].origin_allowed_cidrs", transportIndex, deploymentIndex)
			mode, _ := deployment["origin_protection_mode"].(string)
			if mode == "manual-cidr" {
				result.ipv4CIDRArray(deployment["origin_allowed_cidrs"], path, true)
			} else if _, exists := deployment["origin_allowed_cidrs"]; exists {
				result.ipv4CIDRArray(deployment["origin_allowed_cidrs"], path, false)
			}
		}
	}
	management := nestedObject(config, "system", "management")
	if raw, exists := management["allowed_source_cidrs"]; exists {
		result.ipv4CIDRArray(raw, "system.management.allowed_source_cidrs", false)
		if values, ok := raw.([]any); ok {
			for index, value := range values {
				text, _ := value.(string)
				prefix, err := netip.ParsePrefix(text)
				if err == nil && prefix.Bits() == 0 {
					result.add(fmt.Sprintf("system.management.allowed_source_cidrs[%d]", index), "scope", "Global 0.0.0.0/0 management access is forbidden.")
				}
			}
		}
	}
}

func (result *configValidation) validateReferences(config map[string]any, ids map[string]map[string]struct{}, entities map[string][]map[string]any) {
	deploymentReady := nestedObject(config, "system")["deployment_ready"] == true
	tlsIDs := ids["tls_profiles"]
	transportIDs := ids["transports"]
	policyIDs := ids["policies"]
	networkIDs := ids["networks"]
	activeTLSIDs := make(map[string]struct{})
	tlsProfilesByID := make(map[string]map[string]any)
	for index, profile := range entities["tls_profiles"] {
		path := fmt.Sprintf("tls_profiles[%d]", index)
		if id, ok := profile["id"].(string); ok && id != "" {
			tlsProfilesByID[id] = profile
		}
		certificate, _ := profile["certificate_secret_ref"].(string)
		privateKey, _ := profile["private_key_secret_ref"].(string)
		if (certificate == "") != (privateKey == "") {
			result.add(path, "incomplete_tls_pair", "TLS certificate and private key references must be provided together.")
		}
		if profile["enabled"] != false && certificate != "" && privateKey != "" {
			if id, ok := profile["id"].(string); ok {
				activeTLSIDs[id] = struct{}{}
			}
		} else if deploymentReady && profile["enabled"] != false {
			result.add(path, "required", "Enabled TLS profile requires certificate and private key secrets before Apply.")
		}
	}
	requireTLSProfile := func(value any, path string) {
		result.reference(value, tlsIDs, path, "TLS profile does not exist.")
		if !deploymentReady {
			return
		}
		id, ok := value.(string)
		if !ok {
			return
		}
		if _, exists := tlsIDs[id]; !exists {
			return
		}
		if _, active := activeTLSIDs[id]; !active {
			result.add(path, "inactive_tls_profile", "TLS profile must be enabled and contain a certificate/private-key pair before Apply.")
		}
	}
	enabledTransports := make(map[string]string)
	for index, transport := range entities["transports"] {
		id, _ := transport["id"].(string)
		kind, _ := transport["kind"].(string)
		if transport["enabled"] != false && supportedTransportKinds[kind] {
			enabledTransports[id] = kind
		}
		if certificateTransportKinds[kind] && transport["enabled"] != false {
			requireTLSProfile(transport["tls_profile_id"], fmt.Sprintf("transports[%d].tls_profile_id", index))
		}
		if kind == "grpc-tls" && transport["enabled"] != false {
			profile := tlsProfilesByID[text(transport["tls_profile_id"])]
			if profile != nil && !tlsProfileMetadataCoversHostname(profile, text(transport["tls_server_name"])) {
				result.add(fmt.Sprintf("transports[%d].tls_server_name", index), "tls_hostname", "gRPC TLS SNI must be covered by the selected TLS certificate.")
			}
		}
		if reverseTransportKinds[kind] && transport["enabled"] != false && text(transport["cover_mode"]) == "api" {
			profilePath := fmt.Sprintf("transports[%d].tls_profile_id", index)
			requireTLSProfile(transport["tls_profile_id"], profilePath)
			profile := tlsProfilesByID[text(transport["tls_profile_id"])]
			serverNames := append([]string{text(transport["server_name"])}, stringValues(transport["server_names"])...)
			for nameIndex, serverName := range serverNames {
				if tlsProfileMetadataCoversHostname(profile, serverName) {
					continue
				}
				path := fmt.Sprintf("transports[%d].server_names[%d]", index, nameIndex-1)
				if nameIndex == 0 {
					path = fmt.Sprintf("transports[%d].server_name", index)
				}
				result.add(path, "tls_hostname", "REALITY API cover SNI must be covered by the selected TLS certificate.")
			}
		}
	}
	for index, transport := range entities["transports"] {
		kind, _ := transport["kind"].(string)
		if transport["enabled"] == false || !tlsTransportKinds[kind] {
			continue
		}
		deployments, _ := transport["cdn_deployments"].([]any)
		for deploymentIndex, raw := range deployments {
			deployment, _ := raw.(map[string]any)
			if deployment == nil || deployment["enabled"] == false {
				continue
			}
			requireTLSProfile(deployment["tls_profile_id"], fmt.Sprintf("transports[%d].cdn_deployments[%d].tls_profile_id", index, deploymentIndex))
		}
	}

	ingress, _ := config["ingress"].(map[string]any)
	if strings.TrimSpace(text(ingress["status_hostname"])) != "" {
		requireTLSProfile(ingress["tls_profile_id"], "ingress.tls_profile_id")
	}
	if runtimeconfig.SubscriptionEndpointEnabled(config) {
		requireTLSProfile(ingress["subscription_tls_profile_id"], "ingress.subscription_tls_profile_id")
	}

	for index, policy := range entities["policies"] {
		id, _ := policy["id"].(string)
		if final, exists := policy["final"]; exists && final != nil && final != "" && final != "direct" {
			if text, ok := final.(string); !ok || text == id {
				result.add(fmt.Sprintf("policies[%d].final", index), "reference", "Final route must reference another policy or direct.")
			} else {
				result.reference(text, policyIDs, fmt.Sprintf("policies[%d].final", index), "Final route policy does not exist.")
			}
		}
	}
	for _, collection := range []string{"local_clients", "remote_users"} {
		for index, entity := range entities[collection] {
			if value, exists := entity["policy_id"]; exists && value != nil && value != "" {
				result.reference(value, policyIDs, fmt.Sprintf("%s[%d].policy_id", collection, index), "Referenced policy does not exist.")
			}
		}
	}
	for index, user := range entities["remote_users"] {
		result.referenceArray(user["allowed_network_ids"], networkIDs, fmt.Sprintf("remote_users[%d].allowed_network_ids", index), false)
		if reference, _ := user["uuid_secret_ref"].(string); reference == "" {
			result.add(fmt.Sprintf("remote_users[%d].uuid_secret_ref", index), "secret_ref", "UUID must be referenced from the secrets directory.")
		}
		if exclusions, exists := user["excluded_transports"]; exists {
			result.referenceArray(exclusions, transportIDs, fmt.Sprintf("remote_users[%d].excluded_transports", index), false)
		}
	}
	for index, reverse := range entities["reverse_vless_exits"] {
		path := fmt.Sprintf("reverse_vless_exits[%d].transport_ids", index)
		values, ok := reverse["transport_ids"].([]any)
		if !ok || len(values) == 0 {
			result.add(path, "reference", "Select at least one enabled Direct REALITY, gRPC + REALITY, or XHTTP + REALITY transport.")
			continue
		}
		for _, raw := range values {
			id, ok := raw.(string)
			kind, enabled := enabledTransports[id]
			if !ok || !enabled || !reverseTransportKinds[kind] {
				result.add(path, "reference", "Reverse VLESS references a missing, disabled, or non-REALITY direct transport.")
				break
			}
			if _, exists := transportIDs[id]; !exists {
				result.add(path, "reference", "Referenced transport does not exist.")
				break
			}
		}
		if reference, _ := reverse["uuid_secret_ref"].(string); reference == "" {
			result.add(fmt.Sprintf("reverse_vless_exits[%d].uuid_secret_ref", index), "secret_ref", "Reverse VLESS UUID must be referenced from the secrets directory.")
		}
	}
}

func stringValues(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok {
				result = append(result, value)
			}
		}
		return result
	default:
		return nil
	}
}

func tlsProfileMetadataCoversHostname(profile map[string]any, value string) bool {
	hostname := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !validReverseExportHostname(hostname) || strings.Contains(hostname, "*") {
		return false
	}
	for _, rawName := range stringValues(nestedObject(profile, "certificate_metadata")["dns_names"]) {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawName), "."))
		if name == hostname {
			return true
		}
		if !strings.HasPrefix(name, "*.") {
			continue
		}
		suffix := strings.TrimPrefix(name, "*.")
		if !strings.HasSuffix(hostname, "."+suffix) {
			continue
		}
		prefix := strings.TrimSuffix(hostname, "."+suffix)
		if prefix != "" && !strings.Contains(prefix, ".") {
			return true
		}
	}
	return false
}

func (result *configValidation) validatePublicExposure(config map[string]any, entities map[string][]map[string]any) {
	deploymentReady := nestedObject(config, "system")["deployment_ready"] == true
	exposure, _ := config["public_exposure"].(map[string]any)
	subscription, _ := exposure["subscription"].(map[string]any)
	if raw, exists := subscription["happ_provider_id"]; exists && raw != nil && raw != "" {
		value, ok := raw.(string)
		if !ok || strings.TrimSpace(value) != value || !secretRefPattern.MatchString(value) {
			result.add("public_exposure.subscription.happ_provider_id", "identifier", "Happ Provider ID must contain 1-127 letters, digits, dots, underscores, slashes, or hyphens without surrounding spaces.")
		}
	}
	guard, _ := exposure["connection_guard"].(map[string]any)
	result.optionalBoolean(guard, "enabled", "public_exposure.connection_guard")
	for _, field := range []struct {
		name    string
		minimum int
		maximum int
	}{
		{"new_connection_rate", 5, 1000},
		{"burst", 10, 5000},
		{"quarantine_seconds", 60, 86400},
	} {
		value, ok := jsonInteger(guard[field.name])
		if !ok || value < field.minimum || value > field.maximum {
			result.add("public_exposure.connection_guard."+field.name, "range", fmt.Sprintf("Value must be an integer from %d to %d.", field.minimum, field.maximum))
		}
	}

	ingress, _ := config["ingress"].(map[string]any)
	result.optionalBoolean(ingress, "require_cloudflare_source_ranges", "ingress")
	result.optionalBoolean(ingress, "subscription_endpoint_enabled", "ingress")
	subscriptionEnabled := runtimeconfig.SubscriptionEndpointEnabled(config)
	mode, _ := ingress["subscription_endpoint_mode"].(string)
	if mode == "" {
		mode = "separate"
	}
	if mode != "separate" && mode != "reuse-cdn" && mode != "direct" && mode != "direct-and-cdn" {
		result.add("ingress.subscription_endpoint_mode", "enum", "Subscription endpoint mode is unsupported.")
	}
	subscriptionHost, _ := ingress["subscription_hostname"].(string)
	subscriptionCDNHost, _ := ingress["subscription_cdn_hostname"].(string)
	if subscriptionEnabled && deploymentReady && (mode == "separate" || mode == "direct" || mode == "direct-and-cdn") {
		if !validReverseExportHostname(strings.TrimSpace(subscriptionHost)) {
			result.add("ingress.subscription_hostname", "hostname", "Dedicated subscription endpoint requires a valid public hostname.")
		}
	}
	if subscriptionEnabled && deploymentReady && mode == "separate" && strings.TrimSpace(subscriptionHost) != "" {
		origin, _ := ingress["subscription_origin_server_name"].(string)
		origin = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(origin)), ".")
		if net.ParseIP(origin) != nil || strings.Contains(origin, "*") || !validReverseExportHostname(origin) {
			result.add("ingress.subscription_origin_server_name", "hostname", "Dedicated CDN subscription origin requires a concrete DNS hostname.")
		}
	}
	if subscriptionEnabled && deploymentReady && mode == "direct-and-cdn" && strings.TrimSpace(subscriptionCDNHost) != "" {
		if !validReverseExportHostname(strings.TrimSpace(subscriptionCDNHost)) {
			result.add("ingress.subscription_cdn_hostname", "hostname", "CDN subscription endpoint requires a valid public hostname.")
		}
		origin, _ := ingress["subscription_origin_server_name"].(string)
		origin = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(origin)), ".")
		direct := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(subscriptionHost)), ".")
		if net.ParseIP(origin) != nil || strings.Contains(origin, "*") || !validReverseExportHostname(origin) {
			result.add("ingress.subscription_origin_server_name", "hostname", "Dedicated CDN subscription origin requires a concrete DNS hostname.")
		} else if direct != origin {
			result.add("ingress.subscription_hostname", "hostname", "Direct subscription hostname must match the existing CDN origin hostname.")
		}
	}
	usesDedicatedSubscriptionCDN := mode == "separate" || (mode == "direct-and-cdn" && strings.TrimSpace(subscriptionCDNHost) != "")
	if subscriptionEnabled && usesDedicatedSubscriptionCDN {
		protection, _ := ingress["subscription_origin_protection_mode"].(string)
		provider, _ := ingress["subscription_cdn_provider"].(string)
		publicPort, ok := jsonInteger(ingress["subscription_public_port"])
		if !ok {
			publicPort, _ = jsonInteger(ingress["subscription_listen_port"])
		}
		if strings.EqualFold(provider, "cloudflare") && !cloudflareHTTPSPorts[publicPort] {
			result.add("ingress.subscription_public_port", "provider", "Cloudflare HTTPS proxy does not support this public port.")
		}
		if mode == "separate" && protection != "auto-cidr" && protection != "manual-cidr" && protection != "secret-header" {
			result.add("ingress.subscription_origin_protection_mode", "enum", "Subscription origin protection mode is unsupported.")
		}
		if mode == "separate" && protection == "auto-cidr" && !cdnfeed.Supports(provider) {
			result.add("ingress.subscription_origin_protection_mode", "provider", "No verified official origin CIDR feed adapter is available for this CDN; use a secret header or manual CIDRs.")
		}
		if mode == "separate" && protection == "manual-cidr" {
			result.ipv4CIDRArray(ingress["subscription_origin_allowed_cidrs"], "ingress.subscription_origin_allowed_cidrs", true)
		}
	}

	type listenerOwner struct {
		kind string
		path string
	}
	listeners := make(map[string]listenerOwner)
	register := func(protocol string, port int, kind, path string, shareable bool) {
		if port < 1 || port > 65535 {
			return
		}
		key := protocol + ":" + fmt.Sprint(port)
		if runtimeconfig.Shared443(config) && protocol == "tcp" && port >= 16443 && port <= 16448 {
			result.add(path, "port_conflict", "Ports 16443–16448 are reserved for shared TCP 443.")
		}
		if previous, exists := listeners[key]; exists {
			if shareable && previous.kind == "nginx" {
				return
			}
			result.add(path, "port_conflict", fmt.Sprintf("Listener conflicts with %s on container %s.", previous.path, key))
			return
		}
		listeners[key] = listenerOwner{kind: kind, path: path}
	}
	for index, transport := range entities["transports"] {
		if transport["enabled"] == false {
			continue
		}
		kind, _ := transport["kind"].(string)
		path := fmt.Sprintf("transports[%d]", index)
		if tlsTransportKinds[kind] {
			deployments, _ := transport["cdn_deployments"].([]any)
			for deploymentIndex, raw := range deployments {
				deployment, _ := raw.(map[string]any)
				if deployment == nil || deployment["enabled"] == false {
					continue
				}
				port, _ := jsonInteger(deployment["origin_port"])
				register("tcp", port, "nginx", fmt.Sprintf("%s.cdn_deployments[%d].origin_port", path, deploymentIndex), true)
				protection, _ := deployment["origin_protection_mode"].(string)
				provider, _ := deployment["cdn_provider"].(string)
				if protection == "" && strings.EqualFold(provider, "cloudflare") {
					protection = "auto-cidr"
				}
				if protection != "" && protection != "auto-cidr" && protection != "manual-cidr" && protection != "secret-header" && protection != "none" {
					result.add(fmt.Sprintf("%s.cdn_deployments[%d].origin_protection_mode", path, deploymentIndex), "enum", "CDN origin protection mode is unsupported.")
				}
				if protection == "auto-cidr" && !cdnfeed.Supports(provider) {
					result.add(fmt.Sprintf("%s.cdn_deployments[%d].origin_protection_mode", path, deploymentIndex), "provider", "No verified official origin CIDR feed adapter is available for this CDN; use a secret header or manual CIDRs.")
				}
			}
			continue
		}
		port, _ := jsonInteger(transport["listen_port"])
		protocol := "tcp"
		if kind == "hysteria2" {
			protocol = "udp"
			hop, hopErr := runtimeconfig.ParseHysteriaUDPHop(transport)
			if hopErr == nil && hop.Enabled {
				for _, portRange := range hop.Ranges {
					for publicPort := portRange.Start; publicPort <= portRange.End; publicPort++ {
						register(protocol, publicPort, "direct", path+".xray_hysteria.udp_hop", false)
					}
				}
				continue
			}
		}
		if runtimeconfig.Shared443(config) && port == 443 && runtimeconfig.RealityBackendPort(kind) != 0 {
			register(protocol, port, "nginx", path+".listen_port", true)
		} else {
			register(protocol, port, "direct", path+".listen_port", false)
		}
	}
	if host, _ := ingress["status_hostname"].(string); strings.TrimSpace(host) != "" {
		port, _ := jsonInteger(ingress["status_listen_port"])
		register("tcp", port, "nginx", "ingress.status_listen_port", true)
	}
	if subscriptionEnabled && (mode == "separate" || mode == "direct" || mode == "direct-and-cdn") {
		port, _ := jsonInteger(ingress["subscription_listen_port"])
		register("tcp", port, "nginx", "ingress.subscription_listen_port", true)
	}

	result.optionalBoolean(nestedObject(config, "public_exposure"), "shared_tcp_443", "public_exposure")
	if err := runtimeconfig.ValidateSharedIngress(config); err != nil {
		result.add("public_exposure.shared_tcp_443", "ingress_conflict", err.Error())
	}
	requiresSubscriptionDeployment := mode == "reuse-cdn" ||
		(mode == "direct-and-cdn" && strings.TrimSpace(subscriptionCDNHost) == "")
	if subscriptionEnabled && deploymentReady && requiresSubscriptionDeployment {
		transportID, _ := ingress["subscription_transport_id"].(string)
		deploymentID, _ := ingress["subscription_deployment_id"].(string)
		found := false
		for _, transport := range entities["transports"] {
			if transport["enabled"] == false || transport["id"] != transportID || !tlsTransportKinds[fmt.Sprint(transport["kind"])] {
				continue
			}
			deployments, _ := transport["cdn_deployments"].([]any)
			for _, raw := range deployments {
				deployment, _ := raw.(map[string]any)
				if deployment != nil && deployment["enabled"] != false && deployment["id"] == deploymentID {
					found = true
				}
			}
		}
		if !found {
			result.add("ingress.subscription_deployment_id", "reference", "Select an enabled CDN deployment for the subscription endpoint.")
		}
	}
}

func (result *configValidation) validateWireGuard(config map[string]any) {
	networking := nestedObject(config, "system", "networking")
	values, ok := networking["wireguard_egress_exits"].([]any)
	if !ok {
		result.add("system.networking.wireguard_egress_exits", "type", "WireGuard exits must be an array.")
		return
	}
	if len(values) > 16 {
		result.add("system.networking.wireguard_egress_exits", "range", "At most 16 WireGuard exits may be managed.")
	}
	seenIDs := make(map[string]struct{}, len(values))
	seenInterfaces := make(map[string]struct{}, len(values))
	enabled := 0
	for index, raw := range values {
		path := fmt.Sprintf("system.networking.wireguard_egress_exits[%d]", index)
		exit, ok := raw.(map[string]any)
		if !ok {
			result.add(path, "type", "WireGuard exit must be an object.")
			continue
		}
		result.optionalBoolean(exit, "enabled", path)
		id, _ := exit["id"].(string)
		if !entityIDPattern.MatchString(id) || len(id) > 32 {
			result.add(path+".id", "identifier", "WireGuard exit ID must use 1 to 32 lowercase letters, digits, dots, underscores, or hyphens.")
		} else if _, exists := seenIDs[id]; exists {
			result.add(path+".id", "duplicate", "WireGuard exit IDs must be unique.")
		} else {
			seenIDs[id] = struct{}{}
		}
		name, _ := exit["interface"].(string)
		if strings.TrimSpace(name) == "" || len(name) > 63 {
			result.add(path+".interface", "routeros_interface", "Select a RouterOS WireGuard interface.")
		} else if _, exists := seenInterfaces[name]; exists {
			result.add(path+".interface", "duplicate", "A WireGuard interface may be selected only once.")
		} else {
			seenInterfaces[name] = struct{}{}
		}
		if exit["enabled"] != false {
			enabled++
		}
	}
	if networking["wireguard_egress_enabled"] == true && enabled == 0 {
		result.add("system.networking.wireguard_egress_exits", "required", "Select at least one enabled WireGuard exit.")
	}
}

func (result *configValidation) validateSecretReferences(value any, path string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if strings.HasSuffix(key, "_secret_ref") {
				if text, ok := child.(string); !ok || !validSecretReference(text) {
					result.add(childPath, "secret_ref", "Secret reference must stay inside the secrets directory.")
				}
				continue
			}
			result.validateSecretReferences(child, childPath)
		}
	case []any:
		for index, child := range typed {
			result.validateSecretReferences(child, fmt.Sprintf("%s[%d]", path, index))
		}
	}
}

func validSecretReference(value string) bool {
	if value == "" {
		return true
	}
	if !secretRefPattern.MatchString(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func routerCompatibility(config map[string]any) map[string]any {
	routerOS, _ := config["routeros"].(map[string]any)
	missing := make([]any, 0)
	capabilities, _ := routerOS["capabilities"].(map[string]any)
	if required, ok := routerOS["required_capabilities"].([]any); ok {
		for _, raw := range required {
			name, ok := raw.(string)
			if ok && capabilities[name] != true {
				missing = append(missing, name)
			}
		}
	}
	return map[string]any{
		"compatible": len(missing) == 0, "detected_version": routerOS["detected_version"],
		"channel": routerOS["channel"], "trust_level": "saved", "architecture": routerOS["architecture"],
		"missing_capabilities": missing, "last_tested_baseline": nestedValue(config, "system", "last_tested_routeros_baseline"),
	}
}

func (result configValidation) payload() map[string]any {
	return map[string]any{
		"valid": result.Valid, "errors": result.Errors, "warnings": result.Warnings,
		"revision": result.Revision, "routeros": result.RouterOS,
	}
}

func (result *configValidation) add(path, code, message string) {
	result.Errors = append(result.Errors, validationIssue{Path: path, Code: code, Message: message})
}

func (result *configValidation) port(value any, path string) {
	port, ok := jsonInteger(value)
	if !ok || port < 1 || port > 65535 {
		result.add(path, "port", "Port must be an integer from 1 to 65535.")
	}
}

func (result *configValidation) optionalIntegerRange(object map[string]any, field, path string, minimum, maximum int) {
	value, exists := object[field]
	if !exists || value == nil || value == "" {
		return
	}
	integer, ok := jsonInteger(value)
	if !ok || integer < minimum || integer > maximum {
		result.add(path+"."+field, "range", fmt.Sprintf("Value must be an integer from %d to %d.", minimum, maximum))
	}
}

func (result *configValidation) optionalIntegerRange64(object map[string]any, field, path string, minimum, maximum int64) {
	value, exists := object[field]
	if !exists || value == nil || value == "" {
		return
	}
	integer, ok := jsonInteger64(value)
	if !ok || integer < minimum || integer > maximum {
		result.add(path+"."+field, "range", fmt.Sprintf("Value must be an integer from %d to %d.", minimum, maximum))
	}
}

func (result *configValidation) optionalIntegerZeroOrRange(object map[string]any, field, path string, minimum, maximum int) {
	value, exists := object[field]
	if !exists || value == nil || value == "" {
		return
	}
	integer, ok := jsonInteger(value)
	if !ok || (integer != 0 && (integer < minimum || integer > maximum)) {
		result.add(path+"."+field, "range", fmt.Sprintf("Value must be 0 or an integer from %d to %d.", minimum, maximum))
	}
}

func (result *configValidation) optionalEnum(object map[string]any, field, path string, values map[string]bool) {
	value, exists := object[field]
	if !exists || value == nil || value == "" {
		return
	}
	text, ok := value.(string)
	if !ok || !values[text] {
		result.add(path+"."+field, "enum", "Value is not supported by the runtime generator.")
	}
}

func (result *configValidation) optionalBoolean(object map[string]any, field, path string) {
	value, exists := object[field]
	if !exists || value == nil {
		return
	}
	if _, ok := value.(bool); !ok {
		result.add(path+"."+field, "type", "Value must be true or false.")
	}
}

func (result *configValidation) optionalStringArray(value any, path string, maximum int) {
	values, ok := value.([]any)
	if !ok {
		result.add(path, "type", "Value must be an array of strings.")
		return
	}
	if len(values) > maximum {
		result.add(path, "range", fmt.Sprintf("At most %d values may be configured.", maximum))
	}
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		text, ok := raw.(string)
		if !ok || strings.TrimSpace(text) == "" || len(text) > 2048 {
			result.add(fmt.Sprintf("%s[%d]", path, index), "string", "Value must be a non-empty string up to 2048 characters.")
			continue
		}
		if _, duplicate := seen[text]; duplicate {
			result.add(path, "duplicate", "Values must be unique.")
		}
		seen[text] = struct{}{}
	}
}

func (result *configValidation) stringStringMap(value any, path string, maximum int) {
	entries, ok := value.(map[string]any)
	if !ok {
		result.add(path, "type", "Value must be an object of string values.")
		return
	}
	if len(entries) > maximum {
		result.add(path, "range", fmt.Sprintf("At most %d entries may be configured.", maximum))
	}
	for key, raw := range entries {
		text, ok := raw.(string)
		if strings.TrimSpace(key) == "" || len(key) > 2048 || !ok || strings.TrimSpace(text) == "" || len(text) > 2048 {
			result.add(path+"."+key, "string", "Map keys and values must be non-empty strings up to 2048 characters.")
		}
	}
}

func (result *configValidation) optionalIntegerRangeText(object map[string]any, field, path string) {
	value, exists := object[field]
	if !exists || value == nil || value == "" {
		return
	}
	text, ok := value.(string)
	if !ok || !validIntegerRangeText(text) {
		result.add(path+"."+field, "range", "Value must be a non-negative integer or an ordered integer range.")
	}
}

func (result *configValidation) stringMap(value any, path string) {
	entries, ok := value.(map[string]any)
	if !ok {
		result.add(path, "type", "HTTP headers must be an object of string values.")
		return
	}
	if len(entries) > 64 {
		result.add(path, "range", "At most 64 HTTP headers may be configured.")
	}
	for name, raw := range entries {
		text, ok := raw.(string)
		if strings.TrimSpace(name) == "" || len(name) > 256 || !ok || len(text) > 8192 || strings.ContainsAny(name, "\r\n:") || strings.ContainsAny(text, "\r\n") {
			result.add(path+"."+name, "header", "HTTP header name or value is invalid.")
		}
	}
}

func validIntegerRangeText(value string) bool {
	value = strings.TrimSpace(value)
	matches := integerRangePattern.FindStringSubmatch(value)
	if matches == nil {
		return false
	}
	minimum, err := strconv.ParseUint(matches[1], 10, 31)
	if err != nil {
		return false
	}
	if matches[2] == "" {
		return true
	}
	maximum, err := strconv.ParseUint(matches[2], 10, 31)
	return err == nil && minimum <= maximum
}

func integerRangeMinimum(value any) (uint64, bool) {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" || !validIntegerRangeText(text) {
		return 0, false
	}
	first := strings.SplitN(strings.TrimSpace(text), "-", 2)[0]
	parsed, err := strconv.ParseUint(first, 10, 31)
	return parsed, err == nil
}

func validHostOrIP(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if address := net.ParseIP(value); address != nil {
		return true
	}
	return validReverseExportHostname(value)
}

func validHTTPAuthority(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "/?#@\r\n\t ") {
		return false
	}
	parsed, err := url.Parse("https://" + value)
	if err != nil || parsed.Host != value || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	if !validHostOrIP(parsed.Hostname()) {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		return err == nil && value >= 1 && value <= 65535
	}
	return true
}

func isLoopbackHost(value string) bool {
	if strings.EqualFold(strings.TrimSpace(value), "localhost") {
		return true
	}
	address := net.ParseIP(strings.TrimSpace(value))
	return address != nil && address.IsLoopback()
}

func (result *configValidation) cidrArray(value any, path string, required bool) {
	values, ok := value.([]any)
	if !ok {
		result.add(path, "type", "CIDRs must be an array.")
		return
	}
	if required && len(values) == 0 {
		result.add(path, "required", "At least one CIDR is required.")
	}
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		text, ok := raw.(string)
		prefix, err := netip.ParsePrefix(text)
		if !ok || err != nil {
			result.add(fmt.Sprintf("%s[%d]", path, index), "cidr", "Value must be a valid IPv4 or IPv6 CIDR.")
			continue
		}
		canonical := prefix.Masked().String()
		if _, duplicate := seen[canonical]; duplicate {
			result.add(path, "duplicate", "CIDRs must be unique.")
		}
		seen[canonical] = struct{}{}
	}
}

func (result *configValidation) ipv4CIDRArray(value any, path string, required bool) {
	values, ok := value.([]any)
	if !ok {
		if required {
			result.add(path, "type", "IPv4 CIDRs must be an array.")
		}
		return
	}
	if required && len(values) == 0 {
		result.add(path, "required", "At least one IPv4 CIDR is required.")
	}
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		text, ok := raw.(string)
		prefix, err := netip.ParsePrefix(text)
		if !ok || err != nil || !prefix.Addr().Is4() {
			result.add(fmt.Sprintf("%s[%d]", path, index), "cidr", "Value must be a valid IPv4 CIDR.")
			continue
		}
		canonical := prefix.Masked().String()
		if _, duplicate := seen[canonical]; duplicate {
			result.add(path, "duplicate", "IPv4 CIDRs must be unique.")
		}
		seen[canonical] = struct{}{}
	}
}

func (result *configValidation) reference(value any, ids map[string]struct{}, path, message string) {
	text, ok := value.(string)
	if !ok || text == "" {
		result.add(path, "reference", message)
		return
	}
	if _, exists := ids[text]; !exists {
		result.add(path, "reference", message)
	}
}

func (result *configValidation) referenceArray(value any, ids map[string]struct{}, path string, required bool) {
	values, ok := value.([]any)
	if !ok {
		result.add(path, "type", "References must be an array.")
		return
	}
	if required && len(values) == 0 {
		result.add(path, "required", "At least one reference is required.")
	}
	for _, raw := range values {
		text, ok := raw.(string)
		if !ok {
			result.add(path, "reference", "Reference must be a string ID.")
			continue
		}
		if _, exists := ids[text]; !exists {
			result.add(path, "reference", "Referenced object does not exist.")
		}
	}
}

func jsonInteger(value any) (int, bool) {
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Int64()
		return int(number), err == nil && int64(int(number)) == number
	case int:
		return typed, true
	case int64:
		return int(typed), int64(int(typed)) == typed
	case float64:
		integer := int(typed)
		return integer, float64(integer) == typed
	default:
		return 0, false
	}
}

func jsonInteger64(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		integer := int64(typed)
		return integer, float64(integer) == typed
	default:
		return 0, false
	}
}

func nestedObject(value map[string]any, keys ...string) map[string]any {
	current := value
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			return map[string]any{}
		}
		current = next
	}
	return current
}
