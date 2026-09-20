package runtimeconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

type NginxRenderOptions struct {
	Template                string
	SubscriptionRelaySource string
	OriginCIDRRoot          string
	BootstrapTLSCertificate string
	BootstrapTLSPrivateKey  string
}

type nginxDeployment struct {
	Transport  map[string]any
	Deployment map[string]any
	Kind       string
	Port       int
	Hostname   string
	ProfileID  string
}

type nginxSubscriptionEndpoint struct {
	ID, Mode, Hostname, ProfileID, TransportID, DeploymentID string
	Port                                                     int
}

var (
	regexpNginxVariable   = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)
	regexpNginxHeaderName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,62}$`)
	regexpNginxToken      = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
)

// RenderNginxCandidate renders only the current normalized schema. TLS pairs
// are validated by draft check once; render resolves stable SecretStore paths
// without rereading PEM bodies.
func RenderNginxCandidate(config map[string]any, readSecret SecretReader, secretPath SecretPathResolver, options NginxRenderOptions) (string, error) {
	if err := ValidateDedicatedSubscriptionOrigin(config); err != nil {
		return "", err
	}
	if err := ValidateSharedIngress(config); err != nil {
		return "", err
	}
	if readSecret == nil || secretPath == nil {
		return "", errors.New("Nginx render requires secret and path resolvers")
	}
	if options.Template == "" {
		return "", errors.New("Nginx template is empty")
	}
	uncachedRead := readSecret
	secretCache := make(map[string]string)
	readSecret = func(reference string) (string, error) {
		if value, exists := secretCache[reference]; exists {
			return value, nil
		}
		value, err := uncachedRead(reference)
		if err != nil {
			return "", err
		}
		secretCache[reference] = value
		return value, nil
	}
	byKind := make(map[string]map[string]any)
	for _, transport := range enabledObjects(config["transports"]) {
		kind := textValue(transport["kind"])
		if kind == "ws" || kind == "grpc" || kind == "httpupgrade" || kind == "xhttp" {
			byKind[kind] = transport
		}
	}
	ingress := objectValue(config["ingress"])
	networking := objectValue(objectValue(config["system"])["networking"])
	gateway := strings.TrimSpace(textValue(networking["routeros_gateway"]))
	parsedGateway, err := netip.ParseAddr(gateway)
	if err != nil || !parsedGateway.Is4() {
		return "", errors.New("system.networking.routeros_gateway must be a valid IPv4 address")
	}
	relay := strings.TrimSpace(options.SubscriptionRelaySource)
	if relay == "" {
		relay = "127.0.0.1/32"
	}
	relayPrefix, err := netip.ParsePrefix(relay)
	if err != nil {
		if address, addressErr := netip.ParseAddr(relay); addressErr == nil {
			relayPrefix = netip.PrefixFrom(address, address.BitLen())
		} else {
			return "", errors.New("subscription relay source must be a valid private IP/CIDR")
		}
	}
	relayAddress := relayPrefix.Addr()
	if !relayAddress.IsPrivate() && !relayAddress.IsLoopback() && !relayAddress.IsLinkLocalUnicast() {
		return "", errors.New("subscription relay source must stay on a private network")
	}

	statusHost := strings.TrimSpace(textValue(ingress["status_hostname"]))
	publicProfile := textValue(ingress["tls_profile_id"])
	publicCert := strings.TrimSpace(options.BootstrapTLSCertificate)
	publicKey := strings.TrimSpace(options.BootstrapTLSPrivateKey)
	profileCert, profileKey, profileErr := nginxTLSProfilePaths(config, publicProfile, secretPath)
	if profileErr == nil {
		publicCert, publicKey = profileCert, profileKey
	} else if statusHost != "" {
		return "", profileErr
	}
	if publicCert == "" || publicKey == "" {
		return "", errors.New("Nginx management requires a bootstrap TLS certificate/private-key pair")
	}
	endpoints, err := nginxSubscriptionEndpoints(config)
	if err != nil {
		return "", err
	}
	var dedicated, reused *nginxSubscriptionEndpoint
	for index := range endpoints {
		endpoint := &endpoints[index]
		if dedicated == nil && (endpoint.Mode == "separate" || endpoint.Mode == "direct") {
			dedicated = endpoint
		}
		if reused == nil && endpoint.Mode == "reuse-cdn" {
			reused = endpoint
		}
	}
	subscriptionCert, subscriptionKey := publicCert, publicKey
	if SubscriptionEndpointEnabled(config) {
		subscriptionProfile := publicProfile
		if dedicated != nil && dedicated.ProfileID != "" {
			subscriptionProfile = dedicated.ProfileID
		} else if profile := textValue(ingress["subscription_tls_profile_id"]); profile != "" {
			subscriptionProfile = profile
		}
		if dedicated != nil {
			subscriptionCert, subscriptionKey, err = nginxTLSProfilePaths(config, subscriptionProfile, secretPath)
			if err != nil {
				return "", err
			}
		}
	}
	management := objectValue(objectValue(config["system"])["management"])
	managementCert, managementKey := publicCert, publicKey
	managementCertRef := textValue(management["tls_certificate_secret_ref"])
	managementKeyRef := textValue(management["tls_private_key_secret_ref"])
	if (managementCertRef == "") != (managementKeyRef == "") {
		return "", errors.New("management TLS secret references must be provided together")
	}
	if managementCertRef != "" {
		managementCert, err = secretPath(managementCertRef)
		if err != nil {
			return "", err
		}
		managementKey, err = secretPath(managementKeyRef)
		if err != nil {
			return "", err
		}
	}
	managementToken, err := readSecret("management-api-token")
	if err != nil || !regexpNginxToken.MatchString(managementToken) {
		return "", errors.New("management API token is unavailable")
	}

	deployments, err := nginxDeployments(byKind)
	if err != nil {
		return "", err
	}
	groups := nginxDeploymentGroups(deployments)
	publicPorts := make(map[int]struct{})
	for _, group := range groups {
		publicPorts[group[0].Port] = struct{}{}
	}
	statusPort, err := integerDefault(ingress["status_listen_port"], 443)
	if err != nil {
		return "", err
	}
	if statusHost != "" {
		publicPorts[statusPort] = struct{}{}
	}
	if dedicated != nil {
		publicPorts[dedicated.Port] = struct{}{}
	}
	defaultServer := nginxSharedHTTP(config, nginxDefaultPublicServer(publicPorts, publicCert, publicKey))

	subscriptionMode, subscriptionHost, subscriptionPort := "reuse-cdn", "subscription-disabled.invalid", 443
	if dedicated != nil {
		subscriptionMode, subscriptionHost, subscriptionPort = dedicated.Mode, dedicated.Hostname, dedicated.Port
	}
	subscriptionGuard := ""
	if dedicated != nil && subscriptionMode == "separate" && textValue(ingress["subscription_origin_protection_mode"]) == "secret-header" {
		subscriptionGuard, err = nginxSingleHeaderGuard(
			textDefault(ingress["subscription_origin_header_name"], "X-SB-Origin"),
			textValue(ingress["subscription_origin_header_secret_ref"]), readSecret,
		)
		if err != nil {
			return "", err
		}
	}
	sharedStatus := statusHost != "" && dedicated != nil && equalHostname(statusHost, subscriptionHost) && statusPort == subscriptionPort
	statusSubscriptionLocation := ""
	if sharedStatus {
		statusSubscriptionLocation = nginxSubscriptionLocation(subscriptionGuard)
		subscriptionHost = "subscription-disabled.invalid"
	}
	statusServer := ""
	if statusHost != "" {
		statusServer = fmt.Sprintf(`    server {
        listen %d ssl;
        server_name %s;
        access_log off;
        error_log /logs/nginx/public-error.log crit;
        ssl_certificate %s;
        ssl_certificate_key %s;
        location = /healthz {
            access_log off;
            proxy_http_version 1.1;
            proxy_set_header Host 127.0.0.1;
            proxy_pass http://127.0.0.1:8080/api/health/router-ready;
        }

        location = /traffic-ready {
            access_log off;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_pass http://127.0.0.1:8080/api/health/traffic-ready;
        }
%s        include /opt/sb-gateway/templates/nginx-decoy.inc;
    }
`, statusPort, statusHost, publicCert, publicKey, statusSubscriptionLocation)
		statusServer = strings.Replace(statusServer, "        access_log off;", nginxOriginHostGuard(config, statusPort, statusHost)+"        access_log off;", 1)
		statusServer = nginxSharedHTTP(config, statusServer)
	}

	transportServers, err := nginxTransportServers(config, groups, reused, readSecret, secretPath)
	if err != nil {
		return "", err
	}
	realityCoverServers, err := nginxRealityCoverServers(config, publicCert, publicKey, secretPath)
	if err != nil {
		return "", err
	}
	subscriptionServer := ""
	if dedicated != nil && !sharedStatus {
		subscriptionServer = fmt.Sprintf(`    server {
        listen %d ssl;
        server_name %s;
        access_log off;
        error_log /logs/nginx/public-error.log crit;
        ssl_certificate %s;
        ssl_certificate_key %s;
%s        include /opt/sb-gateway/templates/nginx-decoy.inc;
    }
	`, subscriptionPort, dedicated.Hostname, subscriptionCert, subscriptionKey, nginxSubscriptionLocation(subscriptionGuard))
		subscriptionServer = strings.Replace(subscriptionServer, "        access_log off;", nginxOriginHostGuard(config, subscriptionPort, dedicated.Hostname)+"        access_log off;", 1)
		subscriptionServer = nginxSharedHTTP(config, subscriptionServer)
	}
	values := map[string]string{
		"SHARED_STREAM": nginxSharedStream(config), "ORIGIN_MAPS": nginxOriginMaps(config, options.OriginCIDRRoot),
		"DECOY_ROOT": "/opt/sb-gateway/templates/decoy", "DECOY_HTTP_SERVER": "", "DECOY_HTTPS_SERVER": "",
		"DEFAULT_PUBLIC_SERVER": defaultServer, "REALITY_COVER_SERVER": realityCoverServers, "WS_SERVER": transportServers, "GRPC_SERVER": "", "HU_SERVER": "", "XHTTP_SERVER": "",
		"STATUS_SERVER": statusServer, "SUBSCRIPTION_SERVER": subscriptionServer,
		"ROUTEROS_GATEWAY": parsedGateway.String(), "SUBSCRIPTION_RELAY_SOURCE": relayPrefix.Masked().String(),
		"DEFAULT_TLS_CERT": publicCert, "DEFAULT_TLS_KEY": publicKey, "SUBSCRIPTION_TLS_CERT": subscriptionCert,
		"SUBSCRIPTION_TLS_KEY": subscriptionKey, "MANAGEMENT_TLS_CERT": managementCert, "MANAGEMENT_TLS_KEY": managementKey,
		"MANAGEMENT_TOKEN": managementToken, "SUBSCRIPTION_HOST": subscriptionHost,
	}
	for kind, prefix := range map[string]string{"ws": "WS", "grpc": "GRPC", "httpupgrade": "HU", "xhttp": "XHTTP"} {
		transport := byKind[kind]
		host, path := nginxDisabledHost(kind), nginxDisabledPath(kind)
		port := 443
		if transport != nil {
			host = textValue(transport["origin_server_name"])
			if host == "" {
				host = textValue(transport["hostname"])
			}
			port, err = integerDefault(transport["origin_port"], 443)
			if err != nil {
				return "", err
			}
			secretField := "path_secret_ref"
			if kind == "grpc" {
				secretField = "service_name_secret_ref"
			}
			path, err = readSecret(textValue(transport[secretField]))
			if err != nil {
				return "", err
			}
		}
		values[prefix+"_HOST"], values[prefix+"_LISTEN_PORT"] = host, fmt.Sprint(port)
		if kind == "grpc" {
			values["GRPC_SERVICE"] = path
		} else {
			values[prefix+"_PATH"] = path
		}
	}
	hosts := []string{values["WS_HOST"], values["GRPC_HOST"], values["HU_HOST"], values["XHTTP_HOST"], values["SUBSCRIPTION_HOST"]}
	if statusHost != "" {
		hosts = append(hosts, statusHost)
	}
	for _, group := range groups {
		hosts = append(hosts, group[0].Hostname)
	}
	for _, host := range hosts {
		if !validNginxHostname(host) {
			return "", fmt.Errorf("Nginx hostname %q is invalid", host)
		}
	}
	for _, key := range []string{"WS_PATH", "HU_PATH", "XHTTP_PATH"} {
		if !ingressPathPattern.MatchString(values[key]) {
			return "", fmt.Errorf("%s has invalid ingress path", key)
		}
	}
	if !grpcNamePattern.MatchString(values["GRPC_SERVICE"]) {
		return "", errors.New("GRPC_SERVICE has invalid format")
	}
	result := options.Template
	for key, value := range values {
		result = strings.ReplaceAll(result, "${"+key+"}", value)
	}
	if unresolved := nginxUnresolvedVariables(result); len(unresolved) != 0 {
		return "", fmt.Errorf("Nginx template contains unresolved variables: %s", strings.Join(unresolved, ", "))
	}
	return result, nil
}

func nginxTLSProfilePaths(config map[string]any, profileID string, secretPath SecretPathResolver) (string, string, error) {
	if profileID == "" {
		return "", "", errors.New("current Nginx schema requires a TLS profile")
	}
	for _, profile := range enabledObjects(config["tls_profiles"]) {
		if textValue(profile["id"]) != profileID {
			continue
		}
		certRef, keyRef := textValue(profile["certificate_secret_ref"]), textValue(profile["private_key_secret_ref"])
		if certRef == "" || keyRef == "" {
			break
		}
		cert, err := secretPath(certRef)
		if err != nil {
			return "", "", err
		}
		key, err := secretPath(keyRef)
		return cert, key, err
	}
	return "", "", fmt.Errorf("TLS profile %q is unavailable", profileID)
}

func nginxDeployments(byKind map[string]map[string]any) ([]nginxDeployment, error) {
	result := make([]nginxDeployment, 0)
	for _, kind := range []string{"ws", "grpc", "httpupgrade", "xhttp"} {
		transport := byKind[kind]
		if transport == nil {
			continue
		}
		configured, ok := transport["cdn_deployments"].([]any)
		if !ok {
			return nil, fmt.Errorf("transport %q requires current cdn_deployments", textValue(transport["id"]))
		}
		for _, raw := range configured {
			deployment := objectValue(raw)
			if deployment == nil || deployment["enabled"] == false {
				continue
			}
			port, err := requiredInteger(deployment["origin_port"])
			if err != nil {
				return nil, fmt.Errorf("CDN deployment %q origin_port: %w", textValue(deployment["id"]), err)
			}
			result = append(result, nginxDeployment{
				Transport: transport, Deployment: deployment, Kind: kind, Port: port,
				Hostname: strings.TrimSpace(textValue(deployment["origin_server_name"])), ProfileID: textValue(deployment["tls_profile_id"]),
			})
		}
	}
	return result, nil
}

func nginxDeploymentGroups(values []nginxDeployment) [][]nginxDeployment {
	result := make([][]nginxDeployment, 0)
	index := make(map[string]int)
	for _, value := range values {
		key := fmt.Sprintf("%d\x00%s\x00%s", value.Port, value.Hostname, value.ProfileID)
		if position, exists := index[key]; exists {
			result[position] = append(result[position], value)
			continue
		}
		index[key] = len(result)
		result = append(result, []nginxDeployment{value})
	}
	return result
}

func nginxSubscriptionEndpoints(config map[string]any) ([]nginxSubscriptionEndpoint, error) {
	if !SubscriptionEndpointEnabled(config) {
		return nil, nil
	}
	ingress := objectValue(config["ingress"])
	mode := textDefault(ingress["subscription_endpoint_mode"], "separate")
	result := make([]nginxSubscriptionEndpoint, 0, 2)
	if mode == "separate" || mode == "direct" || mode == "direct-and-cdn" {
		publicHost := strings.TrimSpace(textValue(ingress["subscription_hostname"]))
		if publicHost != "" {
			host := publicHost
			if mode == "separate" {
				host = canonicalOriginHostname(textValue(ingress["subscription_origin_server_name"]))
				if !validNginxDNSHostname(host) {
					return nil, errors.New("separate subscription endpoint requires a concrete DNS origin hostname")
				}
			}
			port, err := integerDefault(ingress["subscription_listen_port"], 443)
			if err != nil {
				return nil, err
			}
			endpointMode, id := "direct", "direct"
			if mode == "separate" {
				endpointMode, id = "separate", "cdn"
			}
			result = append(result, nginxSubscriptionEndpoint{ID: id, Mode: endpointMode, Hostname: host, Port: port, ProfileID: textValue(ingress["subscription_tls_profile_id"])})
		}
	}
	if mode != "reuse-cdn" && mode != "direct-and-cdn" {
		return result, nil
	}
	transportID, deploymentID := textValue(ingress["subscription_transport_id"]), textValue(ingress["subscription_deployment_id"])
	for _, transport := range enabledObjects(config["transports"]) {
		if textValue(transport["id"]) != transportID {
			continue
		}
		for _, deployment := range enabledObjects(transport["cdn_deployments"]) {
			if textValue(deployment["id"]) != deploymentID {
				continue
			}
			port, err := requiredInteger(deployment["origin_port"])
			if err != nil {
				return nil, err
			}
			result = append(result, nginxSubscriptionEndpoint{
				ID: "cdn", Mode: "reuse-cdn", Hostname: textValue(deployment["hostname"]), Port: port,
				ProfileID: textValue(deployment["tls_profile_id"]), TransportID: transportID, DeploymentID: deploymentID,
			})
			return result, nil
		}
	}
	return result, nil
}

func nginxDefaultPublicServer(ports map[int]struct{}, cert, key string) string {
	if len(ports) == 0 {
		return ""
	}
	ordered := make([]int, 0, len(ports))
	for port := range ports {
		ordered = append(ordered, port)
	}
	sort.Ints(ordered)
	var listens strings.Builder
	for _, port := range ordered {
		fmt.Fprintf(&listens, "        listen %d ssl default_server;\n", port)
	}
	return fmt.Sprintf(`    server {
%s        server_name _;
        access_log off;
        error_log /logs/nginx/public-error.log crit;
        ssl_certificate %s;
        ssl_certificate_key %s;
        ssl_reject_handshake on;
    }
`, listens.String(), cert, key)
}

func nginxTransportServers(config map[string]any, groups [][]nginxDeployment, reused *nginxSubscriptionEndpoint, readSecret SecretReader, secretPath SecretPathResolver) (string, error) {
	var result strings.Builder
	for _, group := range groups {
		first := group[0]
		cert, key, err := nginxTLSProfilePaths(config, first.ProfileID, secretPath)
		if err != nil {
			return "", err
		}
		http2 := ""
		for _, entry := range group {
			if entry.Kind == "grpc" || entry.Kind == "xhttp" {
				http2 = "        http2 on;\n"
			}
		}
		fmt.Fprintf(&result, `    server {
        listen %d ssl;
%s        server_name %s;
        access_log off;
        error_log /logs/nginx/public-error.log crit;
        ssl_certificate %s;
        ssl_certificate_key %s;

`, first.Port, http2, first.Hostname, cert, key)
		result.WriteString(nginxOriginHostGuard(config, first.Port, first.Hostname))
		type transportGroup struct {
			entry       nginxDeployment
			deployments []map[string]any
		}
		transportGroups := make([]transportGroup, 0, len(group))
		transportIndex := make(map[string]int)
		for _, entry := range group {
			id := textValue(entry.Transport["id"])
			position, exists := transportIndex[id]
			if !exists {
				position = len(transportGroups)
				transportIndex[id] = position
				transportGroups = append(transportGroups, transportGroup{entry: entry})
			}
			transportGroups[position].deployments = append(transportGroups[position].deployments, entry.Deployment)
		}
		for _, transport := range transportGroups {
			location, locationErr := nginxTransportLocation(transport.entry, transport.deployments, readSecret)
			if locationErr != nil {
				return "", locationErr
			}
			result.WriteString(location)
			if reused != nil && reused.TransportID == textValue(transport.entry.Transport["id"]) && containsDeployment(transport.deployments, reused.DeploymentID) {
				guard, guardErr := nginxOriginHeaderGuard([]map[string]any{findDeployment(transport.deployments, reused.DeploymentID)}, readSecret)
				if guardErr != nil {
					return "", guardErr
				}
				result.WriteString(nginxSubscriptionLocation(guard))
			}
		}
		result.WriteString("        include /opt/sb-gateway/templates/nginx-api-decoy.inc;\n    }\n")
	}
	return nginxSharedHTTP(config, result.String()), nil
}

func nginxRealityCoverServers(config map[string]any, defaultCert, defaultKey string, secretPath SecretPathResolver) (string, error) {
	profileNames := make(map[string][]string)
	nameProfiles := make(map[string]string)
	for _, transport := range enabledObjects(config["transports"]) {
		kind := textValue(transport["kind"])
		if RealityBackendPort(kind) == 0 || textValue(transport["cover_mode"]) != "api" {
			continue
		}
		profileID := textValue(transport["tls_profile_id"])
		for _, rawName := range append([]string{textValue(transport["server_name"])}, stringSlice(transport["server_names"])...) {
			name := strings.ToLower(strings.TrimSpace(rawName))
			if name == "" {
				continue
			}
			if old, exists := nameProfiles[name]; exists && old != profileID {
				return "", fmt.Errorf("REALITY API cover SNI %q uses conflicting TLS profiles", name)
			}
			nameProfiles[name] = profileID
			if !containsText(profileNames[profileID], name) {
				profileNames[profileID] = append(profileNames[profileID], name)
			}
		}
	}
	if len(profileNames) == 0 {
		return "", nil
	}
	var result strings.Builder
	fmt.Fprintf(&result, `    server {
        listen 127.0.0.1:%d ssl default_server;
        http2 on;
        server_name _;
        access_log off;
        error_log /logs/nginx/public-error.log crit;
        ssl_certificate %s;
        ssl_certificate_key %s;
        ssl_reject_handshake on;
    }
`, RealityCoverPort, defaultCert, defaultKey)
	profiles := make([]string, 0, len(profileNames))
	for profileID := range profileNames {
		profiles = append(profiles, profileID)
	}
	sort.Strings(profiles)
	for _, profileID := range profiles {
		cert, key, err := nginxTLSProfilePaths(config, profileID, secretPath)
		if err != nil {
			return "", err
		}
		names := profileNames[profileID]
		sort.Strings(names)
		fmt.Fprintf(&result, `    server {
        listen 127.0.0.1:%d ssl;
        http2 on;
        server_name %s;
        access_log off;
        error_log /logs/nginx/public-error.log crit;
        ssl_certificate %s;
        ssl_certificate_key %s;
        include /opt/sb-gateway/templates/nginx-api-decoy.inc;
    }
`, RealityCoverPort, strings.Join(names, " "), cert, key)
	}
	return result.String(), nil
}

func nginxTransportLocation(entry nginxDeployment, deployments []map[string]any, readSecret SecretReader) (string, error) {
	guard, err := nginxOriginHeaderGuard(deployments, readSecret)
	if err != nil {
		return "", err
	}
	field := "path_secret_ref"
	if entry.Kind == "grpc" {
		field = "service_name_secret_ref"
	}
	path, err := readSecret(textValue(entry.Transport[field]))
	if err != nil {
		return "", err
	}
	switch entry.Kind {
	case "ws":
		return fmt.Sprintf("        location = %s {\n            access_log off;\n%s            proxy_http_version 1.1;\n            proxy_set_header Upgrade $http_upgrade;\n            proxy_set_header Connection $connection_upgrade;\n            proxy_set_header Host $host;\n            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n            proxy_read_timeout 300s;\n            proxy_send_timeout 300s;\n            proxy_buffering off;\n            proxy_pass http://127.0.0.1:11001;\n        }\n", path, guard), nil
	case "grpc":
		return fmt.Sprintf("        location ^~ /%s/ {\n            access_log off;\n%s            grpc_set_header Host $host;\n            grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n            grpc_read_timeout 300s;\n            grpc_send_timeout 300s;\n            grpc_pass grpc://127.0.0.1:11002;\n        }\n", path, guard), nil
	case "httpupgrade":
		return fmt.Sprintf("        location = %s {\n            access_log off;\n%s            proxy_http_version 1.1;\n            proxy_set_header Upgrade $http_upgrade;\n            proxy_set_header Connection $connection_upgrade;\n            proxy_set_header Host $host;\n            proxy_read_timeout 300s;\n            proxy_send_timeout 300s;\n            proxy_buffering off;\n            proxy_pass http://127.0.0.1:11003;\n        }\n", path, guard), nil
	default:
		return fmt.Sprintf("        location ^~ %s {\n            access_log off;\n%s            proxy_http_version 1.1;\n            proxy_set_header Host $host;\n            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n            proxy_request_buffering off;\n            proxy_buffering off;\n            proxy_cache off;\n            proxy_read_timeout 300s;\n            proxy_send_timeout 300s;\n            proxy_pass http://127.0.0.1:11004;\n        }\n", path, guard), nil
	}
}

func containsDeployment(deployments []map[string]any, id string) bool {
	return findDeployment(deployments, id) != nil
}

func findDeployment(deployments []map[string]any, id string) map[string]any {
	for _, deployment := range deployments {
		if textValue(deployment["id"]) == id {
			return deployment
		}
	}
	return nil
}

func nginxOriginHeaderGuard(deployments []map[string]any, readSecret SecretReader) (string, error) {
	checks := make([][2]string, 0)
	for _, deployment := range deployments {
		if textValue(deployment["origin_protection_mode"]) != "secret-header" {
			continue
		}
		reference := textValue(deployment["origin_header_secret_ref"])
		if reference == "" {
			return "", fmt.Errorf("CDN deployment %q has no origin header secret", textValue(deployment["id"]))
		}
		value, err := readSecret(reference)
		if err != nil || value == "" {
			return "", fmt.Errorf("CDN deployment %q origin header secret is unavailable", textValue(deployment["id"]))
		}
		header := textDefault(deployment["origin_header_name"], "X-SB-Origin")
		if !regexpNginxHeaderName.MatchString(header) {
			return "", fmt.Errorf("CDN deployment %q origin header name is invalid", textValue(deployment["id"]))
		}
		header = strings.ReplaceAll(strings.ToLower(header), "-", "_")
		checks = append(checks, [2]string{"$http_" + header, nginxQuoted(value)})
	}
	if len(checks) == 0 {
		return "", nil
	}
	var result strings.Builder
	result.WriteString("            set $sb_origin_authenticated 0;\n")
	for _, check := range checks {
		fmt.Fprintf(&result, "            if (%s = %s) { set $sb_origin_authenticated 1; }\n", check[0], check[1])
	}
	result.WriteString("            if ($sb_origin_authenticated = 0) { return 404; }\n")
	return result.String(), nil
}

func nginxSingleHeaderGuard(header, reference string, readSecret SecretReader) (string, error) {
	if reference == "" {
		return "", errors.New("subscription origin header secret is not provisioned")
	}
	value, err := readSecret(reference)
	if err != nil || value == "" {
		return "", errors.New("subscription origin header secret is unavailable")
	}
	if !regexpNginxHeaderName.MatchString(header) {
		return "", errors.New("subscription origin header name is invalid")
	}
	header = strings.ReplaceAll(strings.ToLower(header), "-", "_")
	return fmt.Sprintf("            if ($http_%s != %s) { return 404; }\n", header, nginxQuoted(value)), nil
}

func nginxQuoted(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func nginxSubscriptionLocation(guard string) string {
	return fmt.Sprintf(`        location ~ "^/[A-Za-z0-9_-]{43,128}$" {
            access_log off;
            limit_except GET { deny all; }
%s            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_buffering off;
            proxy_intercept_errors on;
            add_header Cache-Control "no-store" always;
            add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
            proxy_pass http://127.0.0.1:8080;
        }
`, guard)
}

func validNginxHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !domainLabelPattern.MatchString(strings.ToLower(label)) {
			return false
		}
	}
	return true
}

func validNginxDNSHostname(host string) bool {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if strings.Contains(host, "*") || !validNginxHostname(host) {
		return false
	}
	_, err := netip.ParseAddr(host)
	return err != nil
}

func equalHostname(left, right string) bool {
	return strings.EqualFold(strings.TrimSuffix(left, "."), strings.TrimSuffix(right, "."))
}

func nginxDisabledHost(kind string) string {
	return map[string]string{"ws": "websocket-disabled.invalid", "grpc": "grpc-disabled.invalid", "httpupgrade": "httpupgrade-disabled.invalid", "xhttp": "xhttp-disabled.invalid"}[kind]
}

func nginxDisabledPath(kind string) string {
	if kind == "grpc" {
		return "disabled-grpc"
	}
	return "/disabled-" + map[string]string{"ws": "websocket", "httpupgrade": "httpupgrade", "xhttp": "xhttp"}[kind]
}

func nginxUnresolvedVariables(value string) []string {
	matches := regexpNginxVariable.FindAllStringSubmatch(value, -1)
	result := make([]string, 0, len(matches))
	seen := make(map[string]struct{})
	for _, match := range matches {
		if _, ok := seen[match[1]]; ok {
			continue
		}
		seen[match[1]] = struct{}{}
		result = append(result, match[1])
	}
	sort.Strings(result)
	return result
}
