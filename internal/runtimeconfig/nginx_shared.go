package runtimeconfig

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

func originGeoName(p OriginPolicy) string {
	sum := sha256.Sum256([]byte(p.Boundary()))
	return fmt.Sprintf("sb_origin_%x", sum[:8])
}

// IP checks use the transport peer, never client-supplied HTTP headers.
func nginxOriginMaps(config map[string]any, root string) string {
	if root == "" {
		root = "/state/control-plane/cdn-origin"
	}
	shared := SharedOriginPorts(config)
	seen := map[string]bool{}
	var out strings.Builder
	out.WriteString("    map $ssl_server_name $sb_origin_sni {\n        hostnames;\n        default \"\";\n")
	for _, p := range OriginPolicies(config) {
		if !seen[p.Host] {
			fmt.Fprintf(&out, "        %s %s;\n", p.Host, p.Host)
			seen[p.Host] = true
		}
	}
	out.WriteString("    }\n")
	seen = map[string]bool{}
	for _, p := range OriginPolicies(config) {
		if !shared[p.Port] || (p.Mode != "auto-cidr" && p.Mode != "manual-cidr") {
			continue
		}
		name := originGeoName(p)
		if seen[name] {
			continue
		}
		seen[name] = true
		fmt.Fprintf(&out, "    geo $remote_addr $%s {\n        default 0;\n", name)
		if p.Mode == "auto-cidr" {
			fmt.Fprintf(&out, "        include %s;\n", nginxQuoted(filepath.ToSlash(filepath.Join(root, p.Provider, "addresses.conf"))))
		} else {
			for _, cidr := range p.CIDRs {
				fmt.Fprintf(&out, "        %s 1;\n", cidr)
			}
		}
		out.WriteString("    }\n")
	}
	return out.String()
}

func nginxOriginHostGuard(config map[string]any, port int, host string) string {
	for _, p := range OriginPolicies(config) {
		if p.Port != port || !equalHostname(p.Host, host) {
			continue
		}
		guard := fmt.Sprintf("        if ($sb_origin_sni != %s) { return 421; }\n", nginxQuoted(p.Host))
		if SharedOriginPorts(config)[port] && (p.Mode == "auto-cidr" || p.Mode == "manual-cidr") {
			guard += fmt.Sprintf("        if ($%s = 0) { return 403; }\n", originGeoName(p))
		}
		return guard
	}
	return ""
}

func nginxSharedStream(config map[string]any) string {
	if !Shared443(config) {
		return ""
	}
	routes := map[string]string{}
	for _, p := range OriginPolicies(config) {
		if p.Port == 443 {
			routes[p.Host] = "127.0.0.1:16443"
		}
	}
	for _, t := range enabledObjects(config["transports"]) {
		port, _ := requiredInteger(t["listen_port"])
		backend := RealityBackendPort(textValue(t["kind"]))
		if port != 443 || backend == 0 {
			continue
		}
		for _, name := range append([]string{textValue(t["server_name"])}, stringSlice(t["server_names"])...) {
			routes[strings.ToLower(strings.TrimSpace(name))] = fmt.Sprintf("127.0.0.1:%d", backend)
		}
	}
	if len(routes) == 0 {
		return ""
	}
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	out.WriteString("load_module /usr/lib/nginx/modules/ngx_stream_module.so;\nstream {\n    map $ssl_preread_server_name $sb_tls_backend {\n        hostnames;\n        default 127.0.0.1:16447;\n")
	for _, name := range names {
		fmt.Fprintf(&out, "        %s %s;\n", name, routes[name])
	}
	out.WriteString("    }\n    server {\n        listen 127.0.0.1:16447;\n        return \"\";\n    }\n    server {\n        listen 443;\n        ssl_preread on;\n        preread_timeout 10s;\n        preread_buffer_size 32k;\n        proxy_connect_timeout 5s;\n        proxy_timeout 300s;\n        proxy_socket_keepalive on;\n        proxy_protocol on;\n        proxy_pass $sb_tls_backend;\n    }\n}\n")
	return out.String()
}

func nginxSharedHTTP(config map[string]any, source string) string {
	if !Shared443(config) {
		return source
	}
	source = strings.ReplaceAll(source, "listen 443 ssl", "listen 127.0.0.1:16443 ssl proxy_protocol")
	// Trust PROXY only on the loopback listener owned by the stream proxy.
	lines := strings.Split(source, "\n")
	for index, line := range lines {
		if strings.Contains(line, "listen 127.0.0.1:16443") {
			lines[index] += "\n        set_real_ip_from 127.0.0.1;\n        real_ip_header proxy_protocol;"
		}
	}
	source = strings.Join(lines, "\n")
	return source
}
