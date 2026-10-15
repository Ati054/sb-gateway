package runtimeconfig

import "strings"

const nginxStreamingLimits = "            client_max_body_size 0;\n            client_body_timeout 300s;\n"

// UpgradeNginxStreamingLimits updates only the canonical generated transport
// locations. Persisted schema-3 configurations also need this on image startup.
func UpgradeNginxStreamingLimits(config string) string {
	for _, transport := range []struct{ timeout, upstream string }{
		{"grpc_send_timeout 300s;", "grpc_pass grpc://127.0.0.1:11002;"},
		{"proxy_send_timeout 300s;", "proxy_pass http://127.0.0.1:11004;"},
	} {
		old := transport.timeout + "\n            " + transport.upstream
		updated := transport.timeout + "\n" + nginxStreamingLimits + "            " + transport.upstream
		config = strings.ReplaceAll(config, old, updated)
	}
	return config
}
