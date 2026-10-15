package runtimeconfig

import (
	"strings"
	"testing"
)

func TestCheckNginxStreamingLimits(t *testing.T) {
	for _, test := range []struct {
		name, config string
		warning      bool
	}{
		{"generated grpc", `location /grpc/ { client_max_body_size 0; client_body_timeout 300s; grpc_pass grpc://127.0.0.1:11002; }`, false},
		{"formatted xhttp", "location /stream {\n\tclient_max_body_size\t0 ; # unlimited\n client_body_timeout 5m;\n proxy_pass\n http://127.0.0.1:11004 ; }", false},
		{"missing body limit", `location /grpc/ { client_body_timeout 300s; grpc_pass grpc://127.0.0.1:11002; }`, true},
		{"missing body timeout", `location /stream { client_max_body_size 0; proxy_pass http://127.0.0.1:11004; }`, true},
		{"short body timeout", `location /stream { client_max_body_size 0; client_body_timeout 299s; proxy_pass http://127.0.0.1:11004; }`, true},
		{"limited body", `location /stream { client_max_body_size 2m; client_body_timeout 300s; proxy_pass http://127.0.0.1:11004; }`, true},
		{"bare seconds", `location /grpc/ { client_max_body_size 0; client_body_timeout 300; grpc_pass grpc://127.0.0.1:11002; }`, false},
		{"long timeout", `location /grpc/ { client_max_body_size 0; client_body_timeout 1h; grpc_pass grpc://127.0.0.1:11002; }`, false},
		{"inherited limits declared later", `location /grpc/ { grpc_pass grpc://127.0.0.1:11002; } client_max_body_size 0; client_body_timeout 300s;`, false},
		{"sibling limits do not apply", `location /other { client_max_body_size 0; client_body_timeout 300s; } location /grpc/ { grpc_pass grpc://127.0.0.1:11002; }`, true},
		{"nested location overrides", `location /outer { client_max_body_size 0; client_body_timeout 300s; location /inner { client_max_body_size 1m; grpc_pass grpc://127.0.0.1:11002; } }`, true},
		{"nested location inherits", `location /outer { client_max_body_size 0; client_body_timeout 300s; location /inner { grpc_pass grpc://127.0.0.1:11002; } }`, false},
		{"both transports checked", `location /grpc/ { client_max_body_size 0; client_body_timeout 300s; grpc_pass grpc://127.0.0.1:11002; } location /stream { proxy_pass http://127.0.0.1:11004; }`, true},
		{"comments cannot supply limits", "location /grpc/ {\n# client_max_body_size 0; client_body_timeout 300s; }\n grpc_pass grpc://127.0.0.1:11002; }", true},
		{"quoted fake limits", `location /grpc/ { add_header X-Test "client_max_body_size 0; client_body_timeout 300s; }"; grpc_pass grpc://127.0.0.1:11002; }`, true},
		{"quoted fake upstream", `location /panel { add_header X-Test "grpc_pass grpc://127.0.0.1:11002; }"; proxy_pass http://127.0.0.1:8080; }`, false},
		{"quoted values and delimiters", `location "/test#{};" { client_max_body_size '0'; client_body_timeout "5m"; grpc_pass 'grpc://127.0.0.1:11002'; add_header X-Test "escaped\"; }"; }`, false},
		{"variables and escapes", `location /panel { add_header X-Test ${request_uri}; add_header X-Escaped \{\#\;; proxy_pass http://127.0.0.1:8080; }`, false},
		{"management and upgrade unchanged", `location /panel { proxy_pass http://127.0.0.1:8080; } location /ws { proxy_pass http://127.0.0.1:11001; } location /upgrade { proxy_pass http://127.0.0.1:11003; }`, false},
		{"external include not assumed safe", `location /grpc/ { include /managed.inc; grpc_pass grpc://127.0.0.1:11002; }`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := "http { client_max_body_size 2m; server { " + test.config + " } }"
			for _, text := range []string{config, strings.ReplaceAll(config, "\n", "\r\n")} {
				if err := CheckNginxStreamingLimits(text); (err != nil) != test.warning {
					t.Fatalf("warning = %v, want %t", err, test.warning)
				}
			}
		})
	}
}

func TestCheckNginxStreamingLimitsDoesNotExposeConfig(t *testing.T) {
	for _, config := range []string{
		`http { server { location "/private-secret`,
		`http { server { location /private-secret {`,
		`http { server { private-secret } }`,
		`http { server { private-secret \`,
		`http { server { private-secret ${unfinished`,
		`http { server { ; } }`,
		`http { server { } } }`,
	} {
		if err := CheckNginxStreamingLimits(config); err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatalf("missing or unsafe warning: %v", err)
		}
	}
}

func FuzzCheckNginxStreamingLimits(f *testing.F) {
	f.Add(`http { server { location /grpc/ { grpc_pass grpc://127.0.0.1:11002; } } }`)
	f.Add(`location "/{#;" { add_header X-Value "escaped\"; }"; }`)
	f.Add("\\")
	f.Fuzz(func(t *testing.T, config string) { _ = CheckNginxStreamingLimits(config) })
}
