package runtimeconfig

import (
	"strings"
	"testing"
)

func TestTransportStreamingLimits(t *testing.T) {
	for _, kind := range []string{"grpc", "xhttp", "ws", "httpupgrade"} {
		t.Run(kind, func(t *testing.T) {
			entry := nginxDeployment{Kind: kind, Transport: map[string]any{"path_secret_ref": "path", "service_name_secret_ref": "service"}}
			location, err := nginxTransportLocation(entry, nil, func(ref string) (string, error) {
				if ref == "service" {
					return "Tunnel", nil
				}
				return "/stream", nil
			})
			if err != nil {
				t.Fatal(err)
			}
			streaming := kind == "grpc" || kind == "xhttp"
			if strings.Contains(location, nginxStreamingLimits) != streaming {
				t.Fatalf("unexpected streaming overrides for %s: %s", kind, location)
			}
		})
	}
}

func TestUpgradeNginxStreamingLimits(t *testing.T) {
	legacy := "client_max_body_size 2m;\n            grpc_send_timeout 300s;\n            grpc_pass grpc://127.0.0.1:11002;\n            proxy_send_timeout 300s;\n            proxy_pass http://127.0.0.1:11004;\n            proxy_send_timeout 300s;\n            proxy_pass http://127.0.0.1:8080;\n"
	updated := UpgradeNginxStreamingLimits(legacy)
	if strings.Count(updated, nginxStreamingLimits) != 2 || !strings.HasPrefix(updated, "client_max_body_size 2m;") {
		t.Fatal("transport migration changed global limit or missed a transport")
	}
	if UpgradeNginxStreamingLimits(updated) != updated {
		t.Fatal("transport migration is not idempotent")
	}
	if !strings.HasSuffix(updated, "            proxy_send_timeout 300s;\n            proxy_pass http://127.0.0.1:8080;\n") {
		t.Fatal("management upstream changed")
	}
}
