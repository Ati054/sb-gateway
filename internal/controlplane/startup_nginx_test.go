package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureStartupNginxTrafficReadinessMigratesOnlyInternalProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nginx.conf")
	original := nginxSchema2Header + `
http {
    server {
        listen 9443 ssl;
        location = /healthz { proxy_pass http://127.0.0.1:8080/api/health/router-ready; }
        location = /traffic-ready { proxy_pass http://127.0.0.1:8080/api/health/traffic-ready; }
    }
    server {
        listen 9080;
        server_name _;
        location = /healthz {
            proxy_pass http://127.0.0.1:8080/api/health/router-ready;
        }
        location / { return 404; }
    }
}
`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := EnsureStartupNginxTrafficReadiness(path)
	if err != nil || !migrated {
		t.Fatalf("migration = %t, %v", migrated, err)
	}
	result := string(mustReadFile(t, path))
	if !strings.HasPrefix(result, nginxSchema3Header+"\n") || strings.Count(result, "location = /traffic-ready") != 2 {
		t.Fatalf("migrated config = %s", result)
	}
	if !strings.Contains(result, "listen 9443 ssl;") || strings.Count(result, "location = /healthz") != 2 {
		t.Fatalf("public or health listeners changed: %s", result)
	}
	migrated, err = EnsureStartupNginxTrafficReadiness(path)
	if err != nil || migrated {
		t.Fatalf("idempotent migration = %t, %v", migrated, err)
	}
}

func TestEnsureStartupNginxTrafficReadinessRejectsAmbiguousLegacyConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nginx.conf")
	original := nginxSchema2Header + "\nhttp {\n" + nginxInternalStart + nginxTrafficReady + nginxTrafficReady + nginxInternalTail + "    }\n}\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if migrated, err := EnsureStartupNginxTrafficReadiness(path); err == nil || migrated {
		t.Fatalf("ambiguous migration = %t, %v", migrated, err)
	}
	if result := string(mustReadFile(t, path)); result != original {
		t.Fatal("ambiguous source was modified")
	}
}

func TestEnsureStartupNginxUpgradesStreamingWithoutApply(t *testing.T) {
	for _, header := range []string{nginxSchema2Header, nginxSchema3Header} {
		t.Run(header, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nginx.conf")
			probe := ""
			if header == nginxSchema3Header {
				probe = nginxTrafficReady
			}
			original := header + "\nhttp {\nclient_max_body_size 2m;\n" + nginxInternalStart + probe + nginxInternalTail + "    }\nserver { location /Tunnel/ {\n            grpc_send_timeout 300s;\n            grpc_pass grpc://127.0.0.1:11002;\n} }\n}\n"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			if changed, err := EnsureStartupNginxTrafficReadiness(path); err != nil || !changed {
				t.Fatalf("startup upgrade: %t %v", changed, err)
			}
			updated := string(mustReadFile(t, path))
			if strings.Count(updated, "client_max_body_size 0;") != 1 || !strings.Contains(updated, "client_max_body_size 2m;") || !strings.Contains(updated, "client_body_timeout 300s;") {
				t.Fatal("missing or overbroad streaming migration")
			}
			if changed, err := EnsureStartupNginxTrafficReadiness(path); err != nil || changed {
				t.Fatalf("second startup: %t %v", changed, err)
			}
		})
	}
}

func TestEnsureStartupNginxTrafficReadinessNormalizesCRLF(t *testing.T) {
	for _, header := range []string{nginxSchema2Header, nginxSchema3Header} {
		t.Run(header, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nginx.conf")
			probe := ""
			if header == nginxSchema3Header {
				probe = nginxTrafficReady
			}
			original := header + "\nhttp {\n" + nginxInternalStart + probe + nginxInternalTail + "    }\n}\n"
			original = strings.ReplaceAll(original, "\n", "\r\n")
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			changed, err := EnsureStartupNginxTrafficReadiness(path)
			if err != nil || !changed {
				t.Fatalf("CRLF migration = %t, %v", changed, err)
			}
			result := string(mustReadFile(t, path))
			if strings.Contains(result, "\r") || !strings.HasPrefix(result, nginxSchema3Header+"\n") || strings.Count(result, "location = /traffic-ready") != 1 {
				t.Fatal("CRLF config was not normalized and upgraded")
			}
			if changed, err = EnsureStartupNginxTrafficReadiness(path); err != nil || changed {
				t.Fatalf("second migration = %t, %v", changed, err)
			}
		})
	}
}

func TestEnsureStartupNginxTrafficReadinessPreservesInvalidCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nginx.conf")
	original := nginxSchema3Header + "\nhttp {\n" + nginxInternalStart + nginxTrafficReady + nginxTrafficReady + nginxInternalTail + "    }\n}\n"
	original = strings.ReplaceAll(original, "\n", "\r\n")
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := EnsureStartupNginxTrafficReadiness(path); err == nil || changed {
		t.Fatalf("invalid CRLF migration = %t, %v", changed, err)
	}
	if result := string(mustReadFile(t, path)); result != original {
		t.Fatal("invalid CRLF config was modified")
	}
}
