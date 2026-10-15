package controlplane

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupNginxWarnsOnNoncanonicalStreamingLimits(t *testing.T) {
	var output bytes.Buffer
	writer := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(writer) })
	for _, header := range []string{nginxSchema2Header, nginxSchema3Header} {
		for _, upstream := range []string{"grpc_pass grpc://127.0.0.1:11002;", "proxy_pass http://127.0.0.1:11004;"} {
			path := filepath.Join(t.TempDir(), "nginx.conf")
			probe := ""
			if header == nginxSchema3Header {
				probe = nginxTrafficReady
			}
			original := header + "\nhttp {\n" + nginxInternalStart + probe + nginxInternalTail + "    }\nserver { location /private-secret/ {\n # deliberately noncanonical spacing\n\t" + upstream + "\n} }\n}\n"
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			output.Reset()
			changed, err := EnsureStartupNginxTrafficReadiness(path)
			if err != nil || changed != (header == nginxSchema2Header) {
				t.Fatalf("startup result = %t, %v", changed, err)
			}
			if !strings.Contains(output.String(), "startup Nginx streaming limits warning:") || !strings.Contains(output.String(), "Check and Apply") || strings.Contains(output.String(), "private-secret") {
				t.Fatalf("missing or unsafe startup warning: %s", output.String())
			}
			updated := string(mustReadFile(t, path))
			if !strings.Contains(updated, "location /private-secret/ {\n # deliberately noncanonical spacing\n\t"+upstream) || strings.Contains(updated, "client_max_body_size 0;") {
				t.Fatal("noncanonical transport was silently rewritten")
			}
			fixed := strings.Replace(updated, "\t"+upstream, "\tclient_max_body_size 0;\n\tclient_body_timeout 300s;\n\t"+upstream, 1)
			if err := os.WriteFile(path, []byte(fixed), 0600); err != nil {
				t.Fatal(err)
			}
			output.Reset()
			if changed, err := EnsureStartupNginxTrafficReadiness(path); err != nil || changed || output.Len() != 0 {
				t.Fatalf("fixed config still warned or changed: %t, %v, %s", changed, err, output.String())
			}
		}
	}
}

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

func TestStartupNginxCapacityUpgradesWithoutApply(t *testing.T) {
	for _, header := range []string{nginxSchema2Header, nginxSchema3Header} {
		for _, newline := range []string{"\n", "\r\n"} {
			path := filepath.Join(t.TempDir(), "nginx.conf")
			probe := ""
			if header == nginxSchema3Header {
				probe = nginxTrafficReady
			}
			original := header + "\nworker_processes 1;\nevents {\n\tworker_connections\n 1024 ; # old capacity\n}\nhttp {\n" + nginxInternalStart + probe + nginxInternalTail + "    }\n}\n"
			original = strings.ReplaceAll(original, "\n", newline)
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			if changed, err := EnsureStartupNginxTrafficReadiness(path); err != nil || !changed {
				t.Fatalf("migration=%t %v", changed, err)
			}
			updated := string(mustReadFile(t, path))
			if !strings.Contains(updated, "worker_connections 8192;") || !strings.Contains(updated, "worker_rlimit_nofile 16384;") || !strings.Contains(updated, "# old capacity") {
				t.Fatal("capacity not upgraded or adjacent text lost")
			}
			if changed, err := EnsureStartupNginxTrafficReadiness(path); err != nil || changed {
				t.Fatalf("second startup=%t %v", changed, err)
			}
		}
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
