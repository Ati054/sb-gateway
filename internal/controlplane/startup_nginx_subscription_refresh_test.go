package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupNginxUpgradesSubscriptionRefreshWithoutApply(t *testing.T) {
	for _, header := range []string{nginxSchema2Header, nginxSchema3Header} {
		for _, newline := range []string{"\n", "\r\n"} {
			path := filepath.Join(t.TempDir(), "nginx.conf")
			probe := ""
			if header == nginxSchema3Header {
				probe = nginxTrafficReady
			}
			ordinary := `location /api/ { proxy_set_header Authorization $http_authorization; proxy_pass http://127.0.0.1:8080; }`
			original := header + "\nhttp { server { listen\n9443 ssl; " + ordinary + " }\n" + nginxInternalStart + probe + nginxInternalTail + "    }\n}\n"
			original = strings.ReplaceAll(original, "\n", newline)
			if err := os.WriteFile(path, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			if changed, err := EnsureStartupNginxTrafficReadiness(path); err != nil || !changed {
				t.Fatalf("startup upgrade: %t %v", changed, err)
			}
			updated := string(mustReadFile(t, path))
			if !strings.Contains(updated, ordinary) || strings.Count(updated, "proxy_read_timeout 180s;") != 1 || strings.Count(updated, "Authorization $http_authorization;") != 2 {
				t.Fatal("startup refresh policy missing or ordinary policy changed")
			}
			if changed, err := EnsureStartupNginxTrafficReadiness(path); err != nil || changed {
				t.Fatalf("second startup: %t %v", changed, err)
			}
		}
	}
}
