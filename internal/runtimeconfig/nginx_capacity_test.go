package runtimeconfig

import (
	"strings"
	"testing"
)

func TestUpgradeNginxCapacity(t *testing.T) {
	for _, test := range []struct {
		name, body string
		warning    bool
	}{
		{"legacy", "worker_processes 1;\nevents { worker_connections 1024; }\nhttp { server { location / { return 404; } } }", false},
		{"formatted", "worker_processes\t1;\nevents\n{ # capacity\n worker_connections\n1024 ; }\nhttp { add_header X-Text 'worker_connections 1; { }'; }", false},
		{"missing", "events {} http {}", false},
		{"larger", "worker_rlimit_nofile 65536; events { worker_connections 16384; } http {}", false},
		{"bad value", "events { worker_connections invalid; }", true},
		{"ambiguous", "events { worker_connections 1024; worker_connections 512; }", true},
		{"bad blocks", "events {", true},
		{"included events", "events { include /custom-events.conf; }", true},
		{"included global", "include /custom-main.conf; events { worker_connections 1024; }", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := "# sb-gateway-nginx-schema: 3\n" + test.body
			updated, err := UpgradeNginxCapacity(original)
			if (err != nil) != test.warning {
				t.Fatalf("warning=%v", err)
			}
			if test.warning {
				if updated != original {
					t.Fatal("invalid config changed")
				}
				return
			}
			if !strings.HasPrefix(updated, "# sb-gateway-nginx-schema: 3\n") {
				t.Fatal("schema header lost")
			}
			if test.name == "larger" {
				if updated != original {
					t.Fatal("larger custom limit reduced")
				}
			} else if !strings.Contains(updated, "worker_connections 8192;") || !strings.Contains(updated, "worker_rlimit_nofile 16384;") {
				t.Fatal("capacity upgrade missing")
			}
			again, err := UpgradeNginxCapacity(updated)
			if err != nil || again != updated {
				t.Fatalf("non-idempotent: %v", err)
			}
		})
	}
}
