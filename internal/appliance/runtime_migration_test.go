package appliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/controlplane"
)

func TestRunStopsBeforeCoreOnProbeContractMigrationFailure(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	generations := filepath.Join(state, "generations")
	if err := os.MkdirAll(generations, 0o700); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{
		"policies": []any{map[string]any{"id": "best", "mode": "best"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(config)
	revision := hex.EncodeToString(digest[:])
	active, err := json.Marshal(map[string]any{"revision": revision})
	if err != nil {
		t.Fatal(err)
	}
	nginx := filepath.Join(root, "nginx.conf")
	xray := filepath.Join(root, "xray.json")
	pool := filepath.Join(root, "urltest-pool.json")
	for path, body := range map[string][]byte{
		filepath.Join(generations, revision+".json"): config,
		filepath.Join(state, "active.json"):          active,
		nginx:                                        []byte("# sb-gateway-nginx-schema: 3\n    server {\n        listen 9080;\n        server_name _;\n        location = /traffic-ready { return 200; }\n        location / { return 404; }\n    }\n"),
		xray:                                         []byte(`{"inbounds":[]}`),
		pool:                                         []byte(`{"probe_budget":5,"health_policies":{"best":{"policy":{"probe_batch_size":2}}}}`),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// There is deliberately no committed node snapshot. A warning-and-continue
	// would let new workers target listeners that the preserved core lacks.
	opts := Options{
		NginxConfig: nginx,
		NginxBinary: filepath.Join(root, "must-not-start-nginx"),
		ControlPlane: controlplane.Options{
			StateDir: state, SecretsDir: filepath.Join(root, "secrets"),
			Runtime: controlplane.RuntimeOptions{XrayConfig: xray, XrayHealthPool: pool},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Run(ctx, opts); !errors.Is(err, controlplane.ErrProbeContractMigration) {
		t.Fatalf("startup did not stop on unsafe probe contract: %v", err)
	}
}
