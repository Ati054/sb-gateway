package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestPinnedXrayGeoIPCandidateValidation(t *testing.T) {
	binary := os.Getenv("SB_TEST_XRAY")
	if binary == "" {
		t.Skip("set SB_TEST_XRAY to the pinned Xray binary for the native GeoIP check")
	}
	root := t.TempDir()
	assets := filepath.Join(root, "rulesets")
	reference, err := geoipasset.Publish(assets, "geoip-ru", []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
		"routing": map[string]any{"rules": []any{map[string]any{
			"type": "field", "ip": []string{reference}, "outboundTag": "direct",
		}}},
	}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(root, "live.json")
	baseline := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	if err := os.WriteFile(live, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "candidates"), map[string]string{"xray.json": live})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := store.Prepare(strings.Repeat("c", 64), map[string][]byte{"xray.json": body})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_LOCATION_ASSET", filepath.Join(root, "wrong-inherited-assets"))
	controller := &recordingRuntimeController{}
	r := &nativeRuntime{store: store, controller: controller, options: RuntimeOptions{
		XrayBinary: binary, RuleSetDir: assets, XrayConfig: live,
		ApplyGuardFile: filepath.Join(root, "apply-guard"),
	}}
	r.validate = r.validateCandidate
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := r.validateCandidate(ctx, candidate, []string{"xray.json"}); err != nil {
		t.Fatalf("configured GeoIP assets did not override inherited lookup: %v", err)
	}
	name, valid := geoipasset.ReferenceName(reference)
	if !valid {
		t.Fatal("invalid generated reference")
	}
	if err := os.Remove(filepath.Join(assets, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.activate(ctx, candidate); err == nil || !strings.Contains(err.Error(), "failed to open") {
		t.Fatalf("missing GeoIP asset did not reject activation through validation: %v", err)
	}
	if current, err := os.ReadFile(live); err != nil || string(current) != string(baseline) {
		t.Fatalf("invalid candidate replaced live configuration: %v", err)
	}
	if len(controller.restarts) != 0 || len(controller.probes) != 0 {
		t.Fatalf("rejected candidate disturbed live processes: restarts=%v probes=%v", controller.restarts, controller.probes)
	}
}
