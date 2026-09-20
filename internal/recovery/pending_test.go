package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyPendingRestore(t *testing.T) {
	root := t.TempDir()
	options := Options{
		ConfigDir: filepath.Join(root, "config"),
		StateDir:  filepath.Join(root, "state"),
		DataDir:   filepath.Join(root, "data"),
	}
	operationID := "0123456789abcdef"
	staging := filepath.Join(options.DataDir, "recovery-staging", operationID)
	source := filepath.Join(staging, "state", "draft.json")
	payload := []byte("{\"schema_version\":1}\n")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	pending := map[string]any{
		"operation_id": operationID,
		"archive_name": "SB-GATEWAY-state-test.sbgw",
		"staging_path": staging,
		"manifest": map[string]any{"files": []any{map[string]any{
			"path": "state/draft.json", "size_bytes": len(payload), "sha256": hex.EncodeToString(digest[:]),
		}}},
	}
	if err := writeTestJSON(filepath.Join(options.ConfigDir, ".sb-gateway-recovery-pending.json"), pending); err != nil {
		t.Fatal(err)
	}
	result, err := ApplyPending(options)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Operation != "restored" || result.RestoredFiles != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	restored, err := os.ReadFile(filepath.Join(options.StateDir, "draft.json"))
	if err != nil || string(restored) != string(payload) {
		t.Fatalf("restored content mismatch: %q, %v", restored, err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatal("staging directory was not removed")
	}
	if _, err := os.Stat(filepath.Join(options.ConfigDir, ".sb-gateway-recovery-pending.json")); !os.IsNotExist(err) {
		t.Fatal("pending marker was not removed")
	}
}

func TestApplyPendingRejectsChecksumWithoutOverwriting(t *testing.T) {
	root := t.TempDir()
	options := Options{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), DataDir: filepath.Join(root, "data")}
	operationID := "0123456789abcdef"
	staging := filepath.Join(options.DataDir, "recovery-staging", operationID)
	source := filepath.Join(staging, "config", "gateway.yaml")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("unsafe"), 0o600); err != nil {
		t.Fatal(err)
	}
	pending := map[string]any{
		"operation_id": operationID, "staging_path": staging,
		"manifest": map[string]any{"files": []any{map[string]any{
			"path": "config/gateway.yaml", "size_bytes": 6, "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
		}}},
	}
	if err := writeTestJSON(filepath.Join(options.ConfigDir, ".sb-gateway-recovery-pending.json"), pending); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyPending(options); err == nil {
		t.Fatal("invalid checksum was accepted")
	}
	if _, err := os.Stat(filepath.Join(options.ConfigDir, "gateway.yaml")); !os.IsNotExist(err) {
		t.Fatal("invalid staged file overwrote the destination")
	}
}

func TestApplyPendingWithoutMarkerIsNoop(t *testing.T) {
	root := t.TempDir()
	result, err := ApplyPending(Options{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), DataDir: filepath.Join(root, "data")})
	if err != nil || !result.OK || result.Operation != "none" {
		t.Fatalf("unexpected no-op result: %#v, %v", result, err)
	}
}

func writeTestJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}
