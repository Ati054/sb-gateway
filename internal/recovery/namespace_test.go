package recovery

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

func TestCatalogRecoveryUnsetSecretsFollowFinalConfigDirectory(t *testing.T) {
	final, pending := bootRecoveryFixture(t)
	ref := bootRecoveryCatalog(t, pending, 1, 0)
	bootRecoverySave(t, final, pending)
	t.Setenv("SB_GATEWAY_CONFIG_DIR", filepath.Join(t.TempDir(), "initial-config"))
	t.Setenv("SB_GATEWAY_SECRETS_DIR", "")
	options := OptionsFromEnvironment()
	if options.SecretsDir != "" {
		t.Fatal("unset secret namespace was prematurely bound")
	}
	// Model a CLI config-dir override after reading environment defaults.
	options.ConfigDir, options.StateDir, options.DataDir = final.ConfigDir, final.StateDir, final.DataDir
	if result, err := ApplyPending(options); err != nil || !result.OK {
		t.Fatal("final configuration root lost default catalog namespace:", err)
	}
	reader, err := subscriptioncatalog.Open(filepath.Join(final.ConfigDir, "secrets", "subscription-catalogs"), ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if record, err := reader.Get(context.Background(), "node-00000"); err != nil || record.ID != "node-00000" {
		t.Fatal("default-relative catalog was not restored")
	}
}

func TestCatalogRecoveryExplicitCustomSecretEnvironmentRemainsGuarded(t *testing.T) {
	final, pending := bootRecoveryFixture(t)
	bootRecoveryCatalog(t, pending, 1, 0)
	bootRecoverySave(t, final, pending)
	t.Setenv("SB_GATEWAY_CONFIG_DIR", final.ConfigDir)
	t.Setenv("SB_GATEWAY_STATE_DIR", final.StateDir)
	t.Setenv("SB_GATEWAY_DATA_DIR", final.DataDir)
	t.Setenv("SB_GATEWAY_SECRETS_DIR", filepath.Join(final.ConfigDir, "private"))
	if _, err := ApplyPending(OptionsFromEnvironment()); err == nil {
		t.Fatal("explicit custom namespace silently fell back to default")
	}
}
