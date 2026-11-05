package controlplane

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	recoveryboot "github.com/sb-gateway/sb-gateway/internal/recovery"
)

func recoveryPrivateSecretsFixture(t *testing.T, server *Server) {
	t.Helper()
	server.opts.SecretsDir = filepath.Join(filepath.Dir(server.opts.SecretsDir), "private")
	store, err := newSecretStore(server.opts.SecretsDir)
	if err != nil {
		t.Fatal(err)
	}
	server.secrets = store
	if err := store.write("management-api-token", "management-test-token", false); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryLegacyReservedSecretNamespacesFailBeforeArchivePublication(t *testing.T) {
	for _, namespace := range []string{"generated", "rulesets", catalogCompatDirectory} {
		t.Run(namespace, func(t *testing.T) {
			server, root := newRecoveryTestServer(t)
			server.opts.SecretsDir = filepath.Join(root, "config", namespace)
			store, err := newSecretStore(server.opts.SecretsDir)
			if err != nil {
				t.Fatal(err)
			}
			server.secrets = store
			if err := store.write("management-api-token", "management-test-token", false); err != nil {
				t.Fatal(err)
			}
			_, _ = bootstrapSession(t, server)
			if err := store.write("tls/.pending-key", "synthetic-private-material", false); err != nil {
				t.Fatal(err)
			}
			configRoot, _, _ := server.recoveryRoots()
			if _, err := collectRecoveryFilesWithSecrets(configRoot, server.opts.SecretsDir, server.opts.StateDir, server.opts.DataDir); !errors.Is(err, errReservedSecretsNamespace) {
				t.Fatal("reserved namespace silently produced a partial legacy inventory:", err)
			}
			if _, err := server.createRecoveryArchive(); !errors.Is(err, errReservedSecretsNamespace) {
				t.Fatal("reserved namespace emitted a nominally usable legacy archive:", err)
			}
			entries, err := os.ReadDir(filepath.Join(root, "data", "recovery-backups"))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatal("reserved export published an archive")
			}
			if value, err := store.read("tls/.pending-key", true); err != nil || value != "synthetic-private-material" {
				t.Fatal("refused export changed the live secret")
			}
		})
	}
}

func TestRecoveryCatalogCustomSecretsExportFailsBeforeArchivePublication(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	recoveryPrivateSecretsFixture(t, server)
	_, _ = bootstrapSession(t, server)
	ref := recoveryCatalogFixture(t, server, 1, 0)
	recoveryCatalogRootState(t, server, ref)
	if _, err := server.createRecoveryArchive(); !errors.Is(err, errRecoveryCatalogSecretsNamespace) {
		t.Fatal("custom catalog namespace emitted an unusable archive:", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "data", "recovery-backups"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed custom export published an archive")
	}
	if _, err := os.Stat(filepath.Join(server.secrets.subscriptionCatalogRoot(), ref.Generation, "records.bin")); err != nil {
		t.Fatal("failed export changed live catalog")
	}
}

func TestRecoveryCatalogCustomSecretsRejectsEncryptedRestoreBeforePending(t *testing.T) {
	source, sourceRoot := newRecoveryTestServer(t)
	_, _ = bootstrapSession(t, source)
	ref := recoveryCatalogFixture(t, source, 1, 0)
	recoveryCatalogRootState(t, source, ref)
	archive, err := source.createRecoveryArchive()
	if err != nil {
		t.Fatal(err)
	}
	target, _ := newRecoveryTestServer(t)
	recoveryPrivateSecretsFixture(t, target)
	archivePath := filepath.Join(sourceRoot, "data", "recovery-backups", archive.Name)
	if _, _, err := target.stageRecoveryArchive(archivePath, archive.Name, "panel-password-123"); !errors.Is(err, errRecoveryCatalogSecretsNamespace) {
		t.Fatal("schema3 restore staged into a different secret namespace:", err)
	}
	configRoot, _, _ := target.recoveryRoots()
	if _, err := os.Lstat(filepath.Join(configRoot, ".sb-gateway-recovery-pending.json")); !os.IsNotExist(err) {
		t.Fatal("rejected custom restore published pending state")
	}
}

func TestRecoveryCatalogCustomSecretsBootRejectsExistingPendingBeforeMutation(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	_, _ = bootstrapSession(t, server)
	ref := recoveryCatalogFixture(t, server, 1, 0)
	recoveryCatalogRootState(t, server, ref)
	archive, err := server.createRecoveryArchive()
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "data", "recovery-backups", archive.Name)
	if _, _, err := server.stageRecoveryArchive(archivePath, archive.Name, "panel-password-123"); err != nil {
		t.Fatal(err)
	}
	configRoot, _, _ := server.recoveryRoots()
	marker := filepath.Join(configRoot, "gateway.yaml")
	if err := os.WriteFile(marker, []byte("preserve-current-configuration"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoveryboot.ApplyPending(recoveryboot.Options{ConfigDir: configRoot, SecretsDir: filepath.Join(configRoot, "private"), StateDir: server.opts.StateDir, DataDir: server.opts.DataDir}); err == nil {
		t.Fatal("boot applied schema3 into wrong secret namespace")
	}
	body, err := os.ReadFile(marker)
	if err != nil || string(body) != "preserve-current-configuration" {
		t.Fatal("rejected boot restore changed authoritative config")
	}
	if _, err := os.Stat(filepath.Join(configRoot, ".sb-gateway-recovery-pending.json")); err != nil {
		t.Fatal("rejected boot restore discarded pending recovery evidence")
	}
}
