package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogCompatibilityIgnoresUnrelatedDataWithoutChangingIt(t *testing.T) {
	roots := syntheticCompatRoots(t)
	id := strings.Repeat("7", 64)
	writeCompatFixture(t, roots.Config, "generated/xray.json", []byte(`{"legacy":true}`))
	writeCompatFixture(t, roots.Config, "secrets/admin-password-hash", []byte("synthetic-admin"))
	writeCompatFixture(t, roots.Config, "secrets/session-signing-key", []byte("synthetic-session"))
	writeCompatFixture(t, roots.Config, "rulesets/geoip.dat", []byte("synthetic-ruleset"))
	writeCompatFixture(t, roots.State, "control-plane/apply-metadata.json", []byte(`{"revision":"legacy"}`))
	writeCompatFixture(t, roots.State, "control-plane/subscription-nodes.json", []byte(`{"source":{"nodes":[{"id":"preserved"}]}}`))
	writeCompatFixture(t, roots.Data, "last-known-good/xray.json", []byte(`{"legacy":true}`))
	artifact := filepath.Join(roots.Data, "unrelated-opaque.bin")
	file, err := os.OpenFile(artifact, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(catalogCompatMaxFileBytes + 4096); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("unchanged"), 0); err != nil {
		file.Close()
		t.Fatal(err)
	}
	before, err := file.Stat()
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	files, err := buildCatalogCompatSnapshot(context.Background(), roots, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 7 {
		t.Fatalf("essential product files omitted: %d", len(files))
	}
	for _, item := range files {
		if item.Area == "data" && !strings.HasPrefix(item.Path, "last-known-good/") {
			t.Fatal("unrelated data was copied")
		}
	}
	if _, err := os.Lstat(filepath.Join(roots.Data, catalogCompatDirectory, id, "data/unrelated-opaque.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unrelated artifact entered baseline")
	}
	after, err := os.Stat(artifact)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		t.Fatal("unrelated artifact changed")
	}
	file, err = os.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var marker [9]byte
	_, err = file.ReadAt(marker[:], 0)
	file.Close()
	if err != nil || string(marker[:]) != "unchanged" {
		t.Fatal("unrelated contents changed")
	}
	if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, true); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogCompatibilityPreservesAtomicWorkerHistory(t *testing.T) {
	roots := syntheticCompatRoots(t)
	id := strings.Repeat("8", 64)
	old := []byte(`{"samples":[1,2,3],"revision":"old"}`)
	updated := []byte(`{"samples":[4,5,6],"revision":"new"}`)
	relative := "control-plane/selector-health.json"
	source := filepath.Join(roots.State, filepath.FromSlash(relative))
	writeCompatFixture(t, roots.State, relative, old)
	writeCompatFixture(t, roots.State, "control-plane/active.json", []byte(`{"revision":"legacy"}`))
	start, done := make(chan struct{}), make(chan error, 1)
	go func() { <-start; done <- writeAtomic(source, updated, 0600, false) }()
	files, err := buildCatalogCompatSnapshotObserved(context.Background(), roots, id, catalogCompatSnapshotHooks{beforeValidate: func() {
		close(start)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}})
	if err != nil {
		t.Fatal("normal atomic worker update rejected baseline:", err)
	}
	saved, err := os.ReadFile(filepath.Join(roots.State, catalogCompatDirectory, id, "state", filepath.FromSlash(relative)))
	if err != nil || !bytes.Equal(saved, old) {
		t.Fatal("complete point-in-time worker history not preserved")
	}
	current, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(current, updated) {
		t.Fatal("live worker history changed")
	}
	if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, true); err != nil {
		t.Fatal(err)
	}
	writeCompatFixture(t, roots.State, filepath.Join(catalogCompatDirectory, id, "state", relative), []byte(`{"corrupt":true}`))
	if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, false); err == nil {
		t.Fatal("worker copy corruption accepted")
	}
}

func TestCatalogCompatibilityOmitsOnlyUnstableWorkerCopy(t *testing.T) {
	for _, operation := range []string{"append", "overwrite", "invalid"} {
		t.Run(operation, func(t *testing.T) {
			roots := syntheticCompatRoots(t)
			id := strings.Repeat("9", 64)
			relative := "control-plane/selector-health.json"
			source := filepath.Join(roots.State, filepath.FromSlash(relative))
			writeCompatFixture(t, roots.State, relative, []byte(`{"samples":[1,2,3]}`))
			writeCompatFixture(t, roots.State, "control-plane/subscription-nodes.json", []byte(`{"preserved":true}`))
			files, err := buildCatalogCompatSnapshotObserved(context.Background(), roots, id, catalogCompatSnapshotHooks{afterOpen: func(area, path string) {
				if area != "state" || path != relative {
					return
				}
				var err error
				switch operation {
				case "append":
					var f *os.File
					f, err = os.OpenFile(source, os.O_APPEND|os.O_WRONLY, 0600)
					if err == nil {
						_, err = f.Write([]byte(" appended"))
						f.Close()
					}
				case "overwrite":
					err = os.WriteFile(source, []byte(`{"different":"longer contents"}`), 0600)
				case "invalid":
					err = os.WriteFile(source, []byte(`{"samples":xxxxxxxx`), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 1 || files[0].Path != "control-plane/subscription-nodes.json" {
				t.Fatal("unstable cache retained or essential state omitted")
			}
			if _, err := os.Lstat(filepath.Join(roots.State, catalogCompatDirectory, id, "state", filepath.FromSlash(relative))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unstable stage cache remains visible")
			}
		})
	}
}

func TestCatalogCompatibilityStillRejectsCriticalSourceMutation(t *testing.T) {
	roots := syntheticCompatRoots(t)
	id := strings.Repeat("a", 64)
	writeCompatFixture(t, roots.State, "control-plane/active.json", []byte(`{"revision":"old"}`))
	_, err := buildCatalogCompatSnapshotObserved(context.Background(), roots, id, catalogCompatSnapshotHooks{beforeValidate: func() { writeCompatFixture(t, roots.State, "control-plane/active.json", []byte(`{"revision":"new"}`)) }})
	var classified catalogCompatSnapshotFailure
	if !errors.As(err, &classified) || classified.stage != "snapshot-source-verify" || !errors.Is(err, errCatalogCompatibility) {
		t.Fatal("critical source change accepted or stage lost")
	}
	if strings.Contains(err.Error(), roots.State) || strings.Contains(err.Error(), "active.json") {
		t.Fatal("private source path leaked in error")
	}
}

func TestCatalogCompatibilityVolatileStatePlacement(t *testing.T) {
	roots := catalogCompatRoots{}
	if !roots.volatile("control-plane/selector-health.json") || roots.volatile("control-plane/generations/selector-health.json") || roots.volatile("selector-health.json") || roots.volatile("control-plane/subscription-nodes.json") {
		t.Fatal("volatile classification crossed authoritative boundary")
	}
	roots.ControlPlaneRelative = "."
	if !roots.volatile("selector-health.json") || roots.volatile("control-plane/selector-health.json") {
		t.Fatal("custom state root not respected")
	}
}

func TestCatalogCompatibilityOmitsOversizedWorkerTokenWithoutOmittingAuthority(t *testing.T) {
	roots := syntheticCompatRoots(t)
	id := strings.Repeat("c", 64)
	writeCompatFixture(t, roots.State, "control-plane/selector-health.json", []byte(`{"optional":"`+strings.Repeat("x", (1<<20)+1)+`"}`))
	writeCompatFixture(t, roots.State, "control-plane/active.json", []byte(`{"revision":"legacy"}`))
	files, err := buildCatalogCompatSnapshot(context.Background(), roots, id)
	if err != nil || len(files) != 1 || files[0].Path != "control-plane/active.json" {
		t.Fatal("optional oversized cache token affected authoritative snapshot:", err)
	}
}

func TestCatalogCompatibilitySkipsOnlyRecognizedAtomicScratchBeforeStat(t *testing.T) {
	for _, operation := range []string{"disappear", "change"} {
		t.Run(operation, func(t *testing.T) {
			roots := syntheticCompatRoots(t)
			id := strings.Repeat("d", 64)
			scratch := []string{".selector-health.json.123456789.tmp", ".client-telemetry.json.123456789.tmp", ".apply-operation.json.123456789.tmp", ".selector-health.json.7.tmp"}
			for _, name := range scratch {
				writeCompatFixture(t, roots.State, "control-plane/"+name, []byte("unfinished"))
			}
			for _, name := range []string{"active.json", ".keep-note.tmp", ".selector-health.json.not-a-counter.tmp"} {
				writeCompatFixture(t, roots.State, "control-plane/"+name, []byte(`{"preserved":true}`))
			}
			seen := 0
			files, err := buildCatalogCompatSnapshotObserved(context.Background(), roots, id, catalogCompatSnapshotHooks{beforeEntry: func(area, relative string) {
				if area != "state" || !recoveryAtomicTemporaryBasename(filepath.Base(relative)) {
					return
				}
				seen++
				target := filepath.Join(roots.State, filepath.FromSlash(relative))
				if operation == "disappear" {
					if err := os.Remove(target); err != nil {
						t.Fatal(err)
					}
				} else {
					file, err := os.OpenFile(target, os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					err = file.Truncate(catalogCompatMaxFileBytes + 1)
					file.Close()
					if err != nil {
						t.Fatal(err)
					}
				}
			}})
			if err != nil || seen != len(scratch) {
				t.Fatal("atomic scratch raced compatibility collection:", err)
			}
			if len(files) != 3 {
				t.Fatalf("authoritative or nonmatching dotfile lost: %d", len(files))
			}
			for _, item := range files {
				if recoveryAtomicTemporaryBasename(filepath.Base(item.Path)) {
					t.Fatal("scratch copied")
				}
			}
			if err := validateCatalogCompatSnapshot(context.Background(), roots, id, files, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCatalogCompatibilityAndRecoveryPreserveScratchLookingSecretReferences(t *testing.T) {
	for _, namespace := range []string{"secrets", "private"} {
		t.Run(namespace, func(t *testing.T) {
			for _, references := range [][]string{{"tls/.key.7.tmp", "tls/.key.abcdef.tmp"}, {"tls/.pending-key", "tls/.catalog-compat/key"}} {
				t.Run(references[0], func(t *testing.T) {
					roots := syntheticCompatRoots(t)
					roots.SecretsRelative = namespace
					id := strings.Repeat("e", 64)
					store, err := newSecretStore(filepath.Join(roots.Config, namespace))
					if err != nil {
						t.Fatal(err)
					}
					config := currentConfigFixture(t)
					profile := config["tls_profiles"].([]any)[0].(map[string]any)
					profile["private_key_secret_ref"] = references[0]
					profile["certificate_secret_ref"] = references[1]
					if validation := validateCurrentConfig(config); !validation.Valid {
						t.Fatal("supported matching-looking references rejected:", validation.Errors)
					}
					for _, reference := range references {
						if err := store.write(reference, "synthetic-private-material", false); err != nil {
							t.Fatal(err)
						}
						if _, err := store.read(reference, true); err != nil {
							t.Fatal(err)
						}
					}
					body, err := canonicalJSON(config)
					if err != nil {
						t.Fatal(err)
					}
					writeCompatFixture(t, roots.Config, "gateway.yaml", body)
					writeCompatFixture(t, roots.Config, "generated/.xray.json.7.tmp", []byte(`{"authoritative":true}`))
					writeCompatFixture(t, roots.Data, "last-known-good/.runtime.abcdef.tmp", []byte(`{"authoritative":true}`))
					writeCompatFixture(t, roots.Data, "last-known-good/.pending-config", []byte(`{"authoritative":true}`))
					writeCompatFixture(t, roots.Data, "last-known-good/.catalog-compat/xray.json", []byte(`{"authoritative":true}`))
					writeCompatFixture(t, roots.State, "control-plane/active.json", []byte(`{"revision":"legacy"}`))
					writeCompatFixture(t, roots.Config, namespace+"/subscription-catalogs/ignored/records.bin", []byte("new-format-excluded"))
					files, err := buildCatalogCompatSnapshot(context.Background(), roots, id)
					if err != nil {
						t.Fatal(err)
					}
					seen := map[string]bool{}
					for _, file := range files {
						seen[file.Area+"/"+file.Path] = true
					}
					for _, name := range []string{"config/" + namespace + "/" + references[0], "config/" + namespace + "/" + references[1], "config/generated/.xray.json.7.tmp", "data/last-known-good/.runtime.abcdef.tmp", "data/last-known-good/.pending-config", "data/last-known-good/.catalog-compat/xray.json"} {
						if !seen[name] {
							t.Fatal("authoritative matching-looking file omitted:", name)
						}
					}
					if seen["config/"+namespace+"/subscription-catalogs/ignored/records.bin"] {
						t.Fatal("configured new-format catalog entered legacy snapshot")
					}
					recovery, err := collectRecoveryFilesWithSecrets(roots.Config, filepath.Join(roots.Config, namespace), filepath.Join(roots.State, "control-plane"), roots.Data)
					if err != nil {
						t.Fatal(err)
					}
					seen = map[string]bool{}
					for _, file := range recovery {
						seen[file.archivePath] = true
					}
					for _, name := range []string{"config/" + namespace + "/" + references[0], "config/" + namespace + "/" + references[1], "data/last-known-good/.runtime.abcdef.tmp", "data/last-known-good/.pending-config", "data/last-known-good/.catalog-compat/xray.json"} {
						if !seen[name] {
							t.Fatal("recovery lost supported matching-looking file:", name)
						}
					}
					if seen["config/"+namespace+"/subscription-catalogs/ignored/records.bin"] {
						t.Fatal("configured new-format catalog entered legacy recovery inventory")
					}
				})
			}
		})
	}
}

func TestCatalogCompatibilityConfiguredSecretNamespaceMustStayInsideRoot(t *testing.T) {
	roots := syntheticCompatRoots(t)
	roots.SecretsRelative = "../outside"
	if _, err := buildCatalogCompatSnapshot(context.Background(), roots, strings.Repeat("f", 64)); err == nil {
		t.Fatal("outside configured secret namespace accepted")
	}
	if _, err := collectRecoveryFilesWithSecrets(roots.Config, filepath.Join(roots.Config, "..", "outside"), roots.State, roots.Data); err == nil {
		t.Fatal("outside recovery secret namespace accepted")
	}
	roots.SecretsRelative = catalogCompatDirectory
	if _, err := buildCatalogCompatSnapshot(context.Background(), roots, strings.Repeat("f", 64)); err == nil {
		t.Fatal("secret namespace colliding with stage root accepted")
	}
	roots.SecretsRelative = "private"
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(roots.Config, "private")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := buildCatalogCompatSnapshot(context.Background(), roots, strings.Repeat("f", 64)); err == nil {
		t.Fatal("redirected configured secret namespace accepted")
	}
	if _, err := collectRecoveryFilesWithSecrets(roots.Config, filepath.Join(roots.Config, "private"), roots.State, roots.Data); err == nil {
		t.Fatal("redirected recovery secret namespace accepted")
	}
}

func TestCatalogCompatibilityAtomicScratchUsesExactManagedStatePlacement(t *testing.T) {
	roots := catalogCompatRoots{}
	for _, name := range []string{"control-plane/.selector-health.json.7.tmp", "control-plane/.selector-status.7.tmp", "control-plane/generations/." + strings.Repeat("a", 64) + ".json.7.tmp"} {
		if !roots.atomicScratch(name) {
			t.Fatal("managed writer scratch unrecognized")
		}
	}
	for _, name := range []string{".active.json.7.tmp", "control-plane/nested/.active.json.7.tmp", "control-plane/generations/.not-a-revision.json.7.tmp", "control-plane/.key.7.tmp"} {
		if roots.atomicScratch(name) {
			t.Fatal("scratch classification crossed managed boundary")
		}
	}
	roots.ControlPlaneRelative = "."
	if !roots.atomicScratch(".active.json.7.tmp") || roots.atomicScratch("control-plane/.active.json.7.tmp") {
		t.Fatal("custom state root scratch classification incorrect")
	}
}
