package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

func bootRecoveryFixture(t *testing.T) (Options, *pendingRestore) {
	t.Helper()
	root := t.TempDir()
	options := Options{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), DataDir: filepath.Join(root, "data")}
	for _, path := range []string{options.ConfigDir, options.StateDir, options.DataDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	operation := "0123456789abcdef"
	stage := filepath.Join(options.DataDir, "recovery-staging", operation)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	return options, &pendingRestore{OperationID: operation, StagingPath: stage, Manifest: pendingManifest{FormatVersion: legacyManifestVersion}}
}
func bootRecoveryAdd(t *testing.T, pending *pendingRestore, path string, body []byte) {
	t.Helper()
	destination := filepath.Join(pending.StagingPath, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	pending.Manifest.Files = append(pending.Manifest.Files, pendingFile{path, int64(len(body)), hex.EncodeToString(sum[:])})
}
func bootRecoverySave(t *testing.T, options Options, pending *pendingRestore) {
	t.Helper()
	if err := writeTestJSON(filepath.Join(options.ConfigDir, ".sb-gateway-recovery-pending.json"), pending); err != nil {
		t.Fatal(err)
	}
}
func bootRecoveryCatalog(t *testing.T, pending *pendingRestore, count, padding int) subscriptioncatalog.Ref {
	t.Helper()
	root := filepath.Join(pending.StagingPath, "config", "secrets", "subscription-catalogs")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	builder, err := subscriptioncatalog.NewBuilder(root, subscriptioncatalog.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("node-%05d", index)
		node, _ := json.Marshal(map[string]any{"id": id, "padding": strings.Repeat("x", padding)})
		metadata, _ := json.Marshal(map[string]any{"id": id})
		if err := builder.Append(context.Background(), subscriptioncatalog.Record{ID: id, Node: node, Metadata: metadata, Secrets: json.RawMessage(`{"uuid":"123e4567-e89b-42d3-a456-426614174000"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := builder.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "records.bin", "metadata.bin", "id.idx", "stable.idx", "endpoint.idx", "logical.idx"} {
		relative := "config/secrets/subscription-catalogs/" + ref.Generation + "/" + name
		path := filepath.Join(pending.StagingPath, filepath.FromSlash(relative))
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.New()
		size, err := io.CopyBuffer(digest, file, make([]byte, 64<<10))
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		pending.Manifest.Files = append(pending.Manifest.Files, pendingFile{relative, size, hex.EncodeToString(digest.Sum(nil))})
	}
	pending.Manifest.FormatVersion = catalogManifestVersion
	body, _ := json.Marshal(map[string]any{"source": map[string]any{"catalog_ref": ref}})
	bootRecoveryAdd(t, pending, "state/subscription-nodes.json", body)
	return ref
}

func TestBootRecoveryCatalogueLargerThanLegacyBound(t *testing.T) {
	options, pending := bootRecoveryFixture(t)
	ref := bootRecoveryCatalog(t, pending, 4096, 4096)
	if ref.Records.Bytes <= maxFileBytes {
		t.Fatal("fixture must have a real records file larger than16MiB")
	}
	bootRecoverySave(t, options, pending)
	result, err := ApplyPending(options)
	if err != nil || !result.OK || result.Operation != "restored" || result.RestoredFiles != len(pending.Manifest.Files) {
		t.Fatalf("large boot restore: %#v %v", result, err)
	}
	root := filepath.Join(options.ConfigDir, "secrets", "subscription-catalogs")
	actual, err := subscriptioncatalog.Inspect(root, ref.Generation)
	if err != nil || actual != ref {
		t.Fatalf("final Ref differs: %v", err)
	}
	reader, err := subscriptioncatalog.Open(root, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, id := range []string{"node-00000", "node-04095"} {
		record, err := reader.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		var secrets map[string]string
		if json.Unmarshal(record.Secrets, &secrets) != nil || secrets["uuid"] != "123e4567-e89b-42d3-a456-426614174000" {
			t.Fatal("final restored credentials differ")
		}
	}
	if _, err := os.Stat(pending.StagingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful restore left staging behind")
	}
}

func TestBootRecoveryPreflightLateFailureNeverOverwritesEarlierFiles(t *testing.T) {
	for _, scenario := range []string{"checksum", "size", "path", "duplicate", "missing-schema", "unknown-schema", "foreign-catalogue", "legacy-catalogue", "incomplete-catalogue", "corrupt-catalogue", "inconsistent-reference", "missing-reference-payload"} {
		t.Run(scenario, func(t *testing.T) {
			options, pending := bootRecoveryFixture(t)
			bootRecoveryAdd(t, pending, "state/first.json", []byte("new first\n"))
			bootRecoveryAdd(t, pending, "state/last.json", []byte("new last\n"))
			first := filepath.Join(options.StateDir, "first.json")
			if err := os.WriteFile(first, []byte("original first\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "checksum":
				pending.Manifest.Files[1].SHA256 = strings.Repeat("0", 64)
			case "size":
				pending.Manifest.Files[1].Size++
			case "path":
				pending.Manifest.Files[1].Path = "state/../last.json"
			case "duplicate":
				pending.Manifest.Files = append(pending.Manifest.Files, pending.Manifest.Files[0])
			case "missing-schema":
				pending.Manifest.FormatVersion = 0
			case "unknown-schema":
				pending.Manifest.FormatVersion = 4
			case "foreign-catalogue":
				pending.Manifest.FormatVersion = 3
				bootRecoveryAdd(t, pending, "config/secrets/subscription-catalogs/"+strings.Repeat("a", 64)+"/foreign.bin", []byte("no"))
			case "legacy-catalogue":
				bootRecoveryAdd(t, pending, "config/secrets/subscription-catalogs/"+strings.Repeat("a", 64)+"/records.bin", []byte("no"))
			case "incomplete-catalogue":
				bootRecoveryCatalog(t, pending, 2, 3)
				pending.Manifest.Files = append(pending.Manifest.Files[:2:2], pending.Manifest.Files[3:]...)
			case "corrupt-catalogue":
				ref := bootRecoveryCatalog(t, pending, 2, 3)
				for index, entry := range pending.Manifest.Files {
					if entry.Path == "config/secrets/subscription-catalogs/"+ref.Generation+"/records.bin" {
						path := filepath.Join(pending.StagingPath, filepath.FromSlash(entry.Path))
						body, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						body[len(body)-1] ^= 1
						if err := os.WriteFile(path, body, 0o600); err != nil {
							t.Fatal(err)
						}
						sum := sha256.Sum256(body)
						pending.Manifest.Files[index].SHA256 = hex.EncodeToString(sum[:])
					}
				}
			case "inconsistent-reference":
				ref := bootRecoveryCatalog(t, pending, 2, 3)
				ref.Count++
				pending.Manifest.Files = pending.Manifest.Files[:len(pending.Manifest.Files)-1]
				body, _ := json.Marshal(map[string]any{"source": map[string]any{"catalog_ref": ref}})
				bootRecoveryAdd(t, pending, "state/subscription-nodes.json", body)
			case "missing-reference-payload":
				pending.Manifest.FormatVersion = 3
				body, _ := json.Marshal(map[string]any{"source": map[string]any{"catalog_ref": subscriptioncatalog.Ref{Schema: 1, Generation: strings.Repeat("a", 64)}}})
				bootRecoveryAdd(t, pending, "state/subscription-nodes.json", body)
			}
			bootRecoverySave(t, options, pending)
			if _, err := ApplyPending(options); err == nil {
				t.Fatal("invalid complete operation passed preflight")
			}
			actual, err := os.ReadFile(first)
			if err != nil || string(actual) != "original first\n" {
				t.Fatal("late preflight failure overwrote an earlier live file")
			}
			if _, err := os.Stat(filepath.Join(options.ConfigDir, ".sb-gateway-recovery-pending.json")); err != nil {
				t.Fatal("failed restore lost pending pointer")
			}
			if _, err := os.Stat(pending.StagingPath); err != nil {
				t.Fatal("failed restore lost retryable staging")
			}
		})
	}
}

func TestBootRecoveryManifestBoundsAreSelectiveAndByteBased(t *testing.T) {
	entry := func(path string, size int64) pendingFile { return pendingFile{path, size, strings.Repeat("a", 64)} }
	ordinary := pendingManifest{FormatVersion: 2, Files: []pendingFile{entry("state/a.json", maxFileBytes)}}
	if err := validateManifestBudget(ordinary); err != nil {
		t.Fatal(err)
	}
	ordinary.Files[0].Size++
	if err := validateManifestBudget(ordinary); err == nil {
		t.Fatal("ordinary file bound was raised")
	}
	ordinary.Files = nil
	for index := 0; index < 4; index++ {
		ordinary.Files = append(ordinary.Files, entry(fmt.Sprintf("state/%d.json", index), maxFileBytes))
	}
	if err := validateManifestBudget(ordinary); err != nil {
		t.Fatal(err)
	}
	ordinary.Files = append(ordinary.Files, entry("state/final.json", 1))
	if err := validateManifestBudget(ordinary); err == nil {
		t.Fatal("ordinary aggregate64MiB bound was removed")
	}
	catalog := pendingManifest{FormatVersion: 3}
	for index := 0; index < 4; index++ {
		catalog.Files = append(catalog.Files, entry(fmt.Sprintf("config/secrets/subscription-catalogs/%064x/records.bin", index), maxCatalogFileBytes))
	}
	if err := validateManifestBudget(catalog); err != nil {
		t.Fatal(err)
	}
	catalog.Files = append(catalog.Files, entry(fmt.Sprintf("config/secrets/subscription-catalogs/%064x/records.bin", 4), 1))
	if err := validateManifestBudget(catalog); err == nil {
		t.Fatal("catalogue aggregate2GiB bound was removed")
	}
	catalog.Files = catalog.Files[:1]
	catalog.Files[0].Size++
	if err := validateManifestBudget(catalog); err == nil {
		t.Fatal("catalogue512MiB per-file bound was removed")
	}
	for _, path := range []string{"config/secrets/subscription-catalogs", "config/secrets/subscription-catalogs/" + strings.Repeat("a", 64) + "/extra.bin", "config/./secrets/subscription-catalogs/" + strings.Repeat("a", 64) + "/extra.bin", "config/.sb-gateway-recovery-pending.json"} {
		if err := validateManifestBudget(pendingManifest{FormatVersion: 3, Files: []pendingFile{entry(path, 0)}}); err == nil {
			t.Fatalf("reserved/noncanonical path accepted: %s", path)
		}
	}
}
