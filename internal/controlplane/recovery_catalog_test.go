package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	recoveryboot "github.com/sb-gateway/sb-gateway/internal/recovery"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

func recoveryCatalogFixture(t *testing.T, server *Server, count, padding int) subscriptioncatalog.Ref {
	t.Helper()
	builder, err := subscriptioncatalog.NewBuilder(server.secrets.subscriptionCatalogRoot(), subscriptioncatalog.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	for index := 0; index < count; index++ {
		base := fmt.Sprintf("node-%05d", index)
		id := "feed-" + base
		node, _ := json.Marshal(map[string]any{"id": base, "subscription_id": "feed", "protocol": "vless", "server": "edge.example.test", "server_port": 443, "uuid_secret_ref": "@catalog:uuid", "synthetic_padding": strings.Repeat("x", padding)})
		metadata, _ := json.Marshal(map[string]any{"id": id, "provider_node_id": base, "subscription_id": "feed", "label": base, "protocol": "vless", "country": "DE", "definition_fingerprint": strings.Repeat("a", 64)})
		if err := builder.Append(context.Background(), subscriptioncatalog.Record{ID: id, Node: node, Metadata: metadata, Secrets: json.RawMessage(`{"@catalog:uuid":"123e4567-e89b-42d3-a456-426614174000"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := builder.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func recoveryCatalogRootState(t *testing.T, server *Server, ref subscriptioncatalog.Ref) {
	t.Helper()
	encoded, _ := json.Marshal(ref)
	reference, err := decodeObject(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"feed": map[string]any{"catalog_ref": reference}}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("subscription-catalog-compatibility", map[string]any{"format_version": 1, "state": "prepared", "catalog_refs": []any{reference}}); err != nil {
		t.Fatal(err)
	}
}

func recoveryStagedManifest(t *testing.T, server *Server) (recoveryManifestDocument, string) {
	t.Helper()
	configRoot, _, _ := server.recoveryRoots()
	value, err := readJSONObject(filepath.Join(configRoot, ".sb-gateway-recovery-pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(value["manifest"])
	if err != nil {
		t.Fatal(err)
	}
	var manifest recoveryManifestDocument
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest, subscriptionText(value["staging_path"])
}

func TestRecoveryCatalogLargeEncryptedSnapshotStageAndReadback(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	_, _ = bootstrapSession(t, server)
	ref := recoveryCatalogFixture(t, server, 4096, 4096)
	if ref.Records.Bytes <= recoveryMaxFileBytes {
		t.Fatal("fixture must contain an actual records file larger than16MiB")
	}
	recoveryCatalogRootState(t, server, ref)
	obsolete := recoveryCatalogFixture(t, server, 1, 3)
	obsoleteRevision := strings.Repeat("e", 64)
	obsoleteBytes, _ := json.Marshal(map[string]any{"revision": obsoleteRevision, "nodes": []any{map[string]any{subscriptionCatalogSentinel: obsolete}}})
	if err := os.WriteFile(filepath.Join(server.repository.root, "subscription-nodes-"+obsoleteRevision+".json"), obsoleteBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	leaseObserved := false
	server.recoveryBeforeSnapshot = func(int) {
		server.secrets.catalogReaders.mu.Lock()
		entry := server.secrets.catalogReaders.entries[ref.Generation]
		leaseObserved = entry != nil && entry.users > 0
		server.secrets.catalogReaders.mu.Unlock()
		if !leaseObserved {
			t.Error("snapshot did not hold its shared reader lease")
		}
		if err := subscriptioncatalog.RemoveGeneration(context.Background(), server.secrets.subscriptionCatalogRoot(), ref); !errors.Is(err, subscriptioncatalog.ErrBusy) {
			t.Errorf("snapshot file lease did not pin generation: %v", err)
		}
	}
	archive, err := server.createRecoveryArchive()
	if err != nil {
		t.Fatal(err)
	}
	if !leaseObserved {
		t.Fatal("snapshot hook did not run")
	}
	path := filepath.Join(root, "data", "recovery-backups", archive.Name)
	prefix, err := readRecoveryArchivePrefix(path)
	if err != nil {
		t.Fatal(err)
	}
	if prefix.payloadOffset <= 0 || archive.Size <= recoveryMaxFileBytes {
		t.Fatal("expected a streamed encrypted large archive")
	}
	if _, _, err := server.stageRecoveryArchive(path, archive.Name, "panel-password-123"); err != nil {
		t.Fatal(err)
	}
	manifest, staged := recoveryStagedManifest(t, server)
	if manifest.FormatVersion != recoveryCatalogFormatVersion {
		t.Fatal("large catalogue did not select inner schema3")
	}
	for _, file := range manifest.Files {
		if strings.Contains(file.Path, obsolete.Generation) || strings.Contains(file.Path, obsoleteRevision) {
			t.Fatal("obsolete snapshot or unreferenced generation entered archive")
		}
	}
	catalogRoot := filepath.Join(staged, "config", "secrets", "subscription-catalogs")
	restored, err := subscriptioncatalog.Inspect(catalogRoot, ref.Generation)
	if err != nil || restored != ref {
		t.Fatalf("restored Ref mismatch: %v", err)
	}
	reader, err := subscriptioncatalog.Open(catalogRoot, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for _, id := range []string{"feed-node-00000", "feed-node-04095"} {
		record, err := reader.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		var secrets map[string]string
		if json.Unmarshal(record.Secrets, &secrets) != nil || secrets["@catalog:uuid"] != "123e4567-e89b-42d3-a456-426614174000" {
			t.Fatal("full opaque record/credential did not survive encrypted restore")
		}
	}
	if _, err := os.Stat(filepath.Join(catalogRoot, obsolete.Generation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreferenced catalogue was restored")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	// Boot recovery runs before a new controller starts. Close this fixture's
	// idle cached descriptors so the test models that process boundary on every
	// platform, rather than depending on rename semantics for open files.
	cache := &server.secrets.catalogReaders
	closeErr := func() error {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		for generation, entry := range cache.entries {
			if entry.users != 0 {
				return fmt.Errorf("catalogue reader still has an active fixture lease")
			}
			if err := entry.reader.Close(); err != nil {
				return err
			}
			delete(cache.entries, generation)
		}
		return nil
	}()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	liveRoot := server.secrets.subscriptionCatalogRoot()
	// A checked final Ref must describe newly restored bytes, not an untouched
	// copy of the original generation that already existed before staging.
	if err := os.WriteFile(filepath.Join(liveRoot, ref.Generation, "records.bin"), []byte("changed before boot restore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if invalidReader, err := subscriptioncatalog.Open(liveRoot, ref); err == nil {
		_ = invalidReader.Close()
		t.Fatal("fixture did not invalidate the pre-restore live catalogue")
	}
	result, err := recoveryboot.ApplyPending(recoveryboot.Options{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), DataDir: filepath.Join(root, "data")})
	if err != nil || !result.OK || result.Operation != "restored" {
		t.Fatalf("large catalogue boot restore failed: %v", err)
	}
	finalRef, err := subscriptioncatalog.Inspect(liveRoot, ref.Generation)
	if err != nil || finalRef != ref {
		t.Fatalf("final restored catalogue Ref mismatch: %v", err)
	}
	finalReader, err := subscriptioncatalog.Open(liveRoot, finalRef)
	if err != nil {
		t.Fatal(err)
	}
	defer finalReader.Close()
	for _, id := range []string{"feed-node-00000", "feed-node-04095"} {
		record, err := finalReader.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		var secrets map[string]string
		if json.Unmarshal(record.Secrets, &secrets) != nil || secrets["@catalog:uuid"] != "123e4567-e89b-42d3-a456-426614174000" {
			t.Fatal("large catalogue credential did not survive actual boot restore")
		}
	}
}

func TestRecoveryCatalogLegacySchema2StillRoundTrips(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	_, _ = bootstrapSession(t, server)
	marker := filepath.Join(root, "state", "legacy-marker.json")
	if err := os.WriteFile(marker, []byte("legacy-original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	archive, err := server.createRecoveryArchive()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.stageRecoveryArchive(filepath.Join(root, "data", "recovery-backups", archive.Name), archive.Name, "panel-password-123"); err != nil {
		t.Fatal(err)
	}
	manifest, _ := recoveryStagedManifest(t, server)
	if manifest.FormatVersion != recoveryFormatVersion {
		t.Fatal("noncatalogue archive stopped using legacy inner schema2")
	}
	result, err := recoveryboot.ApplyPending(recoveryboot.Options{ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), DataDir: filepath.Join(root, "data")})
	if err != nil || !result.OK || result.Operation != "restored" {
		t.Fatalf("legacy boot apply failed: %v", err)
	}
	if string(mustReadFile(t, marker)) != "legacy-original\n" {
		t.Fatal("legacy marker not restored")
	}
}

func recoveryMalformedCatalogArchive(t *testing.T, server *Server, validPath string, files []recoverySourceFile) string {
	t.Helper()
	// collectRecoveryFiles returns live ordinary sources without snapshot
	// digests. Compute bounded hashes after every scenario's alterations so
	// writeRecoveryTar still enforces its real immutable-source digest check.
	for index := range files {
		digest, err := hashFile(files[index].path, recoveryFileByteLimit(files[index].archivePath))
		if err != nil {
			t.Fatal(err)
		}
		files[index].digest = digest
	}
	prefix, err := readRecoveryArchivePrefix(validPath)
	if err != nil {
		t.Fatal(err)
	}
	master, err := unwrapRecoveryMasterKey(prefix.active.wrapper, "panel-password-123")
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	header := cloneJSONObject(prefix.header)
	header["nonce_prefix"] = base64.RawURLEncoding.EncodeToString(nonce)
	encoded, err := encodeRecoveryArchivePrefix(header, prefix.active.wrapper)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "malformed-*.sbgw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write(encoded); err != nil {
		t.Fatal(err)
	}
	encryptor, err := newRecoveryChunkEncryptor(output, master, nonce, header)
	if err != nil {
		t.Fatal(err)
	}
	manifest := recoveryManifest(files, "2026-01-01T00:00:00Z", "")
	if err := writeRecoveryTar(encryptor, files, manifest); err != nil {
		t.Fatal(err)
	}
	if err := encryptor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := output.Sync(); err != nil {
		t.Fatal(err)
	}
	path := output.Name()
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRecoveryCatalogRejectsIncompleteCorruptAndForeignPayloadBeforePending(t *testing.T) {
	for _, scenario := range []string{"missing-records", "corrupt-records", "inconsistent-ref", "foreign-path"} {
		t.Run(scenario, func(t *testing.T) {
			server, root := newRecoveryTestServer(t)
			_, _ = bootstrapSession(t, server)
			ref := recoveryCatalogFixture(t, server, 3, 8)
			recoveryCatalogRootState(t, server, ref)
			archive, err := server.createRecoveryArchive()
			if err != nil {
				t.Fatal(err)
			}
			configRoot, _, _ := server.recoveryRoots()
			files, err := collectRecoveryFiles(configRoot, server.opts.StateDir, server.opts.DataDir, map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			files, release, err := server.appendRecoveryCatalogFiles(context.Background(), files)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			alter := func(index int, body []byte) {
				path := filepath.Join(t.TempDir(), "altered")
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				info, _ := os.Stat(path)
				sum := sha256.Sum256(body)
				files[index].path = path
				files[index].size = info.Size()
				files[index].modified = info.ModTime()
				files[index].digest = hex.EncodeToString(sum[:])
			}
			for index, file := range files {
				if strings.HasSuffix(file.archivePath, "/records.bin") {
					if scenario == "missing-records" {
						files = append(files[:index:index], files[index+1:]...)
						break
					}
					if scenario == "corrupt-records" {
						body := mustReadFile(t, file.path)
						body[len(body)-1] ^= 1
						alter(index, body)
						break
					}
				}
				if scenario == "inconsistent-ref" && file.archivePath == "state/subscription-nodes.json" {
					value, err := readJSONObject(file.path)
					if err != nil {
						t.Fatal(err)
					}
					nodeRef := value["feed"].(map[string]any)["catalog_ref"].(map[string]any)
					nodeRef["count"] = float64(ref.Count + 1)
					body, _ := json.Marshal(value)
					alter(index, body)
					break
				}
			}
			if scenario == "foreign-path" {
				path := filepath.Join(t.TempDir(), "foreign")
				body := []byte("private test\n")
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(body)
				files = append(files, recoverySourceFile{archivePath: "config/secrets/subscription-catalogs/" + ref.Generation + "/foreign.bin", path: path, size: int64(len(body)), digest: hex.EncodeToString(sum[:])})
			}
			malformed := recoveryMalformedCatalogArchive(t, server, filepath.Join(root, "data", "recovery-backups", archive.Name), files)
			if _, _, err := server.stageRecoveryArchive(malformed, archive.Name, "panel-password-123"); err == nil {
				t.Fatal("malformed catalogue became a pending restore")
			}
			if _, err := os.Lstat(filepath.Join(configRoot, ".sb-gateway-recovery-pending.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected catalogue published a pending pointer")
			}
		})
	}
}

type recoveryBoundedWriteObserver struct {
	destination    io.Writer
	maximum, calls int
}

func (observer *recoveryBoundedWriteObserver) Write(body []byte) (int, error) {
	observer.maximum = max(observer.maximum, len(body))
	observer.calls++
	return observer.destination.Write(body)
}

func TestRecoveryCatalogKeepsOrdinaryBudgetsAndActualFileWindows(t *testing.T) {
	path := "config/secrets/subscription-catalogs/" + strings.Repeat("a", 64) + "/records.bin"
	if recoveryFileByteLimit(path) <= recoveryMaxFileBytes || recoveryFileByteLimit("state/ordinary.json") != recoveryMaxFileBytes {
		t.Fatal("catalogue allowance leaked into ordinary files")
	}
	if err := recoveryPayloadBudget([]recoverySourceFile{{archivePath: "state/ordinary.json", size: recoveryMaxFileBytes + 1}}); err == nil {
		t.Fatal("ordinary16MiB file bound was removed")
	}
	ordinary := make([]recoverySourceFile, 5)
	for index := range ordinary {
		ordinary[index] = recoverySourceFile{archivePath: fmt.Sprintf("state/ordinary-%d.json", index), size: recoveryMaxFileBytes}
	}
	if err := recoveryPayloadBudget(ordinary); err == nil {
		t.Fatal("ordinary64MiB total bound was removed")
	}
	file, err := os.CreateTemp(t.TempDir(), "windowed-file-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	writer := newRecoveryFileWriter(file, filepath.Dir(file.Name()), digest)
	observer := &recoveryBoundedWriteObserver{destination: writer.output}
	writer.output = observer
	// Reuse one slightly-over-window buffer, rather than reading or retaining
	// the complete >16MiB output payload in RAM.
	buffer := make([]byte, recoveryFileWindow+17)
	for index := range buffer {
		buffer[index] = 0x5a
	}
	for range 2 {
		if n, err := writer.Write(buffer); err != nil || n != len(buffer) {
			t.Fatalf("windowed write: n=%d err=%v", n, err)
		}
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if observer.maximum > recoveryFileWindow || observer.calls < 4 || writer.pending != 34 {
		t.Fatal("large caller Write bypassed8MiB sync/drop windows")
	}
	info, err := file.Stat()
	if err != nil || info.Size() != int64(2*len(buffer)) {
		t.Fatal("actual large-file size mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	reader := newRecoveryFileReader(file)
	actual := sha256.New()
	if n, err := io.CopyBuffer(actual, reader, make([]byte, 64<<10)); err != nil || n != info.Size() {
		t.Fatal("actual windowed read failed")
	}
	if !strings.EqualFold(hex.EncodeToString(actual.Sum(nil)), hex.EncodeToString(digest.Sum(nil))) || reader.advised < int64(2*recoveryFileWindow) {
		t.Fatal("windowed file content/advice progress mismatch")
	}
}
