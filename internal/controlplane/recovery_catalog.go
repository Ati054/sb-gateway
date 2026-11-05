package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

const (
	recoveryCatalogFormatVersion = 3
	recoveryMaxLegacyPlainBytes  = 64 << 20
	recoveryMaxCatalogPlainBytes = 2 << 30
	recoveryMaxCatalogFileBytes  = 512 << 20
	recoveryTarOverheadBytes     = 8 << 20
	recoveryStorageHeadroom      = 64 << 20
)

var recoveryCatalogPath = regexpMust(`^config/secrets/subscription-catalogs/[a-f0-9]{64}/(?:manifest\.json|records\.bin|metadata\.bin|id\.idx|stable\.idx|endpoint\.idx|logical\.idx)$`)

var errRecoveryCatalogSecretsNamespace = errors.New("catalog recovery requires the default secrets namespace; custom secrets namespaces are not supported")

func (server *Server) requireRecoveryCatalogSecretsNamespace() error {
	configRoot, _, _ := server.recoveryRoots()
	namespace, err := configuredSecretsNamespace(configRoot, server.opts.SecretsDir)
	if err != nil {
		return err
	}
	if namespace != "secrets" {
		return errRecoveryCatalogSecretsNamespace
	}
	return nil
}

func recoveryFileByteLimit(path string) int64 {
	if recoveryCatalogPath.MatchString(path) {
		return recoveryMaxCatalogFileBytes
	}
	return recoveryMaxFileBytes
}

func recoveryPayloadBudget(files []recoverySourceFile) error {
	var ordinary, catalog int64
	for _, file := range files {
		if file.size < 0 || file.size > recoveryFileByteLimit(file.archivePath) {
			return errors.New("recovery file exceeds its size limit")
		}
		if recoveryCatalogPath.MatchString(file.archivePath) {
			catalog += file.size
		} else {
			ordinary += file.size
		}
		if ordinary > recoveryMaxLegacyPlainBytes || catalog > recoveryMaxCatalogPlainBytes {
			return errors.New("recovery payload exceeds its storage budget")
		}
	}
	if len(files) > recoveryMaxFiles {
		return errors.New("recovery file count exceeds the safety limit")
	}
	return nil
}

// Pin only persisted reachable generations. Idle caches are not backup roots;
// their readers still independently protect physical files from deletion.
func (server *Server) appendRecoveryCatalogFiles(ctx context.Context, files []recoverySourceFile) ([]recoverySourceFile, func(), error) {
	retained, err := server.subscriptionRetentionRevisions()
	if err != nil {
		return nil, nil, err
	}
	keep := make(map[string]bool, len(retained))
	for _, revision := range retained {
		keep[revision] = true
	}
	selected := make([]recoverySourceFile, 0, len(files))
	for _, file := range files {
		if match := subscriptionSnapshotName.FindStringSubmatch(filepath.Base(file.archivePath)); len(match) == 2 && strings.HasPrefix(file.archivePath, "state/") && !keep[match[1]] {
			continue
		}
		selected = append(selected, file)
	}
	files = selected
	refs, err := server.subscriptionCatalogReferences(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(refs) != 0 {
		if err := server.requireRecoveryCatalogSecretsNamespace(); err != nil {
			return nil, nil, err
		}
	}
	releases := make([]func(), 0, len(refs))
	releaseAll := func() {
		for _, release := range releases {
			release()
		}
	}
	failed := true
	defer func() {
		if failed {
			releaseAll()
		}
	}()
	generationIDs := make([]string, 0, len(refs))
	for generation := range refs {
		generationIDs = append(generationIDs, generation)
	}
	sort.Strings(generationIDs)
	for _, generation := range generationIDs {
		ref := refs[generation]
		_, release, err := server.secrets.catalogReaders.acquire(server.secrets.subscriptionCatalogRoot(), ref)
		if err != nil {
			return nil, nil, err
		}
		releases = append(releases, release)
		for _, name := range []string{"manifest.json", "records.bin", "metadata.bin", "id.idx", "stable.idx", "endpoint.idx", "logical.idx"} {
			path := filepath.Join(server.secrets.subscriptionCatalogRoot(), generation, name)
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return nil, nil, errors.New("recovery catalog file is unavailable")
			}
			digests := map[string]subscriptioncatalog.FileDigest{"records.bin": ref.Records, "metadata.bin": ref.Metadata, "id.idx": ref.Indexes[0], "stable.idx": ref.Indexes[1], "endpoint.idx": ref.Indexes[2], "logical.idx": ref.Indexes[3]}
			expected := digests[name]
			if name == "manifest.json" {
				value, hashErr := hashFile(path, recoveryMaxFileBytes)
				if hashErr != nil {
					return nil, nil, errors.New("recovery catalog manifest is unavailable")
				}
				expected = subscriptioncatalog.FileDigest{Bytes: info.Size(), SHA256: value}
			}
			if expected.Bytes != info.Size() {
				return nil, nil, errors.New("recovery catalog size mismatch")
			}
			files = append(files, recoverySourceFile{archivePath: "config/secrets/subscription-catalogs/" + generation + "/" + name, path: path, size: info.Size(), modified: info.ModTime(), digest: expected.SHA256})
		}
	}
	if err = recoveryPayloadBudget(files); err != nil {
		return nil, nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].archivePath < files[j].archivePath })
	failed = false
	return files, releaseAll, nil
}

func (server *Server) checkRecoveryRestoreSpace(stagingRoot string, manifest recoveryManifestDocument) error {
	var total uint64
	for _, file := range manifest.Files {
		total += uint64(file.Size)
	}
	needed := total*2 + recoveryStorageHeadroom + recoveryTarOverheadBytes
	configRoot, _, _ := server.recoveryRoots()
	for _, root := range []string{stagingRoot, configRoot, server.opts.StateDir, server.opts.DataDir} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return errors.New("recovery destination is unavailable")
		}
		if err := storagebudget.Check(root, needed); err != nil {
			return err
		}
	}
	return nil
}

func recoveryRequiredManifestVersion(files []recoverySourceFile) int {
	for _, file := range files {
		if recoveryCatalogPath.MatchString(file.archivePath) {
			return recoveryCatalogFormatVersion
		}
	}
	return recoveryFormatVersion
}

func checkRecoverySnapshotSpace(stagingRoot, backupRoot string, files []recoverySourceFile) error {
	var total uint64
	for _, file := range files {
		if file.size < 0 {
			return errors.New("invalid recovery file size")
		}
		total += uint64(file.size)
	}
	needed := total*2 + recoveryStorageHeadroom + recoveryTarOverheadBytes
	for _, root := range []string{stagingRoot, backupRoot} {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return errors.New("recovery storage is unavailable")
		}
		if err := storagebudget.Check(root, needed); err != nil {
			return err
		}
	}
	return nil
}

// Every schema3 catalogue included in a restore must be complete and checked
// before a pending restart/restore pointer is published.
func validateRecoveryCatalogPayload(root string, manifest recoveryManifestDocument) error {
	generations := make(map[string]bool)
	refs := make(map[string]subscriptioncatalog.Ref)
	for _, file := range manifest.Files {
		if recoveryCatalogPath.MatchString(file.Path) {
			generations[strings.Split(file.Path, "/")[3]] = true
		}
		if file.Path == "state/subscription-nodes.json" || file.Path == "state/subscription-catalog-compatibility.json" || strings.HasPrefix(file.Path, "state/subscription-nodes-") && strings.HasSuffix(file.Path, ".json") {
			path, err := recoveryStagingPath(root, file.Path)
			if err != nil {
				return err
			}
			value, err := readJSONObject(path)
			if err != nil {
				return errors.New("restored catalog reference document is invalid")
			}
			if err = collectSubscriptionCatalogRefs(context.Background(), value, refs); err != nil {
				return errors.New("restored catalog reference graph is invalid")
			}
		}
	}
	for generation := range refs {
		if !generations[generation] {
			return errors.New("restored catalog reference has no complete payload")
		}
	}
	if len(generations) == 0 {
		return nil
	}
	if manifest.FormatVersion != recoveryCatalogFormatVersion {
		return errors.New("catalog recovery format is not supported")
	}
	catalogRoot := filepath.Join(root, "config", "secrets", "subscription-catalogs")
	for generation := range generations {
		ref, err := subscriptioncatalog.Inspect(catalogRoot, generation)
		if err != nil {
			return errors.New("restored catalog manifest is invalid")
		}
		if expected, exists := refs[generation]; exists && expected != ref {
			return errors.New("restored catalog reference mismatch")
		}
		reader, err := subscriptioncatalog.Open(catalogRoot, ref)
		if err != nil {
			return errors.New("restored catalog is incomplete or corrupt")
		}
		_ = reader.Close()
	}
	return nil
}
