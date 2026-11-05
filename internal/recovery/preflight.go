package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

const (
	legacyManifestVersion         = 2
	catalogManifestVersion        = 3
	maxLegacyTotalBytes    int64  = 64 << 20
	maxCatalogFileBytes    int64  = 512 << 20
	maxCatalogTotalBytes   int64  = 2 << 30
	restoreStorageHeadroom uint64 = 64 << 20
	restoreStorageOverhead uint64 = 8 << 20
)

var catalogPayloadPath = regexp.MustCompile(`^config/secrets/subscription-catalogs/([a-f0-9]{64})/(manifest\.json|records\.bin|metadata\.bin|id\.idx|stable\.idx|endpoint\.idx|logical\.idx)$`)

type preparedRestoreFile struct {
	entry               pendingFile
	source, destination string
}
type preparedRestore struct {
	files   []preparedRestoreFile
	readers []*subscriptioncatalog.Reader
	total   uint64
}

func recoveryFileLimit(path string) int64 {
	if catalogPayloadPath.MatchString(path) {
		return maxCatalogFileBytes
	}
	return maxFileBytes
}

func (prepared *preparedRestore) close() error {
	var result error
	for _, reader := range prepared.readers {
		if err := reader.Close(); err != nil && result == nil {
			result = err
		}
	}
	prepared.readers = nil
	return result
}

func (prepared *preparedRestore) admitStorage(roots ...string) error {
	return prepared.admitStorageWith(storagebudget.Check, roots...)
}

func (prepared *preparedRestore) admitStorageWith(check func(string, uint64) error, roots ...string) error {
	for _, root := range roots {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
		if err := check(root, prepared.total+restoreStorageHeadroom+restoreStorageOverhead); err != nil {
			return err
		}
	}
	return nil
}

// Validate all serialized bounds before inspecting source contents. In
// particular, malformed totals never require creating/reading gigabyte files.
func validateManifestBudget(manifest pendingManifest) error {
	if manifest.FormatVersion != legacyManifestVersion && manifest.FormatVersion != catalogManifestVersion {
		return errors.New("pending recovery manifest format is unsupported")
	}
	if len(manifest.Files) < 1 || len(manifest.Files) > 4096 {
		return errors.New("pending recovery manifest file count is invalid")
	}
	seen := make(map[string]bool, len(manifest.Files))
	var ordinary, catalog int64
	for _, entry := range manifest.Files {
		canonical := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path)))
		if !pathPattern.MatchString(entry.Path) || canonical != entry.Path || hasParentTraversal(entry.Path) || entry.Path == "config/.sb-gateway-recovery-pending.json" ||
			!digestPattern.MatchString(entry.SHA256) || entry.Size < 0 || entry.Size > recoveryFileLimit(entry.Path) || seen[entry.Path] {
			return errors.New("pending recovery manifest entry is invalid")
		}
		seen[entry.Path] = true
		catalogFile := catalogPayloadPath.MatchString(entry.Path)
		reservedPath := entry.Path
		if runtime.GOOS == "windows" {
			reservedPath = strings.ToLower(reservedPath)
		}
		reserved := reservedPath == "config/secrets/subscription-catalogs" || strings.HasPrefix(reservedPath, "config/secrets/subscription-catalogs/")
		if reserved && (!catalogFile || manifest.FormatVersion != catalogManifestVersion) {
			return errors.New("pending recovery catalogue path or schema is invalid")
		}
		if catalogFile {
			catalog += entry.Size
		} else {
			ordinary += entry.Size
		}
		if ordinary > maxLegacyTotalBytes || catalog > maxCatalogTotalBytes {
			return errors.New("pending recovery payload exceeds its byte budget")
		}
	}
	return nil
}

func destinationIdentity(path string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(path)
	}
	return path
}

// Verify the complete staged operation before overwriting any live file. A
// later I/O error or power loss can still leave earlier files restored; keeping
// pending and the full stage makes the same operation retryable on next boot.
func preflightRestore(staging, config, state, data string, manifest pendingManifest) (prepared *preparedRestore, resultErr error) {
	prepared = &preparedRestore{}
	defer func() {
		if resultErr != nil {
			_ = prepared.close()
		}
	}()
	if err := validateManifestBudget(manifest); err != nil {
		return prepared, err
	}
	destinations := make(map[string]bool)
	generations := make(map[string]map[string]pendingFile)
	for _, entry := range manifest.Files {
		match := catalogPayloadPath.FindStringSubmatch(entry.Path)
		if len(match) > 0 {
			if generations[match[1]] == nil {
				generations[match[1]] = make(map[string]pendingFile)
			}
			generations[match[1]][match[2]] = entry
		}
		source, err := secureDescendant(staging, filepath.FromSlash(entry.Path), true)
		if err != nil {
			return prepared, err
		}
		info, err := os.Lstat(source)
		if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return prepared, errors.New("staged recovery file size does not match its manifest")
		}
		destination, err := restoreDestination(entry.Path, config, state, data)
		if err != nil {
			return prepared, err
		}
		if destinationIdentity(destination) == destinationIdentity(filepath.Join(config, ".sb-gateway-recovery-pending.json")) {
			return prepared, errors.New("pending recovery marker cannot be a restored payload")
		}
		if destinations[destinationIdentity(destination)] {
			return prepared, errors.New("pending recovery destination is duplicated")
		}
		if info, err := os.Lstat(destination); err == nil && !info.Mode().IsRegular() || err != nil && !errors.Is(err, os.ErrNotExist) {
			return prepared, errors.New("pending recovery destination is not a regular file")
		}
		destinations[destinationIdentity(destination)] = true
		prepared.files = append(prepared.files, preparedRestoreFile{entry, source, destination})
		prepared.total += uint64(entry.Size)
	}
	for destination := range destinations {
		for parent := filepath.Dir(destination); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
			if destinations[destinationIdentity(parent)] {
				return prepared, errors.New("pending recovery destinations overlap")
			}
		}
	}
	// Catalogue content is hashed once by its checked Reader below. Compare
	// pending digests with that Ref; ordinary files and manifest.json are hashed
	// here. No node records are decoded or expanded during recovery.
	for _, file := range prepared.files {
		if match := catalogPayloadPath.FindStringSubmatch(file.entry.Path); len(match) > 0 && match[2] != "manifest.json" {
			continue
		}
		if err := verifyStagedFile(file.source, file.entry); err != nil {
			return prepared, err
		}
	}
	if err := prepared.validateCatalogues(staging, generations); err != nil {
		return prepared, err
	}
	return prepared, nil
}

func verifyStagedFile(path string, entry pendingFile) error {
	expected, err := os.Lstat(path)
	if err != nil || !expected.Mode().IsRegular() || expected.Size() != entry.Size {
		return errors.New("staged recovery file size does not match its manifest")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) {
		return errors.New("staged recovery file changed during preflight")
	}
	digest := sha256.New()
	n, err := io.CopyBuffer(digest, io.LimitReader(newRestoreFileReader(file), entry.Size+1), make([]byte, restoreCopyBuffer))
	if err != nil {
		return err
	}
	if n != entry.Size || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
		return errors.New("staged recovery file failed its checksum")
	}
	return nil
}
