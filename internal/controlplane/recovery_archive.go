package controlplane

import (
	"archive/tar"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	recoveryChunkBytes       = 64 << 10
	recoveryMaxPlainBytes    = 64 << 20
	recoveryMaxFileBytes     = 16 << 20
	recoveryRetentionLimit   = 3
	recoveryMaxFiles         = 4096
	recoverySnapshotAttempts = 2
)

type recoveryFailureClass string

const (
	recoveryFailureUnknown          recoveryFailureClass = "unknown"
	recoveryFailureSourceChurn      recoveryFailureClass = "source_churn"
	recoveryFailureSourceCollection recoveryFailureClass = "source_collection"
	recoveryFailureProtection       recoveryFailureClass = "protection"
	recoveryFailureStaging          recoveryFailureClass = "staging"
	recoveryFailureArchiveWrite     recoveryFailureClass = "archive_write"
	recoveryFailureFinalize         recoveryFailureClass = "finalize"
)

type recoveryArchiveError struct {
	class recoveryFailureClass
	err   error
}

func (failure *recoveryArchiveError) Error() string {
	return "recovery archive " + string(failure.class)
}

func (failure *recoveryArchiveError) Unwrap() error { return failure.err }

func recoveryArchiveFailure(class recoveryFailureClass, err error) error {
	return &recoveryArchiveError{class: class, err: err}
}

func recoveryArchiveFailureClass(err error) recoveryFailureClass {
	var failure *recoveryArchiveError
	if errors.As(err, &failure) {
		switch failure.class {
		case recoveryFailureSourceChurn, recoveryFailureSourceCollection, recoveryFailureProtection,
			recoveryFailureStaging, recoveryFailureArchiveWrite, recoveryFailureFinalize:
			return failure.class
		}
	}
	return recoveryFailureUnknown
}

func recoveryArchiveFailurePresentation(err error) (classifier, action, message string) {
	switch recoveryArchiveFailureClass(err) {
	case recoveryFailureSourceChurn:
		return "source_churn", "retry_when_idle", "Состояние шлюза менялось во время подготовки копии. Обновление не запланировано; повторите после завершения текущих операций."
	case recoveryFailureProtection:
		return "protection", "check_recovery_protection", "Защита копии восстановления недоступна. Обновление не запланировано; проверьте защиту резервных копий."
	case recoveryFailureSourceCollection:
		return "source_collection", "check_recovery_data", "Набор данных для копии не прошёл проверку безопасности. Обновление не запланировано."
	case recoveryFailureStaging:
		return "staging", "check_recovery_storage", "Не удалось безопасно подготовить копию восстановления. Обновление не запланировано."
	case recoveryFailureArchiveWrite:
		return "archive_write", "check_recovery_storage", "Не удалось записать копию восстановления. Обновление не запланировано."
	case recoveryFailureFinalize:
		return "finalize", "check_recovery_storage", "Не удалось завершить копию восстановления. Обновление не запланировано."
	default:
		return "unknown", "check_recovery_storage", "Не удалось создать обязательную копию восстановления. Обновление не запланировано."
	}
}

type recoverySourceFile struct {
	archivePath string
	path        string
	size        int64
	digest      string
	modified    time.Time
}

type recoveryArchiveMetadata struct {
	Name               string
	CreatedAt          string
	ApplicationVersion string
	ActiveRevision     any
	Size               int64
	SHA256             any
}

func (metadata recoveryArchiveMetadata) document() map[string]any {
	return map[string]any{
		"name": metadata.Name, "created_at": metadata.CreatedAt, "application_version": metadata.ApplicationVersion,
		"active_revision": metadata.ActiveRevision, "size_bytes": metadata.Size, "sha256": metadata.SHA256,
	}
}

func (server *Server) recoveryRoots() (configRoot, backupRoot, stagingRoot string) {
	configRoot = filepath.Dir(server.opts.SecretsDir)
	backupRoot = filepath.Join(server.opts.DataDir, "recovery-backups")
	stagingRoot = filepath.Join(server.opts.DataDir, "recovery-staging")
	return
}

func (server *Server) recoveryArchiveSnapshotRoot() string {
	return filepath.Join(server.opts.DataDir, "recovery-archive-staging")
}

func (server *Server) createRecoveryArchive() (recoveryArchiveMetadata, error) {
	server.recoveryMu.Lock()
	defer server.recoveryMu.Unlock()
	configRoot, backupRoot, _ := server.recoveryRoots()
	stagingRoot := server.recoveryArchiveSnapshotRoot()
	if err := os.MkdirAll(backupRoot, 0o700); err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	if err := cleanupRecoverySnapshotDirectories(stagingRoot); err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	for attempt := 0; attempt < recoverySnapshotAttempts; attempt++ {
		metadata, err := server.createRecoveryArchiveAttempt(configRoot, backupRoot, stagingRoot, attempt)
		if err == nil {
			return metadata, nil
		}
		if recoveryArchiveFailureClass(err) != recoveryFailureSourceChurn || attempt+1 == recoverySnapshotAttempts {
			return recoveryArchiveMetadata{}, err
		}
	}
	return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureUnknown, errors.New("recovery archive retry was not reached"))
}

func (server *Server) createRecoveryArchiveAttempt(configRoot, backupRoot, stagingRoot string, attempt int) (metadata recoveryArchiveMetadata, resultErr error) {
	files, err := collectRecoveryFiles(configRoot, server.opts.StateDir, server.opts.DataDir)
	if err != nil {
		class := recoveryFailureSourceCollection
		if errors.Is(err, os.ErrNotExist) {
			class = recoveryFailureSourceChurn
		}
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(class, err)
	}
	if server.recoveryBeforeSnapshot != nil {
		server.recoveryBeforeSnapshot(attempt)
	}
	files, cleanup, err := snapshotRecoveryFiles(stagingRoot, files, server.recoveryCleanupSnapshot)
	if err != nil {
		return recoveryArchiveMetadata{}, err
	}
	defer func() {
		if cleanupErr := cleanup(); cleanupErr != nil {
			metadata = recoveryArchiveMetadata{}
			resultErr = recoveryArchiveFailure(recoveryFailureStaging, cleanupErr)
		}
	}()
	activeRevision, err := recoverySnapshotActiveRevision(files)
	if err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	created := server.now().UTC().Truncate(time.Second)
	name := recoveryArchiveFilename(created, activeRevision)
	for attempt := 0; attempt < 10; attempt++ {
		if _, statErr := os.Lstat(filepath.Join(backupRoot, name)); errors.Is(statErr, os.ErrNotExist) {
			break
		}
		created = created.Add(time.Second)
		name = recoveryArchiveFilename(created, activeRevision)
	}
	finalPath := filepath.Join(backupRoot, name)
	if _, err := os.Lstat(finalPath); err == nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureFinalize, errors.New("unique recovery archive name could not be allocated"))
	}
	encodedMaster, err := server.secrets.read(recoveryMasterKeyRef, true)
	if err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureProtection, errors.New("recovery protection is not initialized"))
	}
	master, err := decodeRecoveryMasterKey(encodedMaster)
	if err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureProtection, err)
	}
	encodedWrapper, err := server.secrets.read(recoveryKeyWrapRef, true)
	if err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureProtection, errors.New("recovery protection is not initialized"))
	}
	wrapper, err := decodeRecoveryKeyWrap(encodedWrapper)
	if err != nil || wrapper.KeyID != recoveryKeyID(master) {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureProtection, errors.New("recovery key wrapper is inconsistent"))
	}
	noncePrefix := make([]byte, 4)
	if _, err := rand.Read(noncePrefix); err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	createdAt := created.Format(time.RFC3339)
	header := map[string]any{
		"format_version": recoveryFormatVersion, "created_at": createdAt, "application_version": envOr("SB_GATEWAY_VERSION", "1.5.57"),
		"architecture": runtime.GOARCH, "active_revision": nullableString(activeRevision), "cipher": recoveryArchiveCipher,
		"chunk_size": recoveryChunkBytes, "nonce_prefix": base64.RawURLEncoding.EncodeToString(noncePrefix), "payload_format": "tar",
	}
	prefix, err := encodeRecoveryArchivePrefix(header, wrapper)
	if err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	temporary, err := os.CreateTemp(backupRoot, "."+name+".*.tmp")
	if err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	digest := sha256.New()
	destination := io.MultiWriter(temporary, digest)
	if _, err := destination.Write(prefix); err != nil {
		temporary.Close()
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	encryptor, err := newRecoveryChunkEncryptor(destination, master, noncePrefix, header)
	if err != nil {
		temporary.Close()
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	manifest := recoveryManifest(files, createdAt, activeRevision)
	if err := writeRecoveryTar(encryptor, files, manifest); err != nil {
		temporary.Close()
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	if err := encryptor.Close(); err != nil {
		temporary.Close()
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	dropRecoveryFileCache(temporary)
	info, err := temporary.Stat()
	if err != nil || info.Size() > recoveryMaxArchiveBytes {
		temporary.Close()
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, errors.New("encrypted recovery archive exceeds the safety limit"))
	}
	if err := temporary.Close(); err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureArchiveWrite, err)
	}
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureFinalize, err)
	}
	_ = syncParentDirectory(finalPath)
	metadata = recoveryArchiveMetadata{Name: name, CreatedAt: createdAt, ApplicationVersion: text(header["application_version"]), ActiveRevision: nullableString(activeRevision), Size: info.Size(), SHA256: hex.EncodeToString(digest.Sum(nil))}
	if err := server.pruneRecoveryArchives(backupRoot); err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureFinalize, err)
	}
	if err := server.updateRecoveryIndex(metadata); err != nil {
		return recoveryArchiveMetadata{}, recoveryArchiveFailure(recoveryFailureFinalize, err)
	}
	return metadata, nil
}

var (
	recoveryAtomicTemporaryName = regexp.MustCompile(`^\.[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9]{6,}\.tmp$`)
	recoverySnapshotDirectory   = regexp.MustCompile(`^\.archive-[A-Za-z0-9]+$`)
)

func cleanupRecoverySnapshotDirectories(root string) error {
	if err := ensurePrivateRecoverySnapshotRoot(root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !recoverySnapshotDirectory.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("recovery snapshot entry is unsafe")
		}
		if err := removeRecoverySnapshotTree(filepath.Join(root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func removeRecoverySnapshotTree(path string) error {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		if err := os.RemoveAll(path); err != nil {
			lastErr = err
		} else if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("recovery snapshot still exists after cleanup")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("remove recovery snapshot %q: %w", path, lastErr)
}

func ensurePrivateRecoverySnapshotRoot(root string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery snapshot root is unsafe")
	}
	return os.Chmod(root, 0o700)
}

func snapshotRecoveryFiles(root string, sources []recoverySourceFile, removeSnapshot func(string) error) ([]recoverySourceFile, func() error, error) {
	if err := ensurePrivateRecoverySnapshotRoot(root); err != nil {
		return nil, nil, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	snapshotRoot, err := os.MkdirTemp(root, ".archive-*")
	if err != nil {
		return nil, nil, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	if err := os.Chmod(snapshotRoot, 0o700); err != nil {
		_ = removeRecoverySnapshotTree(snapshotRoot)
		return nil, nil, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	if removeSnapshot == nil {
		removeSnapshot = removeRecoverySnapshotTree
	}
	cleanup := func() error {
		if err := removeSnapshot(snapshotRoot); err != nil {
			return err
		}
		if _, err := os.Lstat(snapshotRoot); !errors.Is(err, os.ErrNotExist) {
			if err == nil {
				return errors.New("recovery snapshot still exists after cleanup")
			}
			return err
		}
		return nil
	}
	staged := make([]recoverySourceFile, 0, len(sources))
	buffer := make([]byte, recoveryChunkBytes)
	for _, source := range sources {
		file, err := snapshotRecoverySource(snapshotRoot, source, buffer)
		if err != nil {
			if cleanupErr := cleanup(); cleanupErr != nil {
				return nil, nil, recoveryArchiveFailure(recoveryFailureStaging, cleanupErr)
			}
			return nil, nil, err
		}
		staged = append(staged, file)
	}
	return staged, cleanup, nil
}

func snapshotRecoverySource(root string, source recoverySourceFile, buffer []byte) (recoverySourceFile, error) {
	before, err := os.Lstat(source.path)
	if errors.Is(err, os.ErrNotExist) {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("recovery source disappeared"))
	}
	if err != nil {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceCollection, err)
	}
	if !recoverySourceUnchanged(source, before) {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("recovery source changed"))
	}
	target, err := recoverySnapshotPath(root, source.archivePath)
	if err != nil {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	input, err := os.Open(source.path)
	if errors.Is(err, os.ErrNotExist) {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("recovery source disappeared"))
	}
	if err != nil {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceCollection, err)
	}
	inputInfo, statErr := input.Stat()
	if statErr != nil {
		_ = input.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceCollection, statErr)
	}
	if !recoverySourceUnchanged(source, inputInfo) {
		_ = input.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("recovery source changed"))
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*.tmp")
	if err != nil {
		_ = input.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		_ = input.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	digest := sha256.New()
	written, copyErr := io.CopyBuffer(io.MultiWriter(temporary, digest), io.LimitReader(input, recoveryMaxFileBytes+1), buffer)
	dropRecoveryFileCache(input)
	closeErr := input.Close()
	if copyErr != nil || closeErr != nil {
		_ = temporary.Close()
		if errors.Is(copyErr, os.ErrNotExist) || errors.Is(closeErr, os.ErrNotExist) {
			return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("recovery source disappeared"))
		}
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceCollection, errors.Join(copyErr, closeErr))
	}
	if written > recoveryMaxFileBytes {
		_ = temporary.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceCollection, errors.New("recovery source exceeds the file limit"))
	}
	after, err := os.Lstat(source.path)
	if errors.Is(err, os.ErrNotExist) {
		_ = temporary.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("recovery source disappeared"))
	}
	if err != nil {
		_ = temporary.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceCollection, err)
	}
	if !recoverySourceUnchanged(source, after) {
		_ = temporary.Close()
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("recovery source changed"))
	}
	if err := temporary.Close(); err != nil {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return recoverySourceFile{}, recoveryArchiveFailure(recoveryFailureStaging, err)
	}
	// The plaintext snapshot is only an operation-local consistency boundary.
	// Durability is required for the final encrypted archive, not every source file.
	return recoverySourceFile{archivePath: source.archivePath, path: target, size: written, digest: hex.EncodeToString(digest.Sum(nil))}, nil
}

func recoverySourceUnchanged(source recoverySourceFile, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Size() == source.size && info.ModTime().Equal(source.modified)
}

func recoverySnapshotPath(root, archivePath string) (string, error) {
	if !recoveryPayloadPathPattern.MatchString(archivePath) {
		return "", errors.New("recovery snapshot path is invalid")
	}
	target := filepath.Join(root, filepath.FromSlash(archivePath))
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return "", errors.New("recovery snapshot path escaped its root")
	}
	return target, nil
}

func recoverySnapshotActiveRevision(files []recoverySourceFile) (string, error) {
	for _, file := range files {
		if file.archivePath != "state/active.json" {
			continue
		}
		input, err := os.Open(file.path)
		if err != nil {
			return "", err
		}
		decoder := json.NewDecoder(io.LimitReader(input, recoveryMaxFileBytes+1))
		decoder.UseNumber()
		value := map[string]any{}
		decodeErr := decoder.Decode(&value)
		if decodeErr == nil {
			if extraErr := decoder.Decode(&struct{}{}); !errors.Is(extraErr, io.EOF) {
				decodeErr = errors.New("recovery active pointer is invalid")
			}
		}
		closeErr := input.Close()
		if decodeErr != nil || closeErr != nil {
			return "", errors.Join(decodeErr, closeErr)
		}
		revision, _ := value["revision"].(string)
		if revision != "" && !safeRevision(revision) {
			return "", errors.New("recovery active revision is invalid")
		}
		return revision, nil
	}
	return "", nil
}

func recoveryAtomicTemporaryArtifact(name string, info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return recoveryAtomicTemporaryName.MatchString(name)
}

func collectRecoveryFiles(configRoot, stateRoot, dataRoot string) ([]recoverySourceFile, error) {
	selectedTop := map[string]bool{"gateway.yaml": true, "users.yaml": true, "networks.yaml": true, "policies.yaml": true, "subscriptions.yaml": true, "rulesets.yaml": true}
	// These files are reconstructed from the committed configuration or live
	// processes.  Including them makes a recovery snapshot race the selector,
	// telemetry and feed workers even though their contents are not needed to
	// restore the gateway.
	volatileState := map[string]bool{
		"audit.jsonl":                         true,
		"cdn-feeds.json":                      true,
		"client-telemetry.json":               true,
		"rulesets-update.json":                true,
		"runtime-status.json":                 true,
		"selector-health.json":                true,
		"subscription-refresh-status.json":    true,
		"subscription-runtime-operation.json": true,
		"subscription-runtime-status.json":    true,
	}
	excludedSecrets := map[string]bool{
		"secrets/admin-password-hash": true, "secrets/session-signing-key": true, "secrets/management-api-token": true,
		"secrets/recovery/master-key": true, "secrets/recovery/key-wrap": true, "secrets/routeros/backup-password": true,
	}
	type rootSpec struct {
		root, prefix string
		skipTop      map[string]bool
	}
	specs := []rootSpec{
		{configRoot, "config", map[string]bool{"generated": true, "rulesets": true}},
		{stateRoot, "state", map[string]bool{"runtime-candidates": true}},
		{filepath.Join(dataRoot, "last-known-good"), "data/last-known-good", nil},
	}
	files := make([]recoverySourceFile, 0)
	var total int64
	for _, spec := range specs {
		if _, err := os.Stat(spec.root); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		err := filepath.WalkDir(spec.root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			relative, err := filepath.Rel(spec.root, path)
			if err != nil {
				return err
			}
			if relative == "." {
				return nil
			}
			parts := strings.Split(filepath.ToSlash(relative), "/")
			if len(parts) == 1 && entry.IsDir() && spec.skipTop[parts[0]] {
				return filepath.SkipDir
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if recoveryAtomicTemporaryArtifact(entry.Name(), info) {
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			archivePath := spec.prefix + "/" + filepath.ToSlash(relative)
			if spec.prefix == "config" {
				if excludedSecrets[filepath.ToSlash(relative)] {
					return nil
				}
				if len(parts) == 1 && !selectedTop[parts[0]] {
					return nil
				}
			}
			if spec.prefix == "state" && len(parts) == 1 && volatileState[parts[0]] {
				return nil
			}
			if !recoveryPayloadPathPattern.MatchString(archivePath) {
				return fmt.Errorf("unsupported recovery path %q", archivePath)
			}
			if info.Size() > recoveryMaxFileBytes {
				return fmt.Errorf("recovery file %s exceeds 16 MiB", archivePath)
			}
			total += info.Size()
			if total > recoveryMaxPlainBytes {
				return errors.New("persistent state exceeds the 64 MiB recovery limit")
			}
			files = append(files, recoverySourceFile{archivePath: archivePath, path: path, size: info.Size(), modified: info.ModTime()})
			if len(files) > recoveryMaxFiles {
				return errors.New("recovery file count exceeds the safety limit")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(files) == 0 {
		return nil, errors.New("no persistent files are available for recovery")
	}
	sort.Slice(files, func(left, right int) bool { return files[left].archivePath < files[right].archivePath })
	return files, nil
}

var recoveryPayloadPathPattern = regexpMust(`^(?:config|state|data/last-known-good)/[A-Za-z0-9._/-]+$`)

func regexpMust(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }

func hashFile(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit {
		return "", errors.New("file exceeds recovery limit")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func recoveryManifest(files []recoverySourceFile, createdAt, revision string) map[string]any {
	entries := make([]any, len(files))
	for index, file := range files {
		entries[index] = map[string]any{"path": file.archivePath, "size_bytes": file.size, "sha256": file.digest}
	}
	return map[string]any{"format_version": recoveryFormatVersion, "created_at": createdAt, "application_version": envOr("SB_GATEWAY_VERSION", "1.5.57"), "active_revision": nullableString(revision), "files": entries}
}

func writeRecoveryTar(destination io.Writer, files []recoverySourceFile, manifest map[string]any) error {
	writer := tar.NewWriter(destination)
	manifestBody, err := canonicalJSON(manifest)
	if err != nil {
		return err
	}
	manifestBody = append(manifestBody, '\n')
	if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifestBody)), ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
		return err
	}
	if _, err := writer.Write(manifestBody); err != nil {
		return err
	}
	buffer := make([]byte, 64<<10)
	for _, source := range files {
		if err := writer.WriteHeader(&tar.Header{Name: source.archivePath, Mode: 0o600, Size: source.size, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
			return err
		}
		file, err := os.Open(source.path)
		if err != nil {
			return err
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() != source.size {
			_ = file.Close()
			return errors.New("staged recovery source changed while archiving")
		}
		digest := sha256.New()
		written, copyErr := io.CopyBuffer(writer, io.TeeReader(io.LimitReader(file, source.size+1), digest), buffer)
		dropRecoveryFileCache(file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if written != source.size {
			return errors.New("recovery source changed while archiving")
		}
		if hex.EncodeToString(digest.Sum(nil)) != source.digest {
			return errors.New("staged recovery digest changed while archiving")
		}
	}
	return writer.Close()
}

type recoveryChunkEncryptor struct {
	destination  io.Writer
	aead         cipher.AEAD
	noncePrefix  [4]byte
	headerDigest [32]byte
	index        uint64
	buffer       []byte
	ciphertext   []byte
	total        int64
}

func newRecoveryChunkEncryptor(destination io.Writer, master, noncePrefix []byte, header map[string]any) (*recoveryChunkEncryptor, error) {
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	headerBody, err := canonicalJSON(header)
	if err != nil {
		return nil, err
	}
	result := &recoveryChunkEncryptor{
		destination: destination, aead: aead, headerDigest: sha256.Sum256(headerBody),
		buffer: make([]byte, 0, recoveryChunkBytes), ciphertext: make([]byte, 0, recoveryChunkBytes+aead.Overhead()),
	}
	copy(result.noncePrefix[:], noncePrefix)
	return result, nil
}

func (writer *recoveryChunkEncryptor) Write(body []byte) (int, error) {
	written := 0
	for len(body) != 0 {
		space := recoveryChunkBytes - len(writer.buffer)
		count := min(space, len(body))
		writer.buffer = append(writer.buffer, body[:count]...)
		body = body[count:]
		written += count
		if len(writer.buffer) == recoveryChunkBytes {
			if err := writer.flush(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (writer *recoveryChunkEncryptor) Close() error {
	if len(writer.buffer) != 0 {
		return writer.flush()
	}
	return nil
}

func (writer *recoveryChunkEncryptor) flush() error {
	if writer.total+int64(len(writer.buffer)) > recoveryMaxPlainBytes {
		return errors.New("recovery plaintext exceeds the safety limit")
	}
	nonce := recoveryChunkNonce(writer.noncePrefix, writer.index)
	aad := recoveryChunkAAD(writer.headerDigest, writer.index, len(writer.buffer))
	ciphertext := writer.aead.Seal(writer.ciphertext[:0], nonce[:], writer.buffer, aad[:])
	var sizeBody [4]byte
	binary.BigEndian.PutUint32(sizeBody[:], uint32(len(writer.buffer)))
	if _, err := writer.destination.Write(sizeBody[:]); err != nil {
		return err
	}
	if _, err := writer.destination.Write(ciphertext); err != nil {
		return err
	}
	writer.ciphertext = ciphertext[:0]
	writer.total += int64(len(writer.buffer))
	writer.index++
	writer.buffer = writer.buffer[:0]
	return nil
}

func recoveryChunkNonce(prefix [4]byte, index uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], index)
	return nonce
}
func recoveryChunkAAD(header [32]byte, index uint64, size int) [44]byte {
	var aad [44]byte
	copy(aad[:], header[:])
	binary.BigEndian.PutUint64(aad[32:], index)
	binary.BigEndian.PutUint32(aad[40:], uint32(size))
	return aad
}

func recoveryArchiveFilename(created time.Time, revision string) string {
	label := strings.Repeat("0", 12)
	if safeRevision(revision) {
		label = revision[:12]
	}
	return "SB-GATEWAY-state-" + created.Format("20060102T150405Z") + "-" + label + ".sbgw"
}

func (server *Server) updateRecoveryIndex(metadata recoveryArchiveMetadata) error {
	index, err := server.repository.loadAuxiliary("recovery-index")
	if errors.Is(err, os.ErrNotExist) {
		index = map[string]any{}
	} else if err != nil {
		return err
	}
	items := objectAt(index, "items")
	items[metadata.Name] = metadata.document()
	_, backupRoot, _ := server.recoveryRoots()
	retained, listErr := retainedRecoveryArchiveNames(backupRoot)
	if listErr != nil {
		return listErr
	}
	keep := make(map[string]bool, min(len(retained), recoveryRetentionLimit))
	for position, name := range retained {
		if position == recoveryRetentionLimit {
			break
		}
		keep[name] = true
	}
	for name := range items {
		if !keep[name] {
			delete(items, name)
		}
	}
	index["items"] = items
	return server.repository.saveAuxiliary("recovery-index", index)
}

func (server *Server) pruneRecoveryArchives(root string) error {
	names, err := retainedRecoveryArchiveNames(root)
	if err != nil {
		return err
	}
	if len(names) <= recoveryRetentionLimit {
		return nil
	}
	for _, name := range names[recoveryRetentionLimit:] {
		if err := os.Remove(filepath.Join(root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (server *Server) recoveryArchiveMetadata(path string, calculateHash bool) (recoveryArchiveMetadata, error) {
	prefix, err := readRecoveryArchivePrefix(path)
	if err != nil {
		return recoveryArchiveMetadata{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return recoveryArchiveMetadata{}, err
	}
	createdAt, version := text(prefix.header["created_at"]), text(prefix.header["application_version"])
	if _, err := time.Parse(time.RFC3339, createdAt); err != nil {
		return recoveryArchiveMetadata{}, errors.New("recovery creation timestamp is invalid")
	}
	revision := prefix.header["active_revision"]
	if revision != nil && !safeRevision(text(revision)) {
		return recoveryArchiveMetadata{}, errors.New("recovery active revision is invalid")
	}
	var digest any
	if calculateHash {
		value, err := hashFile(path, recoveryMaxArchiveBytes)
		if err != nil {
			return recoveryArchiveMetadata{}, err
		}
		digest = value
	}
	return recoveryArchiveMetadata{Name: filepath.Base(path), CreatedAt: createdAt, ApplicationVersion: version, ActiveRevision: revision, Size: info.Size(), SHA256: digest}, nil
}

func (server *Server) listRecoveryArchives() ([]any, error) {
	_, root, _ := server.recoveryRoots()
	names, err := retainedRecoveryArchiveNames(root)
	if err != nil {
		return nil, err
	}
	index, _ := server.repository.loadAuxiliary("recovery-index")
	indexed := objectAt(index, "items")
	items := make([]any, 0, recoveryRetentionLimit)
	for _, name := range names {
		if len(items) == recoveryRetentionLimit {
			break
		}
		metadata, err := server.recoveryArchiveMetadata(filepath.Join(root, name), false)
		if err != nil {
			continue
		}
		if record, ok := indexed[name].(map[string]any); ok && fmt.Sprint(record["size_bytes"]) == fmt.Sprint(metadata.Size) {
			metadata.SHA256 = record["sha256"]
		}
		document := metadata.document()
		document["ssd"] = true
		document["routeros_files"] = false
		items = append(items, document)
	}
	return items, nil
}

func syncParentDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (repository *stateRepository) loadAuxiliary(name string) (map[string]any, error) {
	return repository.readJSON(filepath.Join(repository.root, name+".json"))
}
