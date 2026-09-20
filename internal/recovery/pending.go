package recovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

const (
	maxPendingBytes = 1 << 20
	maxFileBytes    = 16 << 20
)

var (
	operationPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pathPattern      = regexp.MustCompile(`^(?:config|state|data/last-known-good)/[A-Za-z0-9._/-]+$`)
)

type Options struct {
	ConfigDir string
	StateDir  string
	DataDir   string
}

type Result struct {
	OK            bool   `json:"ok"`
	Operation     string `json:"operation"`
	RestoredFiles int    `json:"restored_files"`
	ArchiveName   any    `json:"archive_name,omitempty"`
}

type pendingRestore struct {
	OperationID string          `json:"operation_id"`
	ArchiveName any             `json:"archive_name"`
	StagingPath string          `json:"staging_path"`
	Manifest    pendingManifest `json:"manifest"`
}

type pendingManifest struct {
	Files []pendingFile `json:"files"`
}

type pendingFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

func OptionsFromEnvironment() Options {
	return Options{
		ConfigDir: envOr("SB_GATEWAY_CONFIG_DIR", "/config"),
		StateDir:  envOr("SB_GATEWAY_STATE_DIR", "/state/control-plane"),
		DataDir:   envOr("SB_GATEWAY_DATA_DIR", "/data"),
	}
}

func ApplyPending(options Options) (Result, error) {
	configRoot, err := cleanRoot(options.ConfigDir)
	if err != nil {
		return Result{}, err
	}
	stateRoot, err := cleanRoot(options.StateDir)
	if err != nil {
		return Result{}, err
	}
	dataRoot, err := cleanRoot(options.DataDir)
	if err != nil {
		return Result{}, err
	}
	pendingPath := filepath.Join(configRoot, ".sb-gateway-recovery-pending.json")
	pending, err := readPending(pendingPath)
	if errors.Is(err, os.ErrNotExist) {
		return Result{OK: true, Operation: "none"}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if !operationPattern.MatchString(pending.OperationID) {
		return Result{}, errors.New("pending recovery operation identifier is invalid")
	}
	expectedStaging := filepath.Join(dataRoot, "recovery-staging", pending.OperationID)
	if filepath.Clean(pending.StagingPath) != filepath.Clean(expectedStaging) {
		return Result{}, errors.New("pending recovery staging directory path does not match the requested operation")
	}
	pendingInfo, err := os.Lstat(pending.StagingPath)
	if err != nil || !pendingInfo.IsDir() || pendingInfo.Mode()&os.ModeSymlink != 0 {
		return Result{}, errors.New("pending recovery staging directory type is invalid")
	}
	stagingRoot := filepath.Clean(pending.StagingPath)
	if runtime.GOOS != "windows" {
		stagingRoot, err = filepath.EvalSymlinks(pending.StagingPath)
		if err != nil {
			return Result{}, errors.New("pending recovery staging directory cannot be resolved")
		}
	}
	if len(pending.Manifest.Files) == 0 {
		return Result{}, errors.New("pending recovery manifest has no files")
	}
	if len(pending.Manifest.Files) > 4096 {
		return Result{}, errors.New("pending recovery manifest contains too many files")
	}

	restored := 0
	for _, entry := range pending.Manifest.Files {
		if !pathPattern.MatchString(entry.Path) || hasParentTraversal(entry.Path) ||
			!digestPattern.MatchString(entry.SHA256) || entry.Size < 0 || entry.Size > maxFileBytes {
			return Result{}, errors.New("pending recovery manifest entry is invalid")
		}
		source, err := secureDescendant(stagingRoot, filepath.FromSlash(entry.Path), true)
		if err != nil {
			return Result{}, err
		}
		destination, err := restoreDestination(entry.Path, configRoot, stateRoot, dataRoot)
		if err != nil {
			return Result{}, err
		}
		if err := copyVerifiedAtomic(source, destination, entry.Size, entry.SHA256); err != nil {
			return Result{}, err
		}
		restored++
	}
	if err := os.Remove(pendingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Result{}, err
	}
	_ = syncDirectory(filepath.Dir(pendingPath))
	if err := os.RemoveAll(stagingRoot); err != nil {
		return Result{}, err
	}
	return Result{OK: true, Operation: "restored", RestoredFiles: restored, ArchiveName: pending.ArchiveName}, nil
}

func readPending(path string) (pendingRestore, error) {
	file, err := os.Open(path)
	if err != nil {
		return pendingRestore{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return pendingRestore{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPendingBytes {
		return pendingRestore{}, errors.New("pending recovery operation is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxPendingBytes+1))
	var pending pendingRestore
	if err := decoder.Decode(&pending); err != nil {
		return pendingRestore{}, errors.New("pending recovery operation is corrupt")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return pendingRestore{}, errors.New("pending recovery operation is corrupt")
	}
	return pending, nil
}

func restoreDestination(relative, configRoot, stateRoot, dataRoot string) (string, error) {
	var root, suffix string
	switch {
	case strings.HasPrefix(relative, "config/"):
		root, suffix = configRoot, strings.TrimPrefix(relative, "config/")
	case strings.HasPrefix(relative, "state/"):
		root, suffix = stateRoot, strings.TrimPrefix(relative, "state/")
	case strings.HasPrefix(relative, "data/last-known-good/"):
		root = filepath.Join(dataRoot, "last-known-good")
		suffix = strings.TrimPrefix(relative, "data/last-known-good/")
	default:
		return "", errors.New("recovery archive contains an unsupported path")
	}
	return secureDescendant(root, filepath.FromSlash(suffix), false)
}

func secureDescendant(root, relative string, mustExist bool) (string, error) {
	if filepath.IsAbs(relative) || hasParentTraversal(filepath.ToSlash(relative)) {
		return "", errors.New("recovery path escaped its root")
	}
	candidate := filepath.Clean(filepath.Join(root, relative))
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("recovery path escaped its root")
	}
	current := filepath.Clean(root)
	parts := strings.Split(rel, string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) && !mustExist {
			break
		}
		if statErr != nil {
			return "", errors.New("recovery source is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("recovery path cannot traverse a symbolic link")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", errors.New("recovery path parent is not a directory")
		}
	}
	return candidate, nil
}

func copyVerifiedAtomic(source, destination string, expectedSize int64, expectedDigest string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := input.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != expectedSize {
		return errors.New("staged recovery file size does not match its manifest")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, digest), io.LimitReader(input, maxFileBytes+1))
	if err != nil {
		temporary.Close()
		return err
	}
	if written != expectedSize || hex.EncodeToString(digest.Sum(nil)) != expectedDigest {
		temporary.Close()
		return errors.New("staged recovery file failed its checksum")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func cleanRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func hasParentTraversal(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func (result Result) String() string {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"ok":false,"operation":"error"}`)
	}
	return string(body)
}
