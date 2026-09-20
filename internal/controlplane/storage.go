package controlplane

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type stateRepository struct {
	root        string
	generations string
	mu          sync.RWMutex
	cache       map[string]cachedDocument
}

type cachedDocument struct {
	modified int64
	size     int64
	value    map[string]any
}

// Four entries cover the hot draft, active generation, runtime status and one
// auxiliary document. Older generation variants are read on demand instead of
// occupying router memory "just in case".
const stateDocumentCacheLimit = 4

func newStateRepository(root string) (*stateRepository, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	repository := &stateRepository{
		root:        abs,
		generations: filepath.Join(abs, "generations"),
		cache:       make(map[string]cachedDocument),
	}
	if err := os.MkdirAll(repository.generations, 0o700); err != nil {
		return nil, err
	}
	return repository, nil
}

func canonicalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func revisionFor(value any) (string, error) {
	body, err := canonicalJSON(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (repository *stateRepository) readJSON(path string) (map[string]any, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	repository.mu.RLock()
	cached, ok := repository.cache[path]
	if ok && cached.modified == info.ModTime().UnixNano() && cached.size == info.Size() {
		value := cloneJSONObject(cached.value)
		repository.mu.RUnlock()
		return value, nil
	}
	repository.mu.RUnlock()

	value, err := readJSONObject(path)
	if err != nil {
		return nil, err
	}
	repository.mu.Lock()
	repository.cacheDocument(path, cachedDocument{
		modified: info.ModTime().UnixNano(),
		size:     info.Size(),
		value:    value,
	})
	repository.mu.Unlock()
	return cloneJSONObject(value), nil
}

func readJSONObject(path string) (map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	decoder.UseNumber()
	value := map[string]any{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func (repository *stateRepository) writeJSON(path string, value map[string]any) error {
	body, err := canonicalJSON(value)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if err := writeAtomic(path, body, 0o600, true); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		delete(repository.cache, path)
		return err
	}
	repository.cacheDocument(path, cachedDocument{
		modified: info.ModTime().UnixNano(),
		size:     info.Size(),
		value:    cloneJSONObject(value),
	})
	return nil
}

func writeAtomic(path string, body []byte, mode os.FileMode, skipUnchanged bool) error {
	if skipUnchanged {
		if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, body) {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Windows os.Rename does not replace an existing destination. Production
	// images run Linux and retain the atomic replacement semantics there; this
	// branch keeps native Windows development and release tests deterministic.
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = directory.Sync()
		_ = directory.Close()
	}
	return err
}

func (repository *stateRepository) loadDraft() (map[string]any, error) {
	return repository.readJSON(filepath.Join(repository.root, "draft.json"))
}

func (repository *stateRepository) activeRevision() (string, error) {
	pointer, err := repository.readJSON(filepath.Join(repository.root, "active.json"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	revision, _ := pointer["revision"].(string)
	if revision != "" && !safeRevision(revision) {
		return "", errors.New("active revision is invalid")
	}
	return revision, nil
}

func (repository *stateRepository) lkgRevision() (string, error) {
	pointer, err := repository.readJSON(filepath.Join(repository.root, "last-known-good.json"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	revision, _ := pointer["revision"].(string)
	if revision != "" && !safeRevision(revision) {
		return "", errors.New("last-known-good revision is invalid")
	}
	return revision, nil
}

func (repository *stateRepository) metadata() (map[string]any, error) {
	value, err := repository.readJSON(filepath.Join(repository.root, "apply-metadata.json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	return value, err
}

func (repository *stateRepository) runtimeStatus() (map[string]any, error) {
	value, err := repository.auxiliary("runtime-status")
	if err != nil {
		return nil, err
	}
	if len(value) > 0 {
		return value, nil
	}
	return map[string]any{
		"container": map[string]any{"healthy": nil, "last_probe": nil},
		"watchdog": map[string]any{
			"enabled": true, "state": "unknown", "restarts": 0,
			"max_restarts_per_hour": 6, "budget_remaining": 6,
			"failure_count": 0, "last_action": nil,
		},
	}, nil
}

func (repository *stateRepository) recentAudit(limit int) ([]map[string]any, error) {
	if limit <= 0 {
		return []map[string]any{}, nil
	}
	if limit > 200 {
		limit = 200
	}
	path := filepath.Join(repository.root, "audit.jsonl")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	const tailLimit = int64(512 << 10)
	start := info.Size() - tailLimit
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(file, tailLimit))
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(body, []byte("\n"))
	if start > 0 && len(lines) > 0 {
		// The tail can begin in the middle of a JSONL event.
		lines = lines[1:]
	}
	if len(lines) > limit+1 {
		lines = lines[len(lines)-limit-1:]
	}
	result := make([]map[string]any, 0, limit)
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event map[string]any
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if decoder.Decode(&event) == nil {
			result = append(result, event)
		}
	}
	if len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result, nil
}

func (repository *stateRepository) saveDraft(value map[string]any) (string, error) {
	revision, err := revisionFor(value)
	if err != nil {
		return "", err
	}
	return revision, repository.writeJSON(filepath.Join(repository.root, "draft.json"), value)
}

func (repository *stateRepository) stageGeneration(value map[string]any) (string, error) {
	revision, err := revisionFor(value)
	if err != nil {
		return "", err
	}
	path := filepath.Join(repository.generations, revision+".json")
	if _, err := os.Stat(path); err == nil {
		return revision, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return revision, repository.writeJSON(path, value)
}

func (repository *stateRepository) setActiveRevision(revision string) error {
	if !safeRevision(revision) {
		return errors.New("active revision is invalid")
	}
	if _, err := repository.loadGeneration(revision); err != nil {
		return err
	}
	return repository.writeJSON(filepath.Join(repository.root, "active.json"), map[string]any{"revision": revision})
}

type commitMetadata struct {
	NodeSnapshotRevision         string
	PreviousNodeSnapshotRevision string
	RouterOSSource               string
	Revision                     string
	PreviousRevision             string
	RuntimeRevision              string
	PreviousRuntimeRevision      string
	BackupRef                    any
	Actor                        string
	CommittedAt                  time.Time
}

// commitActive publishes the already durable generation. active.json is the
// commit point; LKG and metadata can be reconstructed from it after a crash.
func (repository *stateRepository) commitActive(metadata commitMetadata) error {
	if !safeRevision(metadata.Revision) {
		return errors.New("active revision is invalid")
	}
	if metadata.PreviousRevision != "" && !safeRevision(metadata.PreviousRevision) {
		return errors.New("previous revision is invalid")
	}
	if metadata.RuntimeRevision != "" && !safeRevision(metadata.RuntimeRevision) {
		return errors.New("runtime revision is invalid")
	}
	if metadata.PreviousRuntimeRevision != "" && !safeRevision(metadata.PreviousRuntimeRevision) {
		return errors.New("previous runtime revision is invalid")
	}
	for _, revision := range []string{metadata.NodeSnapshotRevision, metadata.PreviousNodeSnapshotRevision} {
		if revision != "" && !safeRevision(revision) {
			return errors.New("node snapshot revision is invalid")
		}
	}
	if metadata.Actor == "" || len(metadata.Actor) > 128 {
		return errors.New("commit actor is invalid")
	}
	if _, err := repository.loadGeneration(metadata.Revision); err != nil {
		return err
	}
	committedAt := metadata.CommittedAt.UTC()
	if committedAt.IsZero() {
		committedAt = time.Now().UTC()
	}
	pointer := map[string]any{
		"node_snapshot_revision":          nullableString(metadata.NodeSnapshotRevision),
		"previous_node_snapshot_revision": nullableString(metadata.PreviousNodeSnapshotRevision),
		"routeros_source":                 metadata.RouterOSSource,
		"revision":                        metadata.Revision,
		"previous_revision":               nullableString(metadata.PreviousRevision),
		"runtime_revision":                nullableString(metadata.RuntimeRevision),
		"previous_runtime_revision":       nullableString(metadata.PreviousRuntimeRevision),
		"backup_ref":                      cloneJSONValue(metadata.BackupRef),
		"actor":                           metadata.Actor,
		"committed_at":                    committedAt.Format(time.RFC3339Nano),
	}
	if err := repository.writeJSON(filepath.Join(repository.root, "active.json"), pointer); err != nil {
		return err
	}
	if err := repository.writeJSON(filepath.Join(repository.root, "last-known-good.json"), pointer); err != nil {
		return err
	}
	return repository.writeJSON(filepath.Join(repository.root, "apply-metadata.json"), pointer)
}

// reconcileCommitPointers repairs the two derivative documents only from the
// active commit point. It never guesses a generation and performs no scan.
func (repository *stateRepository) reconcileCommitPointers() error {
	active, err := repository.readJSON(filepath.Join(repository.root, "active.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	revision, _ := active["revision"].(string)
	if !safeRevision(revision) {
		return errors.New("active revision is invalid")
	}
	if _, err := repository.loadGeneration(revision); err != nil {
		return err
	}
	for _, name := range []string{"last-known-good.json", "apply-metadata.json"} {
		current, readErr := repository.readJSON(filepath.Join(repository.root, name))
		if readErr == nil && equalJSONObject(current, active) {
			continue
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if err := repository.writeJSON(filepath.Join(repository.root, name), active); err != nil {
			return err
		}
	}
	return nil
}

func (repository *stateRepository) updateRuntimeRevision(revision string) error {
	if !safeRevision(revision) {
		return errors.New("runtime revision is invalid")
	}
	activePath := filepath.Join(repository.root, "active.json")
	active, err := repository.readJSON(activePath)
	if err != nil {
		return err
	}
	if !safeRevision(text(active["revision"])) {
		return errors.New("active configuration revision is invalid")
	}
	previous := text(active["runtime_revision"])
	active["previous_runtime_revision"] = nullableString(previous)
	active["runtime_revision"] = revision
	if err := repository.writeJSON(activePath, active); err != nil {
		return err
	}
	return repository.reconcileCommitPointers()
}

func equalJSONObject(left, right map[string]any) bool {
	leftBody, leftErr := canonicalJSON(left)
	rightBody, rightErr := canonicalJSON(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBody, rightBody)
}

func (repository *stateRepository) loadGeneration(revision string) (map[string]any, error) {
	if !safeRevision(revision) {
		return nil, errors.New("unsafe generation revision")
	}
	value, err := repository.readJSON(filepath.Join(repository.generations, revision+".json"))
	if err != nil {
		return nil, err
	}
	actual, err := revisionFor(value)
	if err != nil || actual != revision {
		return nil, errors.New("generation checksum mismatch")
	}
	return value, nil
}

func (repository *stateRepository) loadActive() (map[string]any, error) {
	pointer, err := repository.readJSON(filepath.Join(repository.root, "active.json"))
	if err != nil {
		return nil, err
	}
	revision, _ := pointer["revision"].(string)
	return repository.loadGeneration(revision)
}

func (repository *stateRepository) auxiliary(name string) (map[string]any, error) {
	if !safeAuxiliaryName(name) {
		return nil, errors.New("invalid auxiliary state name")
	}
	value, err := repository.readJSON(filepath.Join(repository.root, name+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	return value, err
}

func (repository *stateRepository) saveAuxiliary(name string, value map[string]any) error {
	if !safeAuxiliaryName(name) {
		return errors.New("invalid auxiliary state name")
	}
	return repository.writeJSON(filepath.Join(repository.root, name+".json"), value)
}

func (repository *stateRepository) appendAudit(event map[string]any) error {
	body, err := canonicalJSON(event)
	if err != nil {
		return err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	path := filepath.Join(repository.root, "audit.jsonl")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(body, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func safeRevision(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func safeAuxiliaryName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func requireObject(value any, name string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	return object, nil
}

func cloneJSONObject(value map[string]any) map[string]any {
	return cloneJSONValue(value).(map[string]any)
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = cloneJSONValue(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneJSONValue(item)
		}
		return result
	default:
		return typed
	}
}

func (repository *stateRepository) cacheDocument(path string, document cachedDocument) {
	if _, exists := repository.cache[path]; !exists && len(repository.cache) >= stateDocumentCacheLimit {
		for cachedPath := range repository.cache {
			delete(repository.cache, cachedPath)
			break
		}
	}
	repository.cache[path] = document
}
