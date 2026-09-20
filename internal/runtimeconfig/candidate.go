package runtimeconfig

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
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxCandidateArtifactBytes = 32 << 20
	maxCandidateTotalBytes    = 64 << 20
)

var (
	candidateRevisionPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	candidateArtifactPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

type CandidateStore struct {
	root         string
	lkg          string
	destinations map[string]string
	mu           sync.Mutex
}

type RuntimeCandidate struct {
	Revision  string
	Directory string
	Files     map[string]string
}

type ActivationReceipt struct {
	candidate       RuntimeCandidate
	previous        string
	previousPresent map[string]bool
	changed         []string
}

type candidateManifest struct {
	Artifacts map[string]string `json:"artifacts"`
	Revision  string            `json:"revision"`
}

func NewCandidateStore(stateRoot string, destinations map[string]string) (*CandidateStore, error) {
	stateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return nil, err
	}
	if len(destinations) == 0 {
		return nil, errors.New("runtime candidate has no destinations")
	}
	root := filepath.Join(stateRoot, "runtime-candidates")
	normalized := make(map[string]string, len(destinations))
	seenDestinations := make(map[string]string, len(destinations))
	for name, destination := range destinations {
		if !candidateArtifactPattern.MatchString(name) || filepath.Base(name) != name || name == "manifest.json" {
			return nil, fmt.Errorf("invalid runtime artifact name %q", name)
		}
		if destination == "" {
			return nil, fmt.Errorf("runtime artifact %q has no destination", name)
		}
		absolute, resolveErr := filepath.Abs(destination)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if pathWithin(root, absolute) {
			return nil, fmt.Errorf("runtime artifact %q destination overlaps candidate storage", name)
		}
		key := filepath.Clean(absolute)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if previous, exists := seenDestinations[key]; exists {
			return nil, fmt.Errorf("runtime artifacts %q and %q share a destination", previous, name)
		}
		seenDestinations[key] = name
		normalized[name] = absolute
	}
	return &CandidateStore{
		root: root, lkg: filepath.Join(stateRoot, "runtime-lkg"), destinations: normalized,
	}, nil
}

// Prepare writes one complete, immutable candidate directory. After the new
// directory is durable, reproducible older candidates are removed; rollback
// state lives separately and is never multiplied per revision.
func (store *CandidateStore) Prepare(revision string, artifacts map[string][]byte) (RuntimeCandidate, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !candidateRevisionPattern.MatchString(revision) {
		return RuntimeCandidate{}, errors.New("runtime candidate revision must be a lowercase SHA-256 digest")
	}
	if len(artifacts) == 0 {
		return RuntimeCandidate{}, errors.New("runtime candidate has no artifacts")
	}
	if len(artifacts) != len(store.destinations) {
		return RuntimeCandidate{}, errors.New("runtime candidate must contain every managed artifact")
	}
	names := make([]string, 0, len(artifacts))
	total := 0
	for name, body := range artifacts {
		if _, ok := store.destinations[name]; !ok {
			return RuntimeCandidate{}, fmt.Errorf("runtime artifact %q has no managed destination", name)
		}
		if len(body) > maxCandidateArtifactBytes {
			return RuntimeCandidate{}, fmt.Errorf("runtime artifact %q exceeds 32 MiB", name)
		}
		total += len(body)
		if total > maxCandidateTotalBytes {
			return RuntimeCandidate{}, errors.New("runtime candidate exceeds 64 MiB")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	if err := os.MkdirAll(store.root, 0o700); err != nil {
		return RuntimeCandidate{}, err
	}
	staging, err := os.MkdirTemp(store.root, ".next-")
	if err != nil {
		return RuntimeCandidate{}, err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return RuntimeCandidate{}, err
	}
	manifest := candidateManifest{Artifacts: make(map[string]string, len(names)), Revision: revision}
	for _, name := range names {
		body := artifacts[name]
		path := filepath.Join(staging, name)
		if err := writePrivateFile(path, body); err != nil {
			return RuntimeCandidate{}, err
		}
		digest := sha256.Sum256(body)
		manifest.Artifacts[name] = hex.EncodeToString(digest[:])
	}
	manifestBody, err := marshalCanonical(manifest)
	if err != nil {
		return RuntimeCandidate{}, err
	}
	if err := writePrivateFile(filepath.Join(staging, "manifest.json"), manifestBody); err != nil {
		return RuntimeCandidate{}, err
	}
	if err := syncDirectory(staging); err != nil {
		return RuntimeCandidate{}, err
	}

	directory := filepath.Join(store.root, revision)
	old := filepath.Join(store.root, ".previous")
	if err := removeManagedTree(store.root, old); err != nil {
		return RuntimeCandidate{}, err
	}
	hadOld := false
	if info, statErr := os.Lstat(directory); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return RuntimeCandidate{}, errors.New("runtime candidate destination is not a safe directory")
		}
		if err := renameManagedPath(directory, old); err != nil {
			return RuntimeCandidate{}, err
		}
		hadOld = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return RuntimeCandidate{}, statErr
	}
	if err := renameManagedPath(staging, directory); err != nil {
		if hadOld {
			_ = renameManagedPath(old, directory)
		}
		return RuntimeCandidate{}, err
	}
	if err := syncDirectory(store.root); err != nil {
		return RuntimeCandidate{}, err
	}
	if hadOld {
		if err := removeManagedTree(store.root, old); err != nil {
			return RuntimeCandidate{}, err
		}
	}
	if err := store.pruneExcept(revision); err != nil {
		return RuntimeCandidate{}, err
	}
	return candidateFromManifest(directory, manifest), nil
}

// Load verifies a prepared candidate at the Plan/Apply trust boundary without
// rendering it again or retaining artifact bodies in memory.
func (store *CandidateStore) Load(revision string) (RuntimeCandidate, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !candidateRevisionPattern.MatchString(revision) {
		return RuntimeCandidate{}, errors.New("runtime candidate revision is invalid")
	}
	directory := filepath.Join(store.root, revision)
	manifestPath := filepath.Join(directory, "manifest.json")
	file, err := os.Open(manifestPath)
	if err != nil {
		return RuntimeCandidate{}, err
	}
	manifestInfo, err := file.Stat()
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > 1<<20 {
		file.Close()
		return RuntimeCandidate{}, errors.New("runtime candidate manifest is not a bounded regular file")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	var manifest candidateManifest
	decodeErr := decoder.Decode(&manifest)
	if decodeErr == nil {
		decodeErr = rejectTrailingJSON(decoder)
	}
	closeErr := file.Close()
	if decodeErr != nil {
		return RuntimeCandidate{}, fmt.Errorf("decode runtime candidate manifest: %w", decodeErr)
	}
	if closeErr != nil {
		return RuntimeCandidate{}, closeErr
	}
	if manifest.Revision != revision || len(manifest.Artifacts) != len(store.destinations) {
		return RuntimeCandidate{}, errors.New("runtime candidate manifest does not match the requested revision")
	}
	hashBuffer := make([]byte, 128<<10)
	for name := range store.destinations {
		expected, ok := manifest.Artifacts[name]
		if !ok || !candidateRevisionPattern.MatchString(expected) {
			return RuntimeCandidate{}, fmt.Errorf("runtime candidate manifest is missing artifact %q", name)
		}
		path := filepath.Join(directory, name)
		actual, hashErr := hashRegularFile(path, maxCandidateArtifactBytes, hashBuffer)
		if hashErr != nil {
			return RuntimeCandidate{}, fmt.Errorf("verify runtime artifact %q: %w", name, hashErr)
		}
		if actual != expected {
			return RuntimeCandidate{}, fmt.Errorf("runtime artifact %q does not match its manifest", name)
		}
	}
	return candidateFromManifest(directory, manifest), nil
}

func (store *CandidateStore) Activate(candidate RuntimeCandidate) (ActivationReceipt, error) {
	return store.ActivateAfter(candidate, nil)
}

// ActivateAfter computes the changed set once, lets the caller validate that
// exact set, and only then publishes it while holding the store lock. This
// avoids hashing every destination twice and prevents a concurrent publisher
// from changing the proof-to-publish boundary.
func (store *CandidateStore) ActivateAfter(candidate RuntimeCandidate, validate func([]string) error) (ActivationReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.validateCandidate(candidate); err != nil {
		return ActivationReceipt{}, err
	}
	previous := filepath.Join(candidate.Directory, ".previous-runtime")
	names := sortedKeys(candidate.Files)
	receipt := ActivationReceipt{
		candidate: candidate, previous: previous,
		previousPresent: make(map[string]bool, len(names)), changed: make([]string, 0, len(names)),
	}
	for _, name := range names {
		source := candidate.Files[name]
		destination := store.destinations[name]
		equal, err := filesEqual(source, destination)
		if err == nil && equal {
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ActivationReceipt{}, err
		}
		receipt.changed = append(receipt.changed, name)
	}
	if len(receipt.changed) == 0 {
		return receipt, nil
	}
	if validate != nil {
		if err := validate(append([]string(nil), receipt.changed...)); err != nil {
			return ActivationReceipt{}, err
		}
	}
	if err := removeManagedTree(candidate.Directory, previous); err != nil {
		return ActivationReceipt{}, err
	}
	if err := os.MkdirAll(previous, 0o700); err != nil {
		return ActivationReceipt{}, err
	}
	for _, name := range receipt.changed {
		destination := store.destinations[name]
		if info, statErr := os.Stat(destination); statErr == nil {
			if !info.Mode().IsRegular() {
				return ActivationReceipt{}, fmt.Errorf("runtime destination %q is not a regular file", name)
			}
			receipt.previousPresent[name] = true
			if err := copyFileAtomic(destination, filepath.Join(previous, name)); err != nil {
				return ActivationReceipt{}, err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return ActivationReceipt{}, statErr
		}
	}
	for _, name := range receipt.changed {
		if err := copyFileAtomic(candidate.Files[name], store.destinations[name]); err != nil {
			_ = store.rollbackLocked(receipt)
			return ActivationReceipt{}, fmt.Errorf("publish runtime artifact %q: %w", name, err)
		}
	}
	return receipt, nil
}

func (store *CandidateStore) Rollback(receipt ActivationReceipt) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.rollbackLocked(receipt)
}

func (store *CandidateStore) rollbackLocked(receipt ActivationReceipt) error {
	var failures []error
	for _, name := range receipt.changed {
		destination, ok := store.destinations[name]
		if !ok {
			failures = append(failures, fmt.Errorf("runtime artifact %q is no longer managed", name))
			continue
		}
		if receipt.previousPresent[name] {
			if err := copyFileAtomic(filepath.Join(receipt.previous, name), destination); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, err)
		}
	}
	result := errors.Join(failures...)
	if result == nil {
		result = removeManagedTree(receipt.candidate.Directory, receipt.previous)
	}
	return result
}

func (store *CandidateStore) CommitLastKnownGood(candidate RuntimeCandidate) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.validateCandidate(candidate); err != nil {
		return err
	}
	if err := os.MkdirAll(store.lkg, 0o700); err != nil {
		return err
	}
	for _, name := range sortedKeys(candidate.Files) {
		equal, err := filesEqual(candidate.Files[name], filepath.Join(store.lkg, name))
		if err == nil && equal {
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := copyFileAtomic(candidate.Files[name], filepath.Join(store.lkg, name)); err != nil {
			return err
		}
	}
	return removeManagedTree(candidate.Directory, filepath.Join(candidate.Directory, ".previous-runtime"))
}

func (receipt ActivationReceipt) Changed() []string {
	return append([]string(nil), receipt.changed...)
}

func (store *CandidateStore) validateCandidate(candidate RuntimeCandidate) error {
	if !candidateRevisionPattern.MatchString(candidate.Revision) {
		return errors.New("runtime candidate revision is invalid")
	}
	want := filepath.Join(store.root, candidate.Revision)
	directory, err := filepath.Abs(candidate.Directory)
	if err != nil || !samePath(directory, want) {
		return errors.New("runtime candidate directory is outside the managed store")
	}
	for name, path := range candidate.Files {
		if _, ok := store.destinations[name]; !ok || !samePath(path, filepath.Join(want, name)) {
			return fmt.Errorf("runtime candidate artifact %q is outside the managed directory", name)
		}
		info, statErr := os.Stat(path)
		if statErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("runtime candidate artifact %q is unavailable", name)
		}
	}
	return nil
}

func (store *CandidateStore) pruneExcept(revision string) error {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == revision {
			continue
		}
		managedTemporary := strings.HasPrefix(entry.Name(), ".next-") || entry.Name() == ".previous"
		if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() || (!candidateRevisionPattern.MatchString(entry.Name()) && !managedTemporary) {
			continue
		}
		if err := removeManagedTree(store.root, filepath.Join(store.root, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func candidateFromManifest(directory string, manifest candidateManifest) RuntimeCandidate {
	files := make(map[string]string, len(manifest.Artifacts))
	for name := range manifest.Artifacts {
		files[name] = filepath.Join(directory, name)
	}
	return RuntimeCandidate{Revision: manifest.Revision, Directory: directory, Files: files}
}

func marshalCanonical(value any) ([]byte, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func writePrivateFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(body); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func copyFileAtomic(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	buffer := make([]byte, 128<<10)
	if _, err := io.CopyBuffer(temporary, input, buffer); err != nil {
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
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(destination))
}

func filesEqual(first, second string) (bool, error) {
	leftInfo, err := os.Stat(first)
	if err != nil {
		return false, err
	}
	rightInfo, err := os.Stat(second)
	if err != nil {
		return false, err
	}
	if leftInfo.Size() != rightInfo.Size() {
		return false, nil
	}
	left, err := os.Open(first)
	if err != nil {
		return false, err
	}
	defer left.Close()
	right, err := os.Open(second)
	if err != nil {
		return false, err
	}
	defer right.Close()
	leftBuffer := make([]byte, 128<<10)
	rightBuffer := make([]byte, 128<<10)
	for {
		leftCount, leftErr := left.Read(leftBuffer)
		rightCount, rightErr := right.Read(rightBuffer)
		if leftCount != rightCount || !bytes.Equal(leftBuffer[:leftCount], rightBuffer[:rightCount]) {
			return false, nil
		}
		if leftErr == io.EOF && rightErr == io.EOF {
			return true, nil
		}
		if leftErr != nil && leftErr != io.EOF {
			return false, leftErr
		}
		if rightErr != nil && rightErr != io.EOF {
			return false, rightErr
		}
	}
}

func hashRegularFile(path string, limit int64, buffer []byte) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return "", errors.New("artifact is not a bounded regular file")
	}
	digest := sha256.New()
	if _, err := io.CopyBuffer(digest, file, buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON documents")
		}
		return err
	}
	return nil
}

func removeManagedTree(root, target string) error {
	root, rootErr := filepath.Abs(root)
	target, targetErr := filepath.Abs(target)
	if rootErr != nil || targetErr != nil || samePath(root, target) || !pathWithin(root, target) {
		return errors.New("refusing to remove path outside runtime candidate store")
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to remove symlinked runtime candidate path")
	}
	var removeErr error
	for attempt := 0; attempt < 4; attempt++ {
		removeErr = os.RemoveAll(target)
		if removeErr == nil || runtime.GOOS != "windows" {
			return removeErr
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return removeErr
}

func renameManagedPath(source, target string) error {
	var renameErr error
	for attempt := 0; attempt < 7; attempt++ {
		renameErr = os.Rename(source, target)
		if renameErr == nil || runtime.GOOS != "windows" {
			return renameErr
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return renameErr
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

func sortedKeys[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func samePath(left, right string) bool {
	left, _ = filepath.Abs(left)
	right, _ = filepath.Abs(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func pathWithin(root, candidate string) bool {
	root, rootErr := filepath.Abs(root)
	candidate, candidateErr := filepath.Abs(candidate)
	if rootErr != nil || candidateErr != nil {
		return false
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
}
