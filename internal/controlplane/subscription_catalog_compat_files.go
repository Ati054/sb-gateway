package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const catalogCompatDirectory = ".catalog-compat"
const catalogCompatMaxBytes = 512 << 20
const catalogCompatMaxFileBytes = 128 << 20
const catalogCompatMaxFiles = 8192

var errCatalogCompatibility = errors.New("subscription catalog image compatibility is unconfirmed")

type catalogCompatFile struct {
	Area   string `json:"area"`
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type catalogCompatRoots struct {
	Config, State, Data  string
	ControlPlaneRelative string
	SecretsRelative      string
}

func (roots catalogCompatRoots) secretsNamespace() (string, error) {
	value := roots.SecretsRelative
	if value == "" {
		value = "secrets"
	}
	if filepath.IsAbs(value) {
		return "", errCatalogCompatibility
	}
	namespace, err := configuredSecretsNamespace(roots.Config, filepath.Join(roots.Config, filepath.FromSlash(value)))
	if err != nil {
		return "", err
	}
	return namespace, nil
}

func (roots catalogCompatRoots) volatile(path string) bool {
	prefix := roots.ControlPlaneRelative
	if prefix == "" {
		prefix = "control-plane"
	}
	return filepath.ToSlash(filepath.Dir(path)) == prefix && volatileControlPlaneStateFile(filepath.Base(path))
}

func (roots catalogCompatRoots) atomicScratch(path string) bool {
	prefix := roots.ControlPlaneRelative
	if prefix == "" {
		prefix = "control-plane"
	}
	relative := filepath.ToSlash(path)
	if prefix != "." {
		if !strings.HasPrefix(relative, prefix+"/") {
			return false
		}
		relative = strings.TrimPrefix(relative, prefix+"/")
	}
	return managedControlPlaneAtomicScratch(relative)
}

// Error text contains only bounded product stages, never source paths or data.
type catalogCompatSnapshotFailure struct {
	stage, class string
	cause        error
}

func (failure catalogCompatSnapshotFailure) Error() string {
	return "subscription catalog image compatibility is unconfirmed (" + failure.stage + ": " + failure.class + ")"
}
func (failure catalogCompatSnapshotFailure) Unwrap() error { return failure.cause }
func (failure catalogCompatSnapshotFailure) Is(target error) bool {
	return target == errCatalogCompatibility
}

func catalogCompatSnapshotError(ctx context.Context, stage string, err error) error {
	if err == nil {
		return nil
	}
	var classified catalogCompatSnapshotFailure
	if errors.As(err, &classified) {
		return err
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	class := "integrity-or-storage"
	if errors.Is(err, context.DeadlineExceeded) {
		class = "deadline"
	} else if errors.Is(err, context.Canceled) {
		class = "cancelled"
	}
	return catalogCompatSnapshotFailure{stage: stage, class: class, cause: err}
}

type catalogCompatSnapshotHooks struct {
	beforeEntry    func(area, path string)
	afterOpen      func(area, path string)
	beforeValidate func()
}

func (roots catalogCompatRoots) areas() []struct{ name, path string } {
	return []struct{ name, path string }{{"config", roots.Config}, {"state", roots.State}, {"data", roots.Data}}
}

func compatSnapshotExcluded(area, path string, directory bool, secretsNamespace string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	// A supported secret reference may contain names that resemble our staging
	// trees. Protect the authoritative namespace before scratch classification.
	if area == "config" && inConfiguredNamespace(path, secretsNamespace) {
		return inConfiguredNamespace(path, secretsNamespace+"/subscription-catalogs")
	}
	if area == "data" {
		// Product restore payloads remain authoritative regardless of basename.
		return parts[0] != "last-known-good"
	}
	for _, part := range parts {
		if part == catalogCompatDirectory || strings.HasPrefix(part, ".pending-") || strings.HasPrefix(part, ".prepare-") || strings.HasPrefix(part, ".archive-") {
			return true
		}
	}
	if area == "state" {
		if parts[0] == "runtime-candidates" {
			return true
		}
		if !directory && filepath.Base(path) == "subscription-catalog-compatibility.json" {
			return true
		}
	}
	return false
}

func compatOpenRoot(path string) (*os.Root, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, errCatalogCompatibility
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return nil, errCatalogCompatibility
	}
	before, err := os.Lstat(abs)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errCatalogCompatibility
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, errCatalogCompatibility
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errCatalogCompatibility
	}
	after, err := dir.Stat()
	dir.Close()
	if err != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, errCatalogCompatibility
	}
	return root, nil
}

func compatHash(ctx context.Context, file *os.File) (string, int64, error) {
	return compatHashBuffer(ctx, file, make([]byte, 64<<10))
}

func compatHashBuffer(ctx context.Context, file *os.File, buffer []byte) (string, int64, error) {
	hash := sha256.New()
	reader := newRecoveryFileReader(file)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", total, err
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			total += int64(n)
			hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", total, errCatalogCompatibility
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), total, nil
}

func compatPrivateDirectory(root *os.Root, path string) (*os.Root, error) {
	current := ""
	for _, part := range strings.Split(path, "/") {
		if current != "" {
			current += "/"
		}
		current += part
		if err := root.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errCatalogCompatibility
		}
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return nil, errCatalogCompatibility
		}
	}
	child, err := root.OpenRoot(path)
	if err != nil {
		return nil, errCatalogCompatibility
	}
	before, beforeErr := root.Lstat(path)
	opened, openErr := child.Open(".")
	if beforeErr != nil || openErr != nil {
		child.Close()
		return nil, errCatalogCompatibility
	}
	after, afterErr := opened.Stat()
	opened.Close()
	if afterErr != nil || !os.SameFile(before, after) {
		child.Close()
		return nil, errCatalogCompatibility
	}
	return child, nil
}

// Snapshot paths are fixed descendants of already mounted roots. This is a full
// private legacy baseline, not a bounded node projection. A failure leaves only
// unreferenced owned files; no caller may publish new-format pointers on error.
func buildCatalogCompatSnapshot(ctx context.Context, roots catalogCompatRoots, id string) ([]catalogCompatFile, error) {
	return buildCatalogCompatSnapshotObserved(ctx, roots, id, catalogCompatSnapshotHooks{})
}

func buildCatalogCompatSnapshotObserved(ctx context.Context, roots catalogCompatRoots, id string, hooks catalogCompatSnapshotHooks) (result []catalogCompatFile, resultErr error) {
	stage := "snapshot-prepare"
	defer func() { resultErr = catalogCompatSnapshotError(ctx, stage, resultErr) }()
	secretsNamespace, err := roots.secretsNamespace()
	if err != nil {
		return nil, err
	}
	if !safeRevision(id) {
		return nil, errCatalogCompatibility
	}
	var files []catalogCompatFile
	var total int64
	entriesVisited := 0
	buffer := make([]byte, 64<<10)
	for _, area := range roots.areas() {
		stage = "snapshot-copy"
		source, err := compatOpenRoot(area.path)
		if err != nil {
			return nil, err
		}
		base := catalogCompatDirectory + "/" + id + "/" + area.name
		if _, err := source.Lstat(base); err == nil {
			source.Close()
			return nil, errCatalogCompatibility
		} else if !errors.Is(err, os.ErrNotExist) {
			source.Close()
			return nil, errCatalogCompatibility
		}
		destination, err := compatPrivateDirectory(source, base)
		if err != nil {
			source.Close()
			return nil, errCatalogCompatibility
		}
		ownerBody, _ := json.Marshal(map[string]any{"format_version": 1, "identifier": id, "area": area.name})
		owner, ownerErr := source.OpenFile(catalogCompatDirectory+"/"+id+"/.owner.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if ownerErr != nil {
			destination.Close()
			source.Close()
			return nil, errCatalogCompatibility
		}
		_, ownerErr = owner.Write(ownerBody)
		if ownerErr == nil {
			ownerErr = owner.Sync()
		}
		ownerCloseErr := owner.Close()
		if ownerErr != nil || ownerCloseErr != nil {
			destination.Close()
			source.Close()
			return nil, errCatalogCompatibility
		}
		ownerDirectory, ownerErr := source.Open(catalogCompatDirectory + "/" + id)
		if ownerErr == nil {
			ownerErr = ownerDirectory.Sync()
			ownerDirectory.Close()
		}
		if ownerErr != nil {
			destination.Close()
			source.Close()
			return nil, errCatalogCompatibility
		}
		var walk func(string, int) error
		walk = func(relative string, depth int) error {
			if depth > 64 {
				return errCatalogCompatibility
			}
			directory, err := source.Open(relative)
			if err != nil {
				return errCatalogCompatibility
			}
			defer directory.Close()
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				entries, readErr := directory.ReadDir(32)
				if readErr != nil && readErr != io.EOF {
					return errCatalogCompatibility
				}
				for _, entry := range entries {
					entriesVisited++
					if entriesVisited > catalogCompatMaxFiles*4 {
						return errCatalogCompatibility
					}
					path := entry.Name()
					if relative != "." {
						path = relative + "/" + path
					}
					if hooks.beforeEntry != nil {
						hooks.beforeEntry(area.name, path)
					}
					// Skip only managed state-writer scratch, before Lstat can race
					// its rename. Config/secrets and LKG names remain authoritative.
					if area.name == "state" && !entry.IsDir() && roots.atomicScratch(path) {
						continue
					}
					if compatSnapshotExcluded(area.name, path, entry.IsDir(), secretsNamespace) {
						continue
					}
					volatile := area.name == "state" && roots.volatile(path)
					info, err := source.Lstat(path)
					if volatile && errors.Is(err, os.ErrNotExist) {
						continue
					}
					if err != nil || info.Mode()&os.ModeSymlink != 0 {
						return errCatalogCompatibility
					}
					if info.IsDir() {
						if err := destination.MkdirAll(path, 0700); err != nil {
							return errCatalogCompatibility
						}
						if err := walk(path, depth+1); err != nil {
							return err
						}
						continue
					}
					if volatile && info.Mode().IsRegular() && (info.Size() > catalogCompatMaxFileBytes || info.Size() > catalogCompatMaxBytes-total) {
						continue
					}
					if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > catalogCompatMaxFileBytes || len(files) >= catalogCompatMaxFiles || info.Size() > catalogCompatMaxBytes-total {
						return errCatalogCompatibility
					}
					input, err := source.Open(path)
					if err != nil {
						if volatile && errors.Is(err, os.ErrNotExist) {
							continue
						}
						return errCatalogCompatibility
					}
					opened, err := input.Stat()
					if err != nil || !os.SameFile(info, opened) {
						input.Close()
						if volatile {
							continue
						}
						return errCatalogCompatibility
					}
					if hooks.afterOpen != nil {
						hooks.afterOpen(area.name, path)
					}
					output, err := destination.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
					if err != nil {
						input.Close()
						return errCatalogCompatibility
					}
					hash := sha256.New()
					var reader io.Reader = newRecoveryFileReader(input)
					if volatile {
						reader = io.LimitReader(reader, info.Size())
					}
					writer := newRecoveryFileWriter(output, area.path, hash)
					var copied int64
					for {
						if err = ctx.Err(); err != nil {
							break
						}
						n, readErr := reader.Read(buffer)
						if n > 0 {
							copied += int64(n)
							if copied > info.Size() {
								err = errCatalogCompatibility
								break
							}
							if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
								err = errCatalogCompatibility
								break
							}
						}
						if readErr == io.EOF {
							break
						}
						if readErr != nil {
							err = errCatalogCompatibility
							break
						}
					}
					after, statErr := input.Stat()
					input.Close()
					syncErr := output.Sync()
					closeErr := output.Close()
					if volatile && ctx.Err() == nil && err == nil && syncErr == nil && closeErr == nil && (statErr != nil || copied != info.Size() || after.Size() != info.Size() || after.ModTime() != info.ModTime() || !catalogCompatValidWorkerState(ctx, destination, path)) {
						if err := destination.Remove(path); err != nil {
							return err
						}
						continue
					}
					if err != nil || statErr != nil || syncErr != nil || closeErr != nil || copied != info.Size() || after.Size() != info.Size() || after.ModTime() != info.ModTime() {
						return errCatalogCompatibility
					}
					files = append(files, catalogCompatFile{Area: area.name, Path: filepath.ToSlash(path), Bytes: copied, SHA256: hex.EncodeToString(hash.Sum(nil))})
					total += copied
				}
				if readErr == io.EOF {
					break
				}
			}
			durableDirectory, err := destination.Open(relative)
			if err != nil {
				return errCatalogCompatibility
			}
			err = durableDirectory.Sync()
			durableDirectory.Close()
			if err != nil {
				return errCatalogCompatibility
			}
			return nil
		}
		err = walk(".", 0)
		if err == nil {
			dir, openErr := destination.Open(".")
			if openErr != nil {
				err = errCatalogCompatibility
			} else {
				err = dir.Sync()
				dir.Close()
			}
		}
		destination.Close()
		if err == nil {
			for _, path := range []string{catalogCompatDirectory + "/" + id, catalogCompatDirectory, "."} {
				dir, openErr := source.Open(path)
				if openErr != nil {
					err = errCatalogCompatibility
					break
				}
				syncErr := dir.Sync()
				dir.Close()
				if syncErr != nil {
					err = errCatalogCompatibility
					break
				}
			}
		}
		source.Close()
		if err != nil {
			return nil, errCatalogCompatibility
		}
	}
	if hooks.beforeValidate != nil {
		hooks.beforeValidate()
	}
	stage = "snapshot-verify"
	if err := validateCatalogCompatSnapshot(ctx, roots, id, files, true); err != nil {
		return nil, err
	}
	return files, nil
}

func validateCatalogCompatSnapshot(ctx context.Context, roots catalogCompatRoots, id string, files []catalogCompatFile, checkSource bool) (resultErr error) {
	stage := "snapshot-manifest"
	defer func() { resultErr = catalogCompatSnapshotError(ctx, stage, resultErr) }()
	if _, err := roots.secretsNamespace(); err != nil {
		return err
	}
	if !safeRevision(id) || len(files) == 0 || len(files) > catalogCompatMaxFiles {
		return errCatalogCompatibility
	}
	seen := make(map[string]bool, len(files))
	var total int64
	buffer := make([]byte, 64<<10)
	for _, entry := range files {
		if entry.Area != "config" && entry.Area != "state" && entry.Area != "data" || entry.Bytes < 0 || entry.Bytes > catalogCompatMaxFileBytes || !safeRevision(entry.SHA256) || seen[entry.Area+"/"+entry.Path] {
			return errCatalogCompatibility
		}
		seen[entry.Area+"/"+entry.Path] = true
		total += entry.Bytes
		if total > catalogCompatMaxBytes {
			return errCatalogCompatibility
		}
	}
	for _, area := range roots.areas() {
		root, err := compatOpenRoot(area.path)
		if err != nil {
			return err
		}
		for _, entry := range files {
			if entry.Area != area.name {
				continue
			}
			if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, "\\") {
				root.Close()
				return errCatalogCompatibility
			}
			for _, part := range strings.Split(entry.Path, "/") {
				if part == "" || part == "." || part == ".." {
					root.Close()
					return errCatalogCompatibility
				}
			}
			paths := []string{catalogCompatDirectory + "/" + id + "/" + area.name + "/" + entry.Path}
			if checkSource && !(area.name == "state" && roots.volatile(entry.Path)) {
				paths = append(paths, entry.Path)
			}
			for _, path := range paths {
				stage = "snapshot-copy-verify"
				if path == entry.Path {
					stage = "snapshot-source-verify"
				}
				info, err := root.Lstat(path)
				if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Bytes {
					root.Close()
					return errCatalogCompatibility
				}
				file, err := root.Open(path)
				if err != nil {
					root.Close()
					return errCatalogCompatibility
				}
				digest, count, err := compatHashBuffer(ctx, file, buffer)
				file.Close()
				if err != nil || count != entry.Bytes || digest != entry.SHA256 {
					root.Close()
					return errCatalogCompatibility
				}
			}
		}
		root.Close()
	}
	return nil
}

// Token scanning validates worker JSON without retaining its object graph.
// JSONL audit history permits multiple documents; ordinary caches permit one.
func catalogCompatValidWorkerState(ctx context.Context, root *os.Root, path string) bool {
	file, err := root.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	decoder := json.NewDecoder(&catalogCompatWorkerTokenReader{source: newRecoveryFileReader(file)})
	depth, documents := 0, 0
	for {
		if ctx.Err() != nil {
			return false
		}
		token, err := decoder.Token()
		if err == io.EOF {
			return depth == 0 && (documents == 1 || filepath.Ext(path) == ".jsonl")
		}
		if err != nil {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter == '{' || delimiter == '[' {
				depth++
				if depth > 64 {
					return false
				}
			} else {
				depth--
				if depth == 0 {
					documents++
				}
			}
		} else if depth == 0 {
			documents++
		}
		if documents > 1 && filepath.Ext(path) != ".jsonl" {
			return false
		}
	}
}

// Bound a decoder token before it can grow its internal buffer to a whole
// malformed cache file. This is an optional worker-cache admission bound, not
// a limit on authoritative subscription data or the number of history rows.
type catalogCompatWorkerTokenReader struct {
	source          io.Reader
	quoted, escaped bool
	tokenBytes      int
}

func (reader *catalogCompatWorkerTokenReader) Read(body []byte) (int, error) {
	if len(body) > 64<<10 {
		body = body[:64<<10]
	}
	n, err := reader.source.Read(body)
	for _, value := range body[:n] {
		if reader.quoted {
			reader.tokenBytes++
			if reader.escaped {
				reader.escaped = false
			} else if value == '\\' {
				reader.escaped = true
			} else if value == '"' {
				reader.quoted = false
				reader.tokenBytes = 0
			}
		} else if value == '"' {
			reader.quoted = true
			reader.tokenBytes = 0
		} else if value == ' ' || value == '\t' || value == '\n' || value == '\r' || strings.ContainsRune("{}[],:", rune(value)) {
			reader.tokenBytes = 0
		} else {
			reader.tokenBytes++
		}
		if reader.tokenBytes > 1<<20 {
			return 0, errCatalogCompatibility
		}
	}
	return n, err
}

func catalogCompatJSON(value any) map[string]any {
	body, _ := json.Marshal(value)
	var result map[string]any
	_ = json.Unmarshal(body, &result)
	return result
}
