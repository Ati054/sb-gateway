package subscriptioncatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const (
	maxRecordBytes = 8 << 20
	maxIDBytes     = 512
	entryBytes     = 48
	manifestLimit  = 16 << 10
)

var indexNames = [4]string{"id.idx", "stable.idx", "endpoint.idx", "logical.idx"}

func storageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, syscall.ENOSPC) {
		return ErrNoSpace
	}
	return ErrIO
}

// Existing ancestors must not be symlinks. os.Root anchors all subsequent
// operations and prevents pathname replacement from escaping the supplied root.
func openCatalogRoot(path string, create bool) (*os.Root, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrUnsafePath
	}
	volume := filepath.VolumeName(abs)
	current := volume + string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(abs, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) && create {
			if err := os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return nil, storageError(err)
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return nil, storageError(statErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrUnsafePath
		}
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, storageError(err)
	}
	if !privateMode(info, 0700) {
		return nil, ErrUnsafePath
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, storageError(err)
	}
	if !sameOpenedDirectory(root, info) {
		_ = root.Close()
		return nil, ErrUnsafePath
	}
	return root, nil
}

func privateMode(info os.FileInfo, mode os.FileMode) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm() == mode
}

func openDirectory(root *os.Root, name string) (*os.Root, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, storageError(err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privateMode(info, 0700) {
		return nil, ErrUnsafePath
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, storageError(err)
	}
	if !sameOpenedDirectory(child, info) {
		_ = child.Close()
		return nil, ErrUnsafePath
	}
	return child, nil
}

func sameOpenedDirectory(root *os.Root, before os.FileInfo) bool {
	file, err := root.Open(".")
	if err != nil {
		return false
	}
	defer file.Close()
	after, err := file.Stat()
	return err == nil && after.IsDir() && privateMode(after, 0700) && os.SameFile(before, after)
}

func openRegular(root *os.Root, name string) (*os.File, error) {
	return openRegularFlags(root, name, os.O_RDONLY)
}

func openRegularFlags(root *os.Root, name string, flags int) (*os.File, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, storageError(err)
	}
	if !before.Mode().IsRegular() || !privateMode(before, 0600) {
		return nil, ErrUnsafePath
	}
	file, err := root.OpenFile(name, flags, 0)
	if err != nil {
		return nil, storageError(err)
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !privateMode(after, 0600) || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, ErrUnsafePath
	}
	return file, nil
}

func digestFile(file *os.File) (FileDigest, error) {
	return digestFileContext(context.Background(), file)
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(data []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(data)
}

func digestFileContext(ctx context.Context, file *os.File) (FileDigest, error) {
	return digestFileContextWithAdvice(ctx, file, adviseCatalogCache)
}

func digestFileContextWithAdvice(ctx context.Context, file *os.File, advice func(*os.File, int64, int64)) (FileDigest, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return FileDigest{}, ErrIO
	}
	hash := sha256.New()
	bulk := newCatalogBulkReaderAt(ctx, file, info.Size())
	bulk.window.advise = advice
	defer bulk.finish()
	if _, err := io.CopyBuffer(hash, contextReader{ctx, io.NewSectionReader(bulk, 0, info.Size())}, make([]byte, 32<<10)); err != nil {
		if ctx.Err() != nil {
			return FileDigest{}, ctx.Err()
		}
		return FileDigest{}, storageError(err)
	}
	return FileDigest{Bytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func generation(ref Ref) string {
	ref.Generation = ""
	encoded, _ := json.Marshal(ref)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func validateRef(ref Ref) error {
	if ref.Schema != SchemaVersion || !validDigest(ref.Generation) || generation(ref) != ref.Generation {
		return ErrInvalidRef
	}
	for _, file := range append([]FileDigest{ref.Records, ref.Metadata}, ref.Indexes[:]...) {
		if file.Bytes < 0 || !validDigest(file.SHA256) {
			return ErrInvalidRef
		}
	}
	if ref.Count > uint64(ref.Records.Bytes/4) || ref.Count > uint64(ref.Metadata.Bytes/4) || ref.Count > uint64(^uint64(0)>>1)/entryBytes {
		return ErrInvalidRef
	}
	if ref.Indexes[0].Bytes != int64(ref.Count)*entryBytes {
		return ErrInvalidRef
	}
	for _, index := range ref.Indexes {
		if index.Bytes%entryBytes != 0 || uint64(index.Bytes/entryBytes) > ref.Count {
			return ErrInvalidRef
		}
	}
	return nil
}

func readManifest(root *os.Root) (Ref, error) {
	var ref Ref
	file, err := openRegular(root, "manifest.json")
	if err != nil {
		return ref, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() > manifestLimit {
		return ref, ErrIntegrity
	}
	decoder := json.NewDecoder(io.LimitReader(file, manifestLimit+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ref); err != nil {
		return ref, ErrIntegrity
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ref, ErrIntegrity
	}
	return ref, validateRef(ref)
}

func syncDirectory(root *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil // Windows cannot fsync a directory handle through os.File.
	}
	file, err := root.Open(".")
	if err != nil {
		return storageError(err)
	}
	defer file.Close()
	return storageError(file.Sync())
}
