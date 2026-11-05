package subscriptioncatalog

import (
	"context"
	"errors"
	"io"
	"os"
)

var generationFiles = [7]string{"records.bin", "metadata.bin", "id.idx", "stable.idx", "endpoint.idx", "logical.idx", "manifest.json"}

// RemoveGeneration removes exactly one complete immutable generation. The caller
// must first prove it is unreferenced by source, runtime and rollback state. A
// nonblocking exclusive manifest lease additionally protects all open Readers,
// including Readers in other processes. There is no recursive directory delete.
// Cancellation is checked before the first unlink; deletion then finishes even
// if the context is cancelled, rather than deliberately leaving half a catalog.
func RemoveGeneration(ctx context.Context, path string, ref Ref) error {
	return removeGeneration(ctx, path, ref, func(root *os.Root, name string) error { return root.Remove(name) })
}

func removeGeneration(ctx context.Context, path string, ref Ref, unlink func(*os.Root, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRef(ref); err != nil {
		return err
	}
	root, err := openCatalogRoot(path, false)
	if err != nil {
		return err
	}
	defer root.Close()
	identity, err := root.Lstat(ref.Generation)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return storageError(err)
	}
	child, err := openDirectory(root, ref.Generation)
	if err != nil {
		return err
	}
	defer child.Close()
	manifest, err := openRegular(child, "manifest.json")
	if err != nil {
		return err
	}
	defer manifest.Close()
	if err := lockManifest(manifest, true); err != nil {
		return err
	}
	defer unlockManifest(manifest)
	actual, err := readManifest(child)
	if err != nil || actual != ref {
		return ErrIntegrity
	}
	listing, err := child.Open(".")
	if err != nil {
		return storageError(err)
	}
	entries, readErr := listing.ReadDir(len(generationFiles) + 1)
	_ = listing.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return storageError(readErr)
	}
	if len(entries) != len(generationFiles) {
		return ErrUnsafePath
	}
	known := make(map[string]os.FileInfo, len(generationFiles))
	for _, name := range generationFiles {
		info, err := child.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || !privateMode(info, 0600) {
			return ErrUnsafePath
		}
		known[name] = info
	}
	for _, entry := range entries {
		if known[entry.Name()] == nil {
			return ErrUnsafePath
		}
	}
	leaseInfo, err := manifest.Stat()
	if err != nil || !os.SameFile(known["manifest.json"], leaseInfo) {
		return ErrUnsafePath
	}
	digests := append([]FileDigest{ref.Records, ref.Metadata}, ref.Indexes[:]...)
	for index, name := range generationFiles[:6] {
		file, err := openRegular(child, name)
		if err != nil {
			return err
		}
		digest, hashErr := digestFileContext(ctx, file)
		_ = file.Close()
		if hashErr != nil {
			return hashErr
		}
		if digest != digests[index] {
			return ErrIntegrity
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Read-only validation is complete. Recheck the anchored pathname and each
	// exact owned file before unlinking it. Never follow a replacement symlink.
	for index, name := range generationFiles {
		current, err := root.Lstat(ref.Generation)
		if err != nil || !os.SameFile(identity, current) || !current.IsDir() || !privateMode(current, 0700) {
			return ErrUnsafePath
		}
		current, err = child.Lstat(name)
		if err != nil || !os.SameFile(known[name], current) || !current.Mode().IsRegular() || !privateMode(current, 0600) {
			return ErrUnsafePath
		}
		if index == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if err := unlink(child, name); err != nil {
			return storageError(err)
		}
	}
	current, err := root.Lstat(ref.Generation)
	if err != nil || !os.SameFile(identity, current) || !current.IsDir() || !privateMode(current, 0700) {
		return ErrUnsafePath
	}
	if err := root.Remove(ref.Generation); err != nil {
		return storageError(err)
	}
	return syncDirectory(root)
}
