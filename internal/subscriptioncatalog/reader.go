package subscriptioncatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"sync"
)

// Reader owns the generation handle, six data files and a shared manifest lease. Get and LookupUnique use
// ReadAt and are concurrent-safe. Close waits for a current read; subsequent
// operations return ErrClosed. Walk callbacks do not hold a reader lock.
type Reader struct {
	mu         sync.RWMutex
	root       *os.Root
	files      [6]*os.File
	manifest   *os.File
	bulkAdvice func(*os.File, int64, int64)
	ref        Ref
	closed     bool
}

// Inspect verifies the bounded manifest and its content identity. Open separately
// verifies every record/metadata/index file checksum before exposing a Reader.
func Inspect(path, id string) (Ref, error) {
	var ref Ref
	if !validDigest(id) {
		return ref, ErrInvalidRef
	}
	root, err := openCatalogRoot(path, false)
	if err != nil {
		return ref, err
	}
	defer root.Close()
	child, err := openDirectory(root, id)
	if err != nil {
		return ref, err
	}
	defer child.Close()
	ref, err = readManifest(child)
	if err != nil {
		return ref, err
	}
	if ref.Generation != id {
		return ref, ErrIntegrity
	}
	return ref, nil
}

func Open(path string, ref Ref) (*Reader, error) {
	if err := validateRef(ref); err != nil {
		return nil, err
	}
	root, err := openCatalogRoot(path, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return openReader(root, ref)
}

func openReader(root *os.Root, ref Ref) (*Reader, error) {
	child, err := openDirectory(root, ref.Generation)
	if err != nil {
		return nil, err
	}
	lease, err := openRegular(child, "manifest.json")
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	if err := lockManifest(lease, false); err != nil {
		_ = lease.Close()
		_ = child.Close()
		return nil, err
	}
	reader := &Reader{root: child, ref: ref, manifest: lease}
	manifest, err := readManifest(child)
	if err != nil || manifest != ref {
		_ = reader.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrIntegrity
	}
	leaseInfo, leaseErr := lease.Stat()
	pathInfo, pathErr := child.Lstat("manifest.json")
	if leaseErr != nil || pathErr != nil || !os.SameFile(leaseInfo, pathInfo) || !pathInfo.Mode().IsRegular() || !privateMode(pathInfo, 0600) {
		_ = reader.Close()
		return nil, ErrUnsafePath
	}
	names := append([]string{"records.bin", "metadata.bin"}, indexNames[:]...)
	digests := append([]FileDigest{ref.Records, ref.Metadata}, ref.Indexes[:]...)
	for i, name := range names {
		file, err := openRegular(child, name)
		if err != nil {
			_ = reader.Close()
			return nil, err
		}
		reader.files[i] = file
		info, err := file.Stat()
		if err != nil || info.Size() != digests[i].Bytes {
			_ = reader.Close()
			return nil, ErrIntegrity
		}
		digest, err := digestFile(file)
		if err != nil || digest != digests[i] {
			_ = reader.Close()
			if err != nil {
				return nil, err
			}
			return nil, ErrIntegrity
		}
	}
	return reader, nil
}

func (reader *Reader) Close() error {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.closed {
		return nil
	}
	reader.closed = true
	var first error
	for _, file := range reader.files {
		if file != nil {
			if err := file.Close(); first == nil {
				first = storageError(err)
			}
		}
	}
	if reader.manifest != nil {
		if err := unlockManifest(reader.manifest); first == nil {
			first = err
		}
		if err := reader.manifest.Close(); first == nil {
			first = storageError(err)
		}
	}
	if reader.root != nil {
		if err := reader.root.Close(); first == nil {
			first = storageError(err)
		}
	}
	return first
}

func (reader *Reader) Get(ctx context.Context, id string) (Record, error) {
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	if reader.closed {
		return Record{}, ErrClosed
	}
	if id == "" || len(id) > maxIDBytes {
		return Record{}, ErrNotFound
	}
	entry, _, err := reader.lookup(ctx, 0, sha256.Sum256([]byte(id)))
	if err != nil {
		return Record{}, err
	}
	record, err := reader.readRecord(entry)
	if err == nil && record.ID != id {
		return Record{}, ErrIntegrity
	}
	return record, err
}

func (reader *Reader) LookupUnique(ctx context.Context, kind Kind, key Key) (Record, error) {
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	if reader.closed {
		return Record{}, ErrClosed
	}
	entry, err := reader.uniqueEntry(ctx, kind, key)
	if err != nil {
		return Record{}, err
	}
	record, err := reader.readRecord(entry)
	if err != nil {
		return record, err
	}
	actual := [4]Key{{}, record.Stable, record.Endpoint, record.Logical}[kind]
	if actual != key {
		return Record{}, ErrIntegrity
	}
	return record, nil
}

// CheckUnique examines only the checked immutable identity index. Unlike
// LookupUnique it neither reads nor decodes the private record payload.
func (reader *Reader) CheckUnique(ctx context.Context, kind Kind, key Key) error {
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	if reader.closed {
		return ErrClosed
	}
	_, err := reader.uniqueEntry(ctx, kind, key)
	return err
}

// Caller holds reader.mu.RLock and has checked reader.closed.
func (reader *Reader) uniqueEntry(ctx context.Context, kind Kind, key Key) (indexEntry, error) {
	if kind < Stable || kind > Logical {
		return indexEntry{}, ErrInvalidRecord
	}
	if key == (Key{}) {
		return indexEntry{}, ErrNotFound
	}
	entry, position, err := reader.lookup(ctx, int(kind), key)
	if err != nil {
		return indexEntry{}, err
	}
	if position+1 < reader.ref.Indexes[kind].Bytes/entryBytes {
		next, err := readIndexEntry(reader.files[int(kind)+2], position+1)
		if err != nil {
			return indexEntry{}, err
		}
		if next.key == key {
			return indexEntry{}, ErrAmbiguous
		}
	}
	return entry, nil
}

func (reader *Reader) lookup(ctx context.Context, index int, key Key) (indexEntry, int64, error) {
	file := reader.files[index+2]
	left, right := int64(0), reader.ref.Indexes[index].Bytes/entryBytes
	for left < right {
		if err := ctx.Err(); err != nil {
			return indexEntry{}, 0, err
		}
		middle := left + (right-left)/2
		entry, err := readIndexEntry(file, middle)
		if err != nil {
			return indexEntry{}, 0, err
		}
		if bytes.Compare(entry.key[:], key[:]) < 0 {
			left = middle + 1
		} else {
			right = middle
		}
	}
	if err := ctx.Err(); err != nil {
		return indexEntry{}, 0, err
	}
	if left == reader.ref.Indexes[index].Bytes/entryBytes {
		return indexEntry{}, 0, ErrNotFound
	}
	entry, err := readIndexEntry(file, left)
	if err != nil {
		return indexEntry{}, 0, err
	}
	if entry.key != key {
		return indexEntry{}, 0, ErrNotFound
	}
	return entry, left, nil
}

func readIndexEntry(file *os.File, position int64) (indexEntry, error) {
	var data [entryBytes]byte
	if _, err := file.ReadAt(data[:], position*entryBytes); err != nil {
		return indexEntry{}, ErrIntegrity
	}
	return decodeEntry(data[:]), nil
}

func readFrame(file *os.File, size int64, offset, expected uint64) ([]byte, uint64, error) {
	return readFrameAt(file, size, offset, expected)
}

func readFrameAt(file interface {
	ReadAt([]byte, int64) (int, error)
}, size int64, offset, expected uint64) ([]byte, uint64, error) {
	if offset > uint64(size) || uint64(size)-offset < 4 {
		return nil, 0, ErrIntegrity
	}
	var header [4]byte
	if _, err := file.ReadAt(header[:], int64(offset)); err != nil {
		return nil, 0, ErrIntegrity
	}
	length := uint64(binary.BigEndian.Uint32(header[:]))
	if length == 0 || length > maxRecordBytes || expected != 0 && length != expected || length > uint64(size)-offset-4 {
		return nil, 0, ErrIntegrity
	}
	data := make([]byte, int(length))
	if _, err := file.ReadAt(data, int64(offset)+4); err != nil {
		return nil, 0, ErrIntegrity
	}
	return data, offset + 4 + length, nil
}

func (reader *Reader) readRecord(entry indexEntry) (Record, error) {
	var record Record
	if entry.length == 0 || entry.length > maxRecordBytes {
		return record, ErrIntegrity
	}
	data, _, err := readFrame(reader.files[0], reader.ref.Records.Bytes, entry.offset, entry.length)
	if err != nil {
		return record, err
	}
	if json.Unmarshal(data, &record) != nil || !validRecord(record) {
		return Record{}, ErrIntegrity
	}
	return record, nil
}

func (reader *Reader) Walk(ctx context.Context, visit func(Record) error) error {
	if visit == nil {
		return ErrInvalidRecord
	}
	return reader.walk(ctx, false, func(data []byte) error {
		var record Record
		if json.Unmarshal(data, &record) != nil || !validRecord(record) {
			return ErrIntegrity
		}
		return visit(record)
	})
}

// WalkMetadata never reads, unmarshals or resolves Node or Secrets.
func (reader *Reader) WalkMetadata(ctx context.Context, visit func(MetadataRecord) error) error {
	if visit == nil {
		return ErrInvalidRecord
	}
	return reader.walk(ctx, true, func(data []byte) error {
		var record MetadataRecord
		if json.Unmarshal(data, &record) != nil || record.ID == "" || len(record.ID) > maxIDBytes || !json.Valid(record.Data) {
			return ErrIntegrity
		}
		return visit(record)
	})
}

func (reader *Reader) walk(ctx context.Context, metadata bool, visit func([]byte) error) error {
	reader.mu.RLock()
	closed := reader.closed
	reader.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	index, size := 0, reader.ref.Records.Bytes
	if metadata {
		index, size = 1, reader.ref.Metadata.Bytes
	}
	bulk := newCatalogBulkReaderAt(ctx, reader.files[index], size)
	if reader.bulkAdvice != nil {
		bulk.window.advise = reader.bulkAdvice
	}
	defer func() {
		reader.mu.RLock()
		defer reader.mu.RUnlock()
		if !reader.closed {
			bulk.finish()
		}
	}()
	var offset, count uint64
	for offset < uint64(size) {
		if err := ctx.Err(); err != nil {
			return err
		}
		reader.mu.RLock()
		if reader.closed {
			reader.mu.RUnlock()
			return ErrClosed
		}
		data, next, err := readFrameAt(bulk, size, offset, 0)
		reader.mu.RUnlock()
		if err != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return err
		}
		if err := visit(data); err != nil {
			return err
		}
		offset = next
		count++
	}
	if count != reader.ref.Count {
		return ErrIntegrity
	}
	return ctx.Err()
}
