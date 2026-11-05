package subscriptioncatalog

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
)

// Builder is single-owner, not concurrent. Abort releases its own staging files
// only; it never removes published or older generations. Defer Abort after New.
type Builder struct {
	root           *os.Root
	stage          *os.Root
	stageName      string
	limits         Limits
	files          [6]*os.File // records, metadata, then four index spools
	count          uint64
	recordSize     int64
	metaSize       int64
	diskBytes      int64
	spaceCredit    int64
	checkSpace     func(string, uint64) error
	writeWindow    int64
	writeRanges    map[string]catalogCacheRange
	writerNames    map[*os.File]string
	syncCacheFile  func(*os.File) error
	dropCacheRange func(*os.File, int64, int64)
	failed         error
	closed         bool
}

func normalizedLimits(value Limits) (Limits, error) {
	defaults := DefaultLimits()
	if value.MaxRecordBytes == 0 {
		value.MaxRecordBytes = defaults.MaxRecordBytes
	}
	if value.MaxCanonicalBytes == 0 {
		value.MaxCanonicalBytes = defaults.MaxCanonicalBytes
	}
	if value.MaxDiskBytes == 0 {
		value.MaxDiskBytes = defaults.MaxDiskBytes
	}
	if value.SortChunkBytes == 0 {
		value.SortChunkBytes = defaults.SortChunkBytes
	}
	if value.MergeFanIn == 0 {
		value.MergeFanIn = defaults.MergeFanIn
	}
	if value.MaxRecordBytes < 1 || value.MaxRecordBytes > maxRecordBytes || value.MaxCanonicalBytes < 1 || value.MaxDiskBytes < 1 || value.SortChunkBytes < 64<<10 || value.SortChunkBytes > 16<<20 || value.MergeFanIn < 2 || value.MergeFanIn > 64 {
		return value, ErrInvalidLimits
	}
	return value, nil
}

func NewBuilder(path string, limits Limits) (*Builder, error) {
	limits, err := normalizedLimits(limits)
	if err != nil {
		return nil, err
	}
	root, err := openCatalogRoot(path, true)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		_ = root.Close()
		return nil, ErrIO
	}
	name := ".pending-" + hex.EncodeToString(nonce[:])
	if err := root.Mkdir(name, 0700); err != nil {
		_ = root.Close()
		return nil, storageError(err)
	}
	stage, err := openDirectory(root, name)
	if err != nil {
		_ = root.RemoveAll(name)
		_ = root.Close()
		return nil, err
	}
	b := &Builder{root: root, stage: stage, stageName: name, limits: limits, checkSpace: storagebudget.Check}
	for i, name := range []string{"records.bin", "metadata.bin", "id.spool", "stable.spool", "endpoint.spool", "logical.spool"} {
		b.files[i], err = b.create(name)
		if err != nil {
			_ = b.Abort()
			return nil, err
		}
	}
	return b, nil
}

func (b *Builder) create(name string) (*os.File, error) {
	file, err := b.stage.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		if b.writerNames == nil {
			b.writerNames = make(map[*os.File]string)
		}
		b.writerNames[file] = name
	}
	return file, storageError(err)
}

func (b *Builder) write(file *os.File, data []byte) error {
	if int64(len(data)) > b.limits.MaxDiskBytes-b.diskBytes {
		return ErrLimit
	}
	if err := b.checkWriteHeadroom(int64(len(data))); err != nil {
		return err
	}
	return b.writeWindowed(file, data)
}

func (b *Builder) remove(name string) error {
	info, err := b.stage.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return ErrIO
	}
	if err := b.stage.Remove(name); err != nil {
		return storageError(err)
	}
	b.diskBytes -= info.Size()
	delete(b.writeRanges, name)
	return nil
}

func encode(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, ErrInvalidRecord
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'}), nil
}

func validRecord(record Record) bool {
	if record.ID == "" || len(record.ID) > maxIDBytes || !utf8.ValidString(record.ID) {
		return false
	}
	for _, data := range []json.RawMessage{record.Node, record.Metadata, record.Secrets} {
		if len(data) != 0 && (!utf8.Valid(data) || !json.Valid(data)) {
			return false
		}
	}
	return len(record.Node) != 0
}

func (b *Builder) Append(ctx context.Context, record Record) (err error) {
	if b.closed {
		return ErrClosed
	}
	if b.failed != nil {
		return b.failed
	}
	defer func() {
		if err != nil {
			b.failed = err
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validRecord(record) {
		return ErrInvalidRecord
	}
	if int64(len(record.ID))+int64(len(record.Node))+int64(len(record.Secrets))+int64(len(record.Metadata)) > b.limits.MaxRecordBytes {
		return ErrLimit
	}
	data, err := encode(record)
	if err != nil {
		return err
	}
	meta, err := encode(MetadataRecord{ID: record.ID, Data: record.Metadata})
	if err != nil {
		return err
	}
	if int64(len(data)) > b.limits.MaxRecordBytes || int64(len(meta)) > b.limits.MaxRecordBytes || int64(len(data)+len(meta))+8 > b.limits.MaxCanonicalBytes-b.recordSize-b.metaSize {
		return ErrLimit
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err := b.write(b.files[0], header[:]); err != nil {
		return err
	}
	if err := b.write(b.files[0], data); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header[:], uint32(len(meta)))
	if err := b.write(b.files[1], header[:]); err != nil {
		return err
	}
	if err := b.write(b.files[1], meta); err != nil {
		return err
	}
	keys := [4]Key{sha256.Sum256([]byte(record.ID)), record.Stable, record.Endpoint, record.Logical}
	for i, key := range keys {
		if i != 0 && key == (Key{}) {
			continue
		}
		entry := indexEntry{key: key, offset: uint64(b.recordSize), length: uint64(len(data))}
		if err := b.writeEntry(b.files[i+2], entry); err != nil {
			return err
		}
	}
	b.recordSize += int64(len(data)) + 4
	b.metaSize += int64(len(meta)) + 4
	b.count++
	return ctx.Err()
}

func (b *Builder) Seal(ctx context.Context) (ref Ref, err error) {
	if b.closed {
		return ref, ErrClosed
	}
	if b.failed != nil {
		return ref, b.failed
	}
	defer func() {
		if err != nil {
			b.failed = err
		}
	}()
	if err := ctx.Err(); err != nil {
		return ref, err
	}
	if err := b.flushWriteWindow(); err != nil {
		return ref, err
	}
	for i, file := range b.files {
		if file == nil {
			continue
		}
		if err := file.Sync(); err != nil {
			return ref, storageError(err)
		}
		if err := b.closeWriter(file); err != nil {
			return ref, err
		}
		b.files[i] = nil
	}
	ref.Schema, ref.Count = SchemaVersion, b.count
	for i := range indexNames {
		if err := b.sortIndex(ctx, i); err != nil {
			return ref, err
		}
	}
	for i, name := range append([]string{"records.bin", "metadata.bin"}, indexNames[:]...) {
		if err := ctx.Err(); err != nil {
			return ref, err
		}
		file, err := openRegular(b.stage, name)
		if err != nil {
			return ref, err
		}
		digest, digestErr := digestFileContext(ctx, file)
		_ = file.Close()
		if digestErr != nil {
			return ref, digestErr
		}
		switch i {
		case 0:
			ref.Records = digest
		case 1:
			ref.Metadata = digest
		default:
			ref.Indexes[i-2] = digest
		}
	}
	ref.Generation = generation(ref)
	if err := validateRef(ref); err != nil {
		return ref, err
	}
	manifest, _ := encode(ref)
	file, err := b.create("manifest.json")
	if err != nil {
		return ref, err
	}
	err = b.write(file, manifest)
	if err == nil {
		err = storageError(file.Sync())
	}
	closeErr := b.closeWriter(file)
	if err != nil {
		return ref, err
	}
	if closeErr != nil {
		return ref, closeErr
	}
	if err := b.flushWriteWindow(); err != nil {
		return ref, err
	}
	if err := syncDirectory(b.stage); err != nil {
		return ref, err
	}
	if err := ctx.Err(); err != nil {
		return ref, err
	}
	if _, statErr := b.root.Lstat(ref.Generation); statErr == nil {
		reader, err := openReader(b.root, ref)
		if err != nil {
			return ref, err
		}
		_ = reader.Close()
		if err := b.Abort(); err != nil {
			return ref, err
		}
		return ref, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return ref, storageError(statErr)
	}
	if err := b.root.Rename(b.stageName, ref.Generation); err != nil {
		return ref, storageError(err)
	}
	b.stageName = "" // Abort must never remove an immutable generation.
	if err := syncDirectory(b.root); err != nil {
		return ref, err
	}
	_ = b.stage.Close()
	_ = b.root.Close()
	b.closed = true
	return ref, nil
}

func (b *Builder) Abort() error {
	if b.closed {
		return nil
	}
	b.closed = true
	var first error
	for _, file := range b.files {
		if file != nil {
			if err := b.closeWriter(file); first == nil {
				first = err
			}
		}
	}
	if b.stage != nil {
		if err := b.stage.Close(); first == nil {
			first = storageError(err)
		}
	}
	if b.stageName != "" {
		if err := b.root.RemoveAll(b.stageName); first == nil {
			first = storageError(err)
		}
	}
	if b.root != nil {
		if err := b.root.Close(); first == nil {
			first = storageError(err)
		}
	}
	return first
}
