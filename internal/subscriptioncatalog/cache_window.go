package subscriptioncatalog

import (
	"context"
	"io"
	"os"
)

const catalogCacheWindow = 8 << 20

type catalogCacheRange struct{ offset, length int64 }

// writeWindowed has one byte window for the entire builder, including closed
// sort runs. It retains only ranges written since the last flush, not every run
// name in the build. Temporary-file removal discards that file's pending range.
func (b *Builder) writeWindowed(file *os.File, data []byte) error {
	name, owned := b.writerNames[file]
	if !owned {
		return ErrIO
	}
	if b.writeRanges == nil {
		b.writeRanges = make(map[string]catalogCacheRange)
	}
	for len(data) > 0 {
		region, exists := b.writeRanges[name]
		if !exists {
			offset, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				return storageError(err)
			}
			region.offset = offset
		}
		length := min(len(data), int(catalogCacheWindow-b.writeWindow))
		n, err := file.Write(data[:length])
		b.diskBytes += int64(n)
		b.spaceCredit -= int64(n)
		region.length += int64(n)
		b.writeWindow += int64(n)
		b.writeRanges[name] = region
		if err != nil {
			return storageError(err)
		}
		if n != length {
			return ErrIO
		}
		data = data[n:]
		if b.writeWindow >= catalogCacheWindow {
			if err := b.flushWriteWindow(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Builder) closeWriter(file *os.File) error {
	delete(b.writerNames, file)
	return storageError(file.Close())
}

func (b *Builder) renameWriter(from, to string) error {
	if err := b.stage.Rename(from, to); err != nil {
		return storageError(err)
	}
	if region, pending := b.writeRanges[from]; pending {
		delete(b.writeRanges, from)
		b.writeRanges[to] = region
	}
	return nil
}

func (b *Builder) flushWriteWindow() error {
	for name, region := range b.writeRanges {
		file, err := openRegularFlags(b.stage, name, os.O_RDWR)
		if err != nil {
			return err
		}
		if b.syncCacheFile != nil {
			err = b.syncCacheFile(file)
		} else {
			err = file.Sync()
		}
		if err != nil {
			_ = file.Close()
			return storageError(err)
		}
		if b.dropCacheRange != nil {
			b.dropCacheRange(file, region.offset, region.length)
		} else {
			adviseCatalogCache(file, region.offset, region.length)
		}
		if err := file.Close(); err != nil {
			return storageError(err)
		}
		delete(b.writeRanges, name)
	}
	b.writeWindow = 0
	return nil
}

// A window belongs to one explicitly linear bulk pass. Ordinary ReadAt lookup
// paths never instantiate it. Small payloads retain their cache; large passes
// advise only already consumed ranges and release the final tail on completion.
type catalogBulkReaderAt struct {
	ctx      context.Context
	file     *os.File
	position int64
	enabled  bool
	window   *catalogReadWindow
}

type catalogReadWindow struct {
	bytes  int64
	ranges map[*os.File]catalogCacheRange
	advise func(*os.File, int64, int64)
}

func newCatalogReadWindow() *catalogReadWindow {
	return &catalogReadWindow{ranges: make(map[*os.File]catalogCacheRange), advise: adviseCatalogCache}
}

func newCatalogBulkReaderAt(ctx context.Context, file *os.File, size int64) *catalogBulkReaderAt {
	return &catalogBulkReaderAt{ctx: ctx, file: file, enabled: size >= catalogCacheWindow, window: newCatalogReadWindow()}
}

func (reader *catalogBulkReaderAt) ReadAt(data []byte, offset int64) (int, error) {
	if !reader.enabled {
		return reader.file.ReadAt(data, offset)
	}
	// The wrapper is private to a sequential SHA or framed Walk. Restarting a
	// pass at another offset releases only its previous consumed tail.
	if offset != reader.position {
		reader.finish()
		reader.position = offset
	}
	total := 0
	for len(data) > 0 {
		if err := reader.ctx.Err(); err != nil {
			return total, err
		}
		length := min(len(data), int(catalogCacheWindow-reader.window.bytes))
		region, exists := reader.window.ranges[reader.file]
		if !exists {
			region.offset = reader.position
		}
		n, err := reader.file.ReadAt(data[:length], reader.position)
		total += n
		reader.position += int64(n)
		region.length += int64(n)
		reader.window.ranges[reader.file] = region
		reader.window.bytes += int64(n)
		data = data[n:]
		if reader.window.bytes >= catalogCacheWindow {
			reader.finish()
		}
		if err != nil {
			return total, err
		}
		if n != length {
			return total, io.ErrUnexpectedEOF
		}
	}
	return total, nil
}

func (reader *catalogBulkReaderAt) finish() {
	if reader.enabled {
		reader.window.finish()
	}
}

func (window *catalogReadWindow) finish() {
	for file, region := range window.ranges {
		if region.length > 0 {
			window.advise(file, region.offset, region.length)
		}
		delete(window.ranges, file)
	}
	window.bytes = 0
}
