package subscriptioncatalog

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
)

type indexEntry struct {
	key    Key
	offset uint64
	length uint64
}

func putEntry(buffer []byte, entry indexEntry) {
	copy(buffer[:32], entry.key[:])
	binary.BigEndian.PutUint64(buffer[32:40], entry.offset)
	binary.BigEndian.PutUint64(buffer[40:48], entry.length)
}

func decodeEntry(buffer []byte) indexEntry {
	var result indexEntry
	copy(result.key[:], buffer[:32])
	result.offset = binary.BigEndian.Uint64(buffer[32:40])
	result.length = binary.BigEndian.Uint64(buffer[40:48])
	return result
}

func lessEntry(left, right indexEntry) bool {
	if comparison := bytes.Compare(left.key[:], right.key[:]); comparison != 0 {
		return comparison < 0
	}
	return left.offset < right.offset
}

func (b *Builder) writeEntry(file *os.File, entry indexEntry) error {
	var data [entryBytes]byte
	putEntry(data[:], entry)
	return b.write(file, data[:])
}

type trackedWriter struct {
	builder *Builder
	file    *os.File
}

func (writer trackedWriter) Write(data []byte) (int, error) {
	if err := writer.builder.write(writer.file, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

func runName(index, pass, run int) string { return fmt.Sprintf("sort-%d-%d-%d.run", index, pass, run) }

func (b *Builder) sortIndex(ctx context.Context, index int) error {
	spoolName := []string{"id.spool", "stable.spool", "endpoint.spool", "logical.spool"}[index]
	spool, err := openRegular(b.stage, spoolName)
	if err != nil {
		return err
	}
	defer spool.Close()
	spoolInfo, err := spool.Stat()
	if err != nil {
		return storageError(err)
	}
	bulkSpool := newCatalogBulkReaderAt(ctx, spool, spoolInfo.Size())
	defer bulkSpool.finish()
	spoolReader := io.NewSectionReader(bulkSpool, 0, spoolInfo.Size())
	// One decoded entry array and one serialization buffer share the chunk
	// budget. Run names are derived from counters, never retained per record.
	capacity := int(b.limits.SortChunkBytes / (2 * entryBytes))
	buffer := make([]byte, capacity*entryBytes)
	entries := make([]indexEntry, 0, capacity)
	runs := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := io.ReadFull(spoolReader, buffer)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			if err := ctx.Err(); err != nil {
				return err
			}
			return storageError(readErr)
		}
		if n%entryBytes != 0 {
			return ErrIntegrity
		}
		if n == 0 {
			break
		}
		entries = entries[:0]
		for offset := 0; offset < n; offset += entryBytes {
			entries = append(entries, decodeEntry(buffer[offset:offset+entryBytes]))
		}
		sort.Slice(entries, func(i, j int) bool { return lessEntry(entries[i], entries[j]) })
		for i, entry := range entries {
			putEntry(buffer[i*entryBytes:(i+1)*entryBytes], entry)
		}
		file, err := b.create(runName(index, 0, runs))
		if err != nil {
			return err
		}
		err = b.write(file, buffer[:n])
		closeErr := b.closeWriter(file)
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		runs++
		if readErr != nil {
			break
		}
	}
	bulkSpool.finish()
	if err := spool.Close(); err != nil {
		return storageError(err)
	}
	if err := b.remove(spoolName); err != nil {
		return err
	}
	pass := 0
	for runs > 1 {
		nextRuns := 0
		for start := 0; start < runs; start += b.limits.MergeFanIn {
			if err := ctx.Err(); err != nil {
				return err
			}
			end := min(start+b.limits.MergeFanIn, runs)
			if err := b.mergeRuns(ctx, index, pass, start, end, nextRuns); err != nil {
				return err
			}
			nextRuns++
		}
		pass++
		runs = nextRuns
	}
	if runs == 0 {
		file, err := b.create(indexNames[index])
		if err != nil {
			return err
		}
		if err := b.closeWriter(file); err != nil {
			return err
		}
	} else if err := b.renameWriter(runName(index, pass, 0), indexNames[index]); err != nil {
		return err
	}
	file, err := openRegularFlags(b.stage, indexNames[index], os.O_RDWR)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return storageError(err)
	}
	if index == 0 {
		info, err := file.Stat()
		if err != nil {
			return storageError(err)
		}
		bulk := newCatalogBulkReaderAt(ctx, file, info.Size())
		defer bulk.finish()
		reader := bufio.NewReaderSize(io.NewSectionReader(bulk, 0, info.Size()), 32<<10)
		var previous Key
		var data [entryBytes]byte
		for count := uint64(0); ; count++ {
			if count%256 == 0 {
				if err := ctx.Err(); err != nil {
					return err
				}
			}
			_, err := io.ReadFull(reader, data[:])
			if err == io.EOF {
				break
			}
			if err != nil {
				if err := ctx.Err(); err != nil {
					return err
				}
				return ErrIntegrity
			}
			current := decodeEntry(data[:]).key
			if count != 0 && current == previous {
				return ErrDuplicateID
			}
			previous = current
		}
	}
	return nil
}

type mergeItem struct {
	entry indexEntry
	input int
}
type mergeHeap []mergeItem

func (h mergeHeap) Len() int           { return len(h) }
func (h mergeHeap) Less(i, j int) bool { return lessEntry(h[i].entry, h[j].entry) }
func (h mergeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *mergeHeap) Push(item any)     { *h = append(*h, item.(mergeItem)) }
func (h *mergeHeap) Pop() any          { old := *h; item := old[len(old)-1]; *h = old[:len(old)-1]; return item }

func (b *Builder) mergeRuns(ctx context.Context, index, pass, start, end, output int) error {
	files := make([]*os.File, 0, end-start)
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	readWindow := newCatalogReadWindow()
	defer readWindow.finish()
	readers := make([]*bufio.Reader, 0, end-start)
	queue := make(mergeHeap, 0, end-start)
	var data [entryBytes]byte
	for input := start; input < end; input++ {
		file, err := openRegular(b.stage, runName(index, pass, input))
		if err != nil {
			return err
		}
		files = append(files, file)
		info, err := file.Stat()
		if err != nil {
			return storageError(err)
		}
		bulk := newCatalogBulkReaderAt(ctx, file, info.Size())
		bulk.enabled = true // one shared window across the bounded merge fan-in
		bulk.window = readWindow
		reader := bufio.NewReaderSize(io.NewSectionReader(bulk, 0, info.Size()), 32<<10)
		readers = append(readers, reader)
		if _, err := io.ReadFull(reader, data[:]); err != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrIntegrity
		}
		heap.Push(&queue, mergeItem{entry: decodeEntry(data[:]), input: input - start})
	}
	file, err := b.create(runName(index, pass+1, output))
	if err != nil {
		return err
	}
	defer b.closeWriter(file)
	writer := bufio.NewWriterSize(trackedWriter{b, file}, 32<<10)
	for count := 0; queue.Len() != 0; count++ {
		if count%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		item := heap.Pop(&queue).(mergeItem)
		putEntry(data[:], item.entry)
		if _, err := writer.Write(data[:]); err != nil {
			return err
		}
		_, readErr := io.ReadFull(readers[item.input], data[:])
		if readErr == nil {
			heap.Push(&queue, mergeItem{entry: decodeEntry(data[:]), input: item.input})
		} else if readErr != io.EOF {
			if err := ctx.Err(); err != nil {
				return err
			}
			return ErrIntegrity
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := b.closeWriter(file); err != nil {
		return err
	}
	readWindow.finish()
	for i, input := range files {
		if err := input.Close(); err != nil {
			return storageError(err)
		}
		if err := b.remove(runName(index, pass, start+i)); err != nil {
			return err
		}
	}
	return nil
}
