package subscriptioncatalog

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"sync"
)

const bulkLookupMaxRanges = 64
const bulkLookupReadChunk = 64 << 10

// BulkLookupSession is an explicit maintenance-read role. It releases consumed
// immutable record pages, including outward page alignment; concurrent ordinary
// lookups may need to recache those pages. It never advises index files and never
// closes its underlying Reader. The caller retains the Reader/cache lease until
// after the session is closed. Calls on one session are serialized.
type BulkLookupSession struct {
	mu       sync.Mutex
	reader   *Reader
	ranges   [bulkLookupMaxRanges]catalogCacheRange
	count    int
	bytes    int64
	pageSize int64
	closed   bool
	advice   func(*os.File, int64, int64)
}

func (reader *Reader) NewBulkLookupSession() (*BulkLookupSession, error) {
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	if reader.closed {
		return nil, ErrClosed
	}
	return &BulkLookupSession{reader: reader, pageSize: int64(os.Getpagesize()), advice: adviseCatalogCache}, nil
}

func (session *BulkLookupSession) LookupUnique(ctx context.Context, kind Kind, key Key) (Record, error) {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return Record{}, ErrClosed
	}
	reader := session.reader
	reader.mu.RLock()
	defer reader.mu.RUnlock()
	if reader.closed {
		return Record{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	entry, err := reader.uniqueEntry(ctx, kind, key)
	if err != nil {
		return Record{}, err
	}
	if entry.length == 0 || entry.length > maxRecordBytes {
		return Record{}, ErrIntegrity
	}
	data, _, err := readFrameAt(bulkLookupReaderAt{session: session, ctx: ctx}, reader.ref.Records.Bytes, entry.offset, entry.length)
	if err != nil {
		if err := ctx.Err(); err != nil {
			return Record{}, err
		}
		return Record{}, err
	}
	var record Record
	if json.Unmarshal(data, &record) != nil || !validRecord(record) {
		return Record{}, ErrIntegrity
	}
	if [4]Key{{}, record.Stable, record.Endpoint, record.Logical}[kind] != key {
		return Record{}, ErrIntegrity
	}
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	return record, nil
}

// Flush is best-effort cache advice, not a file sync or a durability boundary.
func (session *BulkLookupSession) Flush() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return ErrClosed
	}
	return session.flushWithReaderLock()
}

func (session *BulkLookupSession) Close() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	err := session.flushWithReaderLock()
	session.closed = true
	return err
}

func (session *BulkLookupSession) flushWithReaderLock() error {
	session.reader.mu.RLock()
	defer session.reader.mu.RUnlock()
	if session.reader.closed {
		session.count = 0
		session.bytes = 0
		return ErrClosed
	}
	session.flushLocked()
	return nil
}

func (session *BulkLookupSession) flushLocked() {
	for _, region := range session.ranges[:session.count] {
		session.advice(session.reader.files[0], region.offset, region.length)
	}
	session.count, session.bytes = 0, 0
}

// The fixed array stays sorted. Only overlapping/adjacent page ranges merge.
// A prospective read is admitted before I/O; its actual consumed range is then
// committed, including partial reads that later return an integrity error.
func (session *BulkLookupSession) mergeRange(region catalogCacheRange, commit bool) bool {
	first := 0
	for first < session.count && session.ranges[first].offset+session.ranges[first].length < region.offset {
		first++
	}
	last := first
	removed := int64(0)
	end := region.offset + region.length
	for last < session.count && session.ranges[last].offset <= end {
		current := session.ranges[last]
		region.offset = min(region.offset, current.offset)
		end = max(end, current.offset+current.length)
		removed += current.length
		last++
	}
	region.length = end - region.offset
	count := session.count - (last - first) + 1
	bytes := session.bytes - removed + region.length
	if count > bulkLookupMaxRanges || bytes > catalogCacheWindow {
		return false
	}
	if commit {
		copy(session.ranges[first+1:count], session.ranges[last:session.count])
		session.ranges[first] = region
		session.count, session.bytes = count, bytes
	}
	return true
}

func (session *BulkLookupSession) alignedRange(offset int64, length int) (catalogCacheRange, error) {
	page := session.pageSize
	if offset < 0 || length < 1 || page < 1 || offset > math.MaxInt64-int64(length)-(page-1) {
		return catalogCacheRange{}, ErrIntegrity
	}
	start := offset / page * page
	end := (offset + int64(length) + page - 1) / page * page
	return catalogCacheRange{offset: start, length: end - start}, nil
}

type bulkLookupReaderAt struct {
	session *BulkLookupSession
	ctx     context.Context
}

func (reader bulkLookupReaderAt) ReadAt(data []byte, offset int64) (int, error) {
	session := reader.session
	total := 0
	for len(data) > 0 {
		if err := reader.ctx.Err(); err != nil {
			return total, err
		}
		length := min(len(data), bulkLookupReadChunk)
		planned, err := session.alignedRange(offset, length)
		if err != nil {
			return total, err
		}
		startPage := catalogCacheRange{offset: planned.offset, length: session.pageSize}
		if !session.mergeRange(planned, false) || !session.mergeRange(startPage, false) {
			session.flushLocked()
		}
		if err := reader.ctx.Err(); err != nil {
			return total, err
		}
		if !session.mergeRange(planned, false) {
			return total, ErrIntegrity
		}
		n, err := session.reader.files[0].ReadAt(data[:length], offset)
		if n > 0 {
			actual, rangeErr := session.alignedRange(offset, n)
			if rangeErr != nil || !session.mergeRange(actual, true) {
				return total, ErrIntegrity
			}
			total += n
			offset += int64(n)
			data = data[n:]
		}
		if err != nil {
			return total, err
		}
		if n != length {
			return total, ErrIntegrity
		}
	}
	return total, nil
}
