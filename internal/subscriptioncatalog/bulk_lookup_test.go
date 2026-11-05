package subscriptioncatalog

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bulkLookupFixture(t *testing.T, count, payloadBytes int) (string, Ref, *Reader) {
	t.Helper()
	path := privateRoot(t)
	builder, err := NewBuilder(path, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	node, err := json.Marshal(strings.Repeat("x", payloadBytes))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < count; index++ {
		record := syntheticRecord(index)
		record.Node = node
		if err := builder.Append(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := builder.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := Open(path, ref)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	return path, ref, reader
}

func TestBulkLookupBoundsRandomRangesAndPreservesOrdinaryReader(t *testing.T) {
	_, _, reader := bulkLookupFixture(t, 150, 2*os.Getpagesize())
	session, err := reader.NewBulkLookupSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	advice := 0
	session.advice = func(file *os.File, offset, length int64) {
		advice++
		if file != reader.files[0] || offset%session.pageSize != 0 || length%session.pageSize != 0 || length <= 0 || session.count > bulkLookupMaxRanges || session.bytes > catalogCacheWindow {
			t.Fatal("bulk advice escaped its record/page/range budget")
		}
	}
	for index := 0; index < 150; index += 2 {
		want := syntheticRecord(index)
		record, err := session.LookupUnique(context.Background(), Stable, want.Stable)
		if err != nil || record.ID != want.ID {
			t.Fatalf("bulk identity lookup changed result: %v", err)
		}
		if session.count > bulkLookupMaxRanges || session.bytes > catalogCacheWindow {
			t.Fatal("pending bulk ranges exceeded their fixed budget")
		}
	}
	if advice == 0 {
		t.Fatal("more than 64 separated record reads never flushed")
	}
	if err := session.Flush(); err != nil {
		t.Fatal(err)
	}
	if session.count != 0 || session.bytes != 0 {
		t.Fatal("Flush retained consumed ranges")
	}
	before := advice
	want := syntheticRecord(1)
	if _, err := reader.LookupUnique(context.Background(), Stable, want.Stable); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Get(context.Background(), want.ID); err != nil {
		t.Fatal(err)
	}
	if advice != before {
		t.Fatal("ordinary lookup used the maintenance session")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal("Close is not idempotent")
	}
	if _, err := session.LookupUnique(context.Background(), Stable, want.Stable); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed session: %v", err)
	}
	if _, err := reader.Get(context.Background(), want.ID); err != nil {
		t.Fatal("session Close closed its Reader")
	}
}

func TestCheckUniqueIsIndexOnlyAndPreservesAmbiguity(t *testing.T) {
	path := privateRoot(t)
	first, second := syntheticRecord(1), syntheticRecord(2)
	shared := sha256.Sum256([]byte("shared-endpoint"))
	first.Endpoint, second.Endpoint = shared, shared
	ref := buildSynthetic(t, path, DefaultLimits(), first, second)
	reader, err := Open(path, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	// Removing only the in-memory payload handle proves the operation does not
	// decode Node/Secrets. The checked identity-index files remain available.
	reader.mu.Lock()
	payload := reader.files[0]
	reader.files[0] = nil
	reader.mu.Unlock()
	func() {
		defer func() { reader.mu.Lock(); reader.files[0] = payload; reader.mu.Unlock() }()
		if err := reader.CheckUnique(context.Background(), Stable, first.Stable); err != nil {
			t.Fatalf("index-only uniqueness accessed payload: %v", err)
		}
	}()
	session, err := reader.NewBulkLookupSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := reader.CheckUnique(context.Background(), Endpoint, shared); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("index ambiguity: %v", err)
	}
	if _, err := session.LookupUnique(context.Background(), Endpoint, shared); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("bulk ambiguity: %v", err)
	}
	if session.count != 0 {
		t.Fatal("ambiguous lookup read a private record")
	}
	for _, kind := range []Kind{Stable, Logical} {
		if err := reader.CheckUnique(context.Background(), kind, [4]Key{{}, first.Stable, first.Endpoint, first.Logical}[kind]); err != nil {
			t.Fatal(err)
		}
	}
	if err := reader.CheckUnique(context.Background(), Kind(99), first.Stable); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("invalid identity kind accepted")
	}
	if err := reader.CheckUnique(context.Background(), Stable, Key{}); !errors.Is(err, ErrNotFound) {
		t.Fatal("zero identity matched")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := reader.CheckUnique(ctx, Stable, first.Stable); !errors.Is(err, context.Canceled) {
		t.Fatalf("index cancellation: %v", err)
	}
}

func TestBulkLookupByteWindowAndCancellation(t *testing.T) {
	_, _, reader := bulkLookupFixture(t, 10, 1<<20)
	complete, err := reader.NewBulkLookupSession()
	if err != nil {
		t.Fatal(err)
	}
	completeAdvice := 0
	complete.advice = func(file *os.File, offset, length int64) {
		completeAdvice++
		if file != reader.files[0] || complete.bytes > catalogCacheWindow || complete.count > bulkLookupMaxRanges || length > catalogCacheWindow {
			t.Fatal("complete stream exceeded bulk byte window")
		}
	}
	for index := 0; index < 10; index++ {
		record, err := complete.LookupUnique(context.Background(), Stable, syntheticRecord(index).Stable)
		if err != nil || len(record.Node) != (1<<20)+2 {
			t.Fatalf("large bulk stream changed record: %v", err)
		}
	}
	if completeAdvice == 0 {
		t.Fatal("successful 10 MiB stream never flushed its 8 MiB budget")
	}
	if err := complete.Close(); err != nil {
		t.Fatal(err)
	}
	session, err := reader.NewBulkLookupSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	advice := 0
	session.advice = func(file *os.File, offset, length int64) {
		advice++
		if file != reader.files[0] || session.bytes > catalogCacheWindow || session.count > bulkLookupMaxRanges || length > catalogCacheWindow {
			t.Fatal("bulk byte window exceeded")
		}
		cancel()
	}
	var result error
	for index := 0; index < 10; index++ {
		_, result = session.LookupUnique(ctx, Stable, syntheticRecord(index).Stable)
		if result != nil {
			break
		}
	}
	if !errors.Is(result, context.Canceled) || advice == 0 {
		t.Fatalf("bulk cancellation after bounded advice: %v advice=%d", result, advice)
	}
	if err := session.Flush(); err != nil {
		t.Fatal(err)
	}
	if session.count != 0 || session.bytes != 0 {
		t.Fatal("cancelled session retained pending ranges")
	}
	if _, err := reader.Get(context.Background(), syntheticRecord(0).ID); err != nil {
		t.Fatal("cancellation damaged the ordinary Reader")
	}
}

func TestBulkLookupIntegrityFailureAccountsConsumedBytes(t *testing.T) {
	path, ref, reader := bulkLookupFixture(t, 1, 100<<10)
	session, err := reader.NewBulkLookupSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := os.Truncate(filepath.Join(path, ref.Generation, "records.bin"), 8<<10); err != nil {
		t.Fatal(err)
	}
	advice := 0
	session.advice = func(*os.File, int64, int64) { advice++ }
	if _, err := session.LookupUnique(context.Background(), Stable, syntheticRecord(0).Stable); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("truncated record: %v", err)
	}
	if session.count == 0 {
		t.Fatal("partial record read was not accounted for")
	}
	if err := session.Flush(); err != nil || advice == 0 {
		t.Fatalf("partial read was not released: %v", err)
	}
}

func TestBulkLookupDoesNotKeepClosedReaderAlive(t *testing.T) {
	_, _, reader := bulkLookupFixture(t, 1, 16)
	session, err := reader.NewBulkLookupSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := session.LookupUnique(context.Background(), Stable, syntheticRecord(0).Stable); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Reader accepted: %v", err)
	}
	if err := session.Flush(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Reader flush: %v", err)
	}
	if err := session.Close(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed Reader close: %v", err)
	}
	if _, err := reader.NewBulkLookupSession(); !errors.Is(err, ErrClosed) {
		t.Fatal("session created from closed Reader")
	}
}
