package subscriptioncatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCatalogCacheWindowIsSharedAcrossClosedWriterFiles(t *testing.T) {
	builder, _ := headroomBuilder(t)
	builder.checkSpace = func(string, uint64) error { return nil }
	var advised int64
	var syncs int
	builder.syncCacheFile = func(file *os.File) error { syncs++; return file.Sync() }
	builder.dropCacheRange = func(_ *os.File, offset, length int64) {
		if offset != 0 || length != catalogCacheWindow/16 {
			t.Fatal("wrong closed-run range")
		}
		advised += length
	}
	block := make([]byte, catalogCacheWindow/16)
	names := make([]string, 16)
	for index := range names {
		name := fmt.Sprintf("synthetic-%d.run", index)
		names[index] = name
		file, err := builder.create(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := builder.write(file, block); err != nil {
			t.Fatal(err)
		}
		if err := builder.closeWriter(file); err != nil {
			t.Fatal(err)
		}
		if index < 15 && advised != 0 {
			t.Fatal("byte window was replaced by per-file flushing")
		}
	}
	if advised != catalogCacheWindow || syncs != 16 || builder.writeWindow != 0 || len(builder.writeRanges) != 0 || len(builder.writerNames) != 6 {
		t.Fatalf("shared write window did not drain: advised=%d syncs=%d active=%d pending=%d", advised, syncs, len(builder.writerNames), len(builder.writeRanges))
	}
	// Merge readers share a window as well, instead of retaining one window
	// for each input in the bounded merge fan-in.
	window := newCatalogReadWindow()
	advised = 0
	window.advise = func(_ *os.File, offset, length int64) {
		if offset != 0 || length != int64(len(block)) {
			t.Fatal("wrong shared read range")
		}
		advised += length
	}
	for index, name := range names {
		file, err := openRegular(builder.stage, name)
		if err != nil {
			t.Fatal(err)
		}
		bulk := newCatalogBulkReaderAt(context.Background(), file, int64(len(block)))
		bulk.enabled, bulk.window = true, window
		if _, err := bulk.ReadAt(block, 0); err != nil {
			t.Fatal(err)
		}
		// Keep handles until the shared window advises all consumed ranges.
		defer file.Close()
		if index < 15 && advised != 0 {
			t.Fatal("merge input used independent cache windows")
		}
	}
	if advised != catalogCacheWindow || window.bytes != 0 || len(window.ranges) != 0 {
		t.Fatal("shared merge read window did not drain")
	}
}

func TestCatalogCacheWindowSyncFailurePreventsPublication(t *testing.T) {
	builder, path := headroomBuilder(t)
	builder.checkSpace = func(string, uint64) error { return nil }
	syncs, advice := 0, 0
	builder.syncCacheFile = func(*os.File) error { syncs++; return errors.New("synthetic sync failure") }
	builder.dropCacheRange = func(*os.File, int64, int64) { advice++ }
	node, err := json.Marshal(strings.Repeat("x", 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	var appendErr error
	for index := 0; index < 10; index++ {
		record := syntheticRecord(index)
		record.Node = node
		if appendErr = builder.Append(context.Background(), record); appendErr != nil {
			break
		}
	}
	if !errors.Is(appendErr, ErrIO) || syncs != 1 || advice != 0 || builder.diskBytes != catalogCacheWindow {
		t.Fatalf("sync failure boundary: err=%v syncs=%d advice=%d bytes=%d", appendErr, syncs, advice, builder.diskBytes)
	}
	if _, err := builder.Seal(context.Background()); !errors.Is(err, ErrIO) {
		t.Fatalf("failed window published: %v", err)
	}
	assertNoPublished(t, path)
}

func TestCatalogCacheWindowsPreserveLargeGenerationDigestAndWalk(t *testing.T) {
	builder, path := headroomBuilder(t)
	node, err := json.Marshal(strings.Repeat("x", 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 10; index++ {
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
	defer reader.Close()
	var digestBytes, walkBytes int64
	digest, err := digestFileContextWithAdvice(context.Background(), reader.files[0], func(_ *os.File, offset, length int64) {
		if offset != digestBytes || length < 1 || length > catalogCacheWindow {
			t.Fatal("SHA drop-behind skipped or oversized a range")
		}
		digestBytes += length
	})
	if err != nil || digest != ref.Records || digestBytes != ref.Records.Bytes {
		t.Fatalf("large SHA changed: err=%v bytes=%d", err, digestBytes)
	}
	reader.bulkAdvice = func(_ *os.File, offset, length int64) {
		if offset != walkBytes || length < 1 || length > catalogCacheWindow {
			t.Fatal("Walk drop-behind skipped or oversized a range")
		}
		walkBytes += length
	}
	count := 0
	if err := reader.Walk(context.Background(), func(record Record) error {
		if string(record.Node) != string(node) {
			t.Fatal("windowing changed immutable bytes")
		}
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 10 || walkBytes != ref.Records.Bytes {
		t.Fatalf("large Walk count=%d advised=%d", count, walkBytes)
	}
	before := walkBytes
	for index := 0; index < 4; index++ {
		if _, err := reader.Get(context.Background(), "source-node-00000"); err != nil {
			t.Fatal(err)
		}
	}
	if walkBytes != before {
		t.Fatal("tiny Get used bulk advice")
	}
	if err := reader.WalkMetadata(context.Background(), func(MetadataRecord) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if walkBytes != before {
		t.Fatal("small hot metadata used bulk advice")
	}
}
