package controlplane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImageUploadWriterFlushesBoundedWindowsAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upload.tar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := newImageUploadWriter(file)
	var ranges [][2]int64
	writer.flushRange = func(offset, length int64) error {
		ranges = append(ranges, [2]int64{offset, length})
		return file.Sync()
	}
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	for i := 0; i < 130; i++ {
		if count, err := writer.Write(chunk); err != nil || count != len(chunk) {
			t.Fatalf("write %d: %d, %v", i, count, err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || ranges[0] != [2]int64{0, imageUploadCacheWindow} || ranges[1] != [2]int64{imageUploadCacheWindow, 2 * int64(len(chunk))} {
		t.Fatalf("unexpected flush ranges: %#v", ranges)
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 130*int64(len(chunk)) {
		t.Fatalf("upload size changed: %v, %v", info, err)
	}
}

func TestImageUploadWriterPropagatesSyncFailure(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "upload")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	want := errors.New("storage sync failed")
	writer := newImageUploadWriter(file)
	writer.flushRange = func(_, _ int64) error { return want }
	writer.written = imageUploadCacheWindow - 1
	if count, err := writer.Write([]byte("x")); count != 1 || !errors.Is(err, want) {
		t.Fatalf("sync failure lost: %d, %v", count, err)
	}
	if writer.flushed != 0 {
		t.Fatal("failed window was marked as flushed")
	}
}
