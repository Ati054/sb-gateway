package subscriptioncatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func syntheticRecord(number int) Record {
	return Record{
		ID:       fmt.Sprintf("source-node-%05d", number),
		Stable:   sha256.Sum256([]byte(fmt.Sprintf("stable-%d", number))),
		Endpoint: sha256.Sum256([]byte(fmt.Sprintf("endpoint-%d", number))),
		Logical:  sha256.Sum256([]byte(fmt.Sprintf("logical-%d", number))),
		Node:     json.RawMessage(fmt.Sprintf(`{"id":"provider-%d","transport":"%s"}`, number, []string{"ws", "grpc", "tcp"}[number%3])),
		Metadata: json.RawMessage(fmt.Sprintf(`{"display":"synthetic-%d","transport":"%s"}`, number, []string{"ws", "grpc", "tcp"}[number%3])),
		Secrets:  json.RawMessage(fmt.Sprintf(`{"password":"synthetic-credential-%05d"}`, number)),
	}
}

func privateRoot(t *testing.T) string {
	t.Helper()
	// testing.TempDir returns a leaf created with 0777 subject to umask;
	// its private parent does not make that leaf a 0700 catalog root.
	path := filepath.Join(t.TempDir(), "catalog")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildSynthetic(t *testing.T, path string, limits Limits, records ...Record) Ref {
	t.Helper()
	builder, err := NewBuilder(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	for _, record := range records {
		if err := builder.Append(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := builder.Seal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func assertNoPublished(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if validDigest(entry.Name()) {
			t.Fatal("partial generation published")
		}
	}
}

func TestCatalogExternalSortFullInventory(t *testing.T) {
	for _, count := range []int{1000, 5000, 10000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			path := privateRoot(t)
			// A small chunk and two-way merge require several merge passes.
			builder, err := NewBuilder(path, Limits{SortChunkBytes: 64 << 10, MergeFanIn: 2})
			if err != nil {
				t.Fatal(err)
			}
			defer builder.Abort()
			for i := count - 1; i >= 0; i-- {
				if err := builder.Append(context.Background(), syntheticRecord(i)); err != nil {
					t.Fatal(err)
				}
			}
			assertNoPublished(t, path)
			ref, err := builder.Seal(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if ref.Count != uint64(count) || ref.Indexes[0].Bytes != int64(count*entryBytes) {
				t.Fatal("inventory truncated")
			}
			inspected, err := Inspect(path, ref.Generation)
			if err != nil || inspected != ref {
				t.Fatalf("manifest roundtrip: %v", err)
			}
			reader, err := Open(path, ref)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			walked := 0
			err = reader.Walk(context.Background(), func(record Record) error {
				want := syntheticRecord(count - 1 - walked)
				if !reflect.DeepEqual(record, want) {
					return errors.New("record mismatch")
				}
				walked++
				return nil
			})
			if err != nil || walked != count {
				t.Fatalf("walk count=%d: %v", walked, err)
			}
			for _, number := range []int{0, count / 2, count - 1} {
				want := syntheticRecord(number)
				actual, err := reader.Get(context.Background(), want.ID)
				if err != nil || !reflect.DeepEqual(actual, want) {
					t.Fatalf("ID lookup: %v", err)
				}
				for kind, key := range map[Kind]Key{Stable: want.Stable, Endpoint: want.Endpoint, Logical: want.Logical} {
					actual, err := reader.LookupUnique(context.Background(), kind, key)
					if err != nil || !reflect.DeepEqual(actual, want) {
						t.Fatalf("identity lookup: %v", err)
					}
				}
			}
			if _, err := reader.Get(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
				t.Fatal(err)
			}
			// Metadata iteration must not depend on the private record descriptor.
			private := reader.files[0]
			reader.files[0] = nil
			metadataCount := 0
			err = reader.WalkMetadata(context.Background(), func(record MetadataRecord) error {
				if bytes.Contains(record.Data, []byte("credential")) || bytes.Contains(record.Data, []byte("password")) {
					return errors.New("private field in metadata")
				}
				metadataCount++
				return nil
			})
			reader.files[0] = private
			if err != nil || metadataCount != count {
				t.Fatalf("metadata count=%d: %v", metadataCount, err)
			}
			files, err := os.ReadDir(filepath.Join(path, ref.Generation))
			if err != nil || len(files) != 7 {
				t.Fatalf("temporary files retained: %v", err)
			}
		})
	}
}

func TestCatalogDuplicateAndAmbiguousIdentities(t *testing.T) {
	path := privateRoot(t)
	first, second := syntheticRecord(1), syntheticRecord(2)
	second.Stable = first.Stable
	ref := buildSynthetic(t, path, Limits{}, first, second)
	reader, err := Open(path, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := reader.LookupUnique(context.Background(), Stable, first.Stable); !errors.Is(err, ErrAmbiguous) {
		t.Fatal(err)
	}
	if _, err := reader.LookupUnique(context.Background(), Endpoint, first.Endpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.LookupUnique(context.Background(), Logical, Key{}); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	duplicateRoot := privateRoot(t)
	builder, err := NewBuilder(duplicateRoot, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer builder.Abort()
	for i := 0; i < 2; i++ {
		if err := builder.Append(context.Background(), first); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := builder.Seal(context.Background()); !errors.Is(err, ErrDuplicateID) {
		t.Fatal(err)
	}
	assertNoPublished(t, duplicateRoot)
}

func TestCatalogImmutableGenerationsAndConcurrentReads(t *testing.T) {
	path := privateRoot(t)
	first := syntheticRecord(1)
	old := buildSynthetic(t, path, Limits{}, first, syntheticRecord(2))
	if again := buildSynthetic(t, path, Limits{}, first, syntheticRecord(2)); again != old {
		t.Fatal("non-deterministic content identity")
	}
	reader, err := Open(path, old)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	changed := first
	changed.Secrets = json.RawMessage(`{"password":"synthetic-changed"}`)
	next := buildSynthetic(t, path, Limits{}, changed, syntheticRecord(2))
	reordered := buildSynthetic(t, path, Limits{}, syntheticRecord(2), first)
	if old.Generation == next.Generation || old.Generation == reordered.Generation {
		t.Fatal("content change omitted from generation")
	}
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < 32; i++ {
				actual, err := reader.Get(context.Background(), first.ID)
				if err != nil {
					failures <- err
					return
				}
				if !reflect.DeepEqual(actual, first) {
					failures <- errors.New("old generation changed")
					return
				}
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	for _, ref := range []Ref{old, next, reordered} {
		if _, err := Inspect(path, ref.Generation); err != nil {
			t.Fatal(err)
		}
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Get(context.Background(), first.ID); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestCatalogLimitsCancellationAndMalformedInput(t *testing.T) {
	for _, scenario := range []string{"record", "canonical", "disk", "malformed-tail", "long-id", "cancel-append", "cancel-seal"} {
		t.Run(scenario, func(t *testing.T) {
			path := privateRoot(t)
			limits, record := Limits{}, syntheticRecord(1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := ErrLimit
			switch scenario {
			case "record":
				limits.MaxRecordBytes = 64
			case "canonical":
				limits.MaxCanonicalBytes = 64
			case "disk":
				limits.MaxDiskBytes = 64
			case "malformed-tail":
				record.Node = json.RawMessage(`{"good":true} trailing`)
				want = ErrInvalidRecord
			case "long-id":
				record.ID = strings.Repeat("x", maxIDBytes+1)
				want = ErrInvalidRecord
			case "cancel-append":
				cancel()
				want = context.Canceled
			case "cancel-seal":
				want = context.Canceled
			}
			builder, err := NewBuilder(path, limits)
			if err != nil {
				t.Fatal(err)
			}
			defer builder.Abort()
			err = builder.Append(ctx, record)
			if scenario == "cancel-seal" {
				if err != nil {
					t.Fatal(err)
				}
				cancel()
				_, err = builder.Seal(ctx)
			}
			if !errors.Is(err, want) {
				t.Fatalf("expected safe failure: %v", err)
			}
			if strings.Contains(err.Error(), "synthetic-credential") || strings.Contains(err.Error(), record.ID) {
				t.Fatal("record data in error")
			}
			assertNoPublished(t, path)
			if err := builder.Abort(); err != nil {
				t.Fatal(err)
			}
			entries, _ := os.ReadDir(path)
			if len(entries) != 0 {
				t.Fatal("owned staging directory retained after abort")
			}
		})
	}
	if !errors.Is(storageError(syscall.ENOSPC), ErrNoSpace) {
		t.Fatal("ENOSPC classification lost")
	}
}

func TestCatalogNearEightMiBRecordAndKeyEncoding(t *testing.T) {
	record := syntheticRecord(1)
	record.Node = json.RawMessage(`{"payload":"` + strings.Repeat("x", (8<<20)-8192) + `"}`)
	path := privateRoot(t)
	ref := buildSynthetic(t, path, Limits{}, record)
	reader, err := Open(path, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	actual, err := reader.Get(context.Background(), record.ID)
	if err != nil || !bytes.Equal(actual.Node, record.Node) {
		t.Fatal("long record changed")
	}
	encoded, err := json.Marshal(record.Stable)
	if err != nil || len(encoded) != 66 {
		t.Fatal("identity is not compact hex")
	}
	var key Key
	if err := json.Unmarshal(encoded, &key); err != nil || key != record.Stable {
		t.Fatal("key roundtrip failed")
	}
	if _, err := ParseKey(strings.Repeat("A", 64)); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("noncanonical key accepted")
	}
}

func TestCatalogCorruptionAndPathSafety(t *testing.T) {
	for _, name := range []string{"records.bin", "metadata.bin", "id.idx", "stable.idx", "endpoint.idx", "logical.idx"} {
		t.Run(name, func(t *testing.T) {
			path := privateRoot(t)
			ref := buildSynthetic(t, path, Limits{}, syntheticRecord(1))
			file, err := os.OpenFile(filepath.Join(path, ref.Generation, name), os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			original, readErr := os.ReadFile(filepath.Join(path, ref.Generation, name))
			if readErr != nil || len(original) == 0 {
				_ = file.Close()
				t.Fatal("missing synthetic file")
			}
			_, err = file.WriteAt([]byte{original[0] ^ 0xff}, 0)
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			if reader, err := Open(path, ref); !errors.Is(err, ErrIntegrity) {
				if reader != nil {
					reader.Close()
				}
				t.Fatalf("corruption accepted: %v", err)
			}
		})
	}
	if _, err := Inspect(t.TempDir(), "../outside"); !errors.Is(err, ErrInvalidRef) {
		t.Fatal("unsafe generation accepted")
	}
	if runtime.GOOS != "windows" {
		path := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(t.TempDir(), path); err != nil {
			t.Fatal(err)
		}
		if _, err := NewBuilder(path, Limits{}); !errors.Is(err, ErrUnsafePath) {
			t.Fatal("symlink root accepted")
		}
		root := privateRoot(t)
		if err := os.Chmod(root, 0500); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(root, 0700)
		if _, err := NewBuilder(root, Limits{}); !errors.Is(err, ErrUnsafePath) {
			t.Fatal("nonprivate/read-only root accepted")
		}
	}
}

func TestCatalogPostOpenBoundsAndCanceledWalk(t *testing.T) {
	path := privateRoot(t)
	record := syntheticRecord(1)
	ref := buildSynthetic(t, path, Limits{}, record, syntheticRecord(2))
	reader, err := Open(path, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	ctx, cancel := context.WithCancel(context.Background())
	if err := reader.WalkMetadata(ctx, func(MetadataRecord) error { cancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(path, ref.Generation, "records.bin"), os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], ^uint32(0))
	_, err = file.WriteAt(header[:], 0)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Get(context.Background(), record.ID); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unbounded corrupted frame accepted")
	}
}

func TestCatalogOpenedDirectoryIdentity(t *testing.T) {
	first, second := privateRoot(t), privateRoot(t)
	before, err := os.Lstat(first)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := os.OpenRoot(first)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if !sameOpenedDirectory(opened, before) {
		t.Fatal("unchanged private directory rejected")
	}
	other, err := os.OpenRoot(second)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if sameOpenedDirectory(other, before) {
		t.Fatal("replacement directory identity accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(first, 0755); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(first, 0700)
		if sameOpenedDirectory(opened, before) {
			t.Fatal("changed directory permissions accepted")
		}
	}
}
