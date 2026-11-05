package subscriptioncatalog

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
)

func headroomBuilder(t *testing.T) (*Builder, string) {
	t.Helper()
	path := privateRoot(t)
	builder, err := NewBuilder(path, Limits{SortChunkBytes: 64 << 10, MergeFanIn: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = builder.Abort() })
	return builder, path
}

func TestCatalogBuilderHeadroomRejectsBeforeFirstWriteAndStaysFailed(t *testing.T) {
	builder, path := headroomBuilder(t)
	calls := 0
	builder.checkSpace = func(actual string, needed uint64) error {
		calls++
		if actual != path || needed != catalogStorageHeadroom+catalogStorageWriteQuantum {
			t.Fatal("capacity check omitted anchored path or write quantum")
		}
		return storagebudget.ErrNoSpace
	}
	if err := builder.Append(context.Background(), syntheticRecord(1)); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("append: %v", err)
	}
	info, err := builder.files[0].Stat()
	if err != nil || info.Size() != 0 || builder.diskBytes != 0 {
		t.Fatal("headroom refusal wrote record bytes")
	}
	if err := builder.Append(context.Background(), syntheticRecord(2)); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("failed append retried: %v", err)
	}
	if _, err := builder.Seal(context.Background()); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("failed build sealed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("failed builder repeated capacity queries: %d", calls)
	}
	assertNoPublished(t, path)
}

func TestCatalogBuilderHeadroomAmortizesChecksAtExactWriteBoundary(t *testing.T) {
	builder, path := headroomBuilder(t)
	calls := 0
	builder.checkSpace = func(actual string, needed uint64) error {
		calls++
		if actual != path || needed != catalogStorageHeadroom+catalogStorageWriteQuantum {
			t.Fatal("wrong capacity boundary")
		}
		return nil
	}
	block := make([]byte, 1024)
	for count := 0; count < catalogStorageWriteQuantum/len(block); count++ {
		if err := builder.write(builder.files[0], block); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("one MiB required %d checks", calls)
	}
	if err := builder.write(builder.files[0], []byte{1}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("crossing one MiB did not recheck: %d", calls)
	}
}

func TestCatalogBuilderHeadroomIncludesWholeLargeWriteAndUnknownCapacity(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "insufficient", true: "unavailable"}[unknown], func(t *testing.T) {
			builder, _ := headroomBuilder(t)
			payload := make([]byte, 3*catalogStorageWriteQuantum)
			builder.checkSpace = func(_ string, needed uint64) error {
				if needed != uint64(catalogStorageHeadroom+len(payload)) {
					t.Fatal("large write was admitted against only a small quantum")
				}
				if unknown {
					return storagebudget.ErrUnavailable
				}
				return storagebudget.ErrNoSpace
			}
			want := ErrNoSpace
			if unknown {
				want = ErrIO
			}
			if err := builder.write(builder.files[0], payload); !errors.Is(err, want) {
				t.Fatalf("write error=%v want=%v", err, want)
			}
			info, err := builder.files[0].Stat()
			if err != nil || info.Size() != 0 {
				t.Fatal("capacity failure wrote a large record")
			}
		})
	}
}

func TestCatalogBuilderHeadroomCoversSortAndBufferedMerge(t *testing.T) {
	for _, phase := range []string{"sort", "merge"} {
		t.Run(phase, func(t *testing.T) {
			builder, path := headroomBuilder(t)
			builder.checkSpace = func(string, uint64) error { return nil }
			if phase == "sort" {
				if err := builder.Append(context.Background(), syntheticRecord(1)); err != nil {
					t.Fatal(err)
				}
			} else {
				for index := 0; index < 2; index++ {
					file, err := builder.create(runName(0, 0, index))
					if err != nil {
						t.Fatal(err)
					}
					entry := indexEntry{key: sha256.Sum256([]byte{byte(index)}), length: 1}
					if err := builder.writeEntry(file, entry); err != nil {
						t.Fatal(err)
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Model another process consuming storage after the preceding
			// quantum. No filesystem query is injected into a global hook.
			builder.spaceCredit = 0
			calls := 0
			builder.checkSpace = func(string, uint64) error { calls++; return storagebudget.ErrNoSpace }
			var err error
			if phase == "sort" {
				_, err = builder.Seal(context.Background())
			} else {
				err = builder.mergeRuns(context.Background(), 0, 0, 0, 2, 0)
			}
			if !errors.Is(err, ErrNoSpace) || calls != 1 {
				t.Fatalf("%s bypassed headroom: calls=%d err=%v", phase, calls, err)
			}
			assertNoPublished(t, path)
		})
	}
}

func TestCatalogBuilderHeadroomRejectsReplacedRootPath(t *testing.T) {
	builder, path := headroomBuilder(t)
	oldPath := filepath.Join(filepath.Dir(path), "moved-catalog")
	if err := os.Rename(path, oldPath); err != nil {
		t.Skip("opened directory cannot be renamed on this filesystem")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	builder.checkSpace = func(string, uint64) error { t.Fatal("queried a replacement filesystem path"); return nil }
	if err := builder.Append(context.Background(), syntheticRecord(1)); !errors.Is(err, ErrIO) {
		t.Fatalf("replaced root: %v", err)
	}
}
