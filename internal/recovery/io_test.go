package recovery

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
)

func TestBootRecoveryOutputWindowsAndPeriodicStorageAdmission(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "output-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := newRestoreFileWriter(file, filepath.Dir(file.Name()), nil)
	checks, syncs := 0, 0
	var dropped int64
	writer.checkSpace = func(_ string, needed uint64) error {
		checks++
		if needed != restoreStorageHeadroom+restoreStorageOverhead+restoreSpaceQuantum {
			t.Error("periodic storage allowance differs")
		}
		return nil
	}
	writer.syncFile = func() error { syncs++; return file.Sync() }
	writer.dropRange = func(_ *os.File, offset, length int64) {
		if offset != dropped || length != restoreFileWindow {
			t.Error("output cache hint escaped completed owned window")
		}
		dropped += length
	}
	body := make([]byte, restoreFileWindow+23)
	for range 2 {
		if n, err := writer.Write(body); err != nil || n != len(body) {
			t.Fatalf("write: %d %v", n, err)
		}
	}
	if syncs != 2 || dropped != 2*restoreFileWindow || writer.pending != 46 || checks != 17 {
		t.Fatalf("window counters checks=%d syncs=%d dropped=%d pending=%d", checks, syncs, dropped, writer.pending)
	}
	info, err := file.Stat()
	if err != nil || info.Size() != int64(2*len(body)) {
		t.Fatal("actual >16MiB output size differs")
	}
	writer.credit = 0
	writer.checkSpace = func(string, uint64) error { return storagebudget.ErrNoSpace }
	if n, err := writer.Write([]byte("new")); n != 0 || !errors.Is(err, storagebudget.ErrNoSpace) {
		t.Fatal("storage rejection was swallowed or wrote bytes")
	}
	after, _ := file.Stat()
	if after.Size() != info.Size() {
		t.Fatal("rejected write changed actual file")
	}
}

func TestBootRecoveryBulkReaderKeepsSmallInputsAndHintsConsumedPages(t *testing.T) {
	for _, size := range []int64{4096, 2*restoreFileWindow + 37} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "input-")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := file.Truncate(size); err != nil {
				t.Fatal(err)
			}
			reader := newRestoreFileReader(file)
			var advised int64
			reader.dropRange = func(_ *os.File, offset, length int64) {
				if offset != advised || offset+length > reader.position {
					t.Error("input hint included unread pages")
				}
				advised += length
			}
			n, err := io.CopyBuffer(io.Discard, reader, make([]byte, 64<<10))
			if err != nil || n != size {
				t.Fatal("streamed actual input failed")
			}
			if size < restoreFileWindow && advised != 0 {
				t.Fatal("small shared index was evicted")
			}
			if size > restoreFileWindow && advised < 2*restoreFileWindow {
				t.Fatal("bulk consumed windows were never hinted")
			}
		})
	}
}

func TestBootRecoveryAdmissionAccountsPayloadBeforeCopy(t *testing.T) {
	root := t.TempDir()
	prepared := preparedRestore{total: 19 << 20}
	calls := 0
	err := prepared.admitStorageWith(func(path string, needed uint64) error {
		calls++
		if needed != (19<<20)+restoreStorageHeadroom+restoreStorageOverhead {
			t.Error("initial destination admission omitted full payload")
		}
		if calls == 2 {
			return storagebudget.ErrNoSpace
		}
		return nil
	}, filepath.Join(root, "config"), filepath.Join(root, "state"), filepath.Join(root, "data"))
	if !errors.Is(err, storagebudget.ErrNoSpace) || calls != 2 {
		t.Fatal("destination storage admission failure was swallowed")
	}
}
