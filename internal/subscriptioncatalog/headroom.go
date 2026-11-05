package subscriptioncatalog

import (
	"errors"
	"os"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
)

const catalogStorageHeadroom = 64 << 20
const catalogStorageWriteQuantum = 1 << 20

// The credit bounds unchecked payload growth, not available disk or memory.
// Every payload, index-sort, merge and manifest write uses Builder.write. A
// capacity query is therefore amortized over a MiB rather than paid per node.
func (b *Builder) checkWriteHeadroom(next int64) error {
	if next <= b.spaceCredit {
		return nil
	}
	path := b.root.Name()
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !privateMode(info, 0700) || !sameOpenedDirectory(b.root, info) {
		return ErrIO
	}
	quantum := max(int64(catalogStorageWriteQuantum), next)
	check := b.checkSpace
	if check == nil {
		check = storagebudget.Check
	}
	if err := check(path, uint64(catalogStorageHeadroom)+uint64(quantum)); err != nil {
		if errors.Is(err, storagebudget.ErrNoSpace) {
			return ErrNoSpace
		}
		return ErrIO
	}
	b.spaceCredit = quantum
	return nil
}
