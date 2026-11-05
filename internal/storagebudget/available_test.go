//go:build linux || windows

package storagebudget

import (
	"errors"
	"math"
	"path/filepath"
	"testing"
)

func TestAdmissionUsesActualAvailableBytes(t *testing.T) {
	root := t.TempDir()
	if err := Check(root, 1); err != nil {
		t.Fatal(err)
	}
	if err := Check(root, math.MaxUint64); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("impossible admission: %v", err)
	}
	if err := Check(filepath.Join(root, "missing"), 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing filesystem: %v", err)
	}
}
